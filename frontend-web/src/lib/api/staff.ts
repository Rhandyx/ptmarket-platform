import "server-only";
import type { Middleware } from "openapi-fetch";
import { ApiError } from "./index";
import type { components } from "./schema";
import { createServerApi, type ServerApiOptions } from "./server";

// Helper de servidor para o backoffice (spec 12 §2–§3). Regras:
// - reenvia a Origin do pedido (o backend recusa mutações sem Origin do mesmo site);
// - obtém o csrf_token no servidor antes de cada mutação (X-CSRF-Token só em mutações);
// - copia para o browser TODOS os Set-Cookie da API, com os mesmos atributos;
// - cookies, passwords, códigos e tokens nunca vão para logs nem para mensagens de erro.

export type StaffMe = components["schemas"]["StaffMe"];
export type StaffRole = components["schemas"]["Role"];
type StaffLoginResponse = components["schemas"]["StaffLoginResponse"];
type SessionStatus = components["schemas"]["SessionStatus"];

type HeaderSource = { get(name: string): string | null };

/** Cookie já separado em atributos (formato de `cookies().set()` do Next). */
export type CopiedCookie = {
  name: string;
  value: string;
  path?: string;
  domain?: string;
  maxAge?: number;
  expires?: Date;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: "strict" | "lax" | "none";
  partitioned?: boolean;
  priority?: "low" | "medium" | "high";
};

/** Destino dos Set-Cookie (em Server Actions: `await cookies()`). */
export type CookieSink = { set(cookie: CopiedCookie): unknown };

export type StaffDeps = {
  incoming: HeaderSource;
  /** Sem sink (ex.: Server Components) os Set-Cookie não são copiados. */
  cookies?: CookieSink;
  /** Só para testes. */
  api?: ServerApiOptions;
};

export type StaffFailure =
  | { ok: false; kind: "unauthorized"; captchaRequired: boolean }
  | { ok: false; kind: "forbidden" }
  | { ok: false; kind: "conflict" }
  | { ok: false; kind: "invalid" }
  | { ok: false; kind: "rate_limited"; retryAfterSeconds: number | null }
  | { ok: false; kind: "unavailable" };

export type StaffResult<T> = { ok: true; value: T } | StaffFailure;

/** Nome do cookie de backoffice (definido pelo backend; só usado para o limpar se o logout falhar). */
export const STAFF_COOKIE = "__Host-ptm_admin";

// ---------------------------------------------------------------- Set-Cookie

const SAME_SITE = { strict: "strict", lax: "lax", none: "none" } as const;
const PRIORITY = { low: "low", medium: "medium", high: "high" } as const;

/**
 * Separa um cabeçalho Set-Cookie em atributos, sem alterar nenhum. O Next volta a codificar o
 * valor com encodeURIComponent: só aceitamos valores que fazem esse percurso sem mudar.
 * Devolve `null` se o cabeçalho não puder ser copiado fielmente.
 */
export function parseSetCookie(header: string): CopiedCookie | null {
  const [pair = "", ...attrs] = header.split(";");
  const eq = pair.indexOf("=");
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const raw = pair.slice(eq + 1).trim();
  if (!name) return null;
  let value: string;
  try {
    value = decodeURIComponent(raw);
  } catch {
    return null;
  }
  if (encodeURIComponent(value) !== raw) return null;

  const c: CopiedCookie = { name, value };
  for (const a of attrs) {
    const i = a.indexOf("=");
    const key = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
    const val = i < 0 ? "" : a.slice(i + 1).trim();
    switch (key) {
      case "path":
        c.path = val;
        break;
      case "domain":
        c.domain = val;
        break;
      case "max-age": {
        if (!/^-?\d+$/.test(val)) return null;
        c.maxAge = Number(val);
        break;
      }
      case "expires": {
        const d = new Date(val);
        if (Number.isNaN(d.getTime())) return null;
        c.expires = d;
        break;
      }
      case "secure":
        c.secure = true;
        break;
      case "httponly":
        c.httpOnly = true;
        break;
      case "samesite": {
        const s = SAME_SITE[val.toLowerCase() as keyof typeof SAME_SITE];
        if (!s) return null;
        c.sameSite = s;
        break;
      }
      case "partitioned":
        c.partitioned = true;
        break;
      case "priority": {
        const p = PRIORITY[val.toLowerCase() as keyof typeof PRIORITY];
        if (!p) return null;
        c.priority = p;
        break;
      }
      case "":
        break;
      default:
        // Atributo desconhecido: não o podemos reproduzir, logo não copiamos à metade.
        return null;
    }
  }
  return c;
}

/** Cookies que a API pode definir através do painel (sessão de plataforma e de tenant). */
const ALLOWED_COOKIES: ReadonlySet<string> = new Set(["__Host-ptm_admin", "__Host-ptm_session"]);

/** Regras do prefixo `__Host-` (RFC 6265bis): Secure, Path=/ e sem Domain. */
function hostPrefixOk(c: CopiedCookie): boolean {
  return !c.name.startsWith("__Host-") || (c.secure === true && c.path === "/" && c.domain === undefined);
}

/**
 * Copia todos os Set-Cookie de `res` para `sink`. Lança (falha fechada) se algum não puder ser
 * copiado fielmente, não estiver na lista de cookies esperados ou violar o prefixo `__Host-`.
 */
export function copySetCookies(res: Response, sink: CookieSink | undefined): void {
  if (!sink) return;
  const all = res.headers.getSetCookie();
  const parsed = all.map(parseSetCookie);
  const ok = (c: CopiedCookie | null): c is CopiedCookie =>
    c !== null && ALLOWED_COOKIES.has(c.name) && hostPrefixOk(c);
  if (!parsed.every(ok)) throw new Error("Set-Cookie da API não pode ser copiado");
  for (const c of parsed) sink.set(c);
}

// ---------------------------------------------------------------- chamadas

type Api = ReturnType<typeof createServerApi>;

/** Segundos do Retry-After (número ou data HTTP). */
export function retryAfterSeconds(res: Response | undefined, now = Date.now()): number | null {
  const v = res?.headers.get("retry-after")?.trim();
  if (!v) return null;
  if (/^\d+$/.test(v)) return Number(v);
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : Math.max(0, Math.ceil((t - now) / 1000));
}

async function failureFrom(status: number, res: Response | undefined): Promise<StaffFailure> {
  switch (status) {
    case 401: {
      let captchaRequired = false;
      try {
        const body: unknown = res ? await res.clone().json() : undefined;
        captchaRequired =
          !!body && typeof body === "object" && (body as { captcha_required?: unknown }).captcha_required === true;
      } catch {
        captchaRequired = false;
      }
      return { ok: false, kind: "unauthorized", captchaRequired };
    }
    case 403:
      return { ok: false, kind: "forbidden" };
    case 409:
      return { ok: false, kind: "conflict" };
    case 400:
    case 422:
      return { ok: false, kind: "invalid" };
    case 429:
      return { ok: false, kind: "rate_limited", retryAfterSeconds: retryAfterSeconds(res) };
    default:
      return { ok: false, kind: "unavailable" };
  }
}

/**
 * Corre `fn` com um cliente de servidor; guarda a última resposta (para Set-Cookie, Retry-After
 * e corpo do 401) antes de o middleware de erros a transformar em ApiError.
 */
async function run<T>(deps: StaffDeps, fn: (api: Api) => Promise<T>): Promise<StaffResult<{ data: T; res: Response }>> {
  let last: Response | undefined;
  const capture: Middleware = {
    onResponse({ response }) {
      last = response.clone();
      return undefined;
    },
  };
  try {
    const api = createServerApi(deps.incoming, deps.api ?? {});
    api.use(capture);
    let data: T;
    try {
      data = await fn(api);
    } finally {
      if (last) copySetCookies(last, deps.cookies);
    }
    if (!last) return { ok: false, kind: "unavailable" };
    return { ok: true, value: { data, res: last } };
  } catch (e) {
    if (e instanceof ApiError) return failureFrom(e.status, last);
    // Rede, configuração ou Set-Cookie inválido: nunca expor o detalhe.
    return { ok: false, kind: "unavailable" };
  }
}

/** Cabeçalhos de uma mutação: Origin do pedido e, se houver sessão, o token CSRF obtido agora. */
async function mutationHeaders(deps: StaffDeps): Promise<StaffResult<{ headers: Record<string, string>; session: SessionStatus }>> {
  const s = await run(deps, (api) => api.GET("/api/v1/auth/session"));
  if (!s.ok) return s;
  const session = s.value.data.data;
  if (!session) return { ok: false, kind: "unavailable" };
  const headers: Record<string, string> = {};
  const origin = deps.incoming.get("origin");
  if (origin) headers.Origin = origin;
  if (session.csrf_token) headers["X-CSRF-Token"] = session.csrf_token;
  return { ok: true, value: { headers, session } };
}

export type LoginInput = { email: string; password: string; turnstileToken?: string };

/** POST /api/v1/staff/auth/login → `mfaRequired`. */
export async function staffLogin(deps: StaffDeps, input: LoginInput): Promise<StaffResult<{ mfaRequired: boolean }>> {
  const m = await mutationHeaders(deps);
  if (!m.ok) return m;
  const r = await run(deps, (api) =>
    api.POST("/api/v1/staff/auth/login", {
      body: {
        email: input.email,
        password: input.password,
        ...(input.turnstileToken ? { turnstile_token: input.turnstileToken } : {}),
      },
      headers: m.value.headers,
    }),
  );
  if (!r.ok) return r;
  // O operationId "login" está duplicado no openapi.json (cliente e staff): o tipo gerado da
  // resposta é o do login de cliente. Lemos o corpo com o tipo gerado StaffLoginResponse.
  let body: Partial<StaffLoginResponse> = {};
  try {
    body = (await r.value.res.json()) as Partial<StaffLoginResponse>;
  } catch {
    body = {};
  }
  // Na dúvida, pede o 2FA (o backend decide; /painel volta a verificar).
  return { ok: true, value: { mfaRequired: body.mfa_required !== false } };
}

/** GET /api/v1/staff/me. */
export async function staffMe(deps: StaffDeps): Promise<StaffResult<StaffMe>> {
  const r = await run(deps, (api) => api.GET("/api/v1/staff/me"));
  if (!r.ok) return r;
  const me = r.value.data.data;
  return me ? { ok: true, value: me } : { ok: false, kind: "unavailable" };
}

/** POST /api/v1/staff/mfa/verify. Sem sessão: `unauthorized` sem chamar o verify. */
export async function staffVerifyMfa(deps: StaffDeps, code: string): Promise<StaffResult<null>> {
  const m = await mutationHeaders(deps);
  if (!m.ok) return m;
  const token = m.value.headers["X-CSRF-Token"];
  if (!m.value.session.authenticated || !token) return { ok: false, kind: "forbidden" };
  const r = await run(deps, (api) =>
    api.POST("/api/v1/staff/mfa/verify", {
      params: { header: { "X-CSRF-Token": token } },
      body: { code },
      headers: m.value.headers,
    }),
  );
  return r.ok ? { ok: true, value: null } : r;
}

/** POST /api/v1/auth/logout. Sem sessão: sucesso (idempotente). */
export async function staffLogout(deps: StaffDeps): Promise<StaffResult<null>> {
  const m = await mutationHeaders(deps);
  if (!m.ok) return m;
  if (!m.value.session.authenticated) return { ok: true, value: null };
  const r = await run(deps, (api) => api.POST("/api/v1/auth/logout", { headers: m.value.headers }));
  return r.ok ? { ok: true, value: null } : r;
}
