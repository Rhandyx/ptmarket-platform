import { createElement, type ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------- mocks do Next

class Redirect extends Error {
  constructor(readonly to: string) {
    super(`redirect ${to}`);
  }
}
class NotFound extends Error {}

const state = vi.hoisted(() => ({
  incoming: new Headers(),
  jar: { set: (() => undefined) as (c: unknown) => unknown },
}));

vi.mock("server-only", () => ({}));
vi.mock("next/headers", () => ({
  headers: async () => state.incoming,
  cookies: async () => state.jar,
}));
vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    throw new Redirect(to);
  },
  notFound: () => {
    throw new NotFound();
  },
}));

const { loginAction, verifyMfaAction, logoutAction } = await import("./actions");
const { LOGIN_INITIAL, MFA_INITIAL, captchaMissing } = await import("./form-state");
const { LoginFields, LoginForm, firstErrorId } = await import("./entrar/LoginForm");
const { MfaFields, mfaFocusId } = await import("./2fa/MfaForm");
const { default: PainelLayout } = await import("./layout");
const { default: PainelPage } = await import("./page");
const { default: MfaPage } = await import("./2fa/page");
const { default: EntrarPageImpl } = await import("./entrar/page");
const EntrarPage = (params: Record<string, string | string[] | undefined> = {}) =>
  EntrarPageImpl({ searchParams: Promise.resolve(params) });
const { areasFor } = await import("./areas");
const { MSG_CAPTCHA, MSG_CODE, MSG_CREDENTIALS, MSG_SESSION, MSG_UNAVAILABLE, sessionEnded } = await import("./messages");

// ---------------------------------------------------------------- API falsa

type Route = { status: number; body?: unknown; headers?: [string, string][] };
const SESSION_ANON: Route = { status: 200, body: { authenticated: false, actor_type: null, csrf_token: null } };
const SESSION_ADMIN: Route = { status: 200, body: { authenticated: true, actor_type: "admin", csrf_token: "csrf-1" } };
const ME = (mfa_verified: boolean): Route => ({
  status: 200,
  body: { id: "u1", full_name: "Ana Lopes", mfa_verified, roles: [{ role: "sponsor_admin", sponsor_entity_id: "e1" }] },
});

let calls: Request[] = [];
function api(routes: Record<string, Route>) {
  calls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      calls.push(input);
      const r = routes[`${input.method} ${new URL(input.url).pathname}`];
      if (!r) return new Response(null, { status: 503 });
      const h = new Headers(r.headers ?? []);
      if (r.body !== undefined) h.set("content-type", "application/json");
      return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status, headers: h });
    }),
  );
}

const PASSWORD = "Pa55-segredo-muito-longo";
const TOKEN = "turnstile-token-secreto";
const CODE = "482913";

function form(entries: Record<string, string>) {
  const fd = new FormData();
  for (const [k, v] of Object.entries(entries)) fd.set(k, v);
  return fd;
}

async function thrown(p: Promise<unknown> | (() => unknown)): Promise<unknown> {
  try {
    await (typeof p === "function" ? p() : p);
  } catch (e) {
    return e;
  }
  return undefined;
}

let setCookie: ReturnType<typeof vi.fn<(c: unknown) => unknown>>;
beforeEach(() => {
  process.env.API_INTERNAL_URL = "http://api:8080";
  process.env.INTERNAL_PROXY_TOKEN = "t".repeat(32);
  process.env.PLATFORM_ADMIN_HOST = "admin.ptmarket.pt";
  state.incoming = new Headers({ host: "admin.ptmarket.pt", origin: "https://admin.ptmarket.pt", cookie: "x=1" });
  setCookie = vi.fn<(c: unknown) => unknown>();
  state.jar = { set: setCookie };
});
afterEach(() => vi.unstubAllGlobals());

// ---------------------------------------------------------------- login

describe("loginAction", () => {
  const login = (prev = LOGIN_INITIAL, extra: Record<string, string> = {}) =>
    loginAction(prev, form({ email: "ana@exemplo.pt", password: PASSWORD, ...extra }));

  it("401 mostra a mensagem única; o estado nunca leva a password", async () => {
    api({ "GET /api/v1/auth/session": SESSION_ANON, "POST /api/v1/staff/auth/login": { status: 401 } });
    const s = await login();
    expect(s.message).toBe(MSG_CREDENTIALS);
    expect(s.credentials).toBe(true);
    expect(s.captchaRequired).toBe(false);
    expect(s.email).toBe("ana@exemplo.pt");
    expect(JSON.stringify(s)).not.toContain(PASSWORD);
    expect(firstErrorId(s)).toBe("entrar-email");
  });

  it("captcha_required mostra o Turnstile e a repetição leva o token (que não volta no estado)", async () => {
    api({
      "GET /api/v1/auth/session": SESSION_ANON,
      "POST /api/v1/staff/auth/login": { status: 401, body: { captcha_required: true } },
    });
    const s = await login();
    // Credenciais possivelmente certas: nunca "incorretos" quando falta o captcha.
    expect(s.message).toBe(MSG_CAPTCHA);
    expect(s.credentials).toBe(false);
    expect(s.captchaRequired).toBe(true);
    expect(s.email).toBe("ana@exemplo.pt");
    expect(firstErrorId(s)).toBe("entrar-erro");

    const html = renderToStaticMarkup(
      createElement(LoginFields, { state: s, action: () => undefined, pending: false, siteKey: "0xSITE" }),
    );
    expect(html).toContain("data-ptm-captcha");
    expect(html).toContain("Verificação anti-robô");
    expect(html).not.toContain(PASSWORD);

    const plain = renderToStaticMarkup(
      createElement(LoginFields, { state: LOGIN_INITIAL, action: () => undefined, pending: false, siteKey: "0xSITE" }),
    );
    expect(plain).not.toContain("data-ptm-captcha");

    // Sem token: não chama a API.
    const before = calls.length;
    const s2 = await login(s);
    expect(calls.length).toBe(before);
    expect(s2.captchaRequired).toBe(true);

    expect(s2.message).toBe(MSG_CAPTCHA);
    const s3 = await login(s, { turnstile_token: TOKEN });
    expect(await calls.at(-1)!.clone().json()).toMatchObject({ turnstile_token: TOKEN });
    expect(JSON.stringify(s3)).not.toContain(TOKEN);
    expect(s3.attempt).toBeGreaterThan(s.attempt);
    // Com token enviado e 401: aí sim, a mensagem única das credenciais (o widget continua).
    expect(s3.message).toBe(MSG_CREDENTIALS);
    expect(s3.captchaRequired).toBe(true);
  });

  it("captcha por resolver no browser: o submit não segue (captchaMissing)", () => {
    const req = { ...LOGIN_INITIAL, captchaRequired: true };
    expect(captchaMissing(req, form({ email: "a@b.pt", password: PASSWORD }))).toBe(true);
    expect(captchaMissing(req, form({ email: "a@b.pt", password: PASSWORD, turnstile_token: " " }))).toBe(true);
    expect(captchaMissing(req, form({ email: "a@b.pt", password: PASSWORD, turnstile_token: TOKEN }))).toBe(false);
    expect(captchaMissing(req, form({ "cf-turnstile-response": TOKEN }))).toBe(false);
    expect(captchaMissing(LOGIN_INITIAL, form({ email: "a@b.pt", password: PASSWORD }))).toBe(false);

    const html = renderToStaticMarkup(
      createElement(LoginFields, {
        state: { ...req, email: "a@b.pt", message: MSG_CAPTCHA },
        action: () => undefined,
        pending: false,
        siteKey: "0xSITE",
      }),
    );
    expect(html).toMatch(/id="entrar-erro" role="alert" tabindex="-1"/i);
    expect(html).toContain(MSG_CAPTCHA);
    expect(html).not.toContain(MSG_CREDENTIALS);
    expect(html).toContain("data-ptm-captcha");
    expect(html).toContain('value="a@b.pt"');
    expect(html).not.toMatch(/aria-invalid/);
  });

  it("429 → N minutos; 503 → indisponível", async () => {
    api({
      "GET /api/v1/auth/session": SESSION_ANON,
      "POST /api/v1/staff/auth/login": { status: 429, headers: [["retry-after", "300"]] },
    });
    expect((await login()).message).toBe("Demasiadas tentativas. Tente de novo dentro de 5 minutos.");
    api({ "GET /api/v1/auth/session": SESSION_ANON, "POST /api/v1/staff/auth/login": { status: 503 } });
    expect((await login()).message).toBe(MSG_UNAVAILABLE);
  });

  it("campos vazios: erro por campo, sem chamar a API", async () => {
    api({});
    const s = await loginAction(LOGIN_INITIAL, form({ email: " ", password: "" }));
    expect(s.fieldErrors).toEqual({ email: "Indique o email.", password: "Indique a palavra-passe." });
    expect(calls).toHaveLength(0);
    const html = renderToStaticMarkup(
      createElement(LoginFields, { state: s, action: () => undefined, pending: false, siteKey: null }),
    );
    expect(html).toMatch(/id="entrar-email"[^>]*aria-invalid="true"[^>]*aria-describedby="entrar-email-erro"/);
    expect(html).toContain('id="entrar-email-erro" role="alert"');
    expect(html).toMatch(/autocomplete="username"/i);
    expect(html).toMatch(/autocomplete="current-password"/i);
  });

  it("200: copia o Set-Cookie e redireciona para /painel/2fa (caminho fixo)", async () => {
    const cookie = "__Host-ptm_admin=abc; Path=/; Secure; HttpOnly; SameSite=Strict";
    api({
      "GET /api/v1/auth/session": SESSION_ANON,
      "POST /api/v1/staff/auth/login": { status: 200, body: { mfa_required: true }, headers: [["set-cookie", cookie]] },
    });
    const e = await thrown(login());
    expect(e).toBeInstanceOf(Redirect);
    expect((e as Redirect).to).toBe("/painel/2fa");
    expect(setCookie).toHaveBeenCalledWith(
      expect.objectContaining({ name: "__Host-ptm_admin", value: "abc", secure: true, httpOnly: true, sameSite: "strict" }),
    );
  });

  it("Host de canal → 404 sem chamar a API", async () => {
    api({});
    state.incoming = new Headers({ host: "lojaportugal.pt" });
    expect(await thrown(login())).toBeInstanceOf(NotFound);
    expect(calls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------- 2FA e logout

describe("verifyMfaAction / logoutAction", () => {
  const verify = () => verifyMfaAction(MFA_INITIAL, form({ code: "482 913" }));

  it("409 redireciona para /painel/2fa/ativar", async () => {
    api({ "GET /api/v1/auth/session": SESSION_ADMIN, "POST /api/v1/staff/mfa/verify": { status: 409 } });
    const e = await thrown(verify());
    expect((e as Redirect).to).toBe("/painel/2fa/ativar");
    expect(await calls[1]!.clone().json()).toEqual({ code: CODE });
    expect(calls[1]!.headers.get("x-csrf-token")).toBe("csrf-1");
  });

  it("401 → erro no campo; o código nunca volta no estado", async () => {
    api({ "GET /api/v1/auth/session": SESSION_ADMIN, "POST /api/v1/staff/mfa/verify": { status: 401 } });
    const s = await verify();
    expect(s.codeError).toBe(MSG_CODE);
    expect(JSON.stringify(s)).not.toContain(CODE);
    const html = renderToStaticMarkup(createElement(MfaFields, { variant: "totp", state: s, action: () => undefined, pending: false }));
    expect(html).toMatch(/inputmode="numeric"/i);
    expect(html).toMatch(/autocomplete="one-time-code"/i);
    expect(html).toMatch(/aria-describedby="mfa-totp-ajuda mfa-totp-erro"/);
    expect(html).toContain('id="mfa-totp-erro" role="alert"');
  });

  it("401 com JS e sem JS: mensagem única no role=alert, foco no campo, form sem nome repetido", async () => {
    api({ "GET /api/v1/auth/session": SESSION_ADMIN, "POST /api/v1/staff/mfa/verify": { status: 401 } });
    const s1 = await verify();
    const s2 = await verifyMfaAction(s1, form({ code: "000000" }));
    // A segunda falha continua a mostrar a mesma mensagem (o estado muda pelo attempt).
    expect(s2.codeError).toBe(MSG_CODE);
    expect(s2.attempt).toBe(s1.attempt + 1);
    expect(mfaFocusId("totp", s2)).toBe("mfa-totp-codigo");
    const html = renderToStaticMarkup(createElement(MfaFields, { variant: "totp", state: s2, action: () => undefined, pending: false }));
    expect(html.match(/role="alert"/g)).toHaveLength(1);
    expect(html).toContain(`>${MSG_CODE}</p>`);
    expect(html).not.toMatch(/<form[^>]*aria-label/);
  });

  it("código de recuperação: autocomplete=off e sem inputmode numérico", () => {
    const html = renderToStaticMarkup(
      createElement(MfaFields, { variant: "recovery", state: MFA_INITIAL, action: () => undefined, pending: false }),
    );
    expect(html).toMatch(/autocomplete="off"/i);
    expect(html).not.toMatch(/one-time-code/i);
    expect(html).not.toMatch(/inputmode/i);
  });

  it("204 → /painel; sem sessão → /painel/entrar", async () => {
    api({ "GET /api/v1/auth/session": SESSION_ADMIN, "POST /api/v1/staff/mfa/verify": { status: 204 } });
    expect(((await thrown(verify())) as Redirect).to).toBe("/painel");
    api({ "GET /api/v1/auth/session": SESSION_ANON });
    expect(((await thrown(verify())) as Redirect).to).toBe("/painel/entrar?sessao=terminou");
  });

  it("logout: CSRF, cookie limpo e volta a /painel/entrar; API em baixo limpa na mesma", async () => {
    const clear = "__Host-ptm_admin=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict";
    api({ "GET /api/v1/auth/session": SESSION_ADMIN, "POST /api/v1/auth/logout": { status: 204, headers: [["set-cookie", clear]] } });
    expect(((await thrown(logoutAction())) as Redirect).to).toBe("/painel/entrar");
    expect(calls[1]!.headers.get("x-csrf-token")).toBe("csrf-1");
    expect(setCookie).toHaveBeenCalledWith(expect.objectContaining({ name: "__Host-ptm_admin", maxAge: 0 }));

    setCookie.mockClear();
    api({ "GET /api/v1/auth/session": SESSION_ADMIN, "POST /api/v1/auth/logout": { status: 503 } });
    expect(((await thrown(logoutAction())) as Redirect).to).toBe("/painel/entrar");
    expect(setCookie).toHaveBeenCalledWith(
      expect.objectContaining({ name: "__Host-ptm_admin", value: "", maxAge: 0, secure: true, path: "/" }),
    );
  });
});

// ---------------------------------------------------------------- páginas

describe("páginas /painel", () => {
  it("Host de canal → 404 (layout e páginas)", async () => {
    api({ "GET /api/v1/staff/me": ME(true) });
    state.incoming = new Headers({ host: "lojaportugal.pt" });
    expect(await thrown(() => PainelLayout({ children: null }))).toBeInstanceOf(NotFound);
    expect(await thrown(() => PainelPage())).toBeInstanceOf(NotFound);
    expect(await thrown(() => EntrarPage())).toBeInstanceOf(NotFound);
    expect(calls).toHaveLength(0);
    delete process.env.PLATFORM_ADMIN_HOST;
    state.incoming = new Headers({ host: "admin.ptmarket.pt" });
    expect(await thrown(() => PainelLayout({ children: null }))).toBeInstanceOf(NotFound);
  });

  it("sem sessão → /painel/entrar", async () => {
    api({ "GET /api/v1/staff/me": { status: 401 } });
    expect(((await thrown(() => PainelPage())) as Redirect).to).toBe("/painel/entrar");
    expect(((await thrown(() => MfaPage())) as Redirect).to).toBe("/painel/entrar");
  });

  it("com sessão sem 2FA → /painel/2fa; com 2FA a página de 2FA volta a /painel", async () => {
    api({ "GET /api/v1/staff/me": ME(false) });
    expect(((await thrown(() => PainelPage())) as Redirect).to).toBe("/painel/2fa");
    expect(await thrown(() => MfaPage())).toBeUndefined();
    api({ "GET /api/v1/staff/me": ME(true) });
    expect(await thrown(() => PainelPage())).toBeUndefined();
    expect(((await thrown(() => MfaPage())) as Redirect).to).toBe("/painel");
  });

  it("entrar: o componente de cliente só recebe a siteKey", async () => {
    api({ "GET /api/v1/staff/me": { status: 401 } });
    state.incoming = new Headers({
      host: "admin.ptmarket.pt",
      cookie: "__Host-ptm_admin=SEGREDO-COOKIE",
      "x-nonce": "n1",
    });
    const tree = (await EntrarPage()) as ReactElement<{ children: ReactElement[] }>;
    const card = tree.props.children[1] as ReactElement<{ children: (ReactElement<Record<string, unknown>> | null)[] }>;
    const form = card.props.children.find((c) => c !== null && c.type === LoginForm)!;
    const props = form.props;
    expect(Object.keys(props)).toEqual(["siteKey"]);
    expect(JSON.stringify(props)).not.toContain("SEGREDO");
  });

  it("sessao=terminou: só o valor exato mostra o aviso em role=status; o resto é ignorado", async () => {
    expect(sessionEnded({ sessao: "terminou" })).toBe(true);
    for (const v of ["Terminou", "terminou ", "x", "", undefined, ["terminou"], ["terminou", "terminou"]]) {
      expect(sessionEnded({ sessao: v })).toBe(false);
    }
    expect(sessionEnded({ next: "terminou" })).toBe(false);

    api({ "GET /api/v1/staff/me": { status: 401 } });
    const shown = renderToStaticMarkup((await EntrarPage({ sessao: "terminou" })) as ReactElement);
    expect(shown).toContain(`role="status"`);
    expect(shown).toContain(MSG_SESSION);
    for (const sessao of ["<script>alert(1)</script>", "Terminou", "terminou&next=//evil.pt"]) {
      const html = renderToStaticMarkup((await EntrarPage({ sessao })) as ReactElement);
      expect(html).not.toContain(MSG_SESSION);
      expect(html).not.toContain("role=\"status\"");
      expect(html).not.toContain("evil");
      expect(html).not.toContain("<script>alert");
    }
  });

  it("áreas: sponsor_admin → Patrocínios com ligação; outros → Em breve", () => {
    const a = areasFor([
      { role: "merchant_owner", store_id: "s1" },
      { role: "sponsor_admin", sponsor_entity_id: "e1" },
      { role: "sponsor_admin", sponsor_entity_id: "e2" },
    ]);
    expect(a.map((x) => [x.title, x.href])).toEqual([
      ["Patrocínios", "/painel/patrocinios"],
      ["A sua loja", null],
    ]);
  });
});
