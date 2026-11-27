import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
const staff = await import("../../lib/api/staff");
const { isPlatformAdminHost, normalizeHost } = await import("../../lib/platform-host");

type Route = { status: number; body?: unknown; headers?: [string, string][] };

/** fetch falso por "MÉTODO caminho"; regista os pedidos. */
function fakeApi(routes: Record<string, Route>) {
  const calls: Request[] = [];
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const req = input as Request;
    calls.push(req);
    const key = `${req.method} ${new URL(req.url).pathname}`;
    const r = routes[key];
    if (!r) throw new Error(`rota inesperada ${key}`);
    const h = new Headers(r.headers ?? []);
    if (r.body !== undefined) h.set("content-type", "application/json");
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status, headers: h });
  });
  return { fetch, calls };
}

const SESSION_ANON = { status: 200, body: { authenticated: false, actor_type: null, csrf_token: null } };
const SESSION_ADMIN = { status: 200, body: { authenticated: true, actor_type: "admin", csrf_token: "csrf-1" } };
const ADMIN_COOKIE = "__Host-ptm_admin=tok_ABC-123; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800";

function deps(fetch: typeof globalThis.fetch, extra: Record<string, string> = {}) {
  const set = vi.fn();
  return {
    set,
    deps: {
      incoming: new Headers({ host: "admin.ptmarket.pt", origin: "https://admin.ptmarket.pt", cookie: "a=b", ...extra }),
      cookies: { set },
      api: { fetch, baseUrl: "http://api:8080", internalToken: "tok" },
    },
  };
}

describe("isPlatformAdminHost", () => {
  it("compara hostname normalizado, sem porta", () => {
    expect(isPlatformAdminHost("Admin.PTMarket.pt:443", "admin.ptmarket.pt")).toBe(true);
    expect(isPlatformAdminHost("admin.ptmarket.pt.", "admin.ptmarket.pt")).toBe(true);
    expect(isPlatformAdminHost("lojaportugal.pt", "admin.ptmarket.pt")).toBe(false);
    expect(isPlatformAdminHost("admin.ptmarket.pt.evil.pt", "admin.ptmarket.pt")).toBe(false);
    expect(normalizeHost("[::1]:3000")).toBe("[::1]");
  });
  it("sem PLATFORM_ADMIN_HOST nunca é plataforma", () => {
    expect(isPlatformAdminHost("admin.ptmarket.pt", undefined)).toBe(false);
    expect(isPlatformAdminHost("", "")).toBe(false);
  });
});

describe("parseSetCookie / copySetCookies", () => {
  it("mantém todos os atributos", () => {
    expect(staff.parseSetCookie(ADMIN_COOKIE)).toEqual({
      name: "__Host-ptm_admin",
      value: "tok_ABC-123",
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "strict",
      maxAge: 28800,
    });
    const del = staff.parseSetCookie("__Host-ptm_admin=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure");
    expect(del?.maxAge).toBe(0);
    expect(del?.expires?.getTime()).toBe(0);
  });
  it("recusa o que não consegue reproduzir fielmente", () => {
    expect(staff.parseSetCookie("a=b+c/d; Path=/")).toBeNull();
    expect(staff.parseSetCookie("a=b; Foo=bar")).toBeNull();
    expect(staff.parseSetCookie("=b")).toBeNull();
  });
  it("copia TODOS os Set-Cookie", () => {
    const session = "__Host-ptm_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict";
    const res = new Response(null, { headers: [["set-cookie", ADMIN_COOKIE], ["set-cookie", session]] });
    const set = vi.fn();
    staff.copySetCookies(res, { set });
    expect(set).toHaveBeenCalledTimes(2);
    expect(set.mock.calls.map((c) => c[0].name)).toEqual(["__Host-ptm_admin", "__Host-ptm_session"]);
  });
  it("falha fechada: cookie fora da lista ou __Host- sem Secure/Path=/ ou com Domain", () => {
    const bad = [
      "x=1; Path=/",
      "__Host-ptm_admin=a; Path=/; HttpOnly",
      "__Host-ptm_admin=a; Path=/painel; Secure",
      "__Host-ptm_admin=a; Path=/; Secure; Domain=ptmarket.pt",
    ];
    for (const h of bad) {
      const set = vi.fn();
      const res = new Response(null, { headers: [["set-cookie", ADMIN_COOKIE], ["set-cookie", h]] });
      expect(() => staff.copySetCookies(res, { set })).toThrow();
      expect(set).not.toHaveBeenCalled();
    }
  });
});

describe("staffLogin", () => {
  it("200: copia o Set-Cookie, reenvia Origin, sem CSRF quando anónimo", async () => {
    const { fetch, calls } = fakeApi({
      "GET /api/v1/auth/session": SESSION_ANON,
      "POST /api/v1/staff/auth/login": { status: 200, body: { mfa_required: true }, headers: [["set-cookie", ADMIN_COOKIE]] },
    });
    const { deps: d, set } = deps(fetch);
    const r = await staff.staffLogin(d, { email: "a@b.pt", password: "pw" });
    expect(r).toEqual({ ok: true, value: { mfaRequired: true } });
    expect(set).toHaveBeenCalledWith(expect.objectContaining({ name: "__Host-ptm_admin", value: "tok_ABC-123", httpOnly: true }));
    const [get, post] = calls;
    expect(get!.headers.get("x-csrf-token")).toBeNull();
    expect(post!.headers.get("origin")).toBe("https://admin.ptmarket.pt");
    expect(post!.headers.get("x-csrf-token")).toBeNull();
    expect(await post!.clone().json()).toEqual({ email: "a@b.pt", password: "pw" });
  });

  it("com sessão: X-CSRF-Token só na mutação", async () => {
    const { fetch, calls } = fakeApi({
      "GET /api/v1/auth/session": SESSION_ADMIN,
      "POST /api/v1/staff/auth/login": { status: 200, body: { mfa_required: false } },
    });
    const r = await staff.staffLogin(deps(fetch).deps, { email: "a@b.pt", password: "pw", turnstileToken: "t" });
    expect(r).toEqual({ ok: true, value: { mfaRequired: false } });
    expect(calls[0]!.headers.get("x-csrf-token")).toBeNull();
    expect(calls[1]!.headers.get("x-csrf-token")).toBe("csrf-1");
    expect(await calls[1]!.clone().json()).toMatchObject({ turnstile_token: "t" });
  });

  it("401 com captcha_required; 429 com Retry-After; 503", async () => {
    const mk = (r: Route) =>
      fakeApi({ "GET /api/v1/auth/session": SESSION_ANON, "POST /api/v1/staff/auth/login": r }).fetch;
    const login = (f: typeof globalThis.fetch) => staff.staffLogin(deps(f).deps, { email: "a@b.pt", password: "pw" });
    expect(await login(mk({ status: 401, body: { captcha_required: true } }))).toEqual({
      ok: false,
      kind: "unauthorized",
      captchaRequired: true,
    });
    expect(await login(mk({ status: 401 }))).toEqual({ ok: false, kind: "unauthorized", captchaRequired: false });
    expect(await login(mk({ status: 429, headers: [["retry-after", "125"]] }))).toEqual({
      ok: false,
      kind: "rate_limited",
      retryAfterSeconds: 125,
    });
    expect(await login(mk({ status: 503 }))).toEqual({ ok: false, kind: "unavailable" });
  });

  it("API inacessível → unavailable (sem detalhe)", async () => {
    const f = vi.fn<typeof globalThis.fetch>(async () => {
      throw new Error("ECONNREFUSED segredo");
    });
    expect(await staff.staffLogin(deps(f).deps, { email: "a@b.pt", password: "pw" })).toEqual({
      ok: false,
      kind: "unavailable",
    });
  });
});

describe("staffVerifyMfa / staffMe / staffLogout", () => {
  it("verify: CSRF + Origin, Set-Cookie rodado copiado; 409 → conflict", async () => {
    const ok = fakeApi({
      "GET /api/v1/auth/session": SESSION_ADMIN,
      "POST /api/v1/staff/mfa/verify": { status: 204, headers: [["set-cookie", ADMIN_COOKIE]] },
    });
    const { deps: d, set } = deps(ok.fetch);
    expect(await staff.staffVerifyMfa(d, "123456")).toEqual({ ok: true, value: null });
    expect(ok.calls[1]!.headers.get("x-csrf-token")).toBe("csrf-1");
    expect(ok.calls[1]!.headers.get("origin")).toBe("https://admin.ptmarket.pt");
    expect(set).toHaveBeenCalledTimes(1);

    const c = fakeApi({ "GET /api/v1/auth/session": SESSION_ADMIN, "POST /api/v1/staff/mfa/verify": { status: 409 } });
    expect(await staff.staffVerifyMfa(deps(c.fetch).deps, "123456")).toEqual({ ok: false, kind: "conflict" });
  });

  it("verify sem sessão não chama a API", async () => {
    const a = fakeApi({ "GET /api/v1/auth/session": SESSION_ANON });
    expect(await staff.staffVerifyMfa(deps(a.fetch).deps, "123456")).toEqual({ ok: false, kind: "forbidden" });
    expect(a.calls).toHaveLength(1);
  });

  it("me: GET sem CSRF; 401 → unauthorized", async () => {
    const me = { id: "u1", full_name: "Ana", roles: [], mfa_verified: true };
    const a = fakeApi({ "GET /api/v1/staff/me": { status: 200, body: me } });
    expect(await staff.staffMe(deps(a.fetch).deps)).toEqual({ ok: true, value: me });
    expect(a.calls[0]!.headers.get("x-csrf-token")).toBeNull();
    const b = fakeApi({ "GET /api/v1/staff/me": { status: 401 } });
    expect(await staff.staffMe(deps(b.fetch).deps)).toMatchObject({ ok: false, kind: "unauthorized" });
  });

  it("logout: CSRF na mutação e cookie limpo copiado", async () => {
    const clear = "__Host-ptm_admin=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict";
    const a = fakeApi({
      "GET /api/v1/auth/session": SESSION_ADMIN,
      "POST /api/v1/auth/logout": { status: 204, headers: [["set-cookie", clear]] },
    });
    const { deps: d, set } = deps(a.fetch);
    expect(await staff.staffLogout(d)).toEqual({ ok: true, value: null });
    expect(a.calls[1]!.headers.get("x-csrf-token")).toBe("csrf-1");
    expect(set).toHaveBeenCalledWith(expect.objectContaining({ name: "__Host-ptm_admin", value: "", maxAge: 0 }));
  });
});
