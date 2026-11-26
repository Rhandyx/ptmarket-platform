import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, expectTypeOf, it, vi } from "vitest";
import { createBrowserApi } from "./client";
import { ApiError, type TenantInfo } from "./index";

vi.mock("server-only", () => ({}));
const { createServerApi } = await import("./server");

const TENANT = {
  slug: "loja",
  name: "Loja",
  tenant_type: "store",
  country_code: "PT",
  currency: "EUR",
  template_layout: "default",
  theme_config: {},
  legal_config: {},
};

function mockFetch(status = 200, body: unknown = TENANT) {
  return vi.fn<typeof fetch>(async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    }),
  );
}
const sent = (f: ReturnType<typeof mockFetch>) => f.mock.calls[0]![0] as Request;

describe("tipos", () => {
  it("TenantInfo só tem campos do contrato", () => {
    expectTypeOf<TenantInfo>().toHaveProperty("slug");
    // @ts-expect-error campo que não existe na resposta de /api/v1/tenant
    expectTypeOf<TenantInfo>().toHaveProperty("campo_inexistente");
    const t = {} as TenantInfo;
    // @ts-expect-error campo inexistente
    void t.campo_inexistente;
  });
});

describe("createServerApi", () => {
  const incoming = new Headers({ host: "loja.pt", cookie: "sid=abc", "x-request-id": "r1" });
  it("reencaminha tenant, token, cookie e request-id; no-store", async () => {
    const f = mockFetch();
    const api = createServerApi(incoming, { fetch: f, baseUrl: "http://api:8080", internalToken: "tok" });
    const { data } = await api.GET("/api/v1/tenant");
    expect(data?.slug).toBe("loja");
    const r = sent(f);
    expect(r.url).toBe("http://api:8080/api/v1/tenant");
    expect(r.headers.get("x-forwarded-host")).toBe("loja.pt");
    expect(r.headers.get("x-internal-token")).toBe("tok");
    expect(r.headers.get("cookie")).toBe("sid=abc");
    expect(r.headers.get("x-request-id")).toBe("r1");
    expect(r.cache).toBe("no-store");
  });
  it("sem token configurado falha (nunca envia sem segredo)", () => {
    const saved = process.env.INTERNAL_PROXY_TOKEN;
    delete process.env.INTERNAL_PROXY_TOKEN;
    expect(() => createServerApi(incoming, { baseUrl: "http://api" })).toThrow();
    if (saved !== undefined) process.env.INTERNAL_PROXY_TOKEN = saved;
  });
});

describe("createBrowserApi", () => {
  it("não envia cabeçalhos internos; CSRF só em mutações", async () => {
    const f = mockFetch();
    const api = createBrowserApi({ fetch: f, baseUrl: "http://localhost", csrfToken: "csrf1" });
    await api.GET("/api/v1/tenant");
    const g = sent(f);
    expect(g.headers.get("x-forwarded-host")).toBeNull();
    expect(g.headers.get("x-internal-token")).toBeNull();
    expect(g.headers.get("x-csrf-token")).toBeNull();
    expect(g.credentials).toBe("same-origin");

    const f2 = mockFetch();
    const api2 = createBrowserApi({ fetch: f2, baseUrl: "http://localhost", csrfToken: "csrf1" });
    // Rota de mutação ainda não existe no contrato: chamada não tipada só para o teste.
    await (api2 as unknown as { POST(p: string): Promise<unknown> }).POST("/api/v1/x");
    expect(sent(f2).headers.get("x-csrf-token")).toBe("csrf1");
  });
  it("404 vira ApiError not_found; internal esconde a mensagem", async () => {
    const api = createBrowserApi({
      fetch: mockFetch(404, { code: "not_found", message: "x" }),
      baseUrl: "http://localhost",
    });
    await expect(api.GET("/api/v1/tenant")).rejects.toMatchObject({ code: "not_found", status: 404 });
    const api2 = createBrowserApi({
      fetch: mockFetch(500, { code: "internal", message: "segredo SQL" }),
      baseUrl: "http://localhost",
    });
    const e = await api2.GET("/api/v1/tenant").catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).message).not.toContain("SQL");
  });
});

describe("check:api", () => {
  const run = (spec?: string) =>
    spawnSync("node", ["scripts/check-api.mjs", ...(spec ? [spec] : [])], { encoding: "utf8" });
  it("contrato atual sai 0", () => {
    expect(run().status).toBe(0);
  });
  it("contrato alterado sai ≠ 0 com a mensagem", () => {
    const spec = JSON.parse(readFileSync("../backend-rust/openapi.json", "utf8"));
    spec.paths["/healthz"] = spec.paths["/healthz"] ?? {};
    spec.paths["/novo"] = { get: { responses: { "200": { description: "ok" } } } };
    const f = join(mkdtempSync(join(tmpdir(), "oa-")), "openapi.json");
    writeFileSync(f, JSON.stringify(spec));
    const r = run(f);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain("npm run gen:api");
  });
});

