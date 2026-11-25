import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { proxy } from "../src/proxy";

const get = () => proxy(new NextRequest("https://exemplo.pt/"));

describe("cabeçalhos de segurança em /", () => {
  const h = get().headers;

  it("CSP com as diretivas obrigatórias", () => {
    const csp = h.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'self'");
    expect(csp).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("HSTS sem includeSubDomains nem preload", () => {
    const hsts = h.get("strict-transport-security") ?? "";
    expect(hsts).toBe("max-age=31536000");
    expect(hsts).not.toMatch(/preload|includeSubDomains/i);
  });

  it("restantes cabeçalhos", () => {
    expect(h.get("x-content-type-options")).toBe("nosniff");
    expect(h.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    expect(h.get("permissions-policy")).toBeTruthy();
    expect(h.get("cross-origin-opener-policy")).toBe("same-origin");
  });

  it("nonce diferente em cada pedido", () => {
    const nonce = (r: Response) => /'nonce-([^']+)'/.exec(r.headers.get("content-security-policy") ?? "")?.[1];
    const a = nonce(get());
    const b = nonce(get());
    expect(a).toBeTruthy();
    expect(a).not.toBe(b);
  });
});
