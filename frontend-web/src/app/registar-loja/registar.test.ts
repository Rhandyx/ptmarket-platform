import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { createBrowserApi } from "../../lib/api/client";
import { ApiError } from "../../lib/api";
import type { CommissionPreview, SponsorSummary } from "../../lib/api/signup";
import { fetchCommissionPreview } from "../../lib/api/signup";
import { CommissionAnchor } from "./CommissionAnchor";
import { formatBps, formatCents } from "./format";
import { EMPTY_GEO, ParishPicker } from "./ParishPicker";
import { PlanPicker } from "./PlanPicker";
import { RegisterForm } from "./RegisterForm";
import { SponsorBadges } from "./SponsorBadges";

const nbsp = / /g;
const norm = (s: string) => s.replace(nbsp, " ");

const PLANS: CommissionPreview["plans"] = [
  {
    plan_code: "commission_payg",
    is_default: true,
    tiers: [
      { gmv_from_cents: 0, gmv_to_cents: 100000, monthly_fee_cents: 0, marginal_commission_bps: 800 },
      { gmv_from_cents: 100000, gmv_to_cents: null, monthly_fee_cents: 1250, marginal_commission_bps: 650 },
    ],
  },
  {
    plan_code: "plano_fixo",
    is_default: false,
    tiers: [{ gmv_from_cents: 0, gmv_to_cents: null, monthly_fee_cents: 4900, marginal_commission_bps: 300 }],
  },
];

const CAMARA: SponsorSummary = { id: "1", kind: "municipality", name: "Câmara de Teste", slug: "c", logo_key: "logos/c.png" };
const JUNTA: SponsorSummary = { id: "2", kind: "parish", name: "Junta de Teste", slug: "j", logo_key: null };

describe("formatação sem floats", () => {
  it.each([
    [800, "8%"],
    [650, "6,5%"],
    [625, "6,25%"],
    [5, "0,05%"],
    [0, "0%"],
  ])("bps %i → %s", (bps, out) => expect(formatBps(bps)).toBe(out));

  it.each([
    [0, "0 €"],
    [1250, "12,50 €"],
    [4900, "49 €"],
    [5, "0,05 €"],
    [123456789, "1 234 567,89 €"],
  ])("cêntimos %i → %s", (c, out) => expect(norm(formatCents(c)).replace(/ /g, " ")).toBe(out));

  it("recusa não inteiros e negativos", () => {
    expect(() => formatBps(6.5)).toThrow(RangeError);
    expect(() => formatCents(-1)).toThrow(RangeError);
    expect(() => formatCents(0.5)).toThrow(RangeError);
  });
});

describe("CommissionAnchor", () => {
  it("sem patrocínio: só 8%, sem <del>", () => {
    const html = renderToStaticMarkup(h(CommissionAnchor, { referenceBps: 800 }));
    expect(html).toContain("8%");
    expect(html).not.toContain("<del");
  });
  it("com patrocínio: del + ins + texto para leitores de ecrã", () => {
    const html = renderToStaticMarkup(h(CommissionAnchor, { referenceBps: 800, sponsoredBps: 0 }));
    expect(html).toMatch(/<del[^>]*>8%<\/del>/);
    expect(html).toMatch(/<ins[^>]*>0%<\/ins>/);
    expect(html).toContain("Comissão normal 8%. Com patrocínio: 0%.");
  });
});

describe("SponsorBadges", () => {
  it("co-patrocínio: 2 selos pela ordem da API e um só 0%", () => {
    const html = renderToStaticMarkup(
      h("div", null, [
        h(CommissionAnchor, { key: "a", referenceBps: 800, sponsoredBps: 0 }),
        h(SponsorBadges, { key: "b", sponsors: [CAMARA, JUNTA], heading: "Parceiros" }),
      ]),
    );
    expect(html.indexOf("Câmara de Teste")).toBeGreaterThan(-1);
    expect(html.indexOf("Câmara de Teste")).toBeLessThan(html.indexOf("Junta de Teste"));
    expect(html).toContain("Câmara Municipal");
    expect(html).toContain("Junta de Freguesia");
    expect(html.match(/<ins/g)).toHaveLength(1);
    expect(html).toContain('alt="Câmara de Teste"');
    // sem logo_key: só texto
    expect(html.match(/<img/g)).toHaveLength(1);
  });
});

describe("PlanPicker", () => {
  const html = renderToStaticMarkup(h(PlanPicker, { plans: PLANS, value: "commission_payg", onChange: () => {} }));
  it("grupo de rádio com o plano por omissão marcado", () => {
    expect(html).toContain("<fieldset");
    expect(html).toContain("<legend");
    expect(html.match(/type="radio"/g)).toHaveLength(2);
    expect(html).toMatch(/id="plano-commission_payg"[^>]*checked/);
  });
  it("uma tabela por plano, com caption e th scope, valores da resposta", () => {
    expect(html.match(/<table/g)).toHaveLength(2);
    expect(html.match(/<caption/g)).toHaveLength(2);
    expect(html).toContain('scope="col"');
    expect(html).toContain('scope="row"');
    const text = norm(html);
    expect(text).toContain("Até 1000 €");
    expect(text).toContain("A partir de 1000 €");
    expect(text).toContain("12,50 €");
    expect(text).toContain("6,5%");
    expect(text).toContain("3%");
    expect(text).toContain("acresce IVA");
  });
});

describe("erros da API", () => {
  it("geo com erro mostra role=alert associado por aria-describedby", () => {
    const html = renderToStaticMarkup(
      h(ParishPicker, {
        districts: { items: [], loading: false, error: true },
        municipalities: EMPTY_GEO,
        parishes: EMPTY_GEO,
        district: "",
        municipality: "",
        parish: "",
        onDistrict: () => {},
        onMunicipality: () => {},
        onParish: () => {},
      }),
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain('aria-describedby="distrito-erro"');
    expect(html).toContain('id="distrito-erro"');
  });

  it("400 da pré-visualização chega como ApiError", async () => {
    const fetchMock = vi.fn<typeof fetch>(
      async () => new Response(JSON.stringify({ code: "validation", message: "dicofre" }), { status: 400 }),
    );
    const api = createBrowserApi({ fetch: fetchMock, baseUrl: "http://api.test" });
    await expect(fetchCommissionPreview(api, "XXXXXX")).rejects.toBeInstanceOf(ApiError);
  });

  it("preview chama o endpoint com dicofre", async () => {
    const body: CommissionPreview = { reference_bps: 800, sponsored: null, plans: PLANS };
    const fetchMock = vi.fn<typeof fetch>(
      async () => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const api = createBrowserApi({ fetch: fetchMock, baseUrl: "http://api.test" });
    const out = await fetchCommissionPreview(api, "030201");
    expect(out.reference_bps).toBe(800);
    const req = fetchMock.mock.calls[0]?.[0] as Request;
    expect(req.url).toBe("http://api.test/api/v1/signup/commission-preview?dicofre=030201");
  });
});

describe("RegisterForm", () => {
  const html = renderToStaticMarkup(h(RegisterForm, {}));
  it("botão final desligado com explicação visível", () => {
    expect(html).toMatch(/<button[^>]*aria-disabled="true"[^>]*aria-describedby="registo-em-breve"/);
    expect(html).toContain("Registo disponível em breve");
  });
  it("três seletores com labels", () => {
    for (const id of ["distrito", "concelho", "freguesia"]) expect(html).toContain(`for="${id}"`);
  });
});
