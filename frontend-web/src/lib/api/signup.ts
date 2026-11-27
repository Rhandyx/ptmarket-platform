import type { components } from "./schema";
import type { createBrowserApi } from "./client";

export type BrowserApi = ReturnType<typeof createBrowserApi>;
export type GeoItem = components["schemas"]["GeoItem"];
export type CommissionPreview = components["schemas"]["CommissionPreview"];
export type PlanView = components["schemas"]["PlanView"];
export type PlanTierView = components["schemas"]["PlanTierView"];
export type SponsorSummary = components["schemas"]["SponsorSummary"];

// O cliente lança ApiError em respostas não-2xx (errorMiddleware), por isso `data` vem sempre preenchido.
export async function fetchDistricts(api: BrowserApi): Promise<GeoItem[]> {
  const { data } = await api.GET("/api/v1/geo/districts");
  return data ?? [];
}

export async function fetchMunicipalities(api: BrowserApi, district: string): Promise<GeoItem[]> {
  const { data } = await api.GET("/api/v1/geo/municipalities", { params: { query: { district } } });
  return data ?? [];
}

export async function fetchParishes(api: BrowserApi, municipality: string): Promise<GeoItem[]> {
  const { data } = await api.GET("/api/v1/geo/parishes", { params: { query: { municipality } } });
  return data ?? [];
}

/** Sem `dicofre`: só a comissão de referência e os planos. */
export async function fetchCommissionPreview(api: BrowserApi, dicofre?: string): Promise<CommissionPreview> {
  const { data } = await api.GET("/api/v1/signup/commission-preview", {
    params: { query: dicofre ? { dicofre } : {} },
  });
  if (!data) throw new Error("Resposta vazia da pré-visualização.");
  return data;
}
