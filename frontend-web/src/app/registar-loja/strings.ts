// Todos os textos visíveis do registo num só ficheiro: a redação final dos Termos está pendente do owner.
import { formatBps } from "./format";

export const S = {
  title: "Abrir uma loja",
  lead: "Diga-nos onde fica a loja. Mostramos a comissão que se aplica e os parceiros da sua terra.",
  eyebrow: "Registo de loja",
  locationLegend: "Onde fica a loja",
  district: "Distrito",
  municipality: "Concelho",
  parish: "Freguesia",
  choose: "Escolha…",
  loading: "A carregar…",
  loadingPreview: "A atualizar a comissão…",
  geoError: "Não foi possível carregar esta lista. Tente novamente.",
  previewError: "Não foi possível obter a comissão. Tente novamente.",
  retry: "Tentar novamente",
  commissionLabel: "Comissão",
  sponsorsHeading: "Parceiros da sua freguesia",
  warning:
    "A isenção depende da validação pela entidade patrocinadora. Até à aprovação, e se o patrocínio terminar, aplica-se a comissão do plano que escolher.",
  planLegend: "Plano",
  planDefault: "Recomendado para começar",
  vatNote: "Aos valores acresce IVA à taxa legal.",
  tableVolume: "Volume mensal de vendas",
  tableFee: "Mensalidade",
  tableCommission: "Comissão, só sobre o excedente",
  submit: "Registar loja",
  submitSoon: "Registo disponível em breve",
} as const;

export const KIND_LABEL: Record<string, string> = {
  municipality: "Câmara Municipal",
  parish: "Junta de Freguesia",
  association: "Associação",
};

export const PLAN_LABEL: Record<string, string> = {
  commission_payg: "Só comissão",
  tiered_subscription: "Mensalidade fixa por escalões",
};

const PLAN_FALLBACK = "Outro plano";

export function planLabel(code: string): string {
  return PLAN_LABEL[code] ?? PLAN_FALLBACK;
}

export function anchorSrText(referenceBps: number, sponsoredBps: number): string {
  return `Comissão normal ${formatBps(referenceBps)}. Com patrocínio: ${formatBps(sponsoredBps)}.`;
}

export function tableCaption(plan: string): string {
  return `Escalões do plano ${planLabel(plan)}`;
}
