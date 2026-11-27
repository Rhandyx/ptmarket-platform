import "server-only";
import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { staffMe, type StaffMe } from "../../lib/api/staff";
import { isPlatformAdminHost } from "../../lib/platform-host";

/** 404 fora do Host da plataforma (também nas Server Actions). Devolve os cabeçalhos do pedido. */
export async function platformHeaders(): Promise<Headers> {
  const h = await headers();
  if (!isPlatformAdminHost(h.get("host"))) notFound();
  return h;
}

export type StaffSession = { kind: "ok"; me: StaffMe } | { kind: "unavailable" };

/**
 * Sessão de backoffice para as páginas. Sem sessão (ou sem papéis) → /painel/entrar.
 * Com `requireMfa`, sessão sem 2FA → /painel/2fa. Só caminhos fixos (sem "next").
 */
export async function loadStaff({ requireMfa }: { requireMfa: boolean }): Promise<StaffSession> {
  const incoming = await platformHeaders();
  const r = await staffMe({ incoming });
  if (!r.ok) {
    if (r.kind === "unauthorized" || r.kind === "forbidden") redirect("/painel/entrar");
    return { kind: "unavailable" };
  }
  if (requireMfa && !r.value.mfa_verified) redirect("/painel/2fa");
  return { kind: "ok", me: r.value };
}
