import type { Metadata } from "next";
import { platformHeaders } from "./session";

export const metadata: Metadata = {
  title: { template: "%s · Painel PT Market", default: "Painel PT Market" },
  robots: { index: false, follow: false, nocache: true },
};

// Sessão em cada pedido: nunca em cache.
export const dynamic = "force-dynamic";

/** /painel só existe no Host da plataforma (PLATFORM_ADMIN_HOST); noutro Host → 404. */
export default async function PainelLayout({ children }: { children: React.ReactNode }) {
  await platformHeaders();
  return children;
}
