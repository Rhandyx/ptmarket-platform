import type { StaffMe, StaffRole } from "../../lib/api/staff";

export type Area = {
  role: StaffRole;
  title: string;
  description: string;
  /** Caminho fixo quando a área já existe; `null` = "Em breve". */
  href: string | null;
};

const AREAS: Record<StaffRole, Omit<Area, "role">> = {
  sponsor_admin: {
    title: "Patrocínios",
    description: "Aprovar as lojas que pedem o patrocínio da sua entidade e acompanhar as que já patrocina.",
    href: "/painel/patrocinios",
  },
  super_admin: {
    title: "Plataforma",
    description: "Verificações, canais e auditoria de toda a plataforma.",
    href: null,
  },
  tenant_admin: {
    title: "Canal",
    description: "Lojas, montra e definições do seu canal.",
    href: null,
  },
  merchant_owner: {
    title: "A sua loja",
    description: "Produtos, encomendas e equipa da loja.",
    href: null,
  },
  merchant_staff: {
    title: "Loja",
    description: "Produtos e encomendas da loja onde trabalha.",
    href: null,
  },
};

const ORDER: readonly StaffRole[] = ["sponsor_admin", "super_admin", "tenant_admin", "merchant_owner", "merchant_staff"];

/** Uma área por papel (sem repetir quando o mesmo papel existe em vários âmbitos); disponíveis primeiro. */
export function areasFor(roles: StaffMe["roles"]): Area[] {
  const have = new Set(roles.map((r) => r.role));
  return ORDER.filter((r) => have.has(r)).map((role) => ({ role, ...AREAS[role] }));
}
