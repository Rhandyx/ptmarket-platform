import "server-only";

/** Hostname em minúsculas, sem porta nem ponto final. `null` se vazio ou inválido. */
export function normalizeHost(raw: string | null | undefined): string | null {
  const h = (raw ?? "").trim().toLowerCase();
  if (!h) return null;
  let name: string;
  if (h.startsWith("[")) {
    const end = h.indexOf("]");
    if (end < 0) return null;
    name = h.slice(0, end + 1);
  } else {
    name = h.split(":")[0] ?? "";
  }
  name = name.replace(/\.$/, "");
  return name || null;
}

/**
 * O pedido chegou pelo Host da plataforma (`PLATFORM_ADMIN_HOST`, variável de servidor)?
 * Sem a variável configurada: nunca (fecha por defeito → 404 em /painel).
 */
export function isPlatformAdminHost(
  host: string | null | undefined,
  configured: string | undefined = process.env.PLATFORM_ADMIN_HOST,
): boolean {
  const want = normalizeHost(configured);
  const got = normalizeHost(host);
  return want !== null && got === want;
}
