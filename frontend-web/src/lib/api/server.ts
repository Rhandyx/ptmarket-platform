import "server-only";
import createClient from "openapi-fetch";
import { errorMiddleware, type paths } from "./index";

type HeaderSource = { get(name: string): string | null };

export type ServerApiOptions = {
  /** Só para testes. */
  fetch?: typeof fetch;
  baseUrl?: string;
  internalToken?: string;
};

/**
 * Cliente para Server Components/Actions. Reencaminha o tenant (X-Forwarded-Host +
 * X-Internal-Token, segredo de servidor), o cookie de sessão e o X-Request-Id.
 * Nunca registar nem expor `INTERNAL_PROXY_TOKEN`.
 */
export function createServerApi(incoming: HeaderSource, opts: ServerApiOptions = {}) {
  const baseUrl = opts.baseUrl ?? process.env.API_INTERNAL_URL;
  const token = opts.internalToken ?? process.env.INTERNAL_PROXY_TOKEN;
  if (!baseUrl) throw new Error("API_INTERNAL_URL não configurada");
  if (!token) throw new Error("INTERNAL_PROXY_TOKEN não configurado");
  const host = incoming.get("host")?.trim().toLowerCase();
  if (!host) throw new Error("Pedido sem Host");
  // Só `nome[:porta]` ou `[ipv6][:porta]`: nada mais segue para o backend como X-Forwarded-Host.
  if (!/^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.?|\[[0-9a-f:.]+\])(?::\d{1,5})?$/.test(host)) {
    throw new Error("Host inválido");
  }

  const headers: Record<string, string> = {
    "X-Forwarded-Host": host,
    "X-Internal-Token": token,
  };
  const cookie = incoming.get("cookie");
  if (cookie) headers.Cookie = cookie;
  const requestId = incoming.get("x-request-id");
  if (requestId) headers["X-Request-Id"] = requestId;

  const client = createClient<paths>({
    baseUrl,
    headers,
    cache: "no-store",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  client.use(errorMiddleware);
  return client;
}
