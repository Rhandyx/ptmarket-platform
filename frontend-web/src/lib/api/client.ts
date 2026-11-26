import createClient, { type Middleware } from "openapi-fetch";
import { errorMiddleware, type paths } from "./index";

export type BrowserApiOptions = {
  /** Token CSRF (de GET /api/v1/auth/session quando existir no contrato). */
  csrfToken?: string | (() => string | undefined);
  /** Só para testes. */
  fetch?: typeof fetch;
  baseUrl?: string;
};

/** Cliente do browser: mesmo domínio, cookies same-origin, X-CSRF-Token só em mutações. */
export function createBrowserApi(opts: BrowserApiOptions = {}) {
  const client = createClient<paths>({
    baseUrl: opts.baseUrl ?? "",
    credentials: "same-origin",
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  const csrf: Middleware = {
    onRequest({ request }) {
      if (request.method === "GET" || request.method === "HEAD") return undefined;
      const t = typeof opts.csrfToken === "function" ? opts.csrfToken() : opts.csrfToken;
      if (t) request.headers.set("X-CSRF-Token", t);
      return request;
    },
  };
  client.use(csrf, errorMiddleware);
  return client;
}
