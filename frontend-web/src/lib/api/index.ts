// Parte partilhada (servidor e browser) do cliente da API. Não importa server.ts.
import type { Middleware } from "openapi-fetch";
import type { components, paths } from "./schema";

export type { paths };
export type TenantInfo = components["schemas"]["TenantInfo"];

export type ApiErrorCode =
  | "not_found"
  | "unauthorized"
  | "forbidden"
  | "validation"
  | "conflict"
  | "internal";

const CODES: readonly ApiErrorCode[] = [
  "not_found",
  "unauthorized",
  "forbidden",
  "validation",
  "conflict",
  "internal",
];

const BY_STATUS: Record<number, ApiErrorCode> = {
  400: "validation",
  401: "unauthorized",
  403: "forbidden",
  404: "not_found",
  409: "conflict",
  422: "validation",
};

/** Erro tipado da API. `message` de erros `internal` nunca vem da API (texto genérico). */
export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  readonly fields?: Record<string, unknown>;

  constructor(code: ApiErrorCode, status: number, message: string, fields?: Record<string, unknown>) {
    super(code === "internal" ? "Erro interno. Tente novamente mais tarde." : message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.fields = fields;
  }
}

/** Middleware: respostas não-2xx viram ApiError (corpo nunca é registado em consola). */
export const errorMiddleware: Middleware = {
  async onResponse({ response }) {
    if (response.ok) return undefined;
    let body: unknown;
    try {
      body = await response.clone().json();
    } catch {
      body = undefined;
    }
    const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
    const fromBody = CODES.find((c) => c === b.code);
    const code = fromBody ?? BY_STATUS[response.status] ?? "internal";
    const message = typeof b.message === "string" ? b.message : response.statusText;
    const fields =
      b.fields && typeof b.fields === "object" ? (b.fields as Record<string, unknown>) : undefined;
    throw new ApiError(code, response.status, message, fields);
  },
};
