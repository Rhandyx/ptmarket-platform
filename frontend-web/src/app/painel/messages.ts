// Textos do painel (sem segredos, sem dizer se a conta existe).

export const MSG_CREDENTIALS = "Email ou palavra-passe incorretos.";
export const MSG_UNAVAILABLE = "Serviço indisponível. Tente de novo.";
export const MSG_CAPTCHA = "Para continuar, confirme que não é um robô.";
export const MSG_CODE = "Código incorreto ou já usado.";
export const MSG_SESSION = "A sessão terminou. Entre de novo.";

/** "Demasiadas tentativas. Tente de novo dentro de N minutos." (mínimo 1 minuto). */
export function rateLimitMessage(retryAfterSeconds: number | null): string {
  const n = Math.max(1, Math.ceil((retryAfterSeconds ?? 60) / 60));
  return `Demasiadas tentativas. Tente de novo dentro de ${n} ${n === 1 ? "minuto" : "minutos"}.`;
}

/** Só o valor exato `?sessao=terminou` mostra MSG_SESSION; qualquer outro é ignorado (nunca texto do URL). */
export function sessionEnded(params: Record<string, string | string[] | undefined>): boolean {
  return params.sessao === "terminou";
}
