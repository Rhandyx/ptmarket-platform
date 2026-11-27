// Estado dos formulários do painel (vai para o cliente: nunca password, código, token nem cookie).

export type LoginState = {
  /** Email devolvido para voltar a preencher o campo (não é segredo). */
  email: string;
  /** Erro geral (role="alert"). */
  message: string | null;
  /** 401: os dois campos ficam inválidos e descritos pela mensagem única. */
  credentials: boolean;
  fieldErrors: { email?: string; password?: string };
  captchaRequired: boolean;
  /** Muda a cada tentativa: o widget anti-robô é recriado (os tokens são de uso único). */
  attempt: number;
};

export const LOGIN_INITIAL: LoginState = {
  email: "",
  message: null,
  credentials: false,
  fieldErrors: {},
  captchaRequired: false,
  attempt: 0,
};

/** Captcha exigido e widget ainda por resolver (sem token no formulário): o submit não segue. */
export function captchaMissing(state: LoginState, fd: FormData): boolean {
  if (!state.captchaRequired) return false;
  const token = fd.get("turnstile_token") || fd.get("cf-turnstile-response");
  return typeof token !== "string" || token.trim() === "";
}

export type MfaState = {
  message: string | null;
  /** Erro ligado ao campo do código. */
  codeError: string | null;
  attempt: number;
};

export const MFA_INITIAL: MfaState = { message: null, codeError: null, attempt: 0 };
