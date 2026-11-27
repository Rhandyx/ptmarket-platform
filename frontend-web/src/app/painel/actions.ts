"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { STAFF_COOKIE, staffLogin, staffLogout, staffVerifyMfa, type StaffFailure } from "../../lib/api/staff";
import type { LoginState, MfaState } from "./form-state";
import { MSG_CAPTCHA, MSG_CODE, MSG_CREDENTIALS, MSG_UNAVAILABLE, rateLimitMessage } from "./messages";
import { platformHeaders } from "./session";

const field = (fd: FormData, name: string): string => {
  const v = fd.get(name);
  return typeof v === "string" ? v : "";
};

/** Entrar: email + palavra-passe (+ token anti-robô quando pedido). Redireciona só para caminhos fixos. */
export async function loginAction(prev: LoginState, fd: FormData): Promise<LoginState> {
  const incoming = await platformHeaders();
  const email = field(fd, "email").trim().slice(0, 255);
  const password = field(fd, "password"); // nunca aparada nem normalizada
  const token = field(fd, "turnstile_token") || field(fd, "cf-turnstile-response");
  const next: LoginState = {
    email,
    message: null,
    credentials: false,
    fieldErrors: {},
    captchaRequired: prev.captchaRequired,
    attempt: prev.attempt + 1,
  };

  if (!email) next.fieldErrors.email = "Indique o email.";
  if (!password) next.fieldErrors.password = "Indique a palavra-passe.";
  if (next.fieldErrors.email || next.fieldErrors.password) return next;
  if (field(fd, "email").trim().length > 255 || password.length > 128) {
    return { ...next, message: MSG_CREDENTIALS, credentials: true };
  }
  if (next.captchaRequired && !token) return { ...next, message: MSG_CAPTCHA };

  const r = await staffLogin(
    { incoming, cookies: await cookies() },
    { email, password, ...(token ? { turnstileToken: token.slice(0, 2048) } : {}) },
  );
  if (r.ok) redirect(r.value.mfaRequired ? "/painel/2fa" : "/painel");
  return loginFailure(next, r, !!token);
}

function loginFailure(next: LoginState, r: StaffFailure, sentToken: boolean): LoginState {
  switch (r.kind) {
    case "unauthorized":
      // Captcha exigido e não enviado: não dizer "incorretos" (as credenciais podem estar certas).
      if (r.captchaRequired && !sentToken) return { ...next, message: MSG_CAPTCHA, captchaRequired: true };
      return {
        ...next,
        message: MSG_CREDENTIALS,
        credentials: true,
        captchaRequired: next.captchaRequired || r.captchaRequired,
      };
    case "invalid":
      return {
        ...next,
        message: MSG_CREDENTIALS,
        credentials: true,
        captchaRequired: next.captchaRequired,
      };
    case "rate_limited":
      return { ...next, message: rateLimitMessage(r.retryAfterSeconds) };
    default:
      return { ...next, message: MSG_UNAVAILABLE };
  }
}

/** 2FA: código TOTP (6 dígitos) ou código de recuperação. */
export async function verifyMfaAction(prev: MfaState, fd: FormData): Promise<MfaState> {
  const incoming = await platformHeaders();
  const code = field(fd, "code").replace(/\s+/g, "");
  const next: MfaState = { message: null, codeError: null, attempt: prev.attempt + 1 };
  if (!code) return { ...next, codeError: "Indique o código." };
  if (code.length > 64) return { ...next, codeError: MSG_CODE };

  const r = await staffVerifyMfa({ incoming, cookies: await cookies() }, code);
  if (r.ok) redirect("/painel");
  switch (r.kind) {
    case "conflict":
      return redirect("/painel/2fa/ativar");
    case "forbidden":
      // Caminho fixo: a página de entrada só reconhece este valor exato.
      return redirect("/painel/entrar?sessao=terminou");
    case "unauthorized":
    case "invalid":
      return { ...next, codeError: MSG_CODE };
    case "rate_limited":
      return { ...next, message: rateLimitMessage(r.retryAfterSeconds) };
    default:
      return { ...next, message: MSG_UNAVAILABLE };
  }
}

/** Terminar sessão. Se a API falhar, o cookie é limpo na mesma (a sessão expira no servidor). */
export async function logoutAction(): Promise<void> {
  const incoming = await platformHeaders();
  const jar = await cookies();
  const r = await staffLogout({ incoming, cookies: jar });
  if (!r.ok) {
    jar.set({ name: STAFF_COOKIE, value: "", path: "/", maxAge: 0, secure: true, httpOnly: true, sameSite: "strict" });
  }
  redirect("/painel/entrar");
}
