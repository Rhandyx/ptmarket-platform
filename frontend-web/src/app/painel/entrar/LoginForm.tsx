"use client";

import { useActionState, useEffect, useMemo, useState, type FormEvent } from "react";
import { Button } from "../../../components/ui/Button";
import { loginAction } from "../actions";
import { captchaMissing, LOGIN_INITIAL, type LoginState } from "../form-state";
import { MSG_CAPTCHA } from "../messages";
import styles from "../painel.module.css";
import { Turnstile } from "./Turnstile";

const ID = {
  alert: "entrar-erro",
  email: "entrar-email",
  emailError: "entrar-email-erro",
  password: "entrar-password",
  passwordError: "entrar-password-erro",
  captcha: "entrar-captcha",
} as const;

/** Primeiro elemento a focar depois de uma tentativa falhada. */
export function firstErrorId(s: LoginState): string | null {
  if (s.fieldErrors.email) return ID.email;
  if (s.fieldErrors.password) return ID.password;
  if (s.credentials) return ID.email;
  if (s.message) return ID.alert;
  return null;
}

const describedBy = (...ids: (string | false | undefined)[]) => ids.filter(Boolean).join(" ") || undefined;

type FieldsProps = {
  state: LoginState;
  action: (fd: FormData) => void;
  pending: boolean;
  siteKey: string | null;
  onSubmit?: (e: FormEvent<HTMLFormElement>) => void;
};

/** Formulário sem estado próprio (testável sem browser). */
export function LoginFields({ state, action, pending, siteKey, onSubmit }: FieldsProps) {
  const emailInvalid = !!state.fieldErrors.email || state.credentials;
  const passwordInvalid = !!state.fieldErrors.password || state.credentials;
  return (
    <form action={action} onSubmit={onSubmit} noValidate className={styles.form} aria-label="Entrar no painel">
      {state.message ? (
        <p id={ID.alert} role="alert" tabIndex={-1} className={styles.alert}>
          {state.message}
        </p>
      ) : null}

      <div className={styles.field}>
        <label className={styles.label} htmlFor={ID.email}>
          Email
        </label>
        <input
          id={ID.email}
          className={styles.input}
          name="email"
          type="email"
          inputMode="email"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={255}
          required
          defaultValue={state.email}
          aria-invalid={emailInvalid || undefined}
          aria-describedby={describedBy(
            !!state.fieldErrors.email && ID.emailError,
            state.credentials && ID.alert,
          )}
        />
        {state.fieldErrors.email ? (
          <p id={ID.emailError} role="alert" className={styles.fieldError}>
            {state.fieldErrors.email}
          </p>
        ) : null}
      </div>

      <div className={styles.field}>
        <label className={styles.label} htmlFor={ID.password}>
          Palavra-passe
        </label>
        <input
          id={ID.password}
          className={styles.input}
          name="password"
          type="password"
          autoComplete="current-password"
          required
          aria-invalid={passwordInvalid || undefined}
          aria-describedby={describedBy(
            !!state.fieldErrors.password && ID.passwordError,
            state.credentials && ID.alert,
          )}
        />
        {state.fieldErrors.password ? (
          <p id={ID.passwordError} role="alert" className={styles.fieldError}>
            {state.fieldErrors.password}
          </p>
        ) : null}
      </div>

      {state.captchaRequired ? (
        <div className={styles.captcha} role="group" aria-labelledby={ID.captcha}>
          <p id={ID.captcha} className={styles.hint}>
            Verificação anti-robô
          </p>
          {siteKey ? (
            <Turnstile key={state.attempt} siteKey={siteKey} />
          ) : (
            <p className={styles.fieldError}>A verificação anti-robô não está disponível. Tente mais tarde.</p>
          )}
          <noscript>
            <p className={styles.hint}>Esta verificação precisa de JavaScript.</p>
          </noscript>
        </div>
      ) : null}

      <Button type="submit" variant="primary" className={styles.submit} aria-disabled={pending || undefined}>
        {pending ? "A entrar…" : "Entrar"}
      </Button>
    </form>
  );
}

export function LoginForm({ siteKey }: { siteKey: string | null }) {
  const [state, action, pending] = useActionState(loginAction, LOGIN_INITIAL);
  // Submit travado no browser (captcha por resolver): o formulário não é enviado, logo o email e
  // a palavra-passe ficam nos campos; mostra-se a mensagem do captcha até à próxima resposta.
  const [blocked, setBlocked] = useState<{ for: LoginState; n: number } | null>(null);
  const shown = useMemo<LoginState>(
    () =>
      blocked?.for === state ? { ...state, message: MSG_CAPTCHA, credentials: false, fieldErrors: {} } : state,
    [blocked, state],
  );
  useEffect(() => {
    const id = firstErrorId(state);
    if (id) document.getElementById(id)?.focus();
  }, [state]);
  useEffect(() => {
    if (blocked) document.getElementById(ID.alert)?.focus();
  }, [blocked]);
  const onSubmit = (e: FormEvent<HTMLFormElement>) => {
    if (!captchaMissing(state, new FormData(e.currentTarget))) return;
    e.preventDefault();
    setBlocked((b) => ({ for: state, n: (b?.n ?? 0) + 1 }));
  };
  return <LoginFields state={shown} action={action} pending={pending} siteKey={siteKey} onSubmit={onSubmit} />;
}
