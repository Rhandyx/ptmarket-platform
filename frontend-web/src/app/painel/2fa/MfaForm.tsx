"use client";

import { useActionState, useEffect } from "react";
import { Button } from "../../../components/ui/Button";
import { verifyMfaAction } from "../actions";
import { MFA_INITIAL, type MfaState } from "../form-state";
import styles from "../painel.module.css";

export type MfaVariant = "totp" | "recovery";

const TEXT: Record<MfaVariant, { label: string; hint: string; submit: string; autoComplete: string }> = {
  totp: {
    autoComplete: "one-time-code",
    label: "Código de 6 dígitos",
    hint: "Está na sua aplicação de autenticação e muda a cada 30 segundos.",
    submit: "Confirmar",
  },
  recovery: {
    // Os gestores de passwords não devem propor aqui o código TOTP.
    autoComplete: "off",
    label: "Código de recuperação",
    hint: "Cada código de recuperação só funciona uma vez.",
    submit: "Usar código de recuperação",
  },
};

const ids = (v: MfaVariant) => ({
  alert: `mfa-${v}-erro-geral`,
  input: `mfa-${v}-codigo`,
  hint: `mfa-${v}-ajuda`,
  error: `mfa-${v}-erro`,
});

/** Primeiro elemento a focar depois de uma tentativa falhada. */
export function mfaFocusId(variant: MfaVariant, s: MfaState): string | null {
  const id = ids(variant);
  if (s.codeError) return id.input;
  if (s.message) return id.alert;
  return null;
}

type FieldsProps = { variant: MfaVariant; state: MfaState; action: (fd: FormData) => void; pending: boolean };

/** Formulário sem estado próprio (testável sem browser). O código nunca volta no estado. */
export function MfaFields({ variant, state, action, pending }: FieldsProps) {
  const id = ids(variant);
  const t = TEXT[variant];
  return (
    <form action={action} noValidate className={styles.form}>
      {state.message ? (
        <p id={id.alert} role="alert" tabIndex={-1} className={styles.alert}>
          {state.message}
        </p>
      ) : null}
      <div className={styles.field}>
        <label className={styles.label} htmlFor={id.input}>
          {t.label}
        </label>
        <input
          id={id.input}
          className={`${styles.input} ${styles.code}`}
          name="code"
          type="text"
          autoComplete={t.autoComplete}
          autoCapitalize="none"
          spellCheck={false}
          required
          {...(variant === "totp" ? { inputMode: "numeric" as const } : {})}
          aria-invalid={state.codeError ? true : undefined}
          aria-describedby={[id.hint, state.codeError ? id.error : null].filter(Boolean).join(" ")}
        />
        <p id={id.hint} className={styles.hint}>
          {t.hint}
        </p>
        {state.codeError ? (
          <p id={id.error} role="alert" className={styles.fieldError}>
            {state.codeError}
          </p>
        ) : null}
      </div>
      <Button
        type="submit"
        variant={variant === "totp" ? "primary" : "secondary"}
        className={styles.submit}
        aria-disabled={pending || undefined}
      >
        {pending ? "A confirmar…" : t.submit}
      </Button>
    </form>
  );
}

export function MfaForm({ variant }: { variant: MfaVariant }) {
  const [state, action, pending] = useActionState(verifyMfaAction, MFA_INITIAL);
  useEffect(() => {
    const id = mfaFocusId(variant, state);
    if (id) document.getElementById(id)?.focus();
  }, [state, variant]);
  return <MfaFields variant={variant} state={state} action={action} pending={pending} />;
}
