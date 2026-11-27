import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { LogoutForm } from "../LogoutForm";
import styles from "../painel.module.css";
import { loadStaff } from "../session";
import { Unavailable } from "../Unavailable";
import { MfaForm } from "./MfaForm";

export const metadata: Metadata = { title: "Verificação em dois passos" };

export default async function MfaPage() {
  const s = await loadStaff({ requireMfa: false });
  if (s.kind === "unavailable") return <Unavailable retry="/painel/2fa" />;
  if (s.me.mfa_verified) redirect("/painel");

  return (
    <div className={`${styles.page} ${styles.auth}`}>
      <section aria-labelledby="mfa-titulo">
        <p className={styles.eyebrow}>Painel · passo 2 de 2</p>
        <h1 id="mfa-titulo" className={styles.title}>
          Verificação em dois passos
        </h1>
        <p className={styles.lead}>Introduza o código da sua aplicação de autenticação para concluir a entrada.</p>
        <div className={styles.aside}>
          <LogoutForm label="Cancelar e terminar sessão" variant="ghost" />
        </div>
      </section>
      <div className={styles.card}>
        <MfaForm variant="totp" />
        <details className={styles.recovery}>
          <summary>Não tem acesso à aplicação?</summary>
          <p className={styles.hint}>Use um dos códigos de recuperação que guardou quando ativou a verificação.</p>
          <MfaForm variant="recovery" />
        </details>
      </div>
    </div>
  );
}
