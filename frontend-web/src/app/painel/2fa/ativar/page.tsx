import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { LogoutForm } from "../../LogoutForm";
import styles from "../../painel.module.css";
import { loadStaff } from "../../session";
import { Unavailable } from "../../Unavailable";

export const metadata: Metadata = { title: "Ativar a verificação em dois passos" };

/** O TOTP ainda não está ativo (409 no verify). A ativação chega no cartão 08. */
export default async function AtivarPage() {
  const s = await loadStaff({ requireMfa: false });
  if (s.kind === "unavailable") return <Unavailable retry="/painel/2fa/ativar" />;
  if (s.me.mfa_verified) redirect("/painel");

  return (
    <section className={styles.page} aria-labelledby="ativar-titulo">
      <p className={styles.eyebrow}>Painel · em breve</p>
      <h1 id="ativar-titulo" className={styles.title}>
        Ative a verificação em dois passos
      </h1>
      <p className={styles.lead}>
        A sua conta ainda não tem uma aplicação de autenticação associada. Em breve poderá ativá-la aqui; até lá, peça
        ajuda à equipa da plataforma.
      </p>
      <div className={styles.aside}>
        <LogoutForm />
      </div>
    </section>
  );
}
