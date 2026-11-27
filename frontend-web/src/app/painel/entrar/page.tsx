import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { staffMe } from "../../../lib/api/staff";
import { MSG_SESSION, sessionEnded } from "../messages";
import styles from "../painel.module.css";
import { platformHeaders } from "../session";
import { LoginForm } from "./LoginForm";

export const metadata: Metadata = { title: "Entrar" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function EntrarPage({ searchParams }: Props) {
  const ended = sessionEnded(await searchParams);
  const incoming = await platformHeaders();
  // Sessão completa já aberta: segue para o painel. Sem API: mostra o formulário na mesma.
  const me = await staffMe({ incoming });
  if (me.ok && me.value.mfa_verified) redirect("/painel");

  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || null;
  return (
    <div className={`${styles.page} ${styles.auth}`}>
      <section aria-labelledby="entrar-titulo">
        <p className={styles.eyebrow}>Painel · passo 1 de 2</p>
        <h1 id="entrar-titulo" className={styles.title}>
          Entrar no painel
        </h1>
        <p className={styles.lead}>
          Acesso reservado às equipas das lojas, dos canais e das entidades patrocinadoras. A seguir pedimos o código
          da verificação em dois passos.
        </p>
      </section>
      <div className={styles.card}>
        {ended ? (
          <p role="status" className={styles.notice}>
            {MSG_SESSION}
          </p>
        ) : null}
        <LoginForm siteKey={siteKey} />
      </div>
    </div>
  );
}
