import styles from "./painel.module.css";

/** Estado sem API (503, rede): mensagem fixa e uma ligação para tentar de novo. */
export function Unavailable({ retry }: { retry: "/painel" | "/painel/2fa" | "/painel/2fa/ativar" }) {
  return (
    <section className={styles.page} aria-labelledby="indisponivel">
      <p className={styles.eyebrow}>Painel PT Market</p>
      <h1 id="indisponivel" className={styles.title}>
        Serviço indisponível
      </h1>
      <p className={styles.lead}>Serviço indisponível. Tente de novo.</p>
      <p className={styles.aside}>
        <a className={styles.link} href={retry}>
          Tentar de novo
        </a>
      </p>
    </section>
  );
}
