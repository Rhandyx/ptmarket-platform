import styles from "./page.module.css";

const principios = [
  {
    titulo: "Lojas com rosto",
    texto: "Cada comerciante tem a sua montra, a sua voz e os seus clientes. Sem anonimato, sem ruído.",
  },
  {
    titulo: "Preços honestos",
    texto: "O preço é o preço, com IVA incluído e histórico à vista. Sem contagens decrescentes nem urgências falsas.",
  },
  {
    titulo: "Perto de si",
    texto: "Do bairro à cidade, a compra local faz-se com poucos cliques e chega depressa.",
  },
];

export default function Home() {
  return (
    <>
      <section className={styles.hero} aria-labelledby="titulo">
        <p className={styles.eyebrow}>Mercado local português</p>
        <h1 id="titulo" className={styles.title}>
          O comércio da sua terra, bem apresentado.
        </h1>
        <p className={styles.lead}>
          Uma plataforma para lojas de proximidade e para quem as prefere. Clara, rápida e sem distrações.
        </p>
        <p className={styles.actions}>
          <a className={styles.primary} href="#lojas">
            Abrir uma loja
          </a>
          <a className={styles.link} href="#principios">
            Como pensamos
          </a>
        </p>
      </section>

      <section id="principios" className={styles.section} aria-labelledby="principios-titulo">
        <h2 id="principios-titulo" className={styles.sectionTitle}>
          Princípios
        </h2>
        <ol className={styles.list}>
          {principios.map((p, i) => (
            <li key={p.titulo} className={styles.item}>
              <span className={styles.index} aria-hidden="true">
                {String(i + 1).padStart(2, "0")}
              </span>
              <h3 className={styles.itemTitle}>{p.titulo}</h3>
              <p className={styles.itemText}>{p.texto}</p>
            </li>
          ))}
        </ol>
      </section>

      <section id="lojas" className={styles.section} aria-labelledby="lojas-titulo">
        <div className={styles.band}>
          <h2 id="lojas-titulo" className={styles.bandTitle}>
            Para quem vende.
          </h2>
          <p className={styles.bandText}>
            Catálogo, pagamentos e faturação num só sítio, com a sua marca e o seu domínio.
          </p>
        </div>
      </section>
    </>
  );
}
