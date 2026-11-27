import type { Metadata } from "next";
import Link from "next/link";
import { areasFor } from "./areas";
import { LogoutForm } from "./LogoutForm";
import styles from "./painel.module.css";
import { loadStaff } from "./session";
import { Unavailable } from "./Unavailable";

export const metadata: Metadata = { title: "Início" };

export default async function PainelPage() {
  const s = await loadStaff({ requireMfa: true });
  if (s.kind === "unavailable") return <Unavailable retry="/painel" />;
  const areas = areasFor(s.me.roles);

  return (
    <>
      <header className={styles.topbar}>
        <p className={styles.context}>Painel</p>
        <div className={styles.who}>
          <span>Sessão de {s.me.full_name}</span>
          <LogoutForm />
        </div>
      </header>
      <section className={styles.page} aria-labelledby="painel-titulo">
        <p className={styles.eyebrow}>Painel PT Market</p>
        <h1 id="painel-titulo" className={styles.title}>
          Olá, {s.me.full_name}
        </h1>
        <p className={styles.lead}>Estas são as áreas a que tem acesso.</p>
        {areas.length === 0 ? (
          <p className={styles.empty}>Ainda não tem áreas atribuídas.</p>
        ) : (
          <ul className={styles.areas}>
            {areas.map((a) => (
              <li key={a.role} className={`${styles.area} ${a.href ? styles.areaOn : ""}`}>
                <h2>
                  {a.href ? (
                    <Link className={styles.areaLink} href={a.href}>
                      {a.title}
                    </Link>
                  ) : (
                    a.title
                  )}
                </h2>
                <p>{a.description}</p>
                <span className={`${styles.badge} ${a.href ? styles.badgeOn : ""}`} aria-hidden={a.href ? true : undefined}>
                  {a.href ? "Abrir" : "Em breve"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
