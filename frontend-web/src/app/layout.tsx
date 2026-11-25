import type { Metadata, Viewport } from "next";
import { connection } from "next/server";
import "../styles/globals.css";
import Link from "next/link";
import styles from "./layout.module.css";

export const metadata: Metadata = {
  title: { default: "PT Market", template: "%s · PT Market" },
  description: "O comércio local português, num só lugar.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Renderização dinâmica: o CSP leva um nonce novo em cada pedido (ver proxy.ts).
  await connection();

  return (
    <html lang="pt-PT">
      <body>
        <a className="skip-link" href="#conteudo">
          Saltar para o conteúdo
        </a>
        <header className={styles.header}>
          <div className={styles.bar}>
            <Link className={styles.brand} href="/" aria-label="PT Market, página inicial">
              PT Market
            </Link>
            <nav aria-label="Principal">
              <ul className={styles.nav}>
                <li>
                  <a href="#principios">Princípios</a>
                </li>
                <li>
                  <a href="#lojas">Para lojas</a>
                </li>
              </ul>
            </nav>
          </div>
        </header>
        <main id="conteudo">{children}</main>
        <footer className={styles.footer}>
          <div className={styles.bar}>
            <p>© PT Market. Feito em Portugal.</p>
            <p className={styles.muted}>Comércio local, sem ruído.</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
