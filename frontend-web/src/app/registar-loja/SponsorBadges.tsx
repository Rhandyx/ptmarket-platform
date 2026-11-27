"use client";

import { useState } from "react";
import type { SponsorSummary } from "../../lib/api/signup";
import { KIND_LABEL } from "./strings";
import styles from "./registar.module.css";

/** Logótipos em storage público servido no mesmo domínio (CSP img-src 'self'). */
export function logoSrc(logoKey: string): string {
  return `/media/${logoKey.split("/").map(encodeURIComponent).join("/")}`;
}

function Badge({ sponsor }: { sponsor: SponsorSummary }) {
  const [broken, setBroken] = useState(false);
  const showLogo = Boolean(sponsor.logo_key) && !broken;
  return (
    <li className={styles.badge}>
      {showLogo && sponsor.logo_key ? (
        // eslint-disable-next-line @next/next/no-img-element -- logótipo pequeno de storage próprio; sem otimizador
        <img
          className={styles.logo}
          src={logoSrc(sponsor.logo_key)}
          alt={sponsor.name}
          width={40}
          height={40}
          loading="lazy"
          onError={() => setBroken(true)}
        />
      ) : null}
      <span className={styles.badgeText}>
        <span className={styles.badgeName}>{sponsor.name}</span>
        <span className={styles.badgeKind}>{KIND_LABEL[sponsor.kind] ?? "Entidade parceira"}</span>
      </span>
    </li>
  );
}

/** Pela ordem que a API devolve (município → freguesia → associação). */
export function SponsorBadges({ sponsors, heading }: { sponsors: SponsorSummary[]; heading: string }) {
  if (sponsors.length === 0) return null;
  return (
    <section aria-label={heading} className={styles.badges}>
      <ul className={styles.badgeList}>
        {sponsors.map((s) => (
          <Badge key={s.id} sponsor={s} />
        ))}
      </ul>
    </section>
  );
}
