"use client";

import { useId, type ReactNode } from "react";
import { buttonClass, type ButtonVariant } from "./Button";
import styles from "./Popover.module.css";

type Props = {
  /** Texto do disparador. */
  label: string;
  /** Nome acessível do painel. */
  title: string;
  children: ReactNode;
  variant?: ButtonVariant;
};

/**
 * Popover API nativa: abre, fecha, Esc e clique fora funcionam sem JavaScript.
 * Posição por CSS (âncora implícita do `popovertarget`).
 */
export function Popover({ label, title, children, variant = "secondary" }: Props) {
  const id = useId();
  return (
    <>
      <button type="button" className={buttonClass(variant)} popoverTarget={id}>
        {label}
      </button>
      <div id={id} popover="auto" role="dialog" aria-label={title} className={styles.panel}>
        <p className={styles.heading}>{title}</p>
        <div className={styles.text}>{children}</div>
      </div>
    </>
  );
}
