"use client";

import type { ButtonHTMLAttributes, Ref } from "react";
import styles from "./Button.module.css";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; ref?: Ref<HTMLButtonElement> };

export function Button({ variant = "primary", className, type = "button", ...rest }: Props) {
  const cls = [styles.button, styles[variant], className].filter(Boolean).join(" ");
  return <button type={type} className={cls} {...rest} />;
}

/** Classe para <button> com atributos que o Button não encaminha (ex.: popovertarget). */
export function buttonClass(variant: ButtonVariant = "secondary"): string {
  return `${styles.button} ${styles[variant]}`;
}
