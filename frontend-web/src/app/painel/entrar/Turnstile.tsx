"use client";

import { useEffect, useRef } from "react";
import styles from "../painel.module.css";

type TurnstileApi = {
  render(el: HTMLElement, opts: Record<string, unknown>): string | undefined;
  remove(id: string): void;
};
type TurnstileWindow = Window & { turnstile?: TurnstileApi };

const SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
/** Largura mínima do tamanho "flexible" do Turnstile (px de CSS, medida do contentor). */
const FLEXIBLE_MIN = 300;

/**
 * Cloudflare Turnstile (só quando a API pede captcha). Desenho explícito em cada montagem (novo
 * `key` a cada tentativa: cada token só serve uma vez): "flexible" ocupa a largura do cartão;
 * abaixo de 300 px usa "compact" para não ser cortado (reflow a 320 px). O script é criado por
 * este código (confiável pelo nonce + 'strict-dynamic' da CSP). O token vai em `turnstile_token`.
 */
export function Turnstile({ siteKey }: { siteKey: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const w = window as TurnstileWindow;
    let cancelled = false;
    let id: string | undefined;
    const draw = () => {
      if (cancelled || !w.turnstile || id) return;
      id = w.turnstile.render(el, {
        sitekey: siteKey,
        size: el.clientWidth < FLEXIBLE_MIN ? "compact" : "flexible",
        "response-field-name": "turnstile_token",
      });
    };
    let script: HTMLScriptElement | null = null;
    if (w.turnstile) {
      draw();
    } else {
      script = document.querySelector<HTMLScriptElement>("script[data-ptm-turnstile]");
      if (!script) {
        script = document.createElement("script");
        script.src = SCRIPT;
        script.async = true;
        script.dataset.ptmTurnstile = "";
        document.head.appendChild(script);
      }
      script.addEventListener("load", draw);
    }
    return () => {
      cancelled = true;
      script?.removeEventListener("load", draw);
      if (id) w.turnstile?.remove(id);
    };
  }, [siteKey]);
  return <div ref={ref} className={styles.widget} data-ptm-captcha="" />;
}
