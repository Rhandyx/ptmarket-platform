"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import styles from "./Toast.module.css";

export type ToastTone = "info" | "success" | "error";

export type ToastInput = {
  title: string;
  description?: string;
  tone?: ToastTone;
  /** ms; mínimo 5000. Ignorado nos erros, que ficam até serem fechados. */
  duration?: number;
};

type ToastItem = ToastInput & { id: number; tone: ToastTone };

type ToastApi = { show: (input: ToastInput) => number; dismiss: (id: number) => void };

const ToastContext = createContext<ToastApi | null>(null);

const MAX_VISIBLE = 3;
const MIN_DURATION = 5000;
const DEFAULT_DURATION = 6000;

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast tem de ser usado dentro de <ToastProvider>.");
  return ctx;
}

function ToastCard({ toast, onDismiss }: { toast: ToastItem; onDismiss: (id: number) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [paused, setPaused] = useState(false);
  const remaining = useRef(Math.max(MIN_DURATION, toast.duration ?? DEFAULT_DURATION));
  const sticky = toast.tone === "error";
  const { id } = toast;

  // Pausa em hover e em foco (2.2.1). Listeners nativos: o <li> não é interativo.
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const pause = () => setPaused(true);
    const resume = () => setPaused(false);
    el.addEventListener("pointerenter", pause);
    el.addEventListener("pointerleave", resume);
    el.addEventListener("focusin", pause);
    el.addEventListener("focusout", resume);
    return () => {
      el.removeEventListener("pointerenter", pause);
      el.removeEventListener("pointerleave", resume);
      el.removeEventListener("focusin", pause);
      el.removeEventListener("focusout", resume);
    };
  }, []);

  useEffect(() => {
    if (sticky || paused) return;
    const startedAt = Date.now();
    const timer = setTimeout(() => onDismiss(id), remaining.current);
    return () => {
      clearTimeout(timer);
      remaining.current -= Date.now() - startedAt;
    };
  }, [sticky, paused, id, onDismiss]);

  return (
    <div ref={ref} className={`${styles.toast} ${styles[toast.tone]}`}>
      <p className={styles.title}>{toast.title}</p>
      {toast.description ? <p className={styles.description}>{toast.description}</p> : null}
      <button
        type="button"
        className={styles.close}
        aria-label={`Fechar notificação: ${toast.title}`}
        onClick={() => onDismiss(id)}
      >
        Fechar
      </button>
    </div>
  );
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setItems((list) => list.filter((t) => t.id !== id));
  }, []);

  const show = useCallback((input: ToastInput) => {
    const id = nextId.current++;
    setItems((list) => [...list, { ...input, id, tone: input.tone ?? "info" }]);
    return id;
  }, []);

  const api = useMemo(() => ({ show, dismiss }), [show, dismiss]);

  // Máx. 3 visíveis; os restantes esperam na fila.
  const visible = items.slice(0, MAX_VISIBLE);
  const polite = visible.filter((t) => t.tone !== "error");
  const errors = visible.filter((t) => t.tone === "error");

  return (
    <ToastContext.Provider value={api}>
      {children}
      {/* Regiões vivas sempre montadas, para os anúncios serem fiáveis. */}
      <div className={styles.viewport}>
        <div role="status" aria-live="polite" aria-label="Notificações" className={styles.region}>
          {polite.map((t) => (
            <ToastCard key={t.id} toast={t} onDismiss={dismiss} />
          ))}
        </div>
        <div role="alert" aria-label="Erros" className={styles.region}>
          {errors.map((t) => (
            <ToastCard key={t.id} toast={t} onDismiss={dismiss} />
          ))}
        </div>
      </div>
    </ToastContext.Provider>
  );
}
