"use client";

import { useEffect, useId, useRef, type ReactNode, type RefObject } from "react";
import { Button } from "./Button";
import styles from "./Modal.module.css";

let scrollLocks = 0;

function lockScroll(): () => void {
  const root = document.documentElement;
  if (scrollLocks++ === 0) root.style.overflow = "hidden";
  return () => {
    if (--scrollLocks === 0) root.style.overflow = "";
  };
}

type OverlayProps = {
  open: boolean;
  onClose: () => void;
  title: string;
  children?: ReactNode;
  footer?: ReactNode;
  /** Clique no backdrop só fecha se `dismissible`. */
  dismissible?: boolean;
  drawer?: boolean;
  hideClose?: boolean;
  initialFocusRef?: RefObject<HTMLElement | null>;
};

function Overlay({
  open,
  onClose,
  title,
  children,
  footer,
  dismissible = false,
  drawer = false,
  hideClose = false,
  initialFocusRef,
}: OverlayProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  });

  // Sincroniza `open` com o <dialog>. O foco é devolvido ao disparador pelo próprio browser.
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      initialFocusRef?.current?.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open, initialFocusRef]);

  useEffect(() => {
    if (!open) return;
    return lockScroll();
  }, [open]);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    let pressedOnBackdrop = false;
    const handleClose = () => onCloseRef.current();
    const handleDown = (e: PointerEvent) => {
      pressedOnBackdrop = e.target === dialog;
    };
    const handleClick = (e: MouseEvent) => {
      if (dismissible && pressedOnBackdrop && e.target === dialog) dialog.close();
      pressedOnBackdrop = false;
    };
    dialog.addEventListener("close", handleClose);
    dialog.addEventListener("pointerdown", handleDown);
    dialog.addEventListener("click", handleClick);
    return () => {
      dialog.removeEventListener("close", handleClose);
      dialog.removeEventListener("pointerdown", handleDown);
      dialog.removeEventListener("click", handleClick);
    };
  }, [dismissible]);

  return (
    <dialog
      ref={ref}
      className={`${styles.dialog} ${drawer ? styles.drawer : ""}`}
      aria-labelledby={titleId}
    >
      <header className={styles.header}>
        <h2 id={titleId} className={styles.title}>
          {title}
        </h2>
        {hideClose ? null : (
          <form method="dialog">
            <Button variant="ghost" type="submit">
              Fechar
            </Button>
          </form>
        )}
      </header>
      <div className={styles.body}>{children}</div>
      {footer ? <div className={styles.footer}>{footer}</div> : null}
    </dialog>
  );
}

type ModalProps = Omit<OverlayProps, "drawer" | "footer"> & { footer?: ReactNode };

export function Modal(props: ModalProps) {
  return <Overlay {...props} />;
}

export function Drawer(props: ModalProps) {
  return <Overlay {...props} drawer />;
}

type ConfirmProps = {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  children?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  /** Ação destrutiva: o foco inicial fica em "Cancelar". */
  destructive?: boolean;
};

/** Substitui `confirm()`. */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  children,
  confirmLabel,
  cancelLabel = "Cancelar",
  destructive = false,
}: ConfirmProps) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  return (
    <Overlay
      open={open}
      onClose={onClose}
      title={title}
      hideClose
      initialFocusRef={cancelRef}
      footer={
        <>
          <form method="dialog" className={styles.form}>
            <Button ref={cancelRef} variant="secondary" type="submit">
              {cancelLabel}
            </Button>
          </form>
          <form method="dialog" className={styles.form} onSubmit={onConfirm}>
            <Button variant={destructive ? "danger" : "primary"} type="submit">
              {confirmLabel}
            </Button>
          </form>
        </>
      }
    >
      {children}
    </Overlay>
  );
}
