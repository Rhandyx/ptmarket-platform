"use client";

import { useState } from "react";
import { Button } from "./Button";
import { ConfirmDialog, Drawer, Modal } from "./Modal";
import { Popover } from "./Popover";
import { ToastProvider, useToast } from "./Toast";
import styles from "./Showcase.module.css";

function Row({ n, name, desc, children }: { n: string; name: string; desc: string; children: React.ReactNode }) {
  return (
    <li className={styles.row}>
      <span className={styles.index} aria-hidden="true">
        {n}
      </span>
      <div>
        <h2 className={styles.name}>{name}</h2>
        <p className={styles.desc}>{desc}</p>
      </div>
      <div className={styles.actions}>{children}</div>
    </li>
  );
}

function Demos() {
  const [modal, setModal] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const toast = useToast();

  return (
    <>
      <ol className={styles.list}>
        <Row
          n="01"
          name="Modal"
          desc="Diálogo nativo estilizado. Esc e “Fechar” fecham; o foco fica preso e volta ao botão que o abriu."
        >
          <Button onClick={() => setModal(true)}>Abrir modal</Button>
        </Row>
        <Row
          n="02"
          name="Confirmação"
          desc="Substitui o confirm() do browser. Em ações destrutivas, o foco inicial fica em “Cancelar”."
        >
          <Button variant="secondary" onClick={() => setConfirm(true)}>
            Apagar produto
          </Button>
        </Row>
        <Row
          n="03"
          name="Drawer"
          desc="Painel lateral para filtros e detalhes; em ecrãs estreitos sobe do fundo."
        >
          <Button variant="secondary" onClick={() => setDrawer(true)}>
            Abrir drawer
          </Button>
        </Row>
        <Row
          n="04"
          name="Popover"
          desc="Popover API nativa: abre e fecha sem JavaScript, com Esc e clique fora."
        >
          <Popover label="Mais informação" title="Preço com IVA">
            O preço apresentado já inclui IVA à taxa em vigor.
          </Popover>
        </Row>
        <Row
          n="05"
          name="Toast"
          desc="Avisos anunciados sem roubar o foco. Pausam com o rato ou o teclado; os erros ficam até serem fechados."
        >
          <Button
            variant="secondary"
            onClick={() => toast.show({ title: "Alterações guardadas", description: "A loja foi atualizada.", tone: "success" })}
          >
            Mostrar aviso
          </Button>
          <Button
            variant="secondary"
            onClick={() => toast.show({ title: "Não foi possível guardar", description: "Tente novamente dentro de instantes.", tone: "error" })}
          >
            Mostrar erro
          </Button>
        </Row>
      </ol>

      <Modal open={modal} onClose={() => setModal(false)} title="Bem-vindo à sua loja" dismissible>
        <p>Este diálogo usa o elemento nativo dialog. Prima Esc, use o botão Fechar ou clique fora para sair.</p>
        <p>Experimente Tab: o foco nunca sai daqui.</p>
        <Button variant="secondary" onClick={() => toast.show({ title: "Olá do modal" })}>
          Mostrar aviso
        </Button>
      </Modal>

      <ConfirmDialog
        open={confirm}
        onClose={() => setConfirm(false)}
        onConfirm={() => toast.show({ title: "Produto apagado", tone: "success" })}
        title="Apagar este produto?"
        confirmLabel="Apagar"
        destructive
      >
        <p>Esta ação não pode ser anulada. O produto deixa de aparecer na loja.</p>
      </ConfirmDialog>

      <Drawer open={drawer} onClose={() => setDrawer(false)} title="Filtros" dismissible>
        <p>Categoria, preço e disponibilidade ficam aqui.</p>
        <p>O painel ancora ao fim da linha e ocupa no máximo 28 rem.</p>
      </Drawer>
    </>
  );
}

export function Showcase() {
  return (
    <div className={styles.shell}>
      <p className={styles.eyebrow}>Design system</p>
      <h1 className={styles.title}>Sobreposições</h1>
      <p className={styles.lead}>
        Modal, confirmação, drawer, popover e toast: acessíveis, animados com sobriedade e nunca nativos.
      </p>
      <ToastProvider>
        <Demos />
      </ToastProvider>
    </div>
  );
}
