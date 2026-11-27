import type { Metadata } from "next";
import { RegisterForm } from "./RegisterForm";
import { S } from "./strings";
import styles from "./registar.module.css";

export const metadata: Metadata = {
  title: S.title,
  description: "Escolha a freguesia da loja e veja a comissão que se aplica.",
};

export default function RegistarLoja() {
  return (
    <div className={styles.page}>
      <header className={styles.intro}>
        <p className={styles.eyebrow}>{S.eyebrow}</p>
        <h1 className={styles.title}>{S.title}</h1>
        <p className={styles.lead}>{S.lead}</p>
      </header>
      <RegisterForm />
    </div>
  );
}
