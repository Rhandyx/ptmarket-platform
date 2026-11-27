import { formatBps } from "./format";
import { anchorSrText, S } from "./strings";
import styles from "./registar.module.css";

type Props = { referenceBps: number; sponsoredBps?: number | null };

/** `<del>8%</del> <ins>0%</ins>` com texto equivalente para leitores de ecrã (del/ins nem sempre são anunciados). */
export function CommissionAnchor({ referenceBps, sponsoredBps }: Props) {
  if (sponsoredBps == null) {
    return (
      <p className={styles.anchor}>
        <span className={styles.anchorLabel}>{S.commissionLabel}:</span>{" "}
        <span className={styles.anchorValue}>{formatBps(referenceBps)}</span>
      </p>
    );
  }
  return (
    <p className={styles.anchor}>
      <span aria-hidden="true">
        <span className={styles.anchorLabel}>{S.commissionLabel}:</span>{" "}
        <del className={styles.del}>{formatBps(referenceBps)}</del>{" "}
        <ins className={styles.ins}>{formatBps(sponsoredBps)}</ins>
      </span>
      <span className={styles.srOnly}>{anchorSrText(referenceBps, sponsoredBps)}</span>
    </p>
  );
}
