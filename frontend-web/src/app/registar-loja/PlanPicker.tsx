import type { PlanTierView, PlanView } from "../../lib/api/signup";
import { formatBps, formatCents } from "./format";
import { planLabel, S, tableCaption } from "./strings";
import styles from "./registar.module.css";

function volume(t: PlanTierView): string {
  if (t.gmv_to_cents == null) return `A partir de ${formatCents(t.gmv_from_cents)}`;
  if (t.gmv_from_cents === 0) return `Até ${formatCents(t.gmv_to_cents)}`;
  return `De ${formatCents(t.gmv_from_cents)} a ${formatCents(t.gmv_to_cents)}`;
}

type Props = { plans: PlanView[]; value: string; onChange: (code: string) => void };

export function PlanPicker({ plans, value, onChange }: Props) {
  return (
    <fieldset className={styles.fieldset}>
      <legend className={styles.legend}>{S.planLegend}</legend>
      <div className={styles.plans}>
        {plans.map((p) => {
          const id = `plano-${p.plan_code}`;
          return (
            <div key={p.plan_code} className={styles.plan} data-selected={value === p.plan_code || undefined}>
              <div className={styles.planHead}>
                <input
                  className={styles.radio}
                  type="radio"
                  name="plano"
                  id={id}
                  value={p.plan_code}
                  checked={value === p.plan_code}
                  onChange={() => onChange(p.plan_code)}
                />
                <label htmlFor={id} className={styles.planName}>
                  {planLabel(p.plan_code)}
                  {p.is_default ? <span className={styles.tag}>{S.planDefault}</span> : null}
                </label>
              </div>
              <div className={styles.tableWrap}>
                <table className={styles.table}>
                  <caption className={styles.srOnly}>{tableCaption(p.plan_code)}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{S.tableVolume}</th>
                      <th scope="col">{S.tableFee}</th>
                      <th scope="col">{S.tableCommission}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {p.tiers.map((t) => (
                      <tr key={t.gmv_from_cents}>
                        <th scope="row" data-label={S.tableVolume}>
                          {volume(t)}
                        </th>
                        <td data-label={S.tableFee}>{formatCents(t.monthly_fee_cents)}</td>
                        <td data-label={S.tableCommission}>{formatBps(t.marginal_commission_bps)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          );
        })}
      </div>
      <p className={styles.note}>{S.vatNote}</p>
    </fieldset>
  );
}
