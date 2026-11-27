import type { GeoItem } from "../../lib/api/signup";
import { S } from "./strings";
import styles from "./registar.module.css";

export type GeoState = { items: GeoItem[]; loading: boolean; error: boolean };
export const EMPTY_GEO: GeoState = { items: [], loading: false, error: false };

type SelectProps = {
  id: string;
  label: string;
  state: GeoState;
  value: string;
  disabled?: boolean;
  onChange: (code: string) => void;
};

function GeoSelect({ id, label, state, value, disabled, onChange }: SelectProps) {
  const errId = `${id}-erro`;
  return (
    <div className={styles.field}>
      <label htmlFor={id} className={styles.label}>
        {label}
      </label>
      <select
        id={id}
        className={styles.select}
        value={value}
        disabled={disabled || state.loading}
        aria-busy={state.loading || undefined}
        aria-invalid={state.error || undefined}
        aria-describedby={state.error ? errId : undefined}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">{state.loading ? S.loading : S.choose}</option>
        {state.items.map((i) => (
          <option key={i.code} value={i.code}>
            {i.name}
          </option>
        ))}
      </select>
      {state.error ? (
        <p id={errId} role="alert" className={styles.error}>
          {S.geoError}
        </p>
      ) : null}
    </div>
  );
}

type Props = {
  districts: GeoState;
  municipalities: GeoState;
  parishes: GeoState;
  district: string;
  municipality: string;
  parish: string;
  onDistrict: (c: string) => void;
  onMunicipality: (c: string) => void;
  onParish: (c: string) => void;
};

/** Três seletores encadeados: distrito → concelho → freguesia (o código da freguesia é o DICOFRE). */
export function ParishPicker(p: Props) {
  return (
    <fieldset className={styles.fieldset}>
      <legend className={styles.legend}>{S.locationLegend}</legend>
      <div className={styles.geoGrid}>
        <GeoSelect id="distrito" label={S.district} state={p.districts} value={p.district} onChange={p.onDistrict} />
        <GeoSelect
          id="concelho"
          label={S.municipality}
          state={p.municipalities}
          value={p.municipality}
          disabled={!p.district}
          onChange={p.onMunicipality}
        />
        <GeoSelect
          id="freguesia"
          label={S.parish}
          state={p.parishes}
          value={p.parish}
          disabled={!p.municipality}
          onChange={p.onParish}
        />
      </div>
    </fieldset>
  );
}
