"use client";

import { useEffect, useRef, useState } from "react";
import { createBrowserApi } from "../../lib/api/client";
import {
  fetchCommissionPreview,
  fetchDistricts,
  fetchMunicipalities,
  fetchParishes,
  type BrowserApi,
  type CommissionPreview,
} from "../../lib/api/signup";
import { CommissionAnchor } from "./CommissionAnchor";
import { EMPTY_GEO, ParishPicker, type GeoState } from "./ParishPicker";
import { PlanPicker } from "./PlanPicker";
import { SponsorBadges } from "./SponsorBadges";
import { S } from "./strings";
import styles from "./registar.module.css";

type PreviewState = { data: CommissionPreview | null; dicofre: string; loading: boolean; error: boolean };

const DISTRICTS_INITIAL: GeoState = { items: [], loading: true, error: false };

export function RegisterForm({ api: injected }: { api?: BrowserApi }) {
  const [api] = useState(() => injected ?? createBrowserApi());
  const [districts, setDistricts] = useState<GeoState>(DISTRICTS_INITIAL);
  const [municipalities, setMunicipalities] = useState<GeoState>(EMPTY_GEO);
  const [parishes, setParishes] = useState<GeoState>(EMPTY_GEO);
  const [district, setDistrict] = useState("");
  const [municipality, setMunicipality] = useState("");
  const [parish, setParish] = useState("");
  const [preview, setPreview] = useState<PreviewState>({ data: null, dicofre: "", loading: true, error: false });
  const [plan, setPlan] = useState("");
  // Contadores: só a resposta do último pedido de cada tipo é aplicada.
  const seq = useRef({ mun: 0, par: 0, prev: 0 });

  function loadPreview(dicofre: string) {
    setPreview((p) => ({ ...p, dicofre, loading: true, error: false }));
    return runPreview(dicofre);
  }

  async function runPreview(dicofre: string) {
    const id = ++seq.current.prev;
    try {
      const data = await fetchCommissionPreview(api, dicofre || undefined);
      if (id !== seq.current.prev) return;
      setPreview({ data, dicofre, loading: false, error: false });
      setPlan((cur) =>
        data.plans.some((p) => p.plan_code === cur) ? cur : (data.plans.find((p) => p.is_default)?.plan_code ?? ""),
      );
    } catch {
      if (id !== seq.current.prev) return;
      setPreview((p) => ({ ...p, dicofre, loading: false, error: true }));
    }
  }

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const items = await fetchDistricts(api);
        if (alive) setDistricts({ items, loading: false, error: false });
      } catch {
        if (alive) setDistricts({ items: [], loading: false, error: true });
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- carga inicial única
  }, []);

  useEffect(() => {
    // O estado inicial já é "a carregar": não há setState síncrono aqui.
    void runPreview("");
    // eslint-disable-next-line react-hooks/exhaustive-deps -- carga inicial única
  }, []);

  function pickDistrict(code: string) {
    setDistrict(code);
    setMunicipality("");
    setParish("");
    setParishes(EMPTY_GEO);
    seq.current.par++;
    const id = ++seq.current.mun;
    if (parish) void loadPreview("");
    if (!code) {
      setMunicipalities(EMPTY_GEO);
      return;
    }
    setMunicipalities({ items: [], loading: true, error: false });
    fetchMunicipalities(api, code).then(
      (items) => id === seq.current.mun && setMunicipalities({ items, loading: false, error: false }),
      () => id === seq.current.mun && setMunicipalities({ items: [], loading: false, error: true }),
    );
  }

  function pickMunicipality(code: string) {
    setMunicipality(code);
    setParish("");
    const id = ++seq.current.par;
    if (parish) void loadPreview("");
    if (!code) {
      setParishes(EMPTY_GEO);
      return;
    }
    setParishes({ items: [], loading: true, error: false });
    fetchParishes(api, code).then(
      (items) => id === seq.current.par && setParishes({ items, loading: false, error: false }),
      () => id === seq.current.par && setParishes({ items: [], loading: false, error: true }),
    );
  }

  function pickParish(code: string) {
    setParish(code);
    void loadPreview(code);
  }

  const data = preview.data;
  // Patrocínio só vale para a freguesia atualmente confirmada (nunca resíduo de uma escolha anterior).
  const sponsored = data && preview.dicofre === parish ? data.sponsored : null;

  return (
    <form className={styles.form} noValidate onSubmit={(e) => e.preventDefault()}>
      <ParishPicker
        districts={districts}
        municipalities={municipalities}
        parishes={parishes}
        district={district}
        municipality={municipality}
        parish={parish}
        onDistrict={pickDistrict}
        onMunicipality={pickMunicipality}
        onParish={pickParish}
      />

      <section className={styles.commission} aria-labelledby="comissao-titulo">
        <h2 id="comissao-titulo" className={styles.h2}>
          {S.commissionLabel}
        </h2>
        <div role="status" aria-live="polite" className={styles.srOnly}>
          {preview.loading ? S.loadingPreview : ""}
        </div>
        {preview.error ? (
          <div role="alert" className={styles.errorBox}>
            <p>{S.previewError}</p>
            <button type="button" className={styles.retry} onClick={() => void loadPreview(parish)}>
              {S.retry}
            </button>
          </div>
        ) : null}
        {data ? (
          <>
            <CommissionAnchor referenceBps={data.reference_bps} sponsoredBps={sponsored?.applied_bps} />
            {sponsored ? (
              <>
                <SponsorBadges sponsors={sponsored.sponsors} heading={S.sponsorsHeading} />
                <p className={styles.warning}>{S.warning}</p>
              </>
            ) : null}
          </>
        ) : null}
      </section>

      {data ? <PlanPicker plans={data.plans} value={plan} onChange={setPlan} /> : null}

      <div className={styles.submitRow}>
        <button type="submit" className={styles.submit} aria-disabled="true" aria-describedby="registo-em-breve">
          {S.submit}
        </button>
        <p id="registo-em-breve" className={styles.note}>
          {S.submitSoon}
        </p>
      </div>
    </form>
  );
}
