-- 0032 — platform_settings (comissão base) e billing_plan_tiers (escalões dos dois planos) com seed (cartão 03/07;
-- spec 14 §3, §4).
-- Rollback mental (só em dev):
--   DROP TABLE billing_plan_tiers; DROP FUNCTION billing_plan_tiers_check_plan(); DROP TABLE platform_settings;
--   (policies, índices, grants, o constraint trigger e os zz_audit_* caem com as tabelas; btree_gist fica (0031).
--    Os eventos gravados, incluindo os do seed, ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * platform_settings: uma só linha (PK boolean = true). base_commission_bps = 800 por defeito, configurável, nunca
--     hardcoded na app. updated_by = quem mudou (super_admin, épico de backoffice).
--   * billing_plan_tiers: o escalão cobre o volume mensal em ]gmv_from_cents, gmv_to_cents] (NULL = sem teto), como
--     backend-rust/src/money/commission.rs (PlanTier/validate_tiers). Dinheiro BIGINT cêntimos, percentagens INT bps.
--     Sobreposição no mesmo plano = 23P01 (EXCLUDE). Escalão vazio = 23514 (CHECK to > from).
--     Constraint trigger DEFERRABLE INITIALLY DEFERRED, por plano tocado (OLD e NEW): existe pelo menos um escalão, o
--     1.º começa em 0, cada from = to do anterior (sem buracos), só o último tem to NULL. Falha (23514) no COMMIT,
--     por isso reorganizar escalões em vários comandos na mesma transação é permitido. Mesmas regras que a função
--     pura validate_tiers (lida por ORDER BY gmv_from_cents).
--     Não coberto: TRUNCATE (não dispara triggers de linha; só o dono o pode fazer e a L1 regista-o).
--   * ptmarket_app: só SELECT (USING true, sem tenant no contexto). Nenhuma escrita para app nem worker; a edição pelo
--     super_admin é do épico de backoffice (função identity_* com 2FA). O migrator escreve via migrator_all (com FORCE
--     o dono também passa pelas policies).
--   * Caixa negra L1: platform_settings.update e billing_plan_tiers.* (ator 'db' pelo migrator; o seed também).

-- ---------------------------------------------------------------------------
-- Tabelas.
-- ---------------------------------------------------------------------------
CREATE TABLE platform_settings (
    id                  BOOLEAN PRIMARY KEY DEFAULT true CHECK (id), -- uma só linha
    base_commission_bps INT         NOT NULL DEFAULT 800 CHECK (base_commission_bps BETWEEN 0 AND 10000),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by          UUID REFERENCES users (id) ON DELETE RESTRICT
);

CREATE INDEX platform_settings_updated_by_idx ON platform_settings (updated_by) WHERE updated_by IS NOT NULL;

CREATE TABLE billing_plan_tiers (
    id                      UUID PRIMARY KEY DEFAULT uuidv7(),
    plan_code               VARCHAR(32) NOT NULL CHECK (plan_code IN ('commission_payg', 'tiered_subscription')),
    gmv_from_cents          BIGINT      NOT NULL CHECK (gmv_from_cents >= 0), -- o escalão cobre ]from, to]
    gmv_to_cents            BIGINT CHECK (gmv_to_cents > gmv_from_cents),     -- NULL = sem teto
    monthly_fee_cents       BIGINT      NOT NULL CHECK (monthly_fee_cents >= 0),
    marginal_commission_bps INT         NOT NULL CHECK (marginal_commission_bps BETWEEN 0 AND 10000),
    CONSTRAINT billing_plan_tiers_no_overlap EXCLUDE USING gist (
        plan_code WITH =, int8range(gmv_from_cents, gmv_to_cents, '(]') WITH &&
    )
);

-- ---------------------------------------------------------------------------
-- Continuidade por plano (constraint trigger diferido; INVOKER; search_path fixo; relações qualificadas).
-- ---------------------------------------------------------------------------
CREATE FUNCTION billing_plan_tiers_check_plan() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS
$$
DECLARE
    v_plan     text;
    v_n        bigint;
    v_min_from bigint;
    v_open     bigint;
    v_gaps     bigint;
BEGIN
    FOREACH v_plan IN ARRAY ARRAY[
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.plan_code END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.plan_code END
    ] LOOP
        CONTINUE WHEN v_plan IS NULL;
        SELECT count(*),
               min(t.gmv_from_cents),
               count(*) FILTER (WHERE t.next_from IS NULL AND t.gmv_to_cents IS NULL),
               count(*) FILTER (WHERE t.next_from IS NOT NULL AND t.gmv_to_cents IS DISTINCT FROM t.next_from)
          INTO v_n, v_min_from, v_open, v_gaps
          FROM (SELECT b.gmv_from_cents, b.gmv_to_cents,
                       lead(b.gmv_from_cents) OVER (ORDER BY b.gmv_from_cents) AS next_from
                  FROM public.billing_plan_tiers b
                 WHERE b.plan_code = v_plan) AS t;
        -- v_open = 1: o último está aberto; v_gaps = 0: todos os outros fecham no from do seguinte (logo têm teto).
        IF v_n = 0 OR v_min_from <> 0 OR v_open <> 1 OR v_gaps <> 0 THEN
            RAISE EXCEPTION 'billing_plan_tiers: escalões de % inválidos (pelo menos um, o 1.º começa em 0, '
                            'contíguos, só o último sem teto)', v_plan
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER billing_plan_tiers_contiguous
    AFTER INSERT OR UPDATE OR DELETE ON billing_plan_tiers
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION billing_plan_tiers_check_plan();

REVOKE ALL ON FUNCTION billing_plan_tiers_check_plan() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Caixa negra L1 (só se a L2 ainda não os criou: ver o cabeçalho da 0018).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['platform_settings', 'billing_plan_tiers'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                       WHERE tgrelid = format('public.%I', t)::regclass AND tgname = 'zz_audit_row') THEN
            EXECUTE format('CREATE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE ON %I '
                           'FOR EACH ROW EXECUTE FUNCTION audit.audit_row_trigger()', t);
            EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER zz_audit_row', t);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                       WHERE tgrelid = format('public.%I', t)::regclass AND tgname = 'zz_audit_truncate') THEN
            EXECUTE format('CREATE TRIGGER zz_audit_truncate BEFORE TRUNCATE ON %I '
                           'FOR EACH STATEMENT EXECUTE FUNCTION audit.audit_row_trigger()', t);
            EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER zz_audit_truncate', t);
        END IF;
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- RLS e grants: a app só lê; escrita só pelo migrator.
-- ---------------------------------------------------------------------------
ALTER TABLE platform_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_settings FORCE ROW LEVEL SECURITY;
ALTER TABLE billing_plan_tiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE billing_plan_tiers FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON platform_settings AS PERMISSIVE FOR SELECT TO ptmarket_app USING (true);
CREATE POLICY app_select ON billing_plan_tiers AS PERMISSIVE FOR SELECT TO ptmarket_app USING (true);
CREATE POLICY migrator_all ON platform_settings AS PERMISSIVE FOR ALL TO ptmarket_migrator
    USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON billing_plan_tiers AS PERMISSIVE FOR ALL TO ptmarket_migrator
    USING (true) WITH CHECK (true);

REVOKE ALL ON platform_settings, billing_plan_tiers FROM PUBLIC;
GRANT SELECT ON platform_settings, billing_plan_tiers TO ptmarket_app;

-- ---------------------------------------------------------------------------
-- Seed (spec 14 §4). tiered_subscription sem saltos: 85000 = 5000 + 800 bps × 1.000.000.
-- ---------------------------------------------------------------------------
INSERT INTO platform_settings DEFAULT VALUES;

INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
VALUES
    ('commission_payg', 0, 2000000, 0, 800),
    ('commission_payg', 2000000, NULL, 0, 600),
    ('tiered_subscription', 0, 100000, 500, 0),
    ('tiered_subscription', 100000, 500000, 1000, 0),
    ('tiered_subscription', 500000, 1000000, 5000, 0),
    ('tiered_subscription', 1000000, 2000000, 5000, 800),
    ('tiered_subscription', 2000000, NULL, 85000, 600);
