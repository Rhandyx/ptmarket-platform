-- 0027 — geo_dicofre: referência oficial de distritos, concelhos e freguesias (DICOFRE; cartão 03/01).
-- Vazia: o seed (cartão 03/02) carrega a CAOP/DGT por script, não por migration. Dado público: sem tenant_id.
-- Uma linha NUNCA é apagada (trigger bloqueia DELETE a todos, migrator incluído); código extinto = valid_to preenchido.
-- Rollback mental (só em dev): DROP TABLE geo_dicofre; DROP FUNCTION geo_dicofre_block_delete();
CREATE TABLE geo_dicofre (
    code        VARCHAR(6) PRIMARY KEY CHECK (code ~ '^[0-9]{2}([0-9]{2}([0-9A-Z]{2})?)?$'),
    level       VARCHAR(12) NOT NULL CHECK (level IN ('district', 'municipality', 'parish')),
    parent_code VARCHAR(4) REFERENCES geo_dicofre (code) ON DELETE RESTRICT,
    name        VARCHAR(160) NOT NULL,
    caop_version VARCHAR(16) NOT NULL, -- última versão da CAOP em que o código apareceu
    valid_to    TIMESTAMPTZ,           -- NULL = em vigor
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (level = CASE length(code) WHEN 2 THEN 'district' WHEN 4 THEN 'municipality' ELSE 'parish' END),
    CHECK ((length(code) = 2 AND parent_code IS NULL) OR parent_code = left(code, length(code) - 2))
);

CREATE INDEX geo_dicofre_parent_idx ON geo_dicofre (parent_code) WHERE valid_to IS NULL;

CREATE FUNCTION geo_dicofre_block_delete() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog AS
$$
BEGIN
    RAISE EXCEPTION 'geo_dicofre: linhas nunca se apagam (preencher valid_to)' USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TRIGGER geo_dicofre_no_delete BEFORE DELETE ON geo_dicofre
    FOR EACH ROW EXECUTE FUNCTION geo_dicofre_block_delete();

-- Caixa negra L1 (só se a L2 ainda não os criou).
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['geo_dicofre'] LOOP
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

ALTER TABLE geo_dicofre ENABLE ROW LEVEL SECURITY;
ALTER TABLE geo_dicofre FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON geo_dicofre AS PERMISSIVE FOR SELECT TO ptmarket_app USING (true);
-- O seed corre como migrator (dono; FORCE RLS aplica-se-lhe): precisa de policies próprias de leitura/escrita.
CREATE POLICY migrator_all ON geo_dicofre AS PERMISSIVE FOR ALL TO ptmarket_migrator USING (true) WITH CHECK (true);

REVOKE ALL ON geo_dicofre FROM PUBLIC;
GRANT SELECT ON geo_dicofre TO ptmarket_app;
