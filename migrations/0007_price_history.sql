-- 0007 — Histórico de preços Omnibus (PT DL 70/2007 red. DL 109-G/2021; ES art. 20 Ley 7/1996).
-- Rollback mental (só em dev; em produção o histórico é prova perante a ASAE — exportar antes):
--   DROP TRIGGER product_variants_price_history_ins ON product_variants;
--   DROP TRIGGER product_variants_price_history_upd ON product_variants;
--   DROP TRIGGER product_variants_lowest_price_30d ON product_variants;
--   SET ROLE ptmarket_price_writer; DROP FUNCTION product_variants_record_price_history(); RESET ROLE;
--   DROP FUNCTION product_variants_set_lowest_price_30d();
--   DROP TABLE product_price_history;  (políticas, grants e índices caem com a tabela.)
--   REVOKE USAGE ON SCHEMA public FROM ptmarket_price_writer; DROP ROLE ptmarket_price_writer;
--   (o papel pode ser partilhado por outras BDs do cluster.)
-- Histórico só de acréscimo: a app só lê; quem escreve é o trigger (SECURITY DEFINER), cujo dono é
-- ptmarket_price_writer (NOLOGIN, sem SUPERUSER/BYPASSRLS, só INSERT aqui) — nunca quem corre a migration.
-- lowest_price_30d_cents é calculado pela BD; o que a app lá escrever é ignorado.

-- Papel dono do trigger DEFINER. Quem migra precisa de SET para ele (ALTER FUNCTION ... OWNER TO);
-- concede-se SET sem INHERIT, como em 0001.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ptmarket_price_writer') THEN
        CREATE ROLE ptmarket_price_writer
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'ptmarket_price_writer' AND (rolsuper OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'O papel ptmarket_price_writer já existe com SUPERUSER ou BYPASSRLS; recusado.';
    END IF;

    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       AND NOT pg_has_role(current_user, 'ptmarket_price_writer', 'SET') THEN
        EXECUTE format('GRANT ptmarket_price_writer TO %I WITH INHERIT FALSE, SET TRUE', current_user);
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO ptmarket_price_writer;

CREATE TABLE product_price_history (
    id          UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   UUID        NOT NULL,
    variant_id  UUID        NOT NULL,
    price_cents BIGINT      NOT NULL CHECK (price_cents >= 0),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, variant_id) REFERENCES product_variants (tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX product_price_history_tenant_variant_recorded_idx
    ON product_price_history (tenant_id, variant_id, recorded_at DESC);
CREATE INDEX product_price_history_recorded_idx
    ON product_price_history (recorded_at);

ALTER TABLE product_price_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE product_price_history FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_read ON product_price_history
    FOR SELECT TO ptmarket_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Só o dono do trigger DEFINER insere, e só no tenant do contexto da transação.
CREATE POLICY writer_insert ON product_price_history
    FOR INSERT TO ptmarket_price_writer
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

GRANT SELECT ON product_price_history TO ptmarket_app; -- sem INSERT/UPDATE/DELETE: a app nunca escreve aqui
GRANT INSERT ON product_price_history TO ptmarket_price_writer; -- só INSERT (sem RETURNING, sem SELECT)

-- Trigger 1 (SECURITY INVOKER): calcula lowest_price_30d_cents antes de gravar a variante.
-- A janela começa no último preço gravado ANTES dos 30 dias (era o preço em vigor no início da janela).
CREATE FUNCTION product_variants_set_lowest_price_30d()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.lowest_price_30d_cents := NULL;
    ELSIF NEW.price_cents IS DISTINCT FROM OLD.price_cents THEN
        NEW.lowest_price_30d_cents := (
            SELECT min(h.price_cents)
            FROM product_price_history h
            WHERE h.variant_id = OLD.id
              AND h.recorded_at >= COALESCE(
                  (SELECT max(p.recorded_at)
                   FROM product_price_history p
                   WHERE p.variant_id = OLD.id
                     AND p.recorded_at <= now() - interval '30 days'),
                  '-infinity'::timestamptz)
        );
    ELSE
        NEW.lowest_price_30d_cents := OLD.lowest_price_30d_cents;
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION product_variants_set_lowest_price_30d() FROM PUBLIC;

CREATE TRIGGER product_variants_lowest_price_30d
    BEFORE INSERT OR UPDATE ON product_variants
    FOR EACH ROW EXECUTE FUNCTION product_variants_set_lowest_price_30d();

-- Trigger 2 (SECURITY DEFINER): grava o preço novo/alterado no histórico.
CREATE FUNCTION product_variants_record_price_history()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.price_cents IS NOT DISTINCT FROM OLD.price_cents THEN
        RETURN NULL;
    END IF;
    INSERT INTO public.product_price_history (tenant_id, variant_id, price_cents)
    VALUES (NEW.tenant_id, NEW.id, NEW.price_cents);
    RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION product_variants_record_price_history() FROM PUBLIC;

CREATE TRIGGER product_variants_price_history_ins
    AFTER INSERT ON product_variants
    FOR EACH ROW EXECUTE FUNCTION product_variants_record_price_history();

CREATE TRIGGER product_variants_price_history_upd
    AFTER UPDATE ON product_variants
    FOR EACH ROW
    WHEN (NEW.price_cents IS DISTINCT FROM OLD.price_cents)
    EXECUTE FUNCTION product_variants_record_price_history();

-- Dono da função DEFINER = ptmarket_price_writer (depois dos triggers: quem migra deixa de ter EXECUTE).
-- O novo dono precisa de CREATE no schema só durante o ALTER; retira-se logo a seguir.
GRANT CREATE ON SCHEMA public TO ptmarket_price_writer;
ALTER FUNCTION product_variants_record_price_history() OWNER TO ptmarket_price_writer;
REVOKE CREATE ON SCHEMA public FROM ptmarket_price_writer;
