-- 0031 — store_sponsorships: patrocínio loja ↔ entidade (N:N) com estado e vigência (cartão 03/06; spec 14 §2, §3).
-- Rollback mental (só em dev):
--   DROP TABLE store_sponsorships; DROP FUNCTION store_sponsorships_guard();
--   (policies, índices, grants e zz_audit_* caem com a tabela; btree_gist fica: pode ser usada por outras tabelas.
--    Os eventos gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * Estados: pending (pedido da loja ou convite da entidade), active, rejected, expired, revoked. "Ativo" no cálculo
--     = status = 'active' AND now() <@ tstzrange(valid_from, valid_to); o job que passa a expired é só higiene.
--   * Co-patrocínio: uma loja pode ter várias entidades ativas ao mesmo tempo (vigências independentes). O mesmo par
--     (loja, entidade) nunca tem dois 'active' sobrepostos (EXCLUDE, 23P01); só um 'pending' por par (23505).
--   * Trigger (INVOKER, search_path fixo): INSERT só nasce 'pending'; pending → active | rejected; active → revoked |
--     expired; mais nenhuma transição. tenant_id, store_id, sponsor_entity_id e initiated_by imutáveis;
--     commission_override_bps só muda em pending. revoked: valid_to = GREATEST(valid_from, LEAST(COALESCE(valid_to,
--     now()), now())): revogar um active que ainda não começou deixa o intervalo vazio (valid_to = valid_from = nunca
--     vigorou), permitido só em revoked/expired.
--     País da entidade = país do tenant da loja. Violações = 23514.
--   * ptmarket_app: tenant_isolation (texto da de stores); SELECT; INSERT/UPDATE só por coluna; sem DELETE; NUNCA
--     commission_override_bps (dinheiro: fica 0 até decisão do owner, escrita pelo migrator via migrator_all).
--   * ptmarket_worker (job de expiração, cartão 24): vê 'active' vencido e 'expired'; altera só 'active' vencido, e só
--     para 'expired' (UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED) RETURNING ids, para o outbox/auditoria).
--   * tenant_id imutável: a FK composta para stores é ON UPDATE NO ACTION (sem CASCADE): mudar stores.tenant_id de uma
--     loja com patrocínios falha (23503). Mover uma loja com patrocínios entre canais exige uma migration própria.
--     NO ACTION e não RESTRICT: o bloco da 0030 (copiado em tests/stores_national_channel.sql) aborta perante FKs
--     ON UPDATE RESTRICT; se voltar a correr, refaz esta FK com CASCADE, mas o trigger continua a recusar (23514).

CREATE EXTENSION IF NOT EXISTS btree_gist;

-- ---------------------------------------------------------------------------
-- Tabela.
-- ---------------------------------------------------------------------------
CREATE TABLE store_sponsorships (
    id                      UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id               UUID         NOT NULL,
    store_id                UUID         NOT NULL,
    sponsor_entity_id       UUID         NOT NULL REFERENCES sponsor_entities (id) ON DELETE RESTRICT,
    status                  VARCHAR(12)  NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'rejected', 'expired', 'revoked')),
    initiated_by            VARCHAR(8)   NOT NULL DEFAULT 'store' CHECK (initiated_by IN ('store', 'sponsor')),
    valid_from              TIMESTAMPTZ,
    valid_to                TIMESTAMPTZ, -- NULL = sem fim
    commission_override_bps INT          NOT NULL DEFAULT 0 CHECK (commission_override_bps BETWEEN 0 AND 10000),
    requested_by            UUID REFERENCES users (id) ON DELETE RESTRICT,
    decided_by              UUID REFERENCES users (id) ON DELETE RESTRICT,
    decided_at              TIMESTAMPTZ,
    decision_reason         VARCHAR(500),
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT store_sponsorships_store_fkey
        FOREIGN KEY (tenant_id, store_id) REFERENCES stores (tenant_id, id) ON UPDATE NO ACTION ON DELETE CASCADE,
    -- Intervalo vazio (valid_to = valid_from) só em revoked/expired: nunca vigorou.
    CONSTRAINT store_sponsorships_valid_range CHECK (
        valid_to IS NULL OR valid_from < valid_to OR (status IN ('revoked', 'expired') AND valid_to = valid_from)
    ),
    CONSTRAINT store_sponsorships_valid_from_needed CHECK (status IN ('pending', 'rejected') OR valid_from IS NOT NULL),
    CONSTRAINT store_sponsorships_no_active_overlap EXCLUDE USING gist (
        store_id WITH =, sponsor_entity_id WITH =, tstzrange(valid_from, valid_to) WITH &&
    ) WHERE (status = 'active')
);

CREATE UNIQUE INDEX store_sponsorships_one_pending_key ON store_sponsorships (store_id, sponsor_entity_id)
    WHERE status = 'pending';
CREATE INDEX store_sponsorships_entity_status_idx ON store_sponsorships (sponsor_entity_id, status);
CREATE INDEX store_sponsorships_tenant_store_idx ON store_sponsorships (tenant_id, store_id); -- FK composta
CREATE INDEX store_sponsorships_requested_by_idx ON store_sponsorships (requested_by) WHERE requested_by IS NOT NULL;
CREATE INDEX store_sponsorships_decided_by_idx ON store_sponsorships (decided_by) WHERE decided_by IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Trigger de estado e coerência (INVOKER; search_path fixo; relações qualificadas).
-- ---------------------------------------------------------------------------
CREATE FUNCTION store_sponsorships_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS
$$
DECLARE
    v_store_country  text;
    v_entity_country text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' THEN
            RAISE EXCEPTION 'store_sponsorships: um patrocínio nasce sempre pending'
                USING ERRCODE = 'check_violation';
        END IF;
        SELECT t.country_code INTO v_store_country FROM public.tenants t WHERE t.id = NEW.tenant_id;
        SELECT e.country_code INTO v_entity_country FROM public.sponsor_entities e WHERE e.id = NEW.sponsor_entity_id;
        -- Tenant ou entidade inexistente: a FK responde (23503).
        IF v_store_country IS NOT NULL AND v_entity_country IS NOT NULL AND v_store_country <> v_entity_country THEN
            RAISE EXCEPTION 'store_sponsorships: a entidade tem de ser do país do tenant da loja'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    -- UPDATE
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.store_id IS DISTINCT FROM OLD.store_id
       OR NEW.sponsor_entity_id IS DISTINCT FROM OLD.sponsor_entity_id
       OR NEW.initiated_by IS DISTINCT FROM OLD.initiated_by THEN
        RAISE EXCEPTION 'store_sponsorships: tenant_id, store_id, sponsor_entity_id e initiated_by são imutáveis'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.commission_override_bps IS DISTINCT FROM OLD.commission_override_bps AND OLD.status <> 'pending' THEN
        RAISE EXCEPTION 'store_sponsorships: commission_override_bps só muda em pending'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NOT ((OLD.status = 'pending' AND NEW.status IN ('active', 'rejected'))
                OR (OLD.status = 'active' AND NEW.status IN ('revoked', 'expired'))) THEN
            RAISE EXCEPTION 'store_sponsorships: transição % → % proibida', OLD.status, NEW.status
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.status = 'revoked' THEN
            NEW.valid_to := GREATEST(NEW.valid_from, LEAST(COALESCE(NEW.valid_to, now()), now()));
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER store_sponsorships_guard BEFORE INSERT OR UPDATE ON store_sponsorships
    FOR EACH ROW EXECUTE FUNCTION store_sponsorships_guard();

REVOKE ALL ON FUNCTION store_sponsorships_guard() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Caixa negra L1 (só se a L2 ainda não os criou: ver o cabeçalho da 0018).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['store_sponsorships'] LOOP
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
-- RLS e grants.
-- ---------------------------------------------------------------------------
ALTER TABLE store_sponsorships ENABLE ROW LEVEL SECURITY;
ALTER TABLE store_sponsorships FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON store_sponsorships
    FOR ALL TO ptmarket_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Job de expiração (cartão 24): só 'active' vencido, e só para 'expired'. worker_select inclui 'expired' porque, com
-- WHERE/RETURNING, a policy SELECT também se aplica à linha nova.
CREATE POLICY worker_select ON store_sponsorships
    AS PERMISSIVE FOR SELECT TO ptmarket_worker
    USING ((status = 'active' AND valid_to <= now()) OR status = 'expired');
CREATE POLICY worker_update ON store_sponsorships
    AS PERMISSIVE FOR UPDATE TO ptmarket_worker
    USING (status = 'active' AND valid_to <= now())
    WITH CHECK (status = 'expired');

-- commission_override_bps e decisões fora da API (com FORCE o dono também passa pelas policies).
CREATE POLICY migrator_all ON store_sponsorships AS PERMISSIVE FOR ALL TO ptmarket_migrator
    USING (true) WITH CHECK (true);

REVOKE ALL ON store_sponsorships FROM PUBLIC;
GRANT SELECT ON store_sponsorships TO ptmarket_app;
GRANT INSERT (id, tenant_id, store_id, sponsor_entity_id, initiated_by, requested_by)
    ON store_sponsorships TO ptmarket_app;
GRANT UPDATE (status, valid_from, valid_to, decided_by, decided_at, decision_reason, updated_at)
    ON store_sponsorships TO ptmarket_app;
GRANT SELECT, UPDATE (status, updated_at) ON store_sponsorships TO ptmarket_worker;
