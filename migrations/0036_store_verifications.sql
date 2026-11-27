-- 0036 — store_verifications: documentos de verificação da loja (cartão 03/09; spec 14 §6; RGPD art. 5.º/1/c e e,
--   art. 32.º).
-- Rollback mental (só em dev):
--   DROP TABLE store_verifications; DROP FUNCTION store_verifications_guard();
--   (policies, índices, grants e zz_audit_* caem com a tabela; os eventos gravados ficam: a caixa negra é só de
--    acréscimo.)
--
-- Regras:
--   * Ficheiros num armazenamento PRIVADO (nunca /media), só por URL assinado de 5 min gerado por um super_admin
--     (cartão 10). Na BD fica só storage_key (a chave no armazenamento), o sha256 (prova) e os metadados. O ficheiro é
--     apagado até 30 dias depois da decisão (delete_after <= reviewed_at + 30 dias, por CHECK); o hash e os metadados
--     ficam.
--   * Tipos: certidao_permanente_code (NIF começado por 5: código de acesso, sem ficheiro obrigatório),
--     certidao_permanente_pdf, declaracao_inicio_atividade, comprovativo_domicilio_fiscal (ENI: NIF 1, 2 ou 3),
--     manual_other (outros prefixos: revisão manual). Todo o ficheiro tem hash; sem storage_key não há ficheiro.
--   * O código da Certidão Permanente NUNCA fica em claro: a app cifra-o com AES-256-GCM (identity::crypto, formato
--     'v1:<kid>:…', chave própria VERIFICATION_ENC_KEY); a BD só aceita 'v1:%' e só nesse tipo. A máscara da caixa
--     negra (0010/0014) cobre *_enc: a L1 nunca vê mais do que o texto cifrado.
--   * Trigger BEFORE UPDATE (INVOKER, search_path fixo): sha256, kind, store_id, tenant_id, access_code_enc e
--     created_at imutáveis; status só pending → approved | rejected; storage_key só pode passar a NULL. Violações =
--     23514. A FK composta para stores é ON UPDATE CASCADE (como as da 0030), mas o trigger recusa a mudança de
--     tenant_id: uma loja com verificações não muda de tenant (23514).
--   * ptmarket_app: tenant_isolation (texto da de stores) + store_scope_select/insert/update/delete AS RESTRICTIVE
--     com store_id = app_store_id() (âmbito por loja da 0035, SEM exceção de admin: o super_admin usa as funções
--     DEFINER do cartão 10). SELECT; INSERT só por coluna; SEM UPDATE nem DELETE (as policies de UPDATE/DELETE só
--     fecham um GRANT futuro e fazem a guarda de tests/store_scope_rls.sql passar).
--   * ptmarket_worker (job de eliminação, cartão 25): vê só as colunas (id, tenant_id, store_id, storage_key,
--     delete_after) das linhas vencidas; altera só storage_key (→ NULL) e file_deleted_at, e só em linha vencida com
--     ficheiro. Sem INSERT nem DELETE.
--     DESVIO DO CARTÃO (decisão pendente do supervisor): o cartão pede worker_select = USING (storage_key IS NOT NULL
--     AND delete_after <= now()). Com WHERE/RETURNING o PostgreSQL aplica também a policy de SELECT à linha NOVA
--     (como em worker_select da 0031); a linha nova tem storage_key NULL e o UPDATE do worker dava sempre 42501.
--     worker_select inclui por isso o estado depois da eliminação: vencida E (com ficheiro OU file_deleted_at posto).
--     Efeito: o worker tem de pôr file_deleted_at ao apagar (senão 42501); não vê pending, não vencidas nem as que
--     nunca tiveram ficheiro.
--   * Sem policy para o migrator: com FORCE, nem o dono lê/escreve sem desligar o FORCE explicitamente.

-- ---------------------------------------------------------------------------
-- Tabela.
-- ---------------------------------------------------------------------------
CREATE TABLE store_verifications (
    id              UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id       UUID          NOT NULL,
    store_id        UUID          NOT NULL,
    kind            VARCHAR(32)   NOT NULL CHECK (kind IN ('certidao_permanente_code', 'certidao_permanente_pdf',
                                                           'declaracao_inicio_atividade',
                                                           'comprovativo_domicilio_fiscal', 'manual_other')),
    sha256          BYTEA         CHECK (octet_length(sha256) = 32),
    storage_key     TEXT, -- chave no armazenamento privado; NULL = sem ficheiro (nunca teve ou já apagado)
    access_code_enc TEXT          CHECK (access_code_enc LIKE 'v1:%'), -- AES-256-GCM (identity::crypto)
    status          VARCHAR(12)   NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    submitted_by    UUID REFERENCES users (id) ON DELETE RESTRICT,
    reviewed_by     UUID REFERENCES users (id) ON DELETE RESTRICT,
    reviewed_at     TIMESTAMPTZ,
    review_reason   VARCHAR(500),
    delete_after    TIMESTAMPTZ,
    file_deleted_at TIMESTAMPTZ,
    metadata        JSONB         NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT store_verifications_store_fkey
        FOREIGN KEY (tenant_id, store_id) REFERENCES stores (tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT store_verifications_code_only_in_code_kind
        CHECK ((kind = 'certidao_permanente_code') = (access_code_enc IS NOT NULL)),
    CONSTRAINT store_verifications_file_kind_has_hash CHECK (kind = 'certidao_permanente_code' OR sha256 IS NOT NULL),
    CONSTRAINT store_verifications_file_has_hash CHECK (storage_key IS NULL OR sha256 IS NOT NULL),
    CONSTRAINT store_verifications_reviewed_at_iff_decided CHECK ((status = 'pending') = (reviewed_at IS NULL)),
    CONSTRAINT store_verifications_deleted_has_no_key CHECK (file_deleted_at IS NULL OR storage_key IS NULL),
    CONSTRAINT store_verifications_delete_within_30d CHECK (
        status = 'pending' OR storage_key IS NULL
        OR (delete_after IS NOT NULL AND delete_after <= reviewed_at + interval '30 days')
    )
);

CREATE INDEX store_verifications_tenant_store_idx ON store_verifications (tenant_id, store_id); -- FK composta
CREATE INDEX store_verifications_pending_idx ON store_verifications (status, created_at) WHERE status = 'pending';
CREATE INDEX store_verifications_delete_after_idx ON store_verifications (delete_after) WHERE storage_key IS NOT NULL;
CREATE INDEX store_verifications_submitted_by_idx ON store_verifications (submitted_by) WHERE submitted_by IS NOT NULL;
CREATE INDEX store_verifications_reviewed_by_idx ON store_verifications (reviewed_by) WHERE reviewed_by IS NOT NULL;

COMMENT ON TABLE store_verifications IS
    'Documentos de verificação da loja (spec 14 §6): ficheiro em armazenamento privado (storage_key), hash como prova, '
    'código da Certidão Permanente só cifrado (v1:…); ficheiro apagado até 30 dias depois da decisão';
COMMENT ON COLUMN store_verifications.access_code_enc IS
    'Código de acesso à Certidão Permanente cifrado pela app (AES-256-GCM, v1:<kid>:…, VERIFICATION_ENC_KEY); nunca '
    'em claro';
COMMENT ON COLUMN store_verifications.delete_after IS
    'Data-limite de eliminação do ficheiro (<= reviewed_at + 30 dias quando há ficheiro e decisão)';

-- ---------------------------------------------------------------------------
-- Trigger de imutáveis e de estado (INVOKER; search_path fixo).
-- ---------------------------------------------------------------------------
CREATE FUNCTION store_verifications_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS
$$
BEGIN
    IF NEW.sha256 IS DISTINCT FROM OLD.sha256
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.store_id IS DISTINCT FROM OLD.store_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.access_code_enc IS DISTINCT FROM OLD.access_code_enc
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'store_verifications: sha256, kind, store_id, tenant_id, access_code_enc e created_at são '
                        'imutáveis'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status
       AND NOT (OLD.status = 'pending' AND NEW.status IN ('approved', 'rejected')) THEN
        RAISE EXCEPTION 'store_verifications: transição % → % proibida', OLD.status, NEW.status
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.storage_key IS DISTINCT FROM OLD.storage_key AND NEW.storage_key IS NOT NULL THEN
        RAISE EXCEPTION 'store_verifications: storage_key só pode passar a NULL'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER store_verifications_guard BEFORE UPDATE ON store_verifications
    FOR EACH ROW EXECUTE FUNCTION store_verifications_guard();

REVOKE ALL ON FUNCTION store_verifications_guard() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Caixa negra L1 (só se a L2 ainda não os criou: ver o cabeçalho da 0018).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['store_verifications'] LOOP
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
ALTER TABLE store_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE store_verifications FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON store_verifications
    FOR ALL TO ptmarket_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Âmbito por loja (0035), sem exceção de admin.
CREATE POLICY store_scope_select ON store_verifications AS RESTRICTIVE FOR SELECT TO ptmarket_app
    USING (store_id = (SELECT app_store_id()));
CREATE POLICY store_scope_insert ON store_verifications AS RESTRICTIVE FOR INSERT TO ptmarket_app
    WITH CHECK (store_id = (SELECT app_store_id()));
CREATE POLICY store_scope_update ON store_verifications AS RESTRICTIVE FOR UPDATE TO ptmarket_app
    USING (store_id = (SELECT app_store_id()))
    WITH CHECK (store_id = (SELECT app_store_id()));
CREATE POLICY store_scope_delete ON store_verifications AS RESTRICTIVE FOR DELETE TO ptmarket_app
    USING (store_id = (SELECT app_store_id()));

DO $$
DECLARE
    c text;
BEGIN
    FOREACH c IN ARRAY ARRAY['select', 'insert', 'update', 'delete'] LOOP
        EXECUTE format(
            'COMMENT ON POLICY %I ON public.store_verifications IS %L',
            'store_scope_' || c,
            'Âmbito por loja (0036, padrão da 0035): RESTRICTIVE para ptmarket_app (app.store_id), sem exceção de '
            || 'admin (o super_admin usa as funções do cartão 10). Defesa em profundidade, não contra uma app '
            || 'comprometida');
    END LOOP;
END
$$;

-- Job de eliminação (cartão 25). worker_select inclui o estado depois da eliminação (file_deleted_at posto): com
-- WHERE/RETURNING a policy SELECT também se aplica à linha nova (ver o cabeçalho: desvio do cartão).
CREATE POLICY worker_select ON store_verifications
    AS PERMISSIVE FOR SELECT TO ptmarket_worker
    USING (delete_after <= now() AND (storage_key IS NOT NULL OR file_deleted_at IS NOT NULL));
CREATE POLICY worker_update ON store_verifications
    AS PERMISSIVE FOR UPDATE TO ptmarket_worker
    USING (storage_key IS NOT NULL AND delete_after <= now())
    WITH CHECK (storage_key IS NULL);

REVOKE ALL ON store_verifications FROM PUBLIC;
GRANT SELECT ON store_verifications TO ptmarket_app;
GRANT INSERT (id, tenant_id, store_id, kind, sha256, storage_key, access_code_enc, submitted_by, metadata)
    ON store_verifications TO ptmarket_app;
GRANT SELECT (id, tenant_id, store_id, storage_key, delete_after) ON store_verifications TO ptmarket_worker;
GRANT UPDATE (storage_key, file_deleted_at) ON store_verifications TO ptmarket_worker;
