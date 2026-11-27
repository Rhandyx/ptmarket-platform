-- Teste 0036 store_verifications (cartão 03/09): CHECKs (código só cifrado v1:, hash de 32 bytes em todo o ficheiro,
-- decisão com reviewed_at, eliminação até 30 dias), trigger de imutáveis/estado, RLS da app (tenant + âmbito por loja
-- sem exceção de admin; sem UPDATE/DELETE) e do worker (só vencidas com ficheiro; só storage_key → NULL), L1.
-- Tenants pelo migrator; lojas pela app (ator admin); linhas com status/datas pelo migrator com o FORCE desligado só
-- nesta transação (sem policy para o migrator). Tudo com ROLLBACK. now() é constante na transação.
--   T1 = nacional PT (L1, L2) · T2 = nacional ES (L3)
-- Com as correções da 0037: código no formato real 'v1:<kid 8 hex>:<base64 ≥ 28 B>', apagado como o ficheiro (o
-- worker apaga os dois e põe file_deleted_at, nunca antes da decisão); access_code_enc só → NULL depois da decisão.
BEGIN;

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_state text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = p_state THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado %, obtido %: %)', p_label, p_state, v_state, v_msg;
    END;
    RAISE EXCEPTION 'FALHOU: % (esperado erro %, mas passou)', p_label, p_state;
END
$$;

CREATE FUNCTION pg_temp.expect_count(p_sql text, p_expected bigint, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_n bigint;
BEGIN
    EXECUTE p_sql INTO v_n;
    IF v_n IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'FALHOU: % (esperado %, obtido %)', p_label, p_expected, v_n;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Linhas afetadas por um UPDATE/DELETE (sem RETURNING).
CREATE FUNCTION pg_temp.expect_rows(p_sql text, p_expected bigint, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_n bigint;
BEGIN
    EXECUTE p_sql;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'FALHOU: % (esperado % linhas, obtido %)', p_label, p_expected, v_n;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Contexto: ator e loja (locais à transação, como o TenantTx).
CREATE FUNCTION pg_temp.ctx(p_actor text, p_store text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', p_actor, true);
    PERFORM set_config('app.store_id', p_store, true);
END
$$;

SELECT set_config('app.actor_label', 'test', true);

-- ---------------------------------------------------------------------------
-- 0. Estrutura: RLS, caixa negra, trigger INVOKER, policies, grants, índices.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class WHERE oid = 'store_verifications'::regclass
         AND relrowsecurity AND relforcerowsecurity$q$,
    1, 'RLS ENABLE + FORCE');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid = 'store_verifications'::regclass AND tgenabled = 'A'
         AND tgfoid = 'audit.audit_row_trigger()'::regprocedure
         AND ((tgname = 'zz_audit_row' AND tgtype = 29) OR (tgname = 'zz_audit_truncate' AND tgtype = 34))$q$,
    2, 'zz_audit_row + zz_audit_truncate (ALWAYS)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc WHERE oid = 'store_verifications_guard()'::regprocedure
         AND NOT prosecdef AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    1, 'trigger de imutáveis INVOKER com search_path fixo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid = 'store_verifications'::regclass AND tgname = 'store_verifications_guard' AND tgtype = 19$q$,
    1, 'trigger BEFORE UPDATE FOR EACH ROW');
SELECT pg_temp.expect_count(
    $q$SELECT count(DISTINCT p.polcmd) FROM pg_policy p
       WHERE p.polrelid = 'store_verifications'::regclass AND NOT p.polpermissive
         AND p.polroles = ARRAY['ptmarket_app'::regrole::oid]
         AND p.polname IN ('store_scope_select', 'store_scope_insert', 'store_scope_update', 'store_scope_delete')
         AND pg_get_expr(COALESCE(p.polqual, p.polwithcheck), p.polrelid) NOT LIKE '%admin%'$q$,
    4, 'store_scope_* RESTRICTIVE (SELECT/INSERT/UPDATE/DELETE) só para ptmarket_app, sem exceção de admin');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', 'store_verifications', p.priv)
          OR has_any_column_privilege('ptmarket_app', 'store_verifications', 'UPDATE')$q$,
    0, 'app sem UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['status', 'reviewed_by', 'reviewed_at', 'review_reason', 'delete_after',
                                         'file_deleted_at', 'created_at']) AS c(col)
       WHERE has_column_privilege('ptmarket_app', 'store_verifications', c.col, 'INSERT')$q$,
    0, 'app não insere status, decisão, datas nem created_at');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'store_verifications' AND grantee = 'ptmarket_worker'
         AND ((privilege_type = 'SELECT'
               AND column_name IN ('id', 'tenant_id', 'store_id', 'storage_key', 'delete_after'))
              OR (privilege_type = 'UPDATE' AND column_name IN ('storage_key', 'access_code_enc', 'file_deleted_at')))$q$,
    8, 'worker: SELECT (id, tenant_id, store_id, storage_key, delete_after), UPDATE (storage_key, access_code_enc, '
       'file_deleted_at)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'store_verifications' AND grantee = 'ptmarket_worker'$q$,
    8, 'worker: mais nenhum privilégio de coluna');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['INSERT', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_worker', 'store_verifications', p.priv)$q$,
    0, 'worker sem INSERT/DELETE/TRUNCATE/REFERENCES/TRIGGER');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid = 'store_verifications'::regclass AND a.grantee = 0$q$,
    0, 'sem privilégios para PUBLIC');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_indexes
       WHERE tablename = 'store_verifications'
         AND indexname IN ('store_verifications_tenant_store_idx', 'store_verifications_pending_idx',
                           'store_verifications_delete_after_idx', 'store_verifications_submitted_by_idx',
                           'store_verifications_reviewed_by_idx')$q$,
    5, 'índices: (tenant_id, store_id), pendentes, delete_after com ficheiro, FKs para users');

-- ---------------------------------------------------------------------------
-- 1. Preparação: tenants (migrator); lojas pela app com o ator admin.
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000036a1', 'svf-npt', 'svf-npt.teste.invalid', 'Nacional PT 36', 'national_portal', 'PT'),
    ('00000000-0000-7000-8000-0000000036a2', 'svf-nes', 'svf-nes.teste.invalid', 'Nacional ES 36', 'national_portal', 'ES');

SET ROLE ptmarket_app;
SELECT pg_temp.ctx('admin', '');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000036a1', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000036b1', '00000000-0000-7000-8000-0000000036a1',
     'Loja L1', 'svf-l1', 'L1 Lda', '500003601', 'PT50000000000000000003601', 'l1@teste.invalid'),
    ('00000000-0000-7000-8000-0000000036b2', '00000000-0000-7000-8000-0000000036a1',
     'Loja L2', 'svf-l2', 'L2 Lda', '500003602', 'PT50000000000000000003602', 'l2@teste.invalid');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000036a2', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000036b3', '00000000-0000-7000-8000-0000000036a2',
     'Loja L3', 'svf-l3', 'L3 SL', '500003603', 'PT50000000000000000003603', 'l3@teste.invalid');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 2. CHECKs e trigger (migrator, FORCE desligado só nesta transação).
-- ---------------------------------------------------------------------------
ALTER TABLE store_verifications NO FORCE ROW LEVEL SECURITY;
SELECT pg_temp.ctx('system', '');

-- Válidos: código cifrado sem ficheiro; PDF com hash e ficheiro.
INSERT INTO store_verifications (id, tenant_id, store_id, kind, access_code_enc) VALUES
    ('00000000-0000-7000-8000-000000003601', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b1', 'certidao_permanente_code', 'v1:0a1b2c3d:PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWc');
INSERT INTO store_verifications (id, tenant_id, store_id, kind, sha256, storage_key) VALUES
    ('00000000-0000-7000-8000-000000003602', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b1', 'certidao_permanente_pdf', sha256('pdf'::bytea), 'verif/3602.pdf');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications
       WHERE id IN ('00000000-0000-7000-8000-000000003601', '00000000-0000-7000-8000-000000003602')
         AND status = 'pending' AND reviewed_at IS NULL$q$,
    2, 'código cifrado (v1:) sem ficheiro e PDF com hash passam (nascem pending)');

SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, access_code_enc) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_code', '1234-5678-9012')$q$,
    '23514', 'access_code_enc sem prefixo v1: (código em claro) falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, access_code_enc) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_code', 'v1:1234-5678')$q$,
    '23514', 'v1:1234-5678 (código em claro com prefixo) falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, access_code_enc) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_code', 'v1:0a1b2c3d:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')$q$,
    '23514', 'base64 de 27 bytes (menos que nonce + tag) falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, access_code_enc) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_code', 'v1:k1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==')$q$,
    '23514', 'kid fora do formato (8 hex) falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1', 'certidao_permanente_code')$q$,
    '23514', 'certidao_permanente_code pending sem código falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256, access_code_enc) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_pdf', sha256('x'::bytea), 'v1:0a1b2c3d:PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWc')$q$,
    '23514', 'código cifrado fora de certidao_permanente_code falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, storage_key) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'declaracao_inicio_atividade', 'verif/sem-hash.pdf')$q$,
    '23514', 'PDF sem hash falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, access_code_enc, storage_key) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_code', 'v1:0a1b2c3d:PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWc', 'verif/sem-hash.pdf')$q$,
    '23514', 'ficheiro (storage_key) sem hash falha, mesmo no tipo código');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'comprovativo_domicilio_fiscal', substring(sha256('x'::bytea) FROM 1 FOR 31))$q$,
    '23514', 'hash de 31 bytes falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'outro_tipo', sha256('x'::bytea))$q$,
    '23514', 'kind fora da lista falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256, status) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'manual_other', sha256('x'::bytea), 'approved')$q$,
    '23514', 'approved sem reviewed_at falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256, reviewed_at) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'manual_other', sha256('x'::bytea), now())$q$,
    '23514', 'pending com reviewed_at falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256, storage_key, status, reviewed_at,
                                        delete_after) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_pdf', sha256('x'::bytea), 'verif/31d.pdf', 'approved', now(), now() + interval '31 days')$q$,
    '23514', 'delete_after a 31 dias da decisão falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256, storage_key, status, reviewed_at) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_pdf', sha256('x'::bytea), 'verif/sem-prazo.pdf', 'rejected', now())$q$,
    '23514', 'decisão com ficheiro sem delete_after falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256, storage_key, file_deleted_at) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'certidao_permanente_pdf', sha256('x'::bytea), 'verif/apagado.pdf', now())$q$,
    '23514', 'file_deleted_at com storage_key falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256) VALUES
       ('00000000-0000-7000-8000-0000000036a2', '00000000-0000-7000-8000-0000000036b1',
        'manual_other', sha256('x'::bytea))$q$,
    '23503', 'loja de outro tenant (FK composta) falha');

-- Linhas para o worker (todas em L1):
--   3603 vencida com ficheiro · 3604 decidida, ainda não vencida · 3605 já apagada (file_deleted_at)
--   3606 código sem ficheiro, decidida há muito (código vencido, a apagar) · 3602 pending com ficheiro (acima)
INSERT INTO store_verifications (id, tenant_id, store_id, kind, sha256, storage_key, access_code_enc, status,
                                 reviewed_at, delete_after, file_deleted_at) VALUES
    ('00000000-0000-7000-8000-000000003603', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b1', 'declaracao_inicio_atividade', sha256('due'::bytea), 'verif/3603.pdf',
     NULL, 'approved', now() - interval '20 days', now() - interval '1 day', NULL),
    ('00000000-0000-7000-8000-000000003604', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b1', 'comprovativo_domicilio_fiscal', sha256('fut'::bytea), 'verif/3604.pdf',
     NULL, 'rejected', now(), now() + interval '30 days', NULL),
    ('00000000-0000-7000-8000-000000003605', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b1', 'manual_other', sha256('done'::bytea), NULL,
     NULL, 'approved', now() - interval '40 days', now() - interval '10 days', now() - interval '9 days'),
    ('00000000-0000-7000-8000-000000003606', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b1', 'certidao_permanente_code', NULL, NULL,
     'v1:0a1b2c3d:Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa', 'approved', now() - interval '40 days', now() - interval '10 days', NULL);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications
       WHERE id IN ('00000000-0000-7000-8000-000000003604')
         AND delete_after = reviewed_at + interval '30 days'$q$,
    1, 'delete_after exatamente a 30 dias da decisão passa');

-- Trigger: imutáveis, transições, storage_key só → NULL.
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET sha256 = sha256('outro'::bytea) WHERE id = '00000000-0000-7000-8000-000000003602'$q$,
    '23514', 'sha256 imutável');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET kind = 'manual_other' WHERE id = '00000000-0000-7000-8000-000000003602'$q$,
    '23514', 'kind imutável');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET store_id = '00000000-0000-7000-8000-0000000036b2'
       WHERE id = '00000000-0000-7000-8000-000000003602'$q$,
    '23514', 'store_id imutável');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET access_code_enc = 'v1:0a1b2c3d:P3m7e0NbBTIWUdrv03TNxoHcBvqmXjdOODN7iMoE' WHERE id = '00000000-0000-7000-8000-000000003601'$q$,
    '23514', 'access_code_enc não muda para outro valor');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET access_code_enc = NULL WHERE id = '00000000-0000-7000-8000-000000003601'$q$,
    '23514', 'access_code_enc → NULL com pending falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET created_at = created_at - interval '1 day'
       WHERE id = '00000000-0000-7000-8000-000000003601'$q$,
    '23514', 'created_at imutável');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET storage_key = 'verif/outro.pdf' WHERE id = '00000000-0000-7000-8000-000000003602'$q$,
    '23514', 'storage_key não muda para outro valor');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET storage_key = 'verif/novo.pdf', sha256 = sha256('novo'::bytea)
       WHERE id = '00000000-0000-7000-8000-000000003601'$q$,
    '23514', 'storage_key NULL → valor falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET status = 'pending', reviewed_at = NULL
       WHERE id = '00000000-0000-7000-8000-000000003603'$q$,
    '23514', 'approved → pending proibido');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET status = 'approved' WHERE id = '00000000-0000-7000-8000-000000003604'$q$,
    '23514', 'rejected → approved proibido');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_verifications SET status = 'approved', reviewed_at = now(), delete_after = now() + interval '1 day'
       WHERE id = '00000000-0000-7000-8000-000000003601'$q$,
    1, 'pending → approved passa (código, sem ficheiro)');

ALTER TABLE store_verifications FORCE ROW LEVEL SECURITY;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class WHERE oid = 'store_verifications'::regclass AND relforcerowsecurity$q$,
    1, 'FORCE RLS reposto');
SELECT pg_temp.expect_count('SELECT count(*) FROM store_verifications', 0, 'migrator com FORCE: sem policy, 0 linhas');

-- ---------------------------------------------------------------------------
-- 3. Como ptmarket_app (lojista de L1): insere e lê em L1; L2 e outro tenant fechados; sem UPDATE/DELETE.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000036a1', true);

-- Uma linha em L2 pelo lojista de L2.
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000036b2');
INSERT INTO store_verifications (id, tenant_id, store_id, kind, sha256, storage_key) VALUES
    ('00000000-0000-7000-8000-000000003621', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b2', 'manual_other', sha256('l2'::bytea), 'verif/3621.pdf');

SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000036b1');
INSERT INTO store_verifications (id, tenant_id, store_id, kind, access_code_enc, metadata) VALUES
    ('00000000-0000-7000-8000-000000003611', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b1', 'certidao_permanente_code', 'v1:0a1b2c3d:GKw+c0PwFokMUQ6T+TUmEWnZ4/VlQ2Qpgw+vCTT0', '{"nif_prefix": "5"}');
INSERT INTO store_verifications (id, tenant_id, store_id, kind, sha256, storage_key) VALUES
    ('00000000-0000-7000-8000-000000003612', '00000000-0000-7000-8000-0000000036a1',
     '00000000-0000-7000-8000-0000000036b1', 'certidao_permanente_pdf', sha256('app'::bytea), 'verif/3612.pdf');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications
       WHERE id IN ('00000000-0000-7000-8000-000000003611', '00000000-0000-7000-8000-000000003612')
         AND status = 'pending'$q$,
    2, 'L1: insere e lê as suas (pending)');
SELECT pg_temp.expect_count(
    'SELECT count(*) FROM store_verifications', 8,
    'L1: vê só as 8 linhas de L1 (6 do migrator + 2 da app)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications WHERE store_id <> '00000000-0000-7000-8000-0000000036b1'$q$,
    0, 'L1: nenhuma linha de outra loja');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications WHERE store_id = '00000000-0000-7000-8000-0000000036b2'$q$,
    0, 'L1: SELECT de L2 (mesmo tenant/país) → 0 linhas');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b2',
        'manual_other', sha256('x'::bytea))$q$,
    '42501', 'L1: INSERT em L2 (mesmo tenant/país) → 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256, status) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'manual_other', sha256('x'::bytea), 'approved')$q$,
    '42501', 'app não insere status (sem grant)');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET storage_key = NULL WHERE id = '00000000-0000-7000-8000-000000003612'$q$,
    '42501', 'app: UPDATE → 42501');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET status = 'approved' WHERE id = '00000000-0000-7000-8000-000000003612'$q$,
    '42501', 'app: UPDATE de status → 42501');
SELECT pg_temp.expect_error(
    $q$DELETE FROM store_verifications WHERE id = '00000000-0000-7000-8000-000000003612'$q$,
    '42501', 'app: DELETE → 42501');
SELECT pg_temp.expect_error('TRUNCATE store_verifications', '42501', 'app: TRUNCATE → 42501');

-- Sem exceção de admin: o super_admin usa as funções do cartão 10.
SELECT pg_temp.ctx('admin', '');
SELECT pg_temp.expect_count('SELECT count(*) FROM store_verifications', 0, 'ator admin sem app.store_id: 0 linhas');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'manual_other', sha256('x'::bytea))$q$,
    '42501', 'ator admin sem app.store_id: INSERT → 42501');

-- Outro tenant (com app.store_id = L1): tenant_isolation recusa.
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000036b1');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000036a2', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM store_verifications', 0, 'outro tenant: 0 linhas');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind, sha256) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1',
        'manual_other', sha256('x'::bytea))$q$,
    '42501', 'outro tenant: INSERT na loja de T1 → 42501');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. Como ptmarket_worker (cartão 25): só vencidas com ficheiro ou código; ficheiro e código → NULL com
--    file_deleted_at (nunca antes da decisão).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_worker;
SELECT pg_temp.ctx('system', '');
SELECT set_config('app.current_tenant_id', '', true); -- o job corre sem tenant (vários tenants)
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications WHERE storage_key IS NOT NULL$q$,
    1, 'worker: com ficheiro, vê só a vencida (3603)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications
       WHERE id IN ('00000000-0000-7000-8000-000000003601', '00000000-0000-7000-8000-000000003602',
                    '00000000-0000-7000-8000-000000003604',
                    '00000000-0000-7000-8000-000000003611', '00000000-0000-7000-8000-000000003612',
                    '00000000-0000-7000-8000-000000003621')$q$,
    0, 'worker não vê pending nem não vencidas (ficheiro ou código)');
SELECT pg_temp.expect_count(
    'SELECT count(*) FROM store_verifications', 3,
    'worker vê 3: a vencida com ficheiro (3603), a vencida só com código (3606) e a já apagada (3605)');
SELECT pg_temp.expect_error(
    $q$SELECT sha256 FROM store_verifications$q$, '42501', 'worker não lê sha256');
SELECT pg_temp.expect_error(
    $q$SELECT access_code_enc FROM store_verifications$q$, '42501', 'worker não lê access_code_enc');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET sha256 = sha256('x'::bytea) WHERE id = '00000000-0000-7000-8000-000000003603'$q$,
    '42501', 'worker não mexe em sha256');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET status = 'rejected' WHERE id = '00000000-0000-7000-8000-000000003603'$q$,
    '42501', 'worker não mexe em status');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET access_code_enc = 'v1:0a1b2c3d:P3m7e0NbBTIWUdrv03TNxoHcBvqmXjdOODN7iMoE' WHERE id = '00000000-0000-7000-8000-000000003603'$q$,
    '23514', 'worker não põe access_code_enc com valor (trigger)');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET storage_key = 'verif/outro.pdf', file_deleted_at = NULL
       WHERE id = '00000000-0000-7000-8000-000000003603'$q$,
    '23514', 'worker não troca storage_key por outro valor (trigger)');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET storage_key = NULL WHERE id = '00000000-0000-7000-8000-000000003603'$q$,
    '42501', 'worker: apagar sem file_deleted_at → 42501 (WITH CHECK de worker_update)');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET access_code_enc = NULL WHERE id = '00000000-0000-7000-8000-000000003606'$q$,
    '42501', 'worker: apagar o código sem file_deleted_at → 42501');
SELECT pg_temp.expect_error(
    $q$UPDATE store_verifications SET storage_key = NULL, file_deleted_at = now() - interval '30 days'
       WHERE id = '00000000-0000-7000-8000-000000003603'$q$,
    '23514', 'worker: file_deleted_at anterior à decisão → 23514');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_verifications SET storage_key = NULL, file_deleted_at = now()
       WHERE id = '00000000-0000-7000-8000-000000003604'$q$,
    0, 'worker não apaga o ficheiro de uma não vencida (0 linhas)');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_verifications SET storage_key = NULL, file_deleted_at = now()
       WHERE id = '00000000-0000-7000-8000-000000003602'$q$,
    0, 'worker não apaga o ficheiro de uma pending (0 linhas)');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_verifications SET file_deleted_at = now() WHERE id = '00000000-0000-7000-8000-000000003605'$q$,
    0, 'worker não altera uma já apagada (0 linhas)');
SELECT pg_temp.expect_error(
    $q$DELETE FROM store_verifications WHERE id = '00000000-0000-7000-8000-000000003603'$q$,
    '42501', 'worker não apaga linhas');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_verifications (tenant_id, store_id, kind) VALUES
       ('00000000-0000-7000-8000-0000000036a1', '00000000-0000-7000-8000-0000000036b1', 'manual_other')$q$,
    '42501', 'worker não insere');
SELECT pg_temp.expect_count(
    $q$WITH u AS (
           UPDATE store_verifications SET storage_key = NULL, access_code_enc = NULL, file_deleted_at = now()
           WHERE id IN (SELECT id FROM store_verifications WHERE delete_after <= now()
                        ORDER BY delete_after LIMIT 500 FOR UPDATE SKIP LOCKED)
           RETURNING id, tenant_id, store_id
       )
       SELECT count(*) FROM u
       WHERE id IN ('00000000-0000-7000-8000-000000003603', '00000000-0000-7000-8000-000000003606')
         AND tenant_id = '00000000-0000-7000-8000-0000000036a1'
         AND store_id = '00000000-0000-7000-8000-0000000036b1' AND (SELECT count(*) FROM u) = 2$q$,
    2, 'job de eliminação: a vencida com ficheiro e a vencida com código (a já apagada fica de fora)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications WHERE storage_key IS NOT NULL$q$,
    0, 'worker: já não há ficheiros vencidos');
RESET ROLE;

-- Prova (migrator, FORCE desligado só aqui): hash, estado e código intactos; ficheiro marcado como apagado.
ALTER TABLE store_verifications NO FORCE ROW LEVEL SECURITY;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications
       WHERE id = '00000000-0000-7000-8000-000000003603' AND storage_key IS NULL AND file_deleted_at = now()
         AND sha256 = sha256('due'::bytea) AND status = 'approved'$q$,
    1, 'depois do worker: hash e estado ficam (prova), ficheiro apagado');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications
       WHERE id = '00000000-0000-7000-8000-000000003606' AND access_code_enc IS NULL AND file_deleted_at = now()
         AND status = 'approved'$q$,
    1, 'depois do worker: código apagado, com file_deleted_at');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_verifications
       WHERE id = '00000000-0000-7000-8000-000000003604' AND storage_key IS NOT NULL$q$,
    1, 'a não vencida mantém o ficheiro');
ALTER TABLE store_verifications FORCE ROW LEVEL SECURITY;

ROLLBACK;
