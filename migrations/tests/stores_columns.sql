-- Teste 0029 stores: colunas de entrega/plano/contrato/moradas (CHECK, contrato tudo-ou-nada, DICOFRE por length + FK,
-- códigos com letras) e trinco de dinheiro (ptmarket_app sem escrita em custom_commission_bps/kyc_verified nem UPDATE
-- de id/tenant_id/created_at). Geografia e tenant pelo migrator; lojas e asserções com SET ROLE ptmarket_app.
-- Tudo com ROLLBACK.
BEGIN;

-- Ator admin (0035): este teste escreve e lê várias lojas do mesmo tenant de seguida; o âmbito por loja
-- (app.store_id) é provado em store_scope_rls.sql. Os trincos por coluna (GRANT) não dependem do ator.
SELECT set_config('app.actor_type', 'admin', true);
SELECT set_config('app.actor_label', 'test', true);

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

-- ---------------------------------------------------------------------------
-- 0. Preparação (migrator): geografia de teste (distrito 96) e um tenant.
-- ---------------------------------------------------------------------------
INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
    ('96', 'district', NULL, 'Distrito Teste 29', 'T'),
    ('9601', 'municipality', '96', 'Concelho Teste 29', 'T'),
    ('960101', 'parish', '9601', 'Freguesia Teste 29-01', 'T'),
    ('9601FA', 'parish', '9601', 'Freguesia Teste 29-FA', 'T');

-- Desde a 0033 as lojas só vivem em tenants national_portal.
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type) VALUES
    ('00000000-0000-7000-8000-0000000029a0', 'stc-a', 'stc-a.teste.invalid', 'Tenant 29 A', 'national_portal');

-- ---------------------------------------------------------------------------
-- 1. Grants por coluna (catálogo).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM information_schema.columns c
       WHERE c.table_schema = 'public' AND c.table_name = 'stores'
         AND has_column_privilege('ptmarket_app', 'public.stores', c.column_name, 'INSERT')
             <> (c.column_name NOT IN ('custom_commission_bps', 'kyc_verified'))$q$,
    0, 'app: INSERT em todas as colunas menos custom_commission_bps e kyc_verified');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM information_schema.columns c
       WHERE c.table_schema = 'public' AND c.table_name = 'stores'
         AND has_column_privilege('ptmarket_app', 'public.stores', c.column_name, 'UPDATE')
             <> (c.column_name NOT IN ('id', 'tenant_id', 'custom_commission_bps', 'kyc_verified', 'created_at'))$q$,
    0, 'app: UPDATE em todas menos id, tenant_id, custom_commission_bps, kyc_verified, created_at');
SELECT pg_temp.expect_count(
    $q$SELECT (has_table_privilege('ptmarket_app', 'public.stores', 'SELECT')
           AND has_table_privilege('ptmarket_app', 'public.stores', 'DELETE')
           AND NOT has_table_privilege('ptmarket_app', 'public.stores', 'INSERT')
           AND NOT has_table_privilege('ptmarket_app', 'public.stores', 'UPDATE'))::int$q$,
    1, 'app: SELECT e DELETE ao nível da tabela; INSERT/UPDATE só por coluna');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM information_schema.columns c
       WHERE c.table_schema = 'public' AND c.table_name = 'stores'
         AND (has_column_privilege('ptmarket_portal', 'public.stores', c.column_name, 'INSERT')
           OR has_column_privilege('ptmarket_portal', 'public.stores', c.column_name, 'UPDATE'))$q$,
    0, 'portal: sem INSERT/UPDATE em stores');

-- ---------------------------------------------------------------------------
-- 2. Como ptmarket_app no tenant A: loja "antiga" (sem colunas novas) e loja com contrato.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000029a0';

INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000029b1', '00000000-0000-7000-8000-0000000029a0',
     'Loja Antiga', 'stc-antiga', 'Antiga Lda', '500002901', 'PT50000000000000000002901', 'antiga@teste.invalid');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores
       WHERE id = '00000000-0000-7000-8000-0000000029b1'
         AND shipping_scope = 'national' AND billing_plan_code = 'commission_payg'
         AND accepted_base_commission_bps IS NULL AND terms_version IS NULL AND terms_accepted_at IS NULL
         AND fiscal_address = '{}' AND storefront_address = '{}' AND storefront_dicofre IS NULL
         AND custom_commission_bps IS NULL AND NOT kyc_verified$q$,
    1, 'loja antiga: national, commission_payg, contrato NULL, moradas vazias');

INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, shipping_scope, billing_plan_code,
                    accepted_base_commission_bps, terms_version, terms_accepted_at, fiscal_address,
                    storefront_address, storefront_dicofre) VALUES
    ('00000000-0000-7000-8000-0000000029b2', '00000000-0000-7000-8000-0000000029a0',
     'Loja Nova', 'stc-nova', 'Nova Lda', '500002902', 'PT50000000000000000002902', 'nova@teste.invalid',
     'local_only', 'tiered_subscription', 800, '2026-11', now(), '{"rua": "Fiscal"}', '{"rua": "Loja"}', '9601FA');
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, storefront_dicofre) VALUES
    ('00000000-0000-7000-8000-0000000029b3', '00000000-0000-7000-8000-0000000029a0',
     'Loja Num', 'stc-num', 'Num Lda', '500002903', 'PT50000000000000000002903', 'num@teste.invalid', '960101');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores WHERE id IN ('00000000-0000-7000-8000-0000000029b2',
                                               '00000000-0000-7000-8000-0000000029b3')$q$,
    2, 'contrato completo e DICOFRE de freguesia (com letras e só algarismos) passam');

-- ---------------------------------------------------------------------------
-- 3. CHECK, contrato tudo-ou-nada e DICOFRE.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET shipping_scope = 'worldwide' WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'shipping_scope fora da lista falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET billing_plan_code = 'free' WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'billing_plan_code fora da lista falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET accepted_base_commission_bps = 10001, terms_version = 'v', terms_accepted_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'accepted_base_commission_bps > 10000 falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET accepted_base_commission_bps = -1, terms_version = 'v', terms_accepted_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'accepted_base_commission_bps < 0 falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET accepted_base_commission_bps = 800 WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'contrato só com accepted_base_commission_bps falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET terms_version = 'v' WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'contrato só com terms_version falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET terms_accepted_at = now() WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'contrato só com terms_accepted_at falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET accepted_base_commission_bps = 800, terms_version = 'v'
       WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'contrato sem terms_accepted_at falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET terms_version = 'v', terms_accepted_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'contrato sem accepted_base_commission_bps falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET accepted_base_commission_bps = 800, terms_accepted_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'contrato sem terms_version falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET terms_version = NULL WHERE id = '00000000-0000-7000-8000-0000000029b2'$q$,
    '23514', 'apagar 1 dos 3 campos de um contrato completo falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET storefront_dicofre = '9601' WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'storefront_dicofre de concelho (4) falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET storefront_dicofre = '96' WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23514', 'storefront_dicofre de distrito (2) falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET storefront_dicofre = '9601ZZ' WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '23503', 'storefront_dicofre inexistente falha (FK)');

-- ---------------------------------------------------------------------------
-- 4. Trinco de dinheiro (ptmarket_app, tenant da loja).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE stores SET name = 'Loja Antiga 2' WHERE id = '00000000-0000-7000-8000-0000000029b1'
                  RETURNING 1) SELECT count(*) FROM u$q$,
    1, 'app: UPDATE de name passa');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE stores SET shipping_scope = 'pickup_only' WHERE id = '00000000-0000-7000-8000-0000000029b1'
                  RETURNING 1) SELECT count(*) FROM u$q$,
    1, 'app: UPDATE de shipping_scope passa');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET custom_commission_bps = 100 WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '42501', 'app: UPDATE de custom_commission_bps → 42501');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET kyc_verified = true WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '42501', 'app: UPDATE de kyc_verified → 42501');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET tenant_id = '00000000-0000-7000-8000-0000000029a0'
       WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '42501', 'app: UPDATE de tenant_id (mesmo valor) → 42501');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET id = '00000000-0000-7000-8000-0000000029bf' WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '42501', 'app: UPDATE de id → 42501');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET created_at = now() WHERE id = '00000000-0000-7000-8000-0000000029b1'$q$,
    '42501', 'app: UPDATE de created_at → 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (tenant_id, name, slug, legal_name, nif, iban, email, custom_commission_bps)
       VALUES ('00000000-0000-7000-8000-0000000029a0', 'X', 'stc-x', 'X', '1', 'PT50', 'x@x.pt', 100)$q$,
    '42501', 'app: INSERT com custom_commission_bps → 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (tenant_id, name, slug, legal_name, nif, iban, email, kyc_verified)
       VALUES ('00000000-0000-7000-8000-0000000029a0', 'X', 'stc-y', 'X', '1', 'PT50', 'x@x.pt', true)$q$,
    '42501', 'app: INSERT com kyc_verified → 42501');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores
       WHERE id = '00000000-0000-7000-8000-0000000029b1' AND custom_commission_bps IS NULL AND NOT kyc_verified$q$,
    1, 'app: custom_commission_bps e kyc_verified intactos');
RESET ROLE;

ROLLBACK;
