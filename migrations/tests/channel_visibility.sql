-- Teste da 0033 (cartão 03/08; spec 14 §1.1): visibilidade por canal em portal_stores, selos em portal_store_badges,
-- portal_read sem gate em products/product_variants, trinco de stores e grants/policies de ptmarket_portal.
-- Tenants, geografia e entidades pelo migrator (policies migrator_all); lojas, produtos e patrocínios pela app
-- (SET ROLE ptmarket_app, cada um no seu tenant). Asserções de acesso com SET ROLE ptmarket_app. Tudo com ROLLBACK.

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

CREATE FUNCTION pg_temp.expect_text(p_sql text, p_expected text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_t text;
BEGIN
    EXECUTE p_sql INTO v_t;
    IF v_t IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'FALHOU: % (esperado %, obtido %)', p_label, p_expected, v_t;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Plano sem seq scan na tabela indicada, com o planeador normal (enable_seqscan ligado) e estatísticas atuais.
CREATE FUNCTION pg_temp.expect_no_seqscan(p_sql text, p_table text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_line text;
    v_plan text := '';
BEGIN
    FOR v_line IN EXECUTE 'EXPLAIN (COSTS OFF) ' || p_sql LOOP
        v_plan := v_plan || v_line || E'\n';
    END LOOP;
    IF v_plan LIKE '%Seq Scan on ' || p_table || ' %' OR v_plan LIKE '%Seq Scan on ' || p_table || E'\n%' THEN
        RAISE EXCEPTION 'FALHOU: % (seq scan em %)%', p_label, p_table, E'\n' || v_plan;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

CREATE FUNCTION pg_temp.as_actor(p_type text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', p_type, true);
END
$$;

SELECT set_config('app.actor_label', 'test', true);

-- ---------------------------------------------------------------------------
-- 0. Preparação (migrator).
--   NP = nacional PT · NE = nacional ES (0035: um só national_portal por país; o caso "nacional inativo" desativa o
--   NP dentro de um savepoint, na secção 3)
--   CA, CB = municipais PT (canais das Câmaras A e B) · CI = municipal PT inativo (canal da Câmara I) · M = municipal PT
--   Entidades: EA Câmara (canal CA) · EB Câmara (canal CB) · EJ Junta (sem canal) · EX Câmara inativa (canal CA) ·
--              EI Câmara (canal CI, inativo).
-- ---------------------------------------------------------------------------
INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
    ('93', 'district', NULL, 'Distrito Teste 33', 'T'),
    ('9301', 'municipality', '93', 'Concelho A 33', 'T'),
    ('9302', 'municipality', '93', 'Concelho B 33', 'T'),
    ('930101', 'parish', '9301', 'Freguesia A 33', 'T');

INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code, is_active) VALUES
    ('00000000-0000-7000-8000-0000000033a0', 'cv-npt', 'cv-npt.teste.invalid', 'Nacional PT 33', 'national_portal', 'PT', true),
    ('00000000-0000-7000-8000-0000000033a1', 'cv-nes', 'cv-nes.teste.invalid', 'Nacional ES 33', 'national_portal', 'ES', true),
    ('00000000-0000-7000-8000-0000000033c1', 'cv-ca', 'cv-ca.teste.invalid', 'Canal A 33', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-0000000033c2', 'cv-cb', 'cv-cb.teste.invalid', 'Canal B 33', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-0000000033c3', 'cv-ci', 'cv-ci.teste.invalid', 'Canal inativo 33', 'municipal', 'PT', false),
    ('00000000-0000-7000-8000-0000000033c4', 'cv-m', 'cv-m.teste.invalid', 'Municipal M 33', 'municipal', 'PT', true);

-- A Junta tem nome alfabeticamente antes da Câmara: a ordem dos selos é pelo tipo, só depois pelo nome.
INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code, channel_tenant_id, is_active) VALUES
    ('00000000-0000-7000-8000-0000000033e1', 'municipality', 'PT', 'Câmara A 33', 'cv-camara-a', '9301',
     '00000000-0000-7000-8000-0000000033c1', true),
    ('00000000-0000-7000-8000-0000000033e2', 'municipality', 'PT', 'Câmara B 33', 'cv-camara-b', '9302',
     '00000000-0000-7000-8000-0000000033c2', true),
    ('00000000-0000-7000-8000-0000000033e3', 'parish', 'PT', 'Aaa Junta 33', 'cv-junta', '930101', NULL, true),
    ('00000000-0000-7000-8000-0000000033e4', 'municipality', 'PT', 'Câmara X 33', 'cv-camara-x', '9301',
     '00000000-0000-7000-8000-0000000033c1', false),
    ('00000000-0000-7000-8000-0000000033e5', 'municipality', 'PT', 'Câmara I 33', 'cv-camara-i', '9302',
     '00000000-0000-7000-8000-0000000033c3', true);

-- ---------------------------------------------------------------------------
-- 1. Lojas, produtos e patrocínios (app).
--   No NP: S1 (EA + EJ ativos) · S2 (EB ativo) · S3 (sem patrocínio, sem opt-in, pickup_only) ·
--          S4 pending · S5 rejected · S6 revoked · S7 expired · S8 active com valid_to passado ·
--          S9 active com valid_from futuro (todos com EA) · S10 inativa (EA ativo) · S11 (EX inativa, ativo) ·
--          S12 (EI, canal inativo, ativo).
--   No NE: SE (ES).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
-- Seed de várias lojas de uma vez: ator admin (âmbito por loja da 0035); as leituras (secções 2 e 3) voltam a 'system'.
SELECT pg_temp.as_actor('admin');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033a0', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, publish_to_national_portal, is_active,
                    shipping_scope)
SELECT format('00000000-0000-7000-8000-0000000033%s', lpad(to_hex(n), 2, '0'))::uuid,
       '00000000-0000-7000-8000-0000000033a0', format('Loja S%s', n), format('cv-s%s', n), format('S%s Lda', n),
       format('5000033%s', lpad(n::text, 2, '0')), format('PT500000000000000000033%s', lpad(n::text, 2, '0')),
       format('s%s@teste.invalid', n), n <> 3, n <> 10, CASE WHEN n = 3 THEN 'pickup_only' ELSE 'national' END
FROM generate_series(1, 12) AS n;

-- Produtos: P1 publicado e P1U não publicado (S1); P2 publicado (S2); P3 publicado (S3).
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps, is_published) VALUES
    ('00000000-0000-7000-8000-0000000033f1', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-000000003301', '{"pt":"P1"}', 2300, true),
    ('00000000-0000-7000-8000-0000000033f2', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-000000003301', '{"pt":"P1U"}', 2300, false),
    ('00000000-0000-7000-8000-0000000033f3', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-000000003302', '{"pt":"P2"}', 2300, true),
    ('00000000-0000-7000-8000-0000000033f4', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-000000003303', '{"pt":"P3"}', 2300, true);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents, is_active) VALUES
    ('00000000-0000-7000-8000-0000000033d1', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-0000000033f1', 100, true),
    ('00000000-0000-7000-8000-0000000033d2', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-0000000033f1', 110, false),
    ('00000000-0000-7000-8000-0000000033d3', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-0000000033f2', 120, true),
    ('00000000-0000-7000-8000-0000000033d4', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-0000000033f3', 130, true),
    ('00000000-0000-7000-8000-0000000033d5', '00000000-0000-7000-8000-0000000033a0',
     '00000000-0000-7000-8000-0000000033f4', 140, true);

-- Patrocínios: nascem pending; a decisão é por UPDATE (trigger da 0031).
-- 0035: o pedido é sempre da loja do contexto (INSERT só com app.store_id = store_id, nem o admin): uma linha de
-- cada vez, com o app.store_id da loja.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('00000000-0000-7000-8000-000000033101', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003301', '00000000-0000-7000-8000-0000000033e1'),
        ('00000000-0000-7000-8000-000000033102', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003301', '00000000-0000-7000-8000-0000000033e3'),
        ('00000000-0000-7000-8000-000000033103', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003302', '00000000-0000-7000-8000-0000000033e2'),
        ('00000000-0000-7000-8000-000000033104', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003304', '00000000-0000-7000-8000-0000000033e1'),
        ('00000000-0000-7000-8000-000000033105', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003305', '00000000-0000-7000-8000-0000000033e1'),
        ('00000000-0000-7000-8000-000000033106', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003306', '00000000-0000-7000-8000-0000000033e1'),
        ('00000000-0000-7000-8000-000000033107', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003307', '00000000-0000-7000-8000-0000000033e1'),
        ('00000000-0000-7000-8000-000000033108', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003308', '00000000-0000-7000-8000-0000000033e1'),
        ('00000000-0000-7000-8000-000000033109', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-000000003309', '00000000-0000-7000-8000-0000000033e1'),
        ('00000000-0000-7000-8000-00000003310a', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-00000000330a', '00000000-0000-7000-8000-0000000033e1'),
        ('00000000-0000-7000-8000-00000003310b', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-00000000330b', '00000000-0000-7000-8000-0000000033e4'),
        ('00000000-0000-7000-8000-00000003310c', '00000000-0000-7000-8000-0000000033a0',
         '00000000-0000-7000-8000-00000000330c', '00000000-0000-7000-8000-0000000033e5')
    ) AS v(id, tenant_id, store_id, sponsor_entity_id) LOOP
        PERFORM set_config('app.store_id', r.store_id, true);
        INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id)
        VALUES (r.id::uuid, r.tenant_id::uuid, r.store_id::uuid, r.sponsor_entity_id::uuid);
    END LOOP;
    PERFORM set_config('app.store_id', '', true);
END
$$;

-- Ativos e vigentes (desde ontem, sem fim): S1 (EA, EJ), S2, S6 e S7 (antes de revogar/expirar), S10, S11, S12.
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
WHERE id IN ('00000000-0000-7000-8000-000000033101', '00000000-0000-7000-8000-000000033102',
             '00000000-0000-7000-8000-000000033103', '00000000-0000-7000-8000-000000033106',
             '00000000-0000-7000-8000-000000033107', '00000000-0000-7000-8000-00000003310a',
             '00000000-0000-7000-8000-00000003310b', '00000000-0000-7000-8000-00000003310c');
UPDATE store_sponsorships SET status = 'rejected' WHERE id = '00000000-0000-7000-8000-000000033105';
UPDATE store_sponsorships SET status = 'revoked' WHERE id = '00000000-0000-7000-8000-000000033106';
-- 'expired' com vigência ainda aberta: o estado basta (sem depender do job).
UPDATE store_sponsorships SET status = 'expired' WHERE id = '00000000-0000-7000-8000-000000033107';
-- 'active' fora da vigência: o job ainda não passou (o estado não basta).
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '10 days', valid_to = now() - interval '1 day'
WHERE id = '00000000-0000-7000-8000-000000033108';
UPDATE store_sponsorships SET status = 'active', valid_from = now() + interval '1 day'
WHERE id = '00000000-0000-7000-8000-000000033109';

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033a1', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000033b1', '00000000-0000-7000-8000-0000000033a1',
     'Tienda SE', 'cv-se', 'SE SL', 'B00003301', 'ES9100000000000000003301', 'se@teste.invalid');
SELECT pg_temp.as_actor('system');

-- ---------------------------------------------------------------------------
-- 2. Isolamento entre canais (white-label; a flag nacional não muda nada num tenant municipal).
-- ---------------------------------------------------------------------------
SET app.portal_national = 'on';
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033c1', true);
SELECT pg_temp.expect_text('SELECT string_agg(name, '','' ORDER BY name) FROM portal_stores', 'Loja S1',
    'canal A vê só S1 (patrocínio ativo e vigente de EA)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id IN (
         '00000000-0000-7000-8000-000000003302', '00000000-0000-7000-8000-000000003303',
         '00000000-0000-7000-8000-000000003304', '00000000-0000-7000-8000-000000003305',
         '00000000-0000-7000-8000-000000003306', '00000000-0000-7000-8000-000000003307',
         '00000000-0000-7000-8000-000000003308', '00000000-0000-7000-8000-000000003309',
         '00000000-0000-7000-8000-00000000330a', '00000000-0000-7000-8000-00000000330b',
         '00000000-0000-7000-8000-0000000033b1')$q$,
    0, 'canal A: sem canal B, sem patrocínio, pending/rejected/revoked/expired, fora da vigência, loja/entidade inativas');
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'canal A: stores sem linhas (tenant_isolation)');
SELECT pg_temp.expect_count('SELECT count(*) FROM store_sponsorships', 0, 'canal A: store_sponsorships sem linhas');

-- Produtos e variantes: só os publicados/ativos das lojas visíveis.
SELECT pg_temp.expect_text('SELECT string_agg(title->>''pt'', '','' ORDER BY id) FROM products', 'P1',
    'canal A lê só o produto publicado de S1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE store_id IN ('00000000-0000-7000-8000-000000003302',
                                                        '00000000-0000-7000-8000-000000003303')$q$,
    0, 'canal A: 0 produtos das lojas não visíveis');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id = '00000000-0000-7000-8000-0000000033d1'$q$,
    1, 'canal A lê a variante ativa do produto publicado');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 1,
    'canal A: sem variante inativa, de produto não publicado ou de loja não visível');

-- Selos: co-patrocínio Câmara A + Junta, ordem fixa municipality → parish.
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id = '00000000-0000-7000-8000-000000003301'$q$,
    1, 'canal A: S1 co-patrocinada aparece uma só vez');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(b.kind || ':' || b.name, ',') FROM (
         SELECT kind, name FROM portal_store_badges WHERE store_id = '00000000-0000-7000-8000-000000003301') b$q$,
    'municipality:Câmara A 33,parish:Aaa Junta 33', 'canal A: 2 selos de S1 pela ordem fixa');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_store_badges', 2, 'canal A: só os selos das lojas visíveis');

-- Nada de dinheiro nem chaves pelas views.
DO $$
DECLARE
    c text;
BEGIN
    FOREACH c IN ARRAY ARRAY['iban', 'eupago_split_key', 'invoicing_credentials_enc', 'stripe_account_id',
                             'custom_commission_bps', 'accepted_base_commission_bps', 'billing_plan_code',
                             'kyc_verified', 'fiscal_address', 'publish_to_national_portal'] LOOP
        PERFORM pg_temp.expect_error(format('SELECT %I FROM portal_stores', c), '42703',
            format('canal A: SELECT %s FROM portal_stores → 42703', c));
    END LOOP;
    FOREACH c IN ARRAY ARRAY['commission_override_bps', 'tenant_id', 'status', 'valid_to', 'decided_by'] LOOP
        PERFORM pg_temp.expect_error(format('SELECT %I FROM portal_store_badges', c), '42703',
            format('canal A: SELECT %s FROM portal_store_badges → 42703', c));
    END LOOP;
END
$$;

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033c2', true);
SELECT pg_temp.expect_text('SELECT string_agg(name, '','' ORDER BY name) FROM portal_stores', 'Loja S2',
    'canal B vê só S2');
SELECT pg_temp.expect_text('SELECT string_agg(title->>''pt'', '','' ORDER BY id) FROM products', 'P2',
    'canal B lê só o produto de S2');
SELECT pg_temp.expect_text('SELECT string_agg(name, '','') FROM portal_store_badges', 'Câmara B 33',
    'canal B: 1 selo (Câmara B)');

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033c3', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'canal inativo: portal_stores vazia');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033c4', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'municipal sem entidade: portal_stores vazia');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'municipal sem entidade: 0 produtos');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_store_badges', 0, 'municipal sem entidade: 0 selos');

-- ---------------------------------------------------------------------------
-- 3. Canal nacional: todas as lojas ativas do país, sem opt-out.
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033a0', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 11,
    'nacional PT: as 11 lojas ativas do tenant (S1-S9, S11, S12)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores
       WHERE id = '00000000-0000-7000-8000-000000003303' AND shipping_scope = 'pickup_only'$q$,
    1, 'nacional PT vê S3 (publish_to_national_portal = false, pickup_only)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id IN ('00000000-0000-7000-8000-00000000330a',
                                                       '00000000-0000-7000-8000-0000000033b1')$q$,
    0, 'nacional PT não vê loja inativa nem loja ES');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id = '00000000-0000-7000-8000-000000003301'$q$,
    1, 'nacional PT: S1 co-patrocinada aparece uma só vez');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(b.kind, ',') FROM (
         SELECT kind FROM portal_store_badges WHERE store_id = '00000000-0000-7000-8000-000000003301') b$q$,
    'municipality,parish', 'nacional PT: 2 selos de S1 pela ordem fixa');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_store_badges', 4,
    'nacional PT: selos só de patrocínios ativos, vigentes, de entidades ativas (S1 x2, S2, S12)');

RESET app.portal_national;
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'nacional PT sem flag: portal_stores vazia');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_store_badges', 0, 'nacional PT sem flag: 0 selos');
SET app.portal_national = 'on';

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033a1', true);
SELECT pg_temp.expect_text('SELECT string_agg(name, '','') FROM portal_stores', 'Tienda SE', 'nacional ES vê só SE');
-- Tenant da loja inativo (0035: um só national_portal por país): o NP é desativado só dentro deste savepoint.
SAVEPOINT cv_ni;
RESET ROLE;
UPDATE tenants SET is_active = false WHERE id = '00000000-0000-7000-8000-0000000033a0';
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033a0', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'nacional inativo: portal_stores vazia');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033c1', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0,
    'canal A: loja de tenant inativo (S1, EA ativo e vigente) não aparece');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'canal A: 0 produtos de loja de tenant inativo');
ROLLBACK TO SAVEPOINT cv_ni;
SELECT set_config('app.current_tenant_id', '', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'sem contexto: portal_stores vazia');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_store_badges', 0, 'sem contexto: 0 selos');

-- ---------------------------------------------------------------------------
-- 4. Trinco: loja num tenant que não é national_portal → 23514.
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033c4', true);
SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (tenant_id, name, slug, legal_name, nif, iban, email)
       VALUES ('00000000-0000-7000-8000-0000000033c4', 'Loja M', 'cv-loja-m', 'M Lda', '500003398',
               'PT50000000000000000003398', 'm@teste.invalid')$q$,
    '23514', 'loja criada num tenant municipal → erro do trinco');
RESET app.portal_national;
SELECT pg_temp.as_actor('');
RESET ROLE;

-- O dono também (UPDATE OF tenant_id; FORCE desligado só para o dono ver a linha).
ALTER TABLE stores NO FORCE ROW LEVEL SECURITY;
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET tenant_id = '00000000-0000-7000-8000-0000000033c4'
       WHERE id = '00000000-0000-7000-8000-000000003303'$q$,
    '23514', 'dono: mover loja para um tenant municipal → erro do trinco');
ALTER TABLE stores FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- 5. Catálogo: papel, views, grants, policies e trigger.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname = 'ptmarket_portal' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls$q$,
    1, 'ptmarket_portal continua NOLOGIN, sem SUPERUSER/BYPASSRLS');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles WHERE rolname = 'ptmarket_portal'
         AND pg_has_role(current_user, oid, 'USAGE')$q$,
    0, 'migrator sem INHERIT em ptmarket_portal');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE oid IN ('portal_stores'::regclass, 'portal_store_badges'::regclass) AND relkind = 'v'
         AND relowner = 'ptmarket_portal'::regrole AND reloptions @> ARRAY['security_barrier=true']$q$,
    2, 'portal_stores e portal_store_badges: views security_barrier, donas ptmarket_portal');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid IN ('portal_stores'::regclass, 'portal_store_badges'::regclass) AND a.grantee <> c.relowner
         AND NOT (a.grantee = 'ptmarket_app'::regrole AND a.privilege_type = 'SELECT')$q$,
    0, 'views do portal: só SELECT para ptmarket_app');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_attribute
       WHERE attrelid = 'portal_store_badges'::regclass AND attnum > 0 AND NOT attisdropped$q$,
    6, 'portal_store_badges: 6 colunas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_description
       WHERE objoid = 'portal_store_badges'::regclass AND description LIKE '%municipality → parish → association%'$q$,
    1, 'portal_store_badges: ordem fixa no COMMENT');

-- ptmarket_portal: só as colunas que a condição e as views leem.
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'store_sponsorships'
         AND has_column_privilege('ptmarket_portal', 'public.store_sponsorships', column_name, 'SELECT')$q$,
    'sponsor_entity_id,status,store_id,valid_from,valid_to', 'ptmarket_portal: colunas de store_sponsorships');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'sponsor_entities'
         AND has_column_privilege('ptmarket_portal', 'public.sponsor_entities', column_name, 'SELECT')$q$,
    'channel_tenant_id,id,is_active,kind,logo_key,name,slug', 'ptmarket_portal: colunas de sponsor_entities');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['shipping_scope', 'storefront_address', 'storefront_dicofre']) AS c(col)
       WHERE has_column_privilege('ptmarket_portal', 'public.stores', c.col, 'SELECT')$q$,
    3, 'ptmarket_portal lê as 3 colunas novas de stores');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['iban', 'custom_commission_bps', 'accepted_base_commission_bps',
                                         'billing_plan_code', 'fiscal_address', 'terms_version',
                                         'publish_to_national_portal']) AS c(col)
       WHERE has_column_privilege('ptmarket_portal', 'public.stores', c.col, 'SELECT')$q$,
    0, 'ptmarket_portal não lê iban, comissões, plano, morada fiscal nem o opt-in antigo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['store_sponsorships', 'sponsor_entities']) AS t(tab),
                            unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_portal', t.tab, p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE') AND has_any_column_privilege('ptmarket_portal', t.tab, p.priv))$q$,
    0, 'ptmarket_portal sem escrita nas tabelas de patrocínio');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid IN ('store_sponsorships'::regclass, 'sponsor_entities'::regclass) AND polname = 'portal_view'
         AND polcmd = 'r' AND polroles = ARRAY['ptmarket_portal'::regrole::oid]$q$,
    2, 'policies portal_view FOR SELECT TO ptmarket_portal em store_sponsorships e sponsor_entities');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid IN ('products'::regclass, 'product_variants'::regclass) AND polname = 'portal_read'
         AND polcmd = 'r' AND polroles = ARRAY['ptmarket_app'::regrole::oid]
         AND pg_get_expr(polqual, polrelid) NOT LIKE '%app_is_national_portal%'
         AND pg_get_expr(polqual, polrelid) LIKE '%portal_stores%'$q$,
    2, 'portal_read de products/product_variants sem o gate, por portal_stores');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid = 'stores'::regclass AND polname = 'portal_view'
         AND pg_get_expr(polqual, polrelid) NOT LIKE '%publish_to_national_portal%'
         AND pg_get_expr(polqual, polrelid) LIKE '%store_sponsorships%'$q$,
    1, 'stores.portal_view: condição nova (sem opt-in, com patrocínio)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid IN ('stores'::regclass, 'products'::regclass, 'product_variants'::regclass,
                          'store_sponsorships'::regclass) AND polname = 'tenant_isolation'$q$,
    4, 'tenant_isolation intacta');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid = 'stores'::regclass AND tgname = 'stores_national_tenant_guard' AND tgenabled = 'A'$q$,
    1, 'stores: trinco stores_national_tenant_guard (ALWAYS)');

-- ---------------------------------------------------------------------------
-- 6. EXPLAIN com 1.000 linhas em store_sponsorships: sem Seq Scan (planeador normal).
-- ---------------------------------------------------------------------------
INSERT INTO sponsor_entities (id, kind, country_code, name, slug)
SELECT format('00000000-0000-7000-8000-%s', lpad(to_hex(x'33e100'::int + n), 12, '0'))::uuid,
       'association', 'PT', format('Associação %s', n), format('cv-assoc-%s', n)
FROM generate_series(1, 100) AS n;
INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id)
SELECT '00000000-0000-7000-8000-0000000033a0',
       format('00000000-0000-7000-8000-0000000033%s', lpad(to_hex(s), 2, '0'))::uuid,
       format('00000000-0000-7000-8000-%s', lpad(to_hex(x'33e100'::int + n), 12, '0'))::uuid
FROM generate_series(1, 10) AS s, generate_series(1, 100) AS n;
UPDATE store_sponsorships SET status = 'rejected'
WHERE status = 'pending' AND sponsor_entity_id::text LIKE '00000000-0000-7000-8000-00000033e1%'
  AND right(sponsor_entity_id::text, 2) <> '01';
ANALYZE store_sponsorships;
ANALYZE sponsor_entities;
ANALYZE stores;
ANALYZE tenants;
SELECT pg_temp.expect_count('SELECT (count(*) >= 1000)::int FROM store_sponsorships', 1,
    'store_sponsorships com pelo menos 1.000 linhas');

SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000033c1', true);
SELECT pg_temp.expect_no_seqscan('SELECT id, name FROM portal_stores', 'store_sponsorships',
    'canal A: portal_stores sem Seq Scan em store_sponsorships');
SELECT pg_temp.expect_no_seqscan('SELECT store_id, kind, name FROM portal_store_badges', 'store_sponsorships',
    'canal A: portal_store_badges sem Seq Scan em store_sponsorships');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM products WHERE store_id = '00000000-0000-7000-8000-000000003301'$q$, 'store_sponsorships',
    'canal A: produtos por loja sem Seq Scan em store_sponsorships');
RESET ROLE;

ROLLBACK;
