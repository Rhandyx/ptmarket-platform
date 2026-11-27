-- Teste do portal (0016; view portal_stores desde a 0021; visibilidade por canal desde a 0033): no canal nacional
-- (tenant do contexto = national_portal ativo + flag) todas as lojas ativas desse tenant; num canal white-label só as
-- lojas patrocinadas e os seus produtos publicados / variantes ativas; escritas continuam isoladas.
-- Asserções correm sempre com SET ROLE ptmarket_app. Só os tenants e a entidade patrocinadora (sem grant de escrita
-- para a app) são criados pelo dono das migrations. Tudo numa transação com ROLLBACK: a BD fica como estava.

BEGIN;

-- Caixa negra L1 (0010): mutações da app exigem ator; fixado para a transação inteira.
SELECT set_config('app.actor_type', 'system', true);
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

-- Plano sem seq scan na tabela indicada (enable_seqscan = off: se houver índice utilizável, é usado).
CREATE FUNCTION pg_temp.expect_no_seqscan(p_sql text, p_table text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_line text;
    v_plan text := '';
BEGIN
    PERFORM set_config('enable_seqscan', 'off', true);
    FOR v_line IN EXECUTE 'EXPLAIN (COSTS OFF) ' || p_sql LOOP
        v_plan := v_plan || v_line || E'\n';
    END LOOP;
    PERFORM set_config('enable_seqscan', 'on', true);
    IF v_plan LIKE '%Seq Scan on ' || p_table || ' %' OR v_plan LIKE '%Seq Scan on ' || p_table || E'\n%' THEN
        RAISE EXCEPTION 'FALHOU: % (seq scan em %)%', p_label, p_table, E'\n' || v_plan;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- ---------------------------------------------------------------------------
-- Tenants (globais; só o dono das migrations escreve). Desde a 0033 as lojas só vivem em tenants national_portal.
--   P  = portal nacional PT (ativo)      PE = portal nacional ES
--   (0035: um só national_portal por país; o caso "portal/tenant inativo" desativa o P dentro de um savepoint.)
--   W  = municipal PT, canal da entidade EW (white-label)                    M  = municipal PT sem entidade
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code, is_active) VALUES
    ('00000000-0000-7000-8000-0000000020f0', 'portal-pt', 'portal-pt.teste.invalid', 'Portal PT', 'national_portal', 'PT', true),
    ('00000000-0000-7000-8000-0000000020f2', 'portal-es', 'portal-es.teste.invalid', 'Portal ES', 'national_portal', 'ES', true),
    ('00000000-0000-7000-8000-00000000200a', 'portal-w', 'portal-w.teste.invalid', 'Canal W', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-00000000200c', 'portal-m', 'portal-m.teste.invalid', 'Tenant M', 'municipal', 'PT', true);

-- Entidade EW (associação, canal W): escrita pelo migrator (policy migrator_all).
INSERT INTO sponsor_entities (id, kind, country_code, name, slug, channel_tenant_id) VALUES
    ('00000000-0000-7000-8000-0000000020ea', 'association', 'PT', 'Associação W', 'portal-assoc-w',
     '00000000-0000-7000-8000-00000000200a');

SET ROLE ptmarket_app;
-- Seed de várias lojas de seguida: ator admin (âmbito por loja da 0035); as leituras (secção 1 em diante) voltam a
-- 'system', sem app.store_id: a leitura pública passa só pelas policies/views do portal.
SELECT set_config('app.actor_type', 'admin', true);

-- ---------------------------------------------------------------------------
-- Dados, criados pela própria app com o contexto de cada tenant.
-- ---------------------------------------------------------------------------
-- Portal P: f3 (sem opt-in), a1 (opt-in), a3 (inativa), a4 (sem opt-in, só recolha).
--   f4 (publicado, f3): variante f5;  a2 (publicado, a1): variantes a2v1 ativa e a2v2 inativa;
--   a5 (NÃO publicado, a1): variante ativa;  a6 (publicado, a4): variante ativa;  a7 (publicado, a3): variante ativa.
--   EW patrocina a1 e a3 (ativo e vigente); a4 e f3 não têm patrocínio.
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f0';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000020f3', '00000000-0000-7000-8000-0000000020f0',
     'Loja P', 'loja-p', 'Loja P Lda', '500000020', 'PT50000000000000000000020', 'p@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000020f4', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020f3', '{"pt":"Produto P"}', 2300);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-0000000020f5', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020f4', 100);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, publish_to_national_portal, is_active,
                    shipping_scope) VALUES
    ('00000000-0000-7000-8000-0000000020a1', '00000000-0000-7000-8000-0000000020f0',
     'Loja A1', 'loja-a1', 'Loja A1 Lda', '500000021', 'PT50000000000000000000021', 'a1@teste.invalid', true, true,
     'national'),
    ('00000000-0000-7000-8000-0000000020a3', '00000000-0000-7000-8000-0000000020f0',
     'Loja A3', 'loja-a3', 'Loja A3 Lda', '500000023', 'PT50000000000000000000023', 'a3@teste.invalid', true, false,
     'national'),
    ('00000000-0000-7000-8000-0000000020a4', '00000000-0000-7000-8000-0000000020f0',
     'Loja A4', 'loja-a4', 'Loja A4 Lda', '500000024', 'PT50000000000000000000024', 'a4@teste.invalid', false, true,
     'pickup_only');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps, is_published) VALUES
    ('00000000-0000-7000-8000-0000000020a2', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a1', '{"pt":"Produto A2"}', 600, true),
    ('00000000-0000-7000-8000-0000000020a5', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a1', '{"pt":"Produto A5"}', 600, false),
    ('00000000-0000-7000-8000-0000000020a6', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a4', '{"pt":"Produto A6"}', 600, true),
    ('00000000-0000-7000-8000-0000000020a7', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a3', '{"pt":"Produto A7"}', 600, true);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents, is_active) VALUES
    ('00000000-0000-7000-8000-00000002a201', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a2', 250, true),
    ('00000000-0000-7000-8000-00000002a202', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a2', 260, false),
    ('00000000-0000-7000-8000-00000002a501', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a5', 270, true),
    ('00000000-0000-7000-8000-00000002a601', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a6', 280, true),
    ('00000000-0000-7000-8000-00000002a701', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a7', 290, true);
-- 0035: o pedido de patrocínio é sempre da loja do contexto (app.store_id = store_id).
SET app.store_id = '00000000-0000-7000-8000-0000000020a1';
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-0000000020b5', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a1', '00000000-0000-7000-8000-0000000020ea');
SET app.store_id = '00000000-0000-7000-8000-0000000020a3';
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-0000000020b6', '00000000-0000-7000-8000-0000000020f0',
     '00000000-0000-7000-8000-0000000020a3', '00000000-0000-7000-8000-0000000020ea');
RESET app.store_id;
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
WHERE tenant_id = '00000000-0000-7000-8000-0000000020f0';

-- Portal ES: e1 ativa, produto e variante.
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f2';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000020e1', '00000000-0000-7000-8000-0000000020f2',
     'Tienda E1', 'tienda-e1', 'Tienda E1 SL', 'B00000027', 'ES9100000000000000000027', 'e1@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000020e2', '00000000-0000-7000-8000-0000000020f2',
     '00000000-0000-7000-8000-0000000020e1', '{"es":"Producto E2"}', 2100);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-00000002e201', '00000000-0000-7000-8000-0000000020f2',
     '00000000-0000-7000-8000-0000000020e2', 300);

SELECT set_config('app.actor_type', 'system', true);

-- ---------------------------------------------------------------------------
-- 1. Portal P com a flag: todas as lojas ativas de P (sem opt-out; publish_to_national_portal e shipping_scope
--    não contam); nenhuma loja ES, inativa ou de tenant inativo.
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f0';
SET app.portal_national = 'on';
SELECT pg_temp.expect_count('SELECT (SELECT app_is_national_portal())::int', 1, 'portal P com flag: modo portal ativo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id IN ('00000000-0000-7000-8000-0000000020f3',
                                                       '00000000-0000-7000-8000-0000000020a1',
                                                       '00000000-0000-7000-8000-0000000020a4')$q$,
    3, 'portal P vê F3, A1 e A4 (com e sem opt-in, pickup_only incluída)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id = '00000000-0000-7000-8000-0000000020a3'$q$,
    0, 'portal não vê loja inativa');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE tenant_id = '00000000-0000-7000-8000-0000000020f2'$q$,
    0, 'portal PT não vê loja de tenant ES');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 3, 'portal_stores tem 3 lojas no total');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM portal_stores$q$,
    'stores', 'listagem de lojas do portal (portal_stores) sem seq scan em stores');

-- ---------------------------------------------------------------------------
-- 2. Canal W (white-label): só lojas patrocinadas por EW; produtos publicados e variantes ativas dessas lojas.
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200a';
SELECT pg_temp.expect_count('SELECT (SELECT app_is_national_portal())::int', 0, 'canal W com flag: modo nacional desligado');
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'canal W: stores sem linhas (não tem lojas)');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 1, 'canal W: portal_stores tem 1 loja');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id = '00000000-0000-7000-8000-0000000020a1'$q$,
    1, 'canal W vê A1 (patrocinada por EW)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id IN ('00000000-0000-7000-8000-0000000020a3',
                                                       '00000000-0000-7000-8000-0000000020a4',
                                                       '00000000-0000-7000-8000-0000000020f3')$q$,
    0, 'canal W não vê A3 (inativa, patrocinada) nem lojas sem patrocínio (A4, F3)');

SELECT pg_temp.expect_count('SELECT count(*) FROM products', 1, 'canal W vê 1 produto (A2)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id = '00000000-0000-7000-8000-0000000020a2'$q$,
    1, 'produtos seguem a loja: A2');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id = '00000000-0000-7000-8000-0000000020a5'$q$,
    0, 'produto não publicado não aparece');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id IN ('00000000-0000-7000-8000-0000000020a6',
                                                  '00000000-0000-7000-8000-0000000020a7',
                                                  '00000000-0000-7000-8000-0000000020f4')$q$,
    0, 'produto publicado de loja sem patrocínio/inativa não aparece');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE tenant_id = '00000000-0000-7000-8000-0000000020f2'$q$,
    0, 'sem produtos de ES');

SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 1, 'canal W vê 1 variante (A2v1)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id = '00000000-0000-7000-8000-00000002a201'$q$,
    1, 'variantes seguem o produto: A2v1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id = '00000000-0000-7000-8000-00000002a202'$q$,
    0, 'variante inativa não aparece');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id IN ('00000000-0000-7000-8000-00000002a501',
                                                          '00000000-0000-7000-8000-00000002a601',
                                                          '00000000-0000-7000-8000-00000002a701')$q$,
    0, 'variante ativa de produto não publicado / loja não visível não aparece');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history$q$,
    0, 'product_price_history sem policy de portal: o canal W não lê histórico de P');

-- Índices: lojas do canal e produtos por loja não precisam de seq scan.
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM products WHERE store_id = '00000000-0000-7000-8000-0000000020a1'$q$,
    'products', 'produtos por loja (store_id) no canal W usam índice');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM products WHERE tenant_id = '00000000-0000-7000-8000-0000000020f0'
                                 AND store_id = '00000000-0000-7000-8000-0000000020a1'$q$,
    'products', 'produtos por (tenant_id, store_id) no canal W usam índice');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM portal_stores$q$,
    'stores', 'listagem de lojas do canal W (portal_stores) sem seq scan em stores');

-- ---------------------------------------------------------------------------
-- 3. No canal W, escritas em linhas de P: erro ou 0 linhas.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (tenant_id, name, slug, legal_name, nif, iban, email)
       VALUES ('00000000-0000-7000-8000-0000000020f0', 'Intrusa', 'intrusa', 'X', '1', 'PT50', 'x@x.pt')$q$,
    '42501', 'canal W: INSERT de loja no tenant P falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO products (tenant_id, store_id, title, vat_rate_bps)
       VALUES ('00000000-0000-7000-8000-0000000020f0', '00000000-0000-7000-8000-0000000020a1', '{}', 2300)$q$,
    '42501', 'canal W: INSERT de produto na loja A1 falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO product_variants (tenant_id, product_id, price_cents)
       VALUES ('00000000-0000-7000-8000-0000000020f0', '00000000-0000-7000-8000-0000000020a2', 1)$q$,
    '42501', 'canal W: INSERT de variante no produto A2 falha');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE stores SET name = 'pirata' WHERE id = '00000000-0000-7000-8000-0000000020a1' RETURNING 1)
       SELECT count(*) FROM u$q$,
    0, 'canal W: UPDATE da loja A1 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE products SET is_published = false WHERE id = '00000000-0000-7000-8000-0000000020a2' RETURNING 1)
       SELECT count(*) FROM u$q$,
    0, 'canal W: UPDATE do produto A2 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE product_variants SET price_cents = 1 WHERE id = '00000000-0000-7000-8000-00000002a201' RETURNING 1)
       SELECT count(*) FROM u$q$,
    0, 'canal W: UPDATE da variante A2v1 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH d AS (DELETE FROM product_variants WHERE id = '00000000-0000-7000-8000-00000002a201' RETURNING 1)
       SELECT count(*) FROM d$q$,
    0, 'canal W: DELETE da variante A2v1 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH d AS (DELETE FROM products WHERE id = '00000000-0000-7000-8000-0000000020a2' RETURNING 1)
       SELECT count(*) FROM d$q$,
    0, 'canal W: DELETE do produto A2 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH d AS (DELETE FROM stores WHERE id = '00000000-0000-7000-8000-0000000020a1' RETURNING 1)
       SELECT count(*) FROM d$q$,
    0, 'canal W: DELETE da loja A1 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (SELECT 1 FROM stores WHERE id = '00000000-0000-7000-8000-0000000020a1' FOR UPDATE) l$q$,
    0, 'canal W: SELECT … FOR UPDATE da loja A1 não tranca nada');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (SELECT 1 FROM products WHERE id = '00000000-0000-7000-8000-0000000020a2' FOR UPDATE) l$q$,
    0, 'canal W: SELECT … FOR UPDATE do produto A2 não tranca nada');
-- As linhas continuam lá e intactas (lidas no canal W).
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores s
       JOIN products p ON p.store_id = s.id AND p.tenant_id = s.tenant_id
       JOIN product_variants v ON v.product_id = p.id AND v.tenant_id = p.tenant_id
       WHERE s.id = '00000000-0000-7000-8000-0000000020a1' AND s.name = 'Loja A1'
         AND p.id = '00000000-0000-7000-8000-0000000020a2' AND v.price_cents = 250$q$,
    1, 'canal W: loja/produto/variante de P intactos');

-- No portal P, a app não muda o tenant de uma loja (sem grant de UPDATE em tenant_id desde a 0029).
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f0';
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET tenant_id = '00000000-0000-7000-8000-00000000200a'
       WHERE id = '00000000-0000-7000-8000-0000000020f3'$q$,
    '42501', 'portal: UPDATE que move a sua loja para o tenant W falha');

-- ---------------------------------------------------------------------------
-- 4. Sem a flag (ou com valor diferente de 'on'), o portal P vê só as suas linhas e portal_stores fica vazia.
-- ---------------------------------------------------------------------------
RESET app.portal_national;
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'portal sem flag: portal_stores vazia');
-- Ler stores diretamente é backoffice: desde a 0035 só a loja do contexto ou o ator admin (aqui: admin, que continua
-- limitado ao tenant P; sem âmbito, 'system' leria 0 — provado em store_scope_rls.sql).
SELECT set_config('app.actor_type', 'admin', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 4, 'portal sem flag: as 4 lojas do tenant P');
SELECT set_config('app.actor_type', 'system', true);
SET app.portal_national = 'true';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'portal com flag = true (≠ on): portal_stores vazia');

-- ---------------------------------------------------------------------------
-- 5. Tenant municipal sem entidade COM a flag continua isolado (anti-IDOR); portal inativo idem; sem contexto: 0.
-- ---------------------------------------------------------------------------
SET app.portal_national = 'on';
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200c';
SELECT pg_temp.expect_count('SELECT (SELECT app_is_national_portal())::int', 0, 'municipal com flag: modo portal desligado');
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'municipal com flag: 0 lojas');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'municipal com flag: 0 produtos');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 0, 'municipal com flag: 0 variantes');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'municipal sem entidade com flag: portal_stores vazia');

-- Portal/tenant inativo (0035: um só national_portal por país): o P é desativado só dentro deste savepoint.
SAVEPOINT portal_ni;
RESET ROLE;
UPDATE tenants SET is_active = false WHERE id = '00000000-0000-7000-8000-0000000020f0';
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f0';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'portal inativo com flag: 0 lojas');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'portal inativo com flag: 0 produtos');
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200a';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'canal W: loja de tenant inativo não aparece');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'canal W: produtos de tenant inativo não aparecem');
ROLLBACK TO SAVEPOINT portal_ni;

RESET app.current_tenant_id;
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'sem contexto com flag: 0 lojas');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'sem contexto com flag: 0 produtos');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 0, 'sem contexto com flag: 0 variantes');
SET app.current_tenant_id = '';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'contexto vazio com flag: 0 lojas');

-- ---------------------------------------------------------------------------
-- 6. Portal ES vê só a loja ES (país do portal).
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f2';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 1, 'portal ES vê 1 loja');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id = '00000000-0000-7000-8000-0000000020e1'$q$,
    1, 'portal ES vê a loja ES');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 1, 'portal ES vê 1 variante (E2)');

RESET app.portal_national;
RESET app.current_tenant_id;
RESET ROLE;

ROLLBACK;
