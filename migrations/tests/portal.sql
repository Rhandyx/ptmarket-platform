-- Teste do portal nacional (0016; lojas de outros tenants pela view portal_stores desde a 0021): leitura só de
-- lojas/produtos/variantes publicadas, mesmo país,
-- tenant do contexto = national_portal ativo; escritas continuam isoladas.
-- Asserções correm sempre com SET ROLE ptmarket_app. Só os tenants (tabela global sem grant de escrita)
-- são criados pelo dono das migrations. Tudo numa transação com ROLLBACK: a BD fica como estava.

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
-- Tenants (globais; só o dono das migrations escreve).
--   P  = portal nacional PT (ativo)      Q  = portal nacional PT INATIVO     PE = portal nacional ES
--   A, B = municipais PT                 M  = municipal PT                   E  = municipal ES
--   X  = municipal PT INATIVO
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code, is_active) VALUES
    ('00000000-0000-7000-8000-0000000020f0', 'portal-pt', 'portal-pt.teste.invalid', 'Portal PT', 'national_portal', 'PT', true),
    ('00000000-0000-7000-8000-0000000020f1', 'portal-q', 'portal-q.teste.invalid', 'Portal inativo', 'national_portal', 'PT', false),
    ('00000000-0000-7000-8000-0000000020f2', 'portal-es', 'portal-es.teste.invalid', 'Portal ES', 'national_portal', 'ES', true),
    ('00000000-0000-7000-8000-00000000200a', 'portal-a', 'portal-a.teste.invalid', 'Tenant A', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-00000000200b', 'portal-b', 'portal-b.teste.invalid', 'Tenant B', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-00000000200c', 'portal-m', 'portal-m.teste.invalid', 'Tenant M', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-00000000200e', 'portal-e', 'portal-e.teste.invalid', 'Tenant E', 'municipal', 'ES', true),
    ('00000000-0000-7000-8000-00000000200d', 'portal-x', 'portal-x.teste.invalid', 'Tenant X', 'municipal', 'PT', false);

SET ROLE ptmarket_app;

-- ---------------------------------------------------------------------------
-- Dados, criados pela própria app com o contexto de cada tenant.
-- ---------------------------------------------------------------------------
-- Portal P: uma loja própria (não publicada), produto e variante.
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

-- Tenant A: a1 publicada e ativa; a3 publicada mas inativa; a4 não publicada.
--   a2 (publicado, a1): variantes a2v1 ativa e a2v2 inativa;  a5 (NÃO publicado, a1): variante ativa;
--   a6 (publicado, a4 não publicada): variante ativa;  a7 (publicado, a3 inativa): variante ativa.
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200a';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, publish_to_national_portal, is_active) VALUES
    ('00000000-0000-7000-8000-0000000020a1', '00000000-0000-7000-8000-00000000200a',
     'Loja A1', 'loja-a1', 'Loja A1 Lda', '500000021', 'PT50000000000000000000021', 'a1@teste.invalid', true, true),
    ('00000000-0000-7000-8000-0000000020a3', '00000000-0000-7000-8000-00000000200a',
     'Loja A3', 'loja-a3', 'Loja A3 Lda', '500000023', 'PT50000000000000000000023', 'a3@teste.invalid', true, false),
    ('00000000-0000-7000-8000-0000000020a4', '00000000-0000-7000-8000-00000000200a',
     'Loja A4', 'loja-a4', 'Loja A4 Lda', '500000024', 'PT50000000000000000000024', 'a4@teste.invalid', false, true);
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps, is_published) VALUES
    ('00000000-0000-7000-8000-0000000020a2', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a1', '{"pt":"Produto A2"}', 600, true),
    ('00000000-0000-7000-8000-0000000020a5', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a1', '{"pt":"Produto A5"}', 600, false),
    ('00000000-0000-7000-8000-0000000020a6', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a4', '{"pt":"Produto A6"}', 600, true),
    ('00000000-0000-7000-8000-0000000020a7', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a3', '{"pt":"Produto A7"}', 600, true);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents, is_active) VALUES
    ('00000000-0000-7000-8000-00000002a201', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a2', 250, true),
    ('00000000-0000-7000-8000-00000002a202', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a2', 260, false),
    ('00000000-0000-7000-8000-00000002a501', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a5', 270, true),
    ('00000000-0000-7000-8000-00000002a601', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a6', 280, true),
    ('00000000-0000-7000-8000-00000002a701', '00000000-0000-7000-8000-00000000200a',
     '00000000-0000-7000-8000-0000000020a7', 290, true);

-- Tenant B: b1 publicada e ativa, produto e variante.
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200b';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, publish_to_national_portal) VALUES
    ('00000000-0000-7000-8000-0000000020b1', '00000000-0000-7000-8000-00000000200b',
     'Loja B1', 'loja-b1', 'Loja B1 Lda', '500000025', 'PT50000000000000000000025', 'b1@teste.invalid', true);
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000020b2', '00000000-0000-7000-8000-00000000200b',
     '00000000-0000-7000-8000-0000000020b1', '{"pt":"Produto B2"}', 2300);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-00000002b201', '00000000-0000-7000-8000-00000000200b',
     '00000000-0000-7000-8000-0000000020b2', 199);

-- Tenant M (municipal): loja própria não publicada.
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200c';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000020c1', '00000000-0000-7000-8000-00000000200c',
     'Loja M1', 'loja-m1', 'Loja M1 Lda', '500000026', 'PT50000000000000000000026', 'm1@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000020c2', '00000000-0000-7000-8000-00000000200c',
     '00000000-0000-7000-8000-0000000020c1', '{"pt":"Produto M2"}', 2300);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-00000002c201', '00000000-0000-7000-8000-00000000200c',
     '00000000-0000-7000-8000-0000000020c2', 150);

-- Tenant E (ES): e1 publicada e ativa.
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200e';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, publish_to_national_portal) VALUES
    ('00000000-0000-7000-8000-0000000020e1', '00000000-0000-7000-8000-00000000200e',
     'Tienda E1', 'tienda-e1', 'Tienda E1 SL', 'B00000027', 'ES9100000000000000000027', 'e1@teste.invalid', true);
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000020e2', '00000000-0000-7000-8000-00000000200e',
     '00000000-0000-7000-8000-0000000020e1', '{"es":"Producto E2"}', 2100);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-00000002e201', '00000000-0000-7000-8000-00000000200e',
     '00000000-0000-7000-8000-0000000020e2', 300);

-- Tenant X (PT, inativo): x1 publicada e ativa, mas o tenant está inativo.
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200d';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, publish_to_national_portal) VALUES
    ('00000000-0000-7000-8000-0000000020d1', '00000000-0000-7000-8000-00000000200d',
     'Loja X1', 'loja-x1', 'Loja X1 Lda', '500000028', 'PT50000000000000000000028', 'x1@teste.invalid', true);
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000020d2', '00000000-0000-7000-8000-00000000200d',
     '00000000-0000-7000-8000-0000000020d1', '{"pt":"Produto X2"}', 2300);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-00000002d201', '00000000-0000-7000-8000-00000000200d',
     '00000000-0000-7000-8000-0000000020d2', 400);

-- ---------------------------------------------------------------------------
-- 1. Portal P com a flag: lojas publicadas e ativas de A e B (mesmo país, tenant ativo) + as suas.
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f0';
SET app.portal_national = 'on';
SELECT pg_temp.expect_count('SELECT (SELECT app_is_national_portal())::int', 1, 'portal P com flag: modo portal ativo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE tenant_id <> '00000000-0000-7000-8000-0000000020f0'$q$,
    2, 'portal vê 2 lojas de outros tenants (portal_stores)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id IN ('00000000-0000-7000-8000-0000000020a1',
                                                       '00000000-0000-7000-8000-0000000020b1')$q$,
    2, 'portal vê a loja publicada de A e a de B (portal_stores)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id IN ('00000000-0000-7000-8000-0000000020a4',
                                                       '00000000-0000-7000-8000-0000000020c1')$q$,
    0, 'portal não vê nenhuma loja não publicada de outro tenant (A4, M1)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id = '00000000-0000-7000-8000-0000000020a3'$q$,
    0, 'portal não vê loja publicada mas inativa');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE tenant_id = '00000000-0000-7000-8000-00000000200e'$q$,
    0, 'portal PT não vê loja de tenant ES');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE tenant_id = '00000000-0000-7000-8000-00000000200d'$q$,
    0, 'portal não vê loja de tenant inativo');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 2,
    'portal_stores tem 2 lojas no total (A1 + B1; a própria não está publicada)');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE tenant_id <> '00000000-0000-7000-8000-0000000020f0'$q$,
    2, 'portal vê 2 produtos de outros tenants (A2 e B2)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id IN ('00000000-0000-7000-8000-0000000020a2',
                                                  '00000000-0000-7000-8000-0000000020b2')$q$,
    2, 'produtos seguem a loja: A2 e B2');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id = '00000000-0000-7000-8000-0000000020a5'$q$,
    0, 'produto não publicado não aparece');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id IN ('00000000-0000-7000-8000-0000000020a6',
                                                  '00000000-0000-7000-8000-0000000020a7')$q$,
    0, 'produto publicado de loja não publicada/inativa não aparece');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE tenant_id IN ('00000000-0000-7000-8000-00000000200e',
                                                         '00000000-0000-7000-8000-00000000200d',
                                                         '00000000-0000-7000-8000-00000000200c')$q$,
    0, 'sem produtos de ES, de tenant inativo ou de loja municipal não publicada');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE tenant_id <> '00000000-0000-7000-8000-0000000020f0'$q$,
    2, 'portal vê 2 variantes de outros tenants (A2v1 e B2v1)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id IN ('00000000-0000-7000-8000-00000002a201',
                                                          '00000000-0000-7000-8000-00000002b201')$q$,
    2, 'variantes seguem o produto: A2v1 e B2v1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id = '00000000-0000-7000-8000-00000002a202'$q$,
    0, 'variante inativa não aparece');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id IN ('00000000-0000-7000-8000-00000002a501',
                                                          '00000000-0000-7000-8000-00000002a601',
                                                          '00000000-0000-7000-8000-00000002a701')$q$,
    0, 'variante ativa de produto não publicado / loja não visível não aparece');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history WHERE tenant_id <> '00000000-0000-7000-8000-0000000020f0'$q$,
    0, 'product_price_history sem policy de portal: só o próprio histórico');

-- Índices: lojas do portal e produtos por loja não precisam de seq scan.
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM products WHERE store_id = '00000000-0000-7000-8000-0000000020b1'$q$,
    'products', 'produtos por loja (store_id) em modo portal usam índice');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM products WHERE tenant_id = '00000000-0000-7000-8000-00000000200b'
                                 AND store_id = '00000000-0000-7000-8000-0000000020b1'$q$,
    'products', 'produtos por (tenant_id, store_id) em modo portal usam índice');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM portal_stores$q$,
    'stores', 'listagem de lojas do portal (portal_stores) sem seq scan em stores');

-- ---------------------------------------------------------------------------
-- 2. Em modo portal, escritas em linhas de outro tenant: erro ou 0 linhas.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (tenant_id, name, slug, legal_name, nif, iban, email, publish_to_national_portal)
       VALUES ('00000000-0000-7000-8000-00000000200a', 'Intrusa', 'intrusa', 'X', '1', 'PT50', 'x@x.pt', true)$q$,
    '42501', 'portal: INSERT de loja no tenant A falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO products (tenant_id, store_id, title, vat_rate_bps)
       VALUES ('00000000-0000-7000-8000-00000000200a', '00000000-0000-7000-8000-0000000020a1', '{}', 2300)$q$,
    '42501', 'portal: INSERT de produto na loja A1 falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO product_variants (tenant_id, product_id, price_cents)
       VALUES ('00000000-0000-7000-8000-00000000200a', '00000000-0000-7000-8000-0000000020a2', 1)$q$,
    '42501', 'portal: INSERT de variante no produto A2 falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET tenant_id = '00000000-0000-7000-8000-00000000200a'
       WHERE id = '00000000-0000-7000-8000-0000000020f3'$q$,
    '42501', 'portal: UPDATE que move a sua loja para o tenant A falha');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE stores SET name = 'pirata' WHERE id = '00000000-0000-7000-8000-0000000020a1' RETURNING 1)
       SELECT count(*) FROM u$q$,
    0, 'portal: UPDATE da loja A1 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE products SET is_published = false WHERE id = '00000000-0000-7000-8000-0000000020a2' RETURNING 1)
       SELECT count(*) FROM u$q$,
    0, 'portal: UPDATE do produto A2 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE product_variants SET price_cents = 1 WHERE id = '00000000-0000-7000-8000-00000002a201' RETURNING 1)
       SELECT count(*) FROM u$q$,
    0, 'portal: UPDATE da variante A2v1 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH d AS (DELETE FROM product_variants WHERE id = '00000000-0000-7000-8000-00000002b201' RETURNING 1)
       SELECT count(*) FROM d$q$,
    0, 'portal: DELETE da variante B2v1 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH d AS (DELETE FROM products WHERE id = '00000000-0000-7000-8000-0000000020b2' RETURNING 1)
       SELECT count(*) FROM d$q$,
    0, 'portal: DELETE do produto B2 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$WITH d AS (DELETE FROM stores WHERE id = '00000000-0000-7000-8000-0000000020b1' RETURNING 1)
       SELECT count(*) FROM d$q$,
    0, 'portal: DELETE da loja B1 afeta 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (SELECT 1 FROM stores WHERE id = '00000000-0000-7000-8000-0000000020a1' FOR UPDATE) l$q$,
    0, 'portal: SELECT … FOR UPDATE da loja A1 não tranca nada');
-- As linhas continuam lá e intactas (lidas em modo portal).
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores s
       JOIN products p ON p.store_id = s.id AND p.tenant_id = s.tenant_id
       JOIN product_variants v ON v.product_id = p.id AND v.tenant_id = p.tenant_id
       WHERE (s.id = '00000000-0000-7000-8000-0000000020a1' AND s.name = 'Loja A1'
              AND p.id = '00000000-0000-7000-8000-0000000020a2' AND v.price_cents = 250)
          OR (s.id = '00000000-0000-7000-8000-0000000020b1' AND v.id = '00000000-0000-7000-8000-00000002b201')$q$,
    2, 'portal: lojas/produtos/variantes de A e B intactos');

-- ---------------------------------------------------------------------------
-- 3. Sem a flag (ou com valor diferente de 'on'), o portal vê só as suas linhas.
-- ---------------------------------------------------------------------------
RESET app.portal_national;
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 1, 'portal sem flag: 1 loja (a sua)');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 1, 'portal sem flag: 1 produto (o seu)');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 1, 'portal sem flag: 1 variante (a sua)');
SET app.portal_national = 'true';
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE tenant_id <> '00000000-0000-7000-8000-0000000020f0'$q$,
    0, 'portal com flag = true (≠ on): portal_stores vazia');

-- ---------------------------------------------------------------------------
-- 4. Tenant municipal COM a flag continua isolado (anti-IDOR); portal inativo idem; sem contexto: 0.
-- ---------------------------------------------------------------------------
SET app.portal_national = 'on';
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200c';
SELECT pg_temp.expect_count('SELECT (SELECT app_is_national_portal())::int', 0, 'municipal com flag: modo portal desligado');
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 1, 'municipal com flag: 1 loja (a sua)');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 1, 'municipal com flag: 1 produto (o seu)');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 1, 'municipal com flag: 1 variante (a sua)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE tenant_id <> '00000000-0000-7000-8000-00000000200c'$q$,
    0, 'municipal com flag não vê lojas de outros tenants (portal_stores)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE tenant_id <> '00000000-0000-7000-8000-00000000200c'$q$,
    0, 'municipal com flag não vê variantes de outros tenants');

SET app.current_tenant_id = '00000000-0000-7000-8000-00000000200a';
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE tenant_id <> '00000000-0000-7000-8000-00000000200a'$q$,
    0, 'municipal A (com lojas publicadas) e flag não vê lojas de outros tenants (portal_stores)');

SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f1';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'portal inativo com flag: 0 lojas');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'portal inativo com flag: 0 produtos');

RESET app.current_tenant_id;
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'sem contexto com flag: 0 lojas');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'sem contexto com flag: 0 produtos');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 0, 'sem contexto com flag: 0 variantes');
SET app.current_tenant_id = '';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'contexto vazio com flag: 0 lojas');

-- ---------------------------------------------------------------------------
-- 5. Portal ES vê só a loja ES publicada (país do portal).
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000020f2';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 1, 'portal ES vê 1 loja');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id = '00000000-0000-7000-8000-0000000020e1'$q$,
    1, 'portal ES vê a loja ES publicada');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 1, 'portal ES vê 1 variante (E2)');

RESET app.portal_national;
RESET app.current_tenant_id;
RESET ROLE;

ROLLBACK;
