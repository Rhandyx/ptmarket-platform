-- Teste da 0039 (cartão 04/01; spec 14 §1.1): catálogo público só pelas views portal_products,
-- portal_product_variants e portal_categories (donas ptmarket_portal); a app deixa de ler products/product_variants/
-- product_price_history de lojas alheias; índices das listagens por cursor; categories.slug único.
-- Tenants, entidades e categorias pelo migrator; lojas, produtos e patrocínios pela app (SET ROLE ptmarket_app).
-- Asserções de acesso com SET ROLE ptmarket_app. Tudo com ROLLBACK.
--   NP = nacional PT · CA, CB = municipais PT (canais das associações EA e EB)
--   Lojas no NP: S1 (EA) · S2 (EB) · S3 (sem patrocínio) · S4 (EA, active com valid_to passado: expirado sem job) ·
--                S5 (inativa, EA) · S6 (EA; revogado a meio do teste)
--   Produtos: P1 (S1, CAT1; V1a ativa stock 5, V1b inativa) · P1U (S1, não publicado; V1U ativa) ·
--             P1N (S1, CAT2, publicado só com variante inativa V1N) · P2 (S2, CAT1; V2 ativa stock 0) ·
--             P2U (S2, não publicado; V2U ativa) · P3 (S3, CAT2; V3) · P4 (S4; V4) · P5 (S5; V5) · P6 (S6; V6)
--   Categorias: CAT1 · CAT2 (filha de CAT1) · CAT3 (sem produtos)

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

-- Plano (planeador normal, com estatísticas) sem Seq Scan na tabela e com o índice indicado na leitura principal da
-- view (alias p de products em portal_products, v de product_variants em portal_product_variants).
CREATE FUNCTION pg_temp.expect_index(p_sql text, p_table text, p_index text, p_label text)
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
    IF v_plan NOT LIKE '%using ' || p_index || ' on ' || p_table || E' p\n%'
       AND v_plan NOT LIKE '%using ' || p_index || ' on ' || p_table || E' v\n%' THEN
        RAISE EXCEPTION 'FALHOU: % (sem o índice %)%', p_label, p_index, E'\n' || v_plan;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Página por cursor: EXPLAIN ANALYZE com Limit no topo, sem Sort, e o índice indicado em products p a ler no máximo
-- p_max linhas (não todos os publicados do tenant).
CREATE FUNCTION pg_temp.expect_page(p_sql text, p_index text, p_max numeric, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_line  text;
    v_plan  text := '';
    v_first text;
    v_rows  numeric;
BEGIN
    FOR v_line IN EXECUTE 'EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF, BUFFERS OFF) ' || p_sql LOOP
        v_first := COALESCE(v_first, v_line);
        v_plan := v_plan || v_line || E'\n';
        IF v_line LIKE '%using ' || p_index || ' on products p (actual %' THEN
            v_rows := substring(v_line FROM 'rows=([0-9.]+)')::numeric;
        END IF;
    END LOOP;
    IF v_first NOT LIKE 'Limit%' OR v_plan LIKE '%Sort%' OR v_rows IS NULL OR v_rows > p_max THEN
        RAISE EXCEPTION 'FALHOU: % (Limit no topo, sem Sort, % em products p com <= % linhas; lidas %)%',
            p_label, p_index, p_max, v_rows, E'\n' || v_plan;
    END IF;
    RAISE NOTICE 'OK: % (% linhas lidas do índice)', p_label, v_rows;
END
$$;

-- Sonda não leakproof (plpgsql) e barata (o planeador é tentado a avaliá-la primeiro): falha se alguma vez receber
-- um id proibido. Prova que as policies RLS da dona filtram ANTES de um predicado arbitrário de quem consulta.
CREATE FUNCTION pg_temp.probe(p_id uuid, p_forbidden uuid[])
RETURNS boolean LANGUAGE plpgsql COST 0.0001 AS $$
BEGIN
    IF p_id = ANY (p_forbidden) THEN
        RAISE EXCEPTION 'FALHOU: predicado arbitrário viu a linha proibida %', p_id;
    END IF;
    RETURN true;
END
$$;

CREATE FUNCTION pg_temp.ctx(p_actor text, p_store text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', p_actor, true);
    PERFORM set_config('app.store_id', p_store, true);
END
$$;

SELECT set_config('app.actor_type', 'system', true);
SELECT set_config('app.actor_label', 'test', true);

-- ---------------------------------------------------------------------------
-- 0. Preparação (migrator): tenants, entidades, categorias.
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code, is_active) VALUES
    ('00000000-0000-7000-8000-0000000039a0', 'pc-npt', 'pc-npt.teste.invalid', 'Nacional PT 39', 'national_portal', 'PT', true),
    ('00000000-0000-7000-8000-0000000039c1', 'pc-ca', 'pc-ca.teste.invalid', 'Canal A 39', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-0000000039c2', 'pc-cb', 'pc-cb.teste.invalid', 'Canal B 39', 'municipal', 'PT', true);

INSERT INTO sponsor_entities (id, kind, country_code, name, slug, channel_tenant_id) VALUES
    ('00000000-0000-7000-8000-0000000039e1', 'association', 'PT', 'Associação A 39', 'pc-assoc-a',
     '00000000-0000-7000-8000-0000000039c1'),
    ('00000000-0000-7000-8000-0000000039e2', 'association', 'PT', 'Associação B 39', 'pc-assoc-b',
     '00000000-0000-7000-8000-0000000039c2');

INSERT INTO categories (id, parent_id, taxonomy_code, slug, name, default_vat_rate_bps, is_featured, sort_order) VALUES
    ('00000000-0000-7000-8000-00000039ca01', NULL, 'pc-t1', 'pc-cat-1', '{"pt":"Categoria 1"}', 600, true, 1),
    ('00000000-0000-7000-8000-00000039ca02', '00000000-0000-7000-8000-00000039ca01', 'pc-t2', 'pc-cat-2',
     '{"pt":"Categoria 2"}', 2300, false, 2),
    ('00000000-0000-7000-8000-00000039ca03', NULL, NULL, 'pc-cat-3', '{"pt":"Categoria 3"}', 2300, false, 3);

-- categories.slug único (0039).
SELECT pg_temp.expect_error(
    $q$INSERT INTO categories (slug, name) VALUES ('pc-cat-1', '{"pt":"Repetida"}')$q$,
    '23505', 'categories: slug repetido → 23505 (categories_slug_key)');

-- ---------------------------------------------------------------------------
-- 1. Lojas, produtos e patrocínios (app; seed com o ator admin, âmbito por loja da 0035).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.ctx('admin', '');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000039a0', true);

INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, is_active)
SELECT format('00000000-0000-7000-8000-0000000039b%s', n)::uuid, '00000000-0000-7000-8000-0000000039a0',
       format('Loja S%s', n), format('pc-s%s', n), format('S%s Lda', n), format('5000039%s', lpad(n::text, 2, '0')),
       format('PT500000000000000000039%s', lpad(n::text, 2, '0')), format('s%s@teste.invalid', n), n <> 5
FROM generate_series(1, 6) AS n;

INSERT INTO products (id, tenant_id, store_id, category_id, title, vat_rate_bps, is_published) VALUES
    ('00000000-0000-7000-8000-00000039f101', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b1', '00000000-0000-7000-8000-00000039ca01', '{"pt":"P1"}', 600, true),
    ('00000000-0000-7000-8000-00000039f102', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b1', '00000000-0000-7000-8000-00000039ca01', '{"pt":"P1U"}', 600, false),
    ('00000000-0000-7000-8000-00000039f103', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b1', '00000000-0000-7000-8000-00000039ca02', '{"pt":"P1N"}', 600, true),
    ('00000000-0000-7000-8000-00000039f201', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b2', '00000000-0000-7000-8000-00000039ca01', '{"pt":"P2"}', 600, true),
    ('00000000-0000-7000-8000-00000039f202', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b2', '00000000-0000-7000-8000-00000039ca01', '{"pt":"P2U"}', 600, false),
    ('00000000-0000-7000-8000-00000039f301', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b3', '00000000-0000-7000-8000-00000039ca02', '{"pt":"P3"}', 2300, true),
    ('00000000-0000-7000-8000-00000039f401', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b4', NULL, '{"pt":"P4"}', 2300, true),
    ('00000000-0000-7000-8000-00000039f501', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b5', NULL, '{"pt":"P5"}', 2300, true),
    ('00000000-0000-7000-8000-00000039f601', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-0000000039b6', NULL, '{"pt":"P6"}', 2300, true);

INSERT INTO product_variants (id, tenant_id, product_id, sku, price_cents, compare_at_price_cents, stock_qty,
                              is_active) VALUES
    ('00000000-0000-7000-8000-00000039d1a1', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f101', 'SKU-V1A', 199, 299, 5, true),
    ('00000000-0000-7000-8000-00000039d1b1', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f101', 'SKU-V1B', 209, NULL, 3, false),
    ('00000000-0000-7000-8000-00000039d1c1', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f102', NULL, 219, NULL, 1, true),
    ('00000000-0000-7000-8000-00000039d1d1', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f103', NULL, 229, NULL, 1, false),
    ('00000000-0000-7000-8000-00000039d201', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f201', NULL, 300, NULL, 0, true),
    ('00000000-0000-7000-8000-00000039d202', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f202', NULL, 310, NULL, 4, true),
    ('00000000-0000-7000-8000-00000039d301', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f301', NULL, 400, NULL, 2, true),
    ('00000000-0000-7000-8000-00000039d401', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f401', NULL, 500, NULL, 2, true),
    ('00000000-0000-7000-8000-00000039d501', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f501', NULL, 600, NULL, 2, true),
    ('00000000-0000-7000-8000-00000039d601', '00000000-0000-7000-8000-0000000039a0',
     '00000000-0000-7000-8000-00000039f601', NULL, 700, NULL, 2, true);

-- Patrocínios: pedidos pela loja do contexto (0035), uma linha de cada vez; decididos pelo ator admin.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('00000000-0000-7000-8000-000000039101', '00000000-0000-7000-8000-0000000039b1',
         '00000000-0000-7000-8000-0000000039e1'),
        ('00000000-0000-7000-8000-000000039102', '00000000-0000-7000-8000-0000000039b2',
         '00000000-0000-7000-8000-0000000039e2'),
        ('00000000-0000-7000-8000-000000039104', '00000000-0000-7000-8000-0000000039b4',
         '00000000-0000-7000-8000-0000000039e1'),
        ('00000000-0000-7000-8000-000000039105', '00000000-0000-7000-8000-0000000039b5',
         '00000000-0000-7000-8000-0000000039e1'),
        ('00000000-0000-7000-8000-000000039106', '00000000-0000-7000-8000-0000000039b6',
         '00000000-0000-7000-8000-0000000039e1')
    ) AS v(id, store_id, sponsor_entity_id) LOOP
        PERFORM set_config('app.store_id', r.store_id, true);
        INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id)
        VALUES (r.id::uuid, '00000000-0000-7000-8000-0000000039a0', r.store_id::uuid, r.sponsor_entity_id::uuid);
    END LOOP;
    PERFORM set_config('app.store_id', '', true);
END
$$;
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
WHERE id IN ('00000000-0000-7000-8000-000000039101', '00000000-0000-7000-8000-000000039102',
             '00000000-0000-7000-8000-000000039105', '00000000-0000-7000-8000-000000039106');
-- S4: 'active' fora da vigência (o job de expiração ainda não passou): sai pelo intervalo, sem job.
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '10 days',
                              valid_to = now() - interval '1 day'
WHERE id = '00000000-0000-7000-8000-000000039104';

-- ---------------------------------------------------------------------------
-- 2. Canal nacional PT: todos os publicados (com variante ativa) das lojas ativas.
-- ---------------------------------------------------------------------------
SELECT pg_temp.ctx('customer', '');
SET app.portal_national = 'on';
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(title->>'pt', ',' ORDER BY title->>'pt') FROM portal_products$q$,
    'P1,P2,P3,P4,P6',
    'nacional: publicados de todas as lojas ativas (sem P1U/P2U não publicados, P1N sem variante ativa, P5 de loja inativa)');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(right(id::text, 4) || ':' || price_cents || ':' || in_stock, ',' ORDER BY id)
       FROM portal_product_variants$q$,
    'd1a1:199:true,d201:300:false,d301:400:true,d401:500:true,d601:700:true',
    'nacional: só variantes ativas de produtos visíveis; in_stock = stock_qty > 0');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(slug || ':' || has_direct_products, ',' ORDER BY slug) FROM portal_categories
       WHERE slug LIKE 'pc-cat-%'$q$,
    'pc-cat-1:true,pc-cat-2:true,pc-cat-3:false', 'nacional: has_direct_products por categoria');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_categories
       WHERE id = '00000000-0000-7000-8000-00000039ca02' AND parent_id = '00000000-0000-7000-8000-00000039ca01'
         AND name->>'pt' = 'Categoria 2' AND NOT is_featured AND sort_order = 2$q$,
    1, 'portal_categories: parent_id, name, is_featured, sort_order');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_products
       WHERE id = '00000000-0000-7000-8000-00000039f101' AND store_id = '00000000-0000-7000-8000-0000000039b1'
         AND category_id = '00000000-0000-7000-8000-00000039ca01' AND vat_rate_bps = 600 AND NOT is_perishable
         AND description = '{}' AND attributes = '{}' AND images = '[]'$q$,
    1, 'portal_products: colunas de exibição de P1');

RESET app.portal_national;
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_products', 0, 'nacional sem a flag: 0 produtos');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_product_variants', 0, 'nacional sem a flag: 0 variantes');
SET app.portal_national = 'on';

-- ---------------------------------------------------------------------------
-- 3. White-label: só lojas patrocinadas por entidades do canal; revogar/expirar sai sem job.
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000039c1', true);
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(title->>'pt', ',' ORDER BY title->>'pt') FROM portal_products$q$,
    'P1,P6', 'canal A: só S1 e S6 (S4 expirado sem job, S5 inativa, S2 de outro canal, S3 sem patrocínio)');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(right(id::text, 4), ',' ORDER BY id) FROM portal_product_variants$q$,
    'd1a1,d601', 'canal A: variantes ativas de P1 e P6');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(slug || ':' || has_direct_products, ',' ORDER BY slug) FROM portal_categories
       WHERE slug LIKE 'pc-cat-%'$q$,
    'pc-cat-1:true,pc-cat-2:false,pc-cat-3:false', 'canal A: has_direct_products segue o canal');

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000039c2', true);
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(title->>'pt', ',' ORDER BY title->>'pt') FROM portal_products$q$,
    'P2', 'canal B: só P2 (S2 patrocinada por EB; P2U não publicado)');

-- Revogação de S6 (ator admin): sai do canal A na hora.
SELECT pg_temp.ctx('admin', '');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000039a0', true);
UPDATE store_sponsorships SET status = 'revoked' WHERE id = '00000000-0000-7000-8000-000000039106';
SELECT pg_temp.ctx('customer', '');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000039c1', true);
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(title->>'pt', ',' ORDER BY title->>'pt') FROM portal_products$q$,
    'P1', 'canal A: patrocínio revogado de S6 sai sem job');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_product_variants WHERE id = '00000000-0000-7000-8000-00000039d601'$q$,
    0, 'canal A: variante de S6 sai com o produto');

-- Sem contexto (ou vazio): 0 linhas; categorias continuam, sem produtos.
SELECT set_config('app.current_tenant_id', '', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_products', 0, 'sem contexto: 0 produtos');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_product_variants', 0, 'sem contexto: 0 variantes');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_categories WHERE has_direct_products', 0,
    'sem contexto: nenhuma categoria com produtos');
RESET app.current_tenant_id;
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_products', 0, 'contexto ausente: 0 produtos');

-- ---------------------------------------------------------------------------
-- 4. Leitura direta fechada; colunas privadas fora das views; views só de leitura.
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000039a0', true);
SELECT pg_temp.ctx('customer', '');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'nacional, sem app.store_id: products direto → 0');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 0,
    'nacional, sem app.store_id: product_variants direto → 0');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_price_history', 0,
    'nacional, sem app.store_id: product_price_history direto → 0');
SELECT pg_temp.ctx('system', '');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'ator system sem app.store_id: products → 0');

DO $$
DECLARE
    c text;
BEGIN
    FOREACH c IN ARRAY ARRAY['stock_qty', 'sku', 'compare_at_price_cents', 'is_active', 'created_at'] LOOP
        PERFORM pg_temp.expect_error(format('SELECT %I FROM portal_product_variants', c), '42703',
            format('SELECT %s FROM portal_product_variants → 42703', c));
    END LOOP;
    FOREACH c IN ARRAY ARRAY['catalog_item_id', 'ai_enriched', 'is_published'] LOOP
        PERFORM pg_temp.expect_error(format('SELECT %I FROM portal_products', c), '42703',
            format('SELECT %s FROM portal_products → 42703', c));
    END LOOP;
    FOREACH c IN ARRAY ARRAY['taxonomy_code', 'default_vat_rate_bps'] LOOP
        PERFORM pg_temp.expect_error(format('SELECT %I FROM portal_categories', c), '42703',
            format('SELECT %s FROM portal_categories → 42703', c));
    END LOOP;
END
$$;

SELECT pg_temp.expect_error(
    $q$INSERT INTO portal_products (tenant_id, store_id, title, vat_rate_bps)
       VALUES ('00000000-0000-7000-8000-0000000039a0', '00000000-0000-7000-8000-0000000039b1', '{}', 2300)$q$,
    '42501', 'portal_products: INSERT → 42501');
SELECT pg_temp.expect_error(
    $q$UPDATE portal_product_variants SET price_cents = 1 WHERE id = '00000000-0000-7000-8000-00000039d1a1'$q$,
    '42501', 'portal_product_variants: UPDATE → 42501');
SELECT pg_temp.expect_error(
    $q$DELETE FROM portal_categories WHERE slug = 'pc-cat-1'$q$,
    '42501', 'portal_categories: DELETE → 42501');

-- Loja S1 (lojista): lê os seus 3 produtos; os não publicados de S2 por nenhuma via.
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000039b1');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 3, 'S1: lê os seus 3 produtos (publicados ou não)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE store_id = '00000000-0000-7000-8000-0000000039b2'$q$,
    0, 'S1: products de S2 → 0 (publicados ou não)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id IN ('00000000-0000-7000-8000-00000039d201',
                                                          '00000000-0000-7000-8000-00000039d202')$q$,
    0, 'S1: product_variants de S2 → 0');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history WHERE variant_id = '00000000-0000-7000-8000-00000039d202'$q$,
    0, 'S1: histórico de S2 → 0');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_products WHERE id = '00000000-0000-7000-8000-00000039f202'$q$,
    0, 'S1 (modo portal): P2U não publicado de S2 fora de portal_products');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_product_variants WHERE id = '00000000-0000-7000-8000-00000039d202'$q$,
    0, 'S1 (modo portal): variante de P2U fora de portal_product_variants');
RESET app.portal_national;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_products WHERE store_id = '00000000-0000-7000-8000-0000000039b2'$q$,
    0, 'S1 (sem modo portal): 0 produtos de S2 pelas views');
SET app.portal_national = 'on';

-- Admin (backoffice da plataforma) continua a ler tudo do tenant.
SELECT pg_temp.ctx('admin', '');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 9, 'admin: lê os 9 produtos');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 10, 'admin: lê as 10 variantes');
SELECT pg_temp.ctx('customer', '');

-- Predicado arbitrário (função não leakproof) em modo portal: nunca vê não publicados nem lojas invisíveis.
--   Nacional: proibidos P1U, P2U (não publicados) e P5 (loja inativa); variantes V1b (inativa), V1U, V2U, V5.
--   Canal A: + P2 (canal B), P3 (sem patrocínio), P4 (expirado), P6 (revogado); variantes V2, V3, V4, V6.
SELECT pg_temp.ctx('customer', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_products
       WHERE pg_temp.probe(id, ARRAY['00000000-0000-7000-8000-00000039f102', '00000000-0000-7000-8000-00000039f202',
                                     '00000000-0000-7000-8000-00000039f501']::uuid[])$q$,
    5, 'nacional: predicado arbitrário em portal_products não vê P1U, P2U nem P5');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_products
       WHERE title->>'pt' LIKE 'P%'
         AND pg_temp.probe(id, ARRAY['00000000-0000-7000-8000-00000039f102', '00000000-0000-7000-8000-00000039f202',
                                     '00000000-0000-7000-8000-00000039f501']::uuid[])
         AND id = ANY (ARRAY['00000000-0000-7000-8000-00000039f102', '00000000-0000-7000-8000-00000039f202',
                             '00000000-0000-7000-8000-00000039f501']::uuid[])$q$,
    0, 'nacional: predicado dirigido aos proibidos devolve 0 sem os ver');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_product_variants
       WHERE pg_temp.probe(id, ARRAY['00000000-0000-7000-8000-00000039d1b1', '00000000-0000-7000-8000-00000039d1c1',
                                     '00000000-0000-7000-8000-00000039d202', '00000000-0000-7000-8000-00000039d501',
                                     '00000000-0000-7000-8000-00000039d1d1']::uuid[])$q$,
    5, 'nacional: predicado arbitrário em portal_product_variants não vê inativas, não publicadas nem de loja inativa');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000039c1', true);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_products
       WHERE pg_temp.probe(id, ARRAY['00000000-0000-7000-8000-00000039f102', '00000000-0000-7000-8000-00000039f202',
                                     '00000000-0000-7000-8000-00000039f501', '00000000-0000-7000-8000-00000039f201',
                                     '00000000-0000-7000-8000-00000039f301', '00000000-0000-7000-8000-00000039f401',
                                     '00000000-0000-7000-8000-00000039f601']::uuid[])$q$,
    1, 'canal A: predicado arbitrário só vê P1 (nem lojas de outro canal, sem patrocínio, expirado ou revogado)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_product_variants
       WHERE pg_temp.probe(id, ARRAY['00000000-0000-7000-8000-00000039d201', '00000000-0000-7000-8000-00000039d301',
                                     '00000000-0000-7000-8000-00000039d401', '00000000-0000-7000-8000-00000039d601',
                                     '00000000-0000-7000-8000-00000039d202', '00000000-0000-7000-8000-00000039d1c1']::uuid[])$q$,
    1, 'canal A: predicado arbitrário em variantes só vê V1a');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000039a0', true);

-- ---------------------------------------------------------------------------
-- 5. Índices das listagens por cursor (id DESC, id < $cursor): sem Seq Scan em products, com os índices novos.
-- ---------------------------------------------------------------------------
SELECT pg_temp.ctx('admin', '');
INSERT INTO products (tenant_id, store_id, category_id, title, vat_rate_bps, is_published)
SELECT '00000000-0000-7000-8000-0000000039a0',
       format('00000000-0000-7000-8000-0000000039b%s', 1 + n % 3)::uuid,
       CASE WHEN n % 2 = 0 THEN '00000000-0000-7000-8000-00000039ca01'::uuid
            ELSE '00000000-0000-7000-8000-00000039ca02'::uuid END,
       jsonb_build_object('pt', 'Massa ' || n), 600, n % 10 <> 0
FROM generate_series(1, 3000) AS n;
INSERT INTO product_variants (tenant_id, product_id, price_cents, stock_qty, is_active)
SELECT p.tenant_id, p.id, 100 + k, 1, k = 1
FROM products p, generate_series(1, 2) AS k
WHERE p.title->>'pt' LIKE 'Massa %';
SELECT pg_temp.ctx('customer', '');
RESET ROLE;
ANALYZE products;
ANALYZE product_variants;
ANALYZE stores;
ANALYZE store_sponsorships;
ANALYZE tenants;
ANALYZE categories;
SET ROLE ptmarket_app;

SELECT pg_temp.expect_index(
    $q$SELECT id, title FROM portal_products
       WHERE tenant_id = '00000000-0000-7000-8000-0000000039a0' AND id < 'ffffffff-ffff-7fff-bfff-ffffffffffff'
       ORDER BY id DESC LIMIT 24$q$,
    'products', 'products_tenant_published_id_idx', 'listagem geral por cursor usa products_tenant_published_id_idx');
SELECT pg_temp.expect_index(
    $q$SELECT id, title FROM portal_products
       WHERE tenant_id = '00000000-0000-7000-8000-0000000039a0'
         AND category_id = '00000000-0000-7000-8000-00000039ca01' AND id < 'ffffffff-ffff-7fff-bfff-ffffffffffff'
       ORDER BY id DESC LIMIT 24$q$,
    'products', 'products_tenant_category_published_idx',
    'listagem por categoria usa products_tenant_category_published_idx');
SELECT pg_temp.expect_index(
    $q$SELECT id, title FROM portal_products
       WHERE tenant_id = '00000000-0000-7000-8000-0000000039a0'
         AND store_id = '00000000-0000-7000-8000-0000000039b2' AND id < 'ffffffff-ffff-7fff-bfff-ffffffffffff'
       ORDER BY id DESC LIMIT 24$q$,
    'products', 'products_tenant_store_published_idx', 'listagem por loja usa products_tenant_store_published_idx');
SELECT pg_temp.expect_index(
    $q$SELECT id, price_cents FROM portal_product_variants
       WHERE tenant_id = '00000000-0000-7000-8000-0000000039a0'
         AND product_id = '00000000-0000-7000-8000-00000039f101'
       ORDER BY price_cents$q$,
    'product_variants', 'product_variants_tenant_product_active_price_idx',
    'variantes de um produto por preço usam product_variants_tenant_product_active_price_idx');

-- Página de 24 (security_barrier = false): Limit por cima do índice, ~24 linhas lidas (não os ~2.700 publicados).
SELECT pg_temp.expect_page(
    $q$SELECT id, title FROM portal_products
       WHERE tenant_id = '00000000-0000-7000-8000-0000000039a0' AND id < 'ffffffff-ffff-7fff-bfff-ffffffffffff'
       ORDER BY id DESC LIMIT 24$q$,
    'products_tenant_published_id_idx', 30, 'página geral de 24 lê ~24 linhas');
SELECT pg_temp.expect_page(
    $q$SELECT id, title FROM portal_products
       WHERE tenant_id = '00000000-0000-7000-8000-0000000039a0'
         AND category_id = '00000000-0000-7000-8000-00000039ca01' AND id < 'ffffffff-ffff-7fff-bfff-ffffffffffff'
       ORDER BY id DESC LIMIT 24$q$,
    'products_tenant_category_published_idx', 30, 'página por categoria de 24 lê ~24 linhas');
SELECT pg_temp.expect_page(
    $q$SELECT id, title FROM portal_products
       WHERE tenant_id = '00000000-0000-7000-8000-0000000039a0'
         AND store_id = '00000000-0000-7000-8000-0000000039b2' AND id < 'ffffffff-ffff-7fff-bfff-ffffffffffff'
       ORDER BY id DESC LIMIT 24$q$,
    'products_tenant_store_published_idx', 30, 'página por loja de 24 lê ~24 linhas');

-- ---------------------------------------------------------------------------
-- 6. Estrutura: donos, membership do migrator, grants e policies.
-- ---------------------------------------------------------------------------
RESET ROLE;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE oid IN ('public.portal_products'::regclass, 'public.portal_product_variants'::regclass,
                     'public.portal_categories'::regclass)
         AND relkind = 'v' AND relowner = 'ptmarket_portal'::regrole
         AND reloptions @> ARRAY['security_barrier=false']$q$,
    3, 'as 3 views: dona ptmarket_portal, security_barrier = false (visibilidade pelas policies portal_view)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_auth_members m
       WHERE m.roleid = 'ptmarket_portal'::regrole AND m.member = to_regrole(current_user)
         AND NOT m.inherit_option AND m.set_option$q$,
    1, 'migrator em ptmarket_portal com INHERIT FALSE, SET TRUE');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname = 'ptmarket_portal' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls$q$,
    1, 'ptmarket_portal: NOLOGIN, sem SUPERUSER/BYPASSRLS');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['portal_products', 'portal_product_variants', 'portal_categories']) AS v(n),
                            unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', 'public.' || v.n, p.priv)$q$,
    0, 'ptmarket_app: só SELECT nas views');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['portal_products', 'portal_product_variants', 'portal_categories']) AS v(n)
       WHERE has_table_privilege('ptmarket_app', 'public.' || v.n, 'SELECT')$q$,
    3, 'ptmarket_app: SELECT nas 3 views');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid IN ('public.portal_products'::regclass, 'public.portal_product_variants'::regclass,
                       'public.portal_categories'::regclass)
         AND a.grantee NOT IN ('ptmarket_app'::regrole, 'ptmarket_portal'::regrole)
         -- 0040: a dona da pesquisa (ptmarket_search) lê portal_products (EXISTS da visibilidade final).
         AND NOT (c.oid = 'public.portal_products'::regclass AND a.grantee = 'ptmarket_search'::regrole
                  AND a.privilege_type = 'SELECT')$q$,
    0, 'views: nenhum privilégio para PUBLIC nem outros papéis (exceto SELECT de ptmarket_search em portal_products)');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'products'
         AND has_column_privilege('ptmarket_portal', 'public.products', column_name, 'SELECT')$q$,
    'attributes,category_id,created_at,description,id,images,is_perishable,is_published,store_id,tenant_id,title,'
    'updated_at,vat_rate_bps',
    'ptmarket_portal: colunas de products (sem catalog_item_id nem ai_enriched)');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'product_variants'
         AND has_column_privilege('ptmarket_portal', 'public.product_variants', column_name, 'SELECT')$q$,
    'attributes,ean,id,is_active,lowest_price_30d_cents,price_cents,product_id,stock_qty,tenant_id',
    'ptmarket_portal: colunas de product_variants (stock_qty só para in_stock; sem sku nem compare_at_price_cents)');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'categories'
         AND has_column_privilege('ptmarket_portal', 'public.categories', column_name, 'SELECT')$q$,
    'id,is_featured,name,parent_id,slug,sort_order',
    'ptmarket_portal: colunas de categories (sem taxonomy_code nem default_vat_rate_bps)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['products', 'product_variants', 'categories']) AS t(n),
                            unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_portal', 'public.' || t.n, p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE') AND has_any_column_privilege('ptmarket_portal', 'public.' || t.n, p.priv))$q$,
    0, 'ptmarket_portal sem escrita em products, product_variants e categories');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid IN ('products'::regclass, 'product_variants'::regclass) AND polname = 'portal_view'
         AND polcmd = 'r' AND polpermissive AND polroles = ARRAY['ptmarket_portal'::regrole::oid]$q$,
    2, 'portal_view FOR SELECT TO ptmarket_portal em products e product_variants');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid IN ('products'::regclass, 'product_variants'::regclass) AND polname = 'portal_read'$q$,
    0, 'portal_read removida de products e product_variants');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid IN ('products'::regclass, 'product_variants'::regclass, 'product_price_history'::regclass)
         AND polname = 'store_scope_select' AND NOT polpermissive
         AND pg_get_expr(polqual, polrelid) NOT LIKE '%portal_stores%'
         AND pg_get_expr(polqual, polrelid) LIKE '%app_store_id%'
         AND pg_get_expr(polqual, polrelid) LIKE '%app_is_platform_admin%'$q$,
    3, 'store_scope_select de products/product_variants/product_price_history: só loja do contexto OR admin');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_constraint
       WHERE conrelid = 'categories'::regclass AND conname = 'categories_slug_key' AND contype = 'u'$q$,
    1, 'categories_slug_key (UNIQUE)');

ROLLBACK;
