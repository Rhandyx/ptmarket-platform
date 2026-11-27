-- Teste da 0035 (cartão 03/08b): isolamento entre lojas do mesmo tenant (app.store_id), âmbito da entidade
-- patrocinadora (app.sponsor_entity_id), exceção do ator admin e leitura pública pelo portal; um só national_portal
-- por país. Tenants, geografia e entidades pelo migrator; tudo o resto com SET ROLE ptmarket_app. Tudo com ROLLBACK.
--   NP = nacional PT · NE = nacional ES · W = municipal PT (canal da Câmara EC)
--   EC = Câmara (canal W) · EJ = Junta (sem canal)
--   L1, L2 = lojas no NP. L1: P1 publicado (V1 ativa), P1U não publicado (V1U). L2: P2 publicado (V2), P2U não
--   publicado (V2U). L1 co-patrocinada por EC (SC) e EJ (SJ).

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

CREATE FUNCTION pg_temp.expect_error_msg(p_sql text, p_state text, p_like text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = p_state AND v_msg LIKE p_like THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado % %, obtido %: %)', p_label, p_state, p_like, v_state, v_msg;
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

-- Linhas afetadas por um UPDATE/DELETE (sem RETURNING, que exigiria a policy de SELECT na linha nova).
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

-- Contexto: ator, loja e entidade (locais à transação, como o TenantTx).
CREATE FUNCTION pg_temp.ctx(p_actor text, p_store text, p_entity text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', p_actor, true);
    PERFORM set_config('app.store_id', p_store, true);
    PERFORM set_config('app.sponsor_entity_id', p_entity, true);
END
$$;

SELECT set_config('app.actor_label', 'test', true);

-- ---------------------------------------------------------------------------
-- 0. Estrutura.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid IN ('public.app_store_id()'::regprocedure, 'public.app_sponsor_entity_id()'::regprocedure,
                       'public.app_is_platform_admin()'::regprocedure)
         AND NOT p.prosecdef AND p.provolatile = 's'
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']
         AND has_function_privilege('ptmarket_app', p.oid, 'EXECUTE')
         AND NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0)
         AND NOT has_function_privilege('ptmarket_worker', p.oid, 'EXECUTE')
         AND NOT has_function_privilege('ptmarket_portal', p.oid, 'EXECUTE')$q$,
    3, 'app_store_id/app_sponsor_entity_id/app_is_platform_admin: INVOKER, STABLE, search_path fixo, EXECUTE só da app');

-- Toda a tabela de public com store_id ou FK para stores/products/product_variants tem as 4 policies RESTRICTIVE
-- (SELECT, INSERT, UPDATE, DELETE) para ptmarket_app. Exceção: user_roles (só own_select).
CREATE TEMP TABLE ssr_store_tables AS
    SELECT DISTINCT c.oid::regclass AS t
    FROM pg_class c
    WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
      AND c.relname NOT IN ('user_roles')
      AND (EXISTS (SELECT 1 FROM pg_attribute a
                   WHERE a.attrelid = c.oid AND a.attname = 'store_id' AND NOT a.attisdropped AND a.attnum > 0)
           -- Fecho transitivo das FKs a partir de stores (ex.: order_items → orders → stores), não só as diretas.
           OR c.oid IN (WITH RECURSIVE r(t) AS (
                            SELECT 'public.stores'::regclass::oid
                            UNION
                            SELECT k.conrelid FROM pg_constraint k JOIN r ON k.confrelid = r.t
                            WHERE k.contype = 'f' AND k.conrelid <> r.t
                              AND k.conrelid::regclass::text NOT IN ('user_roles'))
                        SELECT t FROM r));
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM ssr_store_tables
       WHERE t::text IN ('stores', 'products', 'product_variants', 'product_price_history', 'store_sponsorships',
                         'store_verifications')$q$,
    6, 'tabelas de loja: stores, products, product_variants, product_price_history, store_sponsorships, '
       'store_verifications');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM ssr_store_tables s
       WHERE (SELECT count(DISTINCT p.polcmd) FROM pg_policy p
              WHERE p.polrelid = s.t AND NOT p.polpermissive AND p.polcmd IN ('r', 'a', 'w', 'd')
                AND p.polroles = ARRAY['ptmarket_app'::regrole::oid]
                AND p.polname IN ('store_scope_select', 'store_scope_insert', 'store_scope_update',
                                  'store_scope_delete')) <> 4$q$,
    0, 'todas as tabelas de loja têm store_scope_* RESTRICTIVE (SELECT/INSERT/UPDATE/DELETE) só para ptmarket_app');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy p
       WHERE p.polname LIKE 'store_scope_%' AND (p.polpermissive OR p.polroles <> ARRAY['ptmarket_app'::regrole::oid])$q$,
    0, 'nenhuma store_scope_* permissiva ou para outro papel (portal, identity, worker, price_writer intactos)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy p
       WHERE p.polrelid = 'public.user_roles'::regclass AND p.polname LIKE 'store_scope_%'$q$,
    0, 'user_roles fica de fora');

-- Schema audit (0038): a app só lê (escreve pelas DEFINER do writer). Toda a tabela de audit com store_id a que a
-- app tenha algum privilégio tem store_scope_read RESTRICTIVE FOR SELECT só para ptmarket_app e nenhuma escrita da
-- app; as partições (que fugiriam à policy do pai) não dão nada à app.
CREATE TEMP TABLE ssr_audit_tables AS
    SELECT c.oid::regclass AS t
    FROM pg_class c
    WHERE c.relnamespace = 'audit'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND NOT c.relispartition
      AND EXISTS (SELECT 1 FROM pg_attribute a
                  WHERE a.attrelid = c.oid AND a.attname = 'store_id' AND NOT a.attisdropped AND a.attnum > 0)
      AND (has_table_privilege('ptmarket_app', c.oid,
               'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
           OR has_any_column_privilege('ptmarket_app', c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'));
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM ssr_audit_tables WHERE t = 'audit.audit_events'::regclass$q$,
    1, 'audit: audit_events entra na guarda (store_id + SELECT da app)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM ssr_audit_tables s
       WHERE NOT EXISTS (SELECT 1 FROM pg_policy p
                         WHERE p.polrelid = s.t AND p.polname = 'store_scope_read' AND NOT p.polpermissive
                           AND p.polcmd = 'r' AND p.polroles = ARRAY['ptmarket_app'::regrole::oid])$q$,
    0, 'audit: toda a tabela com store_id lida pela app tem store_scope_read RESTRICTIVE (SELECT) só para ptmarket_app');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM ssr_audit_tables s JOIN pg_class c ON c.oid = s.t
       WHERE NOT (c.relrowsecurity AND c.relforcerowsecurity)$q$,
    0, 'audit: toda a tabela com store_id lida pela app tem RLS ativo e FORCE');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM ssr_audit_tables s JOIN pg_policy p ON p.polrelid = s.t AND p.polname = 'store_scope_read'
       WHERE p.polqual IS NULL
          OR pg_get_expr(p.polqual, p.polrelid) NOT LIKE '%store_id%'
          OR btrim(pg_get_expr(p.polqual, p.polrelid), ' ()') = 'true'$q$,
    0, 'audit: o USING de store_scope_read não é trivial (filtra por store_id)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM ssr_audit_tables s
       WHERE has_table_privilege('ptmarket_app', s.t, 'INSERT, UPDATE, DELETE, TRUNCATE')
          OR has_any_column_privilege('ptmarket_app', s.t, 'INSERT, UPDATE')$q$,
    0, 'audit: a app não escreve em nenhuma tabela com store_id (só pelas DEFINER do writer)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c
       WHERE c.relnamespace = 'audit'::regnamespace AND c.relispartition AND c.relkind IN ('r', 'p')
         AND (has_table_privilege('ptmarket_app', c.oid,
                  'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
              OR has_any_column_privilege('ptmarket_app', c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'))$q$,
    0, 'audit: a app sem acesso direto a nenhuma partição');

-- Um só national_portal por país.
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
       WHERE c.relname = 'tenants_one_national_portal_per_country' AND i.indisunique
         AND i.indrelid = 'public.tenants'::regclass
         AND pg_get_expr(i.indpred, i.indrelid) LIKE '%national_portal%'$q$,
    1, 'tenants_one_national_portal_per_country: UNIQUE (country_code) WHERE national_portal');

-- ---------------------------------------------------------------------------
-- 1. Preparação (migrator): geografia, tenants e entidades.
-- ---------------------------------------------------------------------------
INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
    ('94', 'district', NULL, 'Distrito Teste 35', 'T'),
    ('9401', 'municipality', '94', 'Concelho Teste 35', 'T'),
    ('940101', 'parish', '9401', 'Freguesia Teste 35', 'T');

INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000035a0', 'ssr-npt', 'ssr-npt.teste.invalid', 'Nacional PT 35', 'national_portal', 'PT'),
    ('00000000-0000-7000-8000-0000000035a1', 'ssr-nes', 'ssr-nes.teste.invalid', 'Nacional ES 35', 'national_portal', 'ES'),
    ('00000000-0000-7000-8000-0000000035c1', 'ssr-w', 'ssr-w.teste.invalid', 'Canal W 35', 'municipal', 'PT');

INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code, channel_tenant_id) VALUES
    ('00000000-0000-7000-8000-0000000035e1', 'municipality', 'PT', 'Câmara 35', 'ssr-camara', '9401',
     '00000000-0000-7000-8000-0000000035c1'),
    ('00000000-0000-7000-8000-0000000035e2', 'parish', 'PT', 'Junta 35', 'ssr-junta', '940101', NULL);

-- Segundo national_portal no mesmo país → 23505 (ativo ou não); outro país passa (NE acima).
SELECT pg_temp.expect_error(
    $q$INSERT INTO tenants (slug, custom_domain, name, tenant_type, country_code, is_active)
       VALUES ('ssr-npt2', 'ssr-npt2.teste.invalid', 'Nacional PT 2', 'national_portal', 'PT', false)$q$,
    '23505', 'segundo national_portal PT (inativo) → 23505');
SELECT pg_temp.expect_error(
    $q$INSERT INTO tenants (slug, custom_domain, name, tenant_type, country_code)
       VALUES ('ssr-nes2', 'ssr-nes2.teste.invalid', 'Nacional ES 2', 'national_portal', 'ES')$q$,
    '23505', 'segundo national_portal ES → 23505');
SELECT pg_temp.expect_error(
    $q$UPDATE tenants SET tenant_type = 'national_portal' WHERE id = '00000000-0000-7000-8000-0000000035c1'$q$,
    '23505', 'municipal PT promovido a national_portal com o NP já lá → 23505');

-- A guarda da 0035 (cópia do bloco A): duplicados existentes abortam com mensagem clara. O índice cai só neste
-- savepoint para conseguir criar o duplicado.
SAVEPOINT ssr_dup;
DROP INDEX tenants_one_national_portal_per_country;
INSERT INTO tenants (slug, custom_domain, name, tenant_type, country_code)
    VALUES ('ssr-npt-dup', 'ssr-npt-dup.teste.invalid', 'Nacional PT dup', 'national_portal', 'PT');
SELECT pg_temp.expect_error_msg(
    $q$DO $do$
       DECLARE
           v_bad text;
       BEGIN
           SELECT string_agg(format('%s (%s)', x.country_code, x.slugs), '; ' ORDER BY x.country_code)
           INTO v_bad
           FROM (
               SELECT t.country_code, string_agg(t.slug, ', ' ORDER BY t.slug) AS slugs
               FROM public.tenants t
               WHERE t.tenant_type = 'national_portal'
               GROUP BY t.country_code
               HAVING count(*) > 1
           ) x;
           IF v_bad IS NOT NULL THEN
               RAISE EXCEPTION '0035: mais de um tenant national_portal no mesmo país (ativos ou não); resolver à mão '
                               'antes (fundir ou mudar o tipo): %', v_bad;
           END IF;
       END
       $do$$q$,
    'P0001', '0035: mais de um tenant national_portal no mesmo país%PT (%ssr-npt, ssr-npt-dup%)%',
    'duplicados de national_portal: a 0035 aborta e lista país e slugs');
ROLLBACK TO SAVEPOINT ssr_dup;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class WHERE relname = 'tenants_one_national_portal_per_country'$q$,
    1, 'índice reposto depois do savepoint');

-- ---------------------------------------------------------------------------
-- 2. Lojista de L1 (ator merchant, app.store_id = L1): cria e lê a sua loja, produtos, variantes e preço.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000035a0', true);
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000035b1', '');
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000035b1', '00000000-0000-7000-8000-0000000035a0',
     'Loja L1', 'ssr-l1', 'L1 Lda', '500003501', 'PT50000000000000000003501', 'l1@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps, is_published) VALUES
    ('00000000-0000-7000-8000-0000000035f1', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035b1', '{"pt":"P1"}', 2300, true),
    ('00000000-0000-7000-8000-0000000035f2', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035b1', '{"pt":"P1U"}', 2300, false);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-0000000035d1', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035f1', 1000),
    ('00000000-0000-7000-8000-0000000035d2', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035f2', 1100);

-- L2 criada pelo ator admin (exceção: escreve em qualquer loja do tenant, sem app.store_id).
SELECT pg_temp.ctx('admin', '', '');
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000035b2', '00000000-0000-7000-8000-0000000035a0',
     'Loja L2', 'ssr-l2', 'L2 Lda', '500003502', 'PT50000000000000000003502', 'l2@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps, is_published) VALUES
    ('00000000-0000-7000-8000-0000000035f3', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035b2', '{"pt":"P2"}', 2300, true),
    ('00000000-0000-7000-8000-0000000035f4', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035b2', '{"pt":"P2U"}', 2300, false);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-0000000035d3', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035f3', 2000),
    ('00000000-0000-7000-8000-0000000035d4', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035f4', 2100);
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 2, 'admin: lê as duas lojas do tenant');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 4, 'admin: lê os 4 produtos (publicados ou não)');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_price_history', 4, 'admin: lê o histórico das 4 variantes');
SELECT pg_temp.expect_rows(
    $q$UPDATE stores SET vacation_message = 'admin' WHERE id IN ('00000000-0000-7000-8000-0000000035b1',
                                                                  '00000000-0000-7000-8000-0000000035b2')$q$,
    2, 'admin: UPDATE nas duas lojas');
SELECT pg_temp.expect_rows(
    $q$UPDATE products SET attributes = '{"admin": true}' WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'$q$,
    4, 'admin: UPDATE nos produtos das duas lojas');

-- Admin com impersonação: perde a exceção (como a 0026); sem app.store_id não escreve nem lê lojas.
SELECT set_config('app.impersonator_id', '00000000-0000-7000-8000-0000000035e9', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'admin a impersonar: sem exceção, não lê lojas');
SELECT pg_temp.expect_rows(
    $q$UPDATE stores SET vacation_message = 'imp' WHERE id = '00000000-0000-7000-8000-0000000035b2'$q$,
    0, 'admin a impersonar: UPDATE em L2 afeta 0 linhas');
SELECT set_config('app.impersonator_id', '', true);

-- Lojista de L1.
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000035b1', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores WHERE id = '00000000-0000-7000-8000-0000000035b1'$q$, 1, 'L1: lê a sua loja');
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 1, 'L1: stores só tem a sua loja');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores WHERE id = '00000000-0000-7000-8000-0000000035b2'$q$,
    0, 'L1: SELECT direto da loja L2 → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE store_id = '00000000-0000-7000-8000-0000000035b1'$q$,
    2, 'L1: lê os seus 2 produtos (publicado e não publicado)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id = '00000000-0000-7000-8000-0000000035f4'$q$,
    0, 'L1: produto não publicado de L2 → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE store_id = '00000000-0000-7000-8000-0000000035b2'$q$,
    0, 'L1 (backoffice, sem modo portal): 0 produtos de L2');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE id IN ('00000000-0000-7000-8000-0000000035d3',
                                                          '00000000-0000-7000-8000-0000000035d4')$q$,
    0, 'L1: 0 variantes de L2');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history WHERE variant_id IN ('00000000-0000-7000-8000-0000000035d3',
                                                                       '00000000-0000-7000-8000-0000000035d4')$q$,
    0, 'L1: 0 linhas de histórico de L2');

-- Escritas em L1: passam.
SELECT pg_temp.expect_rows(
    $q$UPDATE stores SET name = 'Loja L1 nova' WHERE id = '00000000-0000-7000-8000-0000000035b1'$q$,
    1, 'L1: UPDATE da sua loja');
SELECT pg_temp.expect_rows(
    $q$UPDATE products SET is_published = true WHERE id = '00000000-0000-7000-8000-0000000035f2'$q$,
    1, 'L1: UPDATE do seu produto');
SELECT pg_temp.expect_rows(
    $q$UPDATE products SET is_published = false WHERE id = '00000000-0000-7000-8000-0000000035f2'$q$,
    1, 'L1: UPDATE do seu produto (repor)');

-- Preço (Omnibus): o trigger DEFINER da 0007 grava o histórico quando o lojista muda o preço.
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history WHERE variant_id = '00000000-0000-7000-8000-0000000035d1'$q$,
    1, 'L1: variante nova → 1 linha de histórico (Omnibus)');
SELECT pg_temp.expect_rows(
    $q$UPDATE product_variants SET price_cents = 900 WHERE id = '00000000-0000-7000-8000-0000000035d1'$q$,
    1, 'L1: muda o preço da sua variante');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history WHERE variant_id = '00000000-0000-7000-8000-0000000035d1'$q$,
    2, 'L1: mudança de preço → histórico Omnibus gravado (2 linhas)');
SELECT pg_temp.expect_count(
    $q$SELECT lowest_price_30d_cents FROM product_variants WHERE id = '00000000-0000-7000-8000-0000000035d1'$q$,
    1000, 'L1: lowest_price_30d calculado a partir do histórico (1000)');
-- V1b (2.ª variante de P1, para a leitura pública).
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-0000000035d5', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035f1', 500);

-- Escritas em L2: UPDATE/DELETE afetam 0 linhas; INSERT → 42501.
SELECT pg_temp.expect_rows(
    $q$UPDATE stores SET name = 'pirata' WHERE id = '00000000-0000-7000-8000-0000000035b2'$q$,
    0, 'L1: UPDATE da loja L2 → 0 linhas');
SELECT pg_temp.expect_rows(
    $q$DELETE FROM stores WHERE id = '00000000-0000-7000-8000-0000000035b2'$q$,
    0, 'L1: DELETE da loja L2 → 0 linhas');
SELECT pg_temp.expect_rows(
    $q$UPDATE products SET title = '{"pt":"pirata"}' WHERE store_id = '00000000-0000-7000-8000-0000000035b2'$q$,
    0, 'L1: UPDATE dos produtos de L2 → 0 linhas');
SELECT pg_temp.expect_rows(
    $q$DELETE FROM products WHERE store_id = '00000000-0000-7000-8000-0000000035b2'$q$,
    0, 'L1: DELETE dos produtos de L2 → 0 linhas');
SELECT pg_temp.expect_rows(
    $q$UPDATE product_variants SET price_cents = 1 WHERE id = '00000000-0000-7000-8000-0000000035d3'$q$,
    0, 'L1: UPDATE de preço de variante de L2 → 0 linhas');
SELECT pg_temp.expect_rows(
    $q$DELETE FROM product_variants WHERE id = '00000000-0000-7000-8000-0000000035d4'$q$,
    0, 'L1: DELETE de variante de L2 → 0 linhas');
SELECT pg_temp.expect_error(
    $q$UPDATE products SET store_id = '00000000-0000-7000-8000-0000000035b2'
       WHERE id = '00000000-0000-7000-8000-0000000035f1'$q$,
    '42501', 'L1: mover o seu produto para L2 → 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
       ('00000000-0000-7000-8000-0000000035b3', '00000000-0000-7000-8000-0000000035a0',
        'Loja L3', 'ssr-l3', 'L3 Lda', '500003503', 'PT50000000000000000003503', 'l3@teste.invalid')$q$,
    '42501', 'L1: INSERT de outra loja → 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO products (tenant_id, store_id, title, vat_rate_bps)
       VALUES ('00000000-0000-7000-8000-0000000035a0', '00000000-0000-7000-8000-0000000035b2', '{}', 2300)$q$,
    '42501', 'L1: INSERT de produto em L2 → 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO product_variants (tenant_id, product_id, price_cents)
       VALUES ('00000000-0000-7000-8000-0000000035a0', '00000000-0000-7000-8000-0000000035f3', 1)$q$,
    '42501', 'L1: INSERT de variante num produto de L2 → 42501');

-- Nada mudou em L2 (lido pelo admin).
SELECT pg_temp.ctx('admin', '', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores s
       WHERE s.id = '00000000-0000-7000-8000-0000000035b2' AND s.name = 'Loja L2'
         AND (SELECT count(*) FROM products p WHERE p.store_id = s.id AND p.title->>'pt' IN ('P2', 'P2U')) = 2
         AND (SELECT price_cents FROM product_variants WHERE id = '00000000-0000-7000-8000-0000000035d3') = 2000
         AND (SELECT count(*) FROM product_variants WHERE id = '00000000-0000-7000-8000-0000000035d4') = 1$q$,
    1, 'L2 intacta depois das tentativas de L1');

-- ---------------------------------------------------------------------------
-- 3. Sem app.store_id: nenhum ator (merchant, municipal, customer, system) escreve; nem lê stores em backoffice.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    a text;
BEGIN
    FOREACH a IN ARRAY ARRAY['merchant', 'municipal', 'customer', 'system'] LOOP
        PERFORM pg_temp.ctx(a, '', '');
        PERFORM pg_temp.expect_error(
            $q$INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
               ('00000000-0000-7000-8000-0000000035b3', '00000000-0000-7000-8000-0000000035a0',
                'Loja L3', 'ssr-l3', 'L3 Lda', '500003503', 'PT50000000000000000003503', 'l3@teste.invalid')$q$,
            '42501', format('%s sem app.store_id: INSERT de loja → 42501', a));
        PERFORM pg_temp.expect_error(
            $q$INSERT INTO products (tenant_id, store_id, title, vat_rate_bps)
               VALUES ('00000000-0000-7000-8000-0000000035a0', '00000000-0000-7000-8000-0000000035b1', '{}', 2300)$q$,
            '42501', format('%s sem app.store_id: INSERT de produto → 42501', a));
        PERFORM pg_temp.expect_error(
            $q$INSERT INTO product_variants (tenant_id, product_id, price_cents)
               VALUES ('00000000-0000-7000-8000-0000000035a0', '00000000-0000-7000-8000-0000000035f1', 1)$q$,
            '42501', format('%s sem app.store_id: INSERT de variante → 42501', a));
        PERFORM pg_temp.expect_error(
            $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id)
               VALUES ('00000000-0000-7000-8000-0000000035a0', '00000000-0000-7000-8000-0000000035b1',
                       '00000000-0000-7000-8000-0000000035e1')$q$,
            '42501', format('%s sem app.store_id: INSERT de patrocínio → 42501', a));
        PERFORM pg_temp.expect_rows(
            $q$UPDATE stores SET name = 'x' WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'$q$,
            0, format('%s sem app.store_id: UPDATE de lojas → 0 linhas', a));
        PERFORM pg_temp.expect_rows(
            $q$UPDATE products SET title = '{"pt":"x"}' WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'$q$,
            0, format('%s sem app.store_id: UPDATE de produtos → 0 linhas', a));
        PERFORM pg_temp.expect_rows(
            $q$UPDATE product_variants SET price_cents = 1 WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'$q$,
            0, format('%s sem app.store_id: UPDATE de variantes → 0 linhas', a));
        PERFORM pg_temp.expect_rows(
            $q$DELETE FROM product_variants WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'$q$,
            0, format('%s sem app.store_id: DELETE de variantes → 0 linhas', a));
        PERFORM pg_temp.expect_count('SELECT count(*) FROM stores', 0,
            format('%s sem app.store_id: stores (backoffice) → 0 linhas', a));
    END LOOP;
END
$$;

-- Leitura pública, canal nacional PT (modo portal, ator customer, sem app.store_id): o mesmo que no cartão 08 —
-- as lojas ativas pela view, os produtos publicados e as variantes ativas desses produtos.
SELECT pg_temp.ctx('customer', '', '');
SET app.portal_national = 'on';
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores WHERE id IN ('00000000-0000-7000-8000-0000000035b1',
                                                       '00000000-0000-7000-8000-0000000035b2')$q$,
    2, 'nacional PT: portal_stores mostra L1 e L2');
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'nacional PT: stores direto continua a 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'$q$,
    2, 'nacional PT: só os produtos publicados (P1, P2)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id IN ('00000000-0000-7000-8000-0000000035f2',
                                                  '00000000-0000-7000-8000-0000000035f4')$q$,
    0, 'nacional PT: produtos não publicados invisíveis');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'$q$,
    3, 'nacional PT: variantes ativas dos produtos publicados (V1, V1b, V2)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history WHERE variant_id = '00000000-0000-7000-8000-0000000035d1'$q$,
    2, 'nacional PT: histórico Omnibus da variante publicada legível');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history WHERE variant_id IN ('00000000-0000-7000-8000-0000000035d2',
                                                                       '00000000-0000-7000-8000-0000000035d4')$q$,
    0, 'nacional PT: histórico de variantes de produtos não publicados invisível');
RESET app.portal_national;

-- ---------------------------------------------------------------------------
-- 4. Co-patrocínio de L1 (Câmara EC + Junta EJ): a loja pede, cada entidade decide só o seu.
-- ---------------------------------------------------------------------------
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000035b1', '');
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000035101', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035b1', '00000000-0000-7000-8000-0000000035e1'),
    ('00000000-0000-7000-8000-000000035102', '00000000-0000-7000-8000-0000000035a0',
     '00000000-0000-7000-8000-0000000035b1', '00000000-0000-7000-8000-0000000035e2');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id)
       VALUES ('00000000-0000-7000-8000-0000000035a0', '00000000-0000-7000-8000-0000000035b2',
               '00000000-0000-7000-8000-0000000035e1')$q$,
    '42501', 'L1: pedido de patrocínio em nome de L2 → 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id, initiated_by)
       VALUES ('00000000-0000-7000-8000-0000000035a0', '00000000-0000-7000-8000-0000000035b1',
               '00000000-0000-7000-8000-0000000035e1', 'sponsor')$q$,
    '42501', 'L1: "convite da entidade" falso (initiated_by = sponsor) → 42501');
SELECT set_config('app.store_id', 'abc', true);
SELECT pg_temp.expect_error(
    'SELECT count(*) FROM products', '22P02', 'app.store_id que não é uuid → 22P02 (falha fechada, sem bypass)');
SELECT set_config('app.store_id', '00000000-0000-7000-8000-0000000035b1', true);

-- Câmara (app.sponsor_entity_id = EC; contexto do tenant da loja).
SELECT pg_temp.ctx('municipal', '', '00000000-0000-7000-8000-0000000035e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM store_sponsorships', 1, 'Câmara: vê só o seu patrocínio de L1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000035102'$q$,
    0, 'Câmara: não vê o patrocínio da Junta');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day', decided_at = now()
       WHERE id = '00000000-0000-7000-8000-000000035101'$q$,
    1, 'Câmara: aceita o seu patrocínio');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'rejected', decided_at = now()
       WHERE id = '00000000-0000-7000-8000-000000035102'$q$,
    0, 'Câmara: UPDATE do patrocínio da Junta → 0 linhas');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id)
       VALUES ('00000000-0000-7000-8000-0000000035a0', '00000000-0000-7000-8000-0000000035b2',
               '00000000-0000-7000-8000-0000000035e1')$q$,
    '42501', 'Câmara sem app.store_id: INSERT de patrocínio → 42501');
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'Câmara: stores (backoffice) → 0 linhas');

-- Junta.
SELECT pg_temp.ctx('municipal', '', '00000000-0000-7000-8000-0000000035e2');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000035102'$q$,
    1, 'Junta: vê o seu patrocínio');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day', decided_at = now()
       WHERE id = '00000000-0000-7000-8000-000000035102'$q$,
    1, 'Junta: aceita o seu patrocínio');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'revoked' WHERE id = '00000000-0000-7000-8000-000000035101'$q$,
    0, 'Junta: UPDATE do patrocínio da Câmara → 0 linhas');

-- Lojista de L1: vê os dois, não consegue UPDATE em nenhum.
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000035b1', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE status = 'active'$q$, 2,
    'L1: vê os dois patrocínios ativos (Câmara e Junta)');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'revoked'
       WHERE id IN ('00000000-0000-7000-8000-000000035101', '00000000-0000-7000-8000-000000035102')$q$,
    0, 'L1: UPDATE dos patrocínios → 0 linhas');
SELECT pg_temp.expect_error(
    $q$DELETE FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000035101'$q$,
    '42501', 'L1: DELETE de patrocínio → 42501');
-- Lojista de L2 não vê os patrocínios de L1.
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000035b2', '');
SELECT pg_temp.expect_count('SELECT count(*) FROM store_sponsorships', 0, 'L2: não vê os patrocínios de L1');
-- Admin decide em qualquer patrocínio.
SELECT pg_temp.ctx('admin', '', '');
SELECT pg_temp.expect_count('SELECT count(*) FROM store_sponsorships', 2, 'admin: vê os dois patrocínios');

-- Leitura pública white-label (canal W da Câmara, ator customer): só L1 e o seu produto publicado.
SELECT pg_temp.ctx('customer', '', '');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000035c1', true);
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 1, 'canal W: portal_stores só com L1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id = '00000000-0000-7000-8000-0000000035f1'$q$,
    1, 'canal W: produto publicado de L1 visível');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 1, 'canal W: só P1 (nem P1U nem L2)');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 2, 'canal W: as 2 variantes ativas de P1');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_store_badges', 2, 'canal W: selos da Câmara e da Junta em L1');

-- ---------------------------------------------------------------------------
-- 5. Índices: as policies usam products (tenant_id, store_id) e as chaves (tenant_id, id); sem Seq Scan.
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000035a0', true);
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-0000000035b1', '');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM products WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'
                                 AND store_id = '00000000-0000-7000-8000-0000000035b1'$q$,
    'products', 'lojista: produtos da loja sem Seq Scan em products');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM product_variants WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'
                                         AND product_id = '00000000-0000-7000-8000-0000000035f1'$q$,
    'products', 'lojista: variantes de um produto sem Seq Scan em products (EXISTS da policy)');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM product_price_history WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'
                                              AND variant_id = '00000000-0000-7000-8000-0000000035d1'$q$,
    'products', 'lojista: histórico de uma variante sem Seq Scan em products');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM product_price_history WHERE tenant_id = '00000000-0000-7000-8000-0000000035a0'
                                              AND variant_id = '00000000-0000-7000-8000-0000000035d1'$q$,
    'product_variants', 'lojista: histórico de uma variante sem Seq Scan em product_variants');

SELECT pg_temp.ctx('', '', '');
RESET ROLE;

ROLLBACK;
