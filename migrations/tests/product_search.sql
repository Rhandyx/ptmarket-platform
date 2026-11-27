-- Teste da 0040 (cartão 04/03; spec 11 D9): pesquisa por texto portal_search_product_ids (dona ptmarket_search),
-- índice GIN de expressão products_search_idx, f_unaccent; nada de pesquisa nos eventos L1.
-- Tenants, entidades pelo migrator; lojas, produtos e patrocínios pela app (SET ROLE ptmarket_app, ator admin).
-- Pesquisa sempre como ptmarket_app (único papel com EXECUTE). Tudo com ROLLBACK.
--   NP = nacional PT · CA, CB = municipais PT (canais das associações EA e EB)
--   Lojas no NP: S1 (EA) · S2 (EB) · S3 (sem patrocínio) · S4 (inativa, EA)
--   Produtos: F101 S1 "Pão de Mafra" · F102 S1 "Pão de ló" (não publicado) · F103 S1 "Pão com chouriço" (só variante
--             inativa) · F201 S2 "PÃO caseiro" · F301 S3 "Queijo da Serra"/es "Queso de la Sierra" · F302 S3 "Bolo de
--             mel" · F401 S4 "Pão alentejano" (loja inativa)

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

-- Resultado da pesquisa como lista de títulos pt (ordem da função: id DESC).
CREATE FUNCTION pg_temp.titles(p_query text)
RETURNS text LANGUAGE sql AS $$
    SELECT string_agg(t.title, '|' ORDER BY t.ord)
    FROM (
        SELECT s.ord, (SELECT pp.title->>'pt' FROM public.portal_products pp WHERE pp.id = s.id) AS title
        FROM public.portal_search_product_ids(p_query, NULL, 49) WITH ORDINALITY AS s(id, ord)
    ) t
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
-- 0. Estrutura (migrator): papel, membros, donos, ACL, grants por coluna.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname = 'ptmarket_search' AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
         AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication$q$,
    1, 'ptmarket_search: NOLOGIN NOINHERIT, sem SUPERUSER/BYPASSRLS/CREATEDB/CREATEROLE/REPLICATION');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_auth_members WHERE member = 'ptmarket_search'::regrole$q$,
    0, 'ptmarket_search não é membro de nenhum papel');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.grantor
       WHERE m.roleid = 'ptmarket_search'::regrole
         AND NOT (m.member = to_regrole(current_user) AND m.admin_option AND NOT m.inherit_option
                  AND NOT m.set_option AND g.rolsuper)$q$,
    0, 'ptmarket_search sem membros (só o ADMIN implícito do CREATE ROLE no migrator, sem INHERIT nem SET)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles r
       WHERE pg_has_role(r.oid, 'ptmarket_search'::regrole, 'USAGE') AND r.rolname <> 'ptmarket_search'
         AND NOT r.rolsuper$q$,
    0, 'nenhum papel (não superuser) herda os privilégios de ptmarket_search');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles r
       WHERE pg_has_role(r.oid, 'ptmarket_search'::regrole, 'SET') AND r.rolname <> 'ptmarket_search'
         AND NOT r.rolsuper$q$,
    0, 'nenhum papel (não superuser) pode fazer SET ROLE ptmarket_search');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname = 'ptmarket_portal' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls$q$,
    1, 'ptmarket_portal continua NOLOGIN, sem SUPERUSER/BYPASSRLS');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_auth_members m
       WHERE m.roleid = 'ptmarket_portal'::regrole AND m.member = to_regrole(current_user)
         AND m.inherit_option$q$,
    0, 'migrator sem INHERIT em ptmarket_portal');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'public.portal_search_product_ids(text, uuid, integer)'::regprocedure
         AND prosecdef AND provolatile = 's' AND prolang = (SELECT oid FROM pg_language WHERE lanname = 'sql')
         AND proowner = 'ptmarket_search'::regrole
         AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    1, 'portal_search_product_ids: sql STABLE SECURITY DEFINER, dona ptmarket_search, search_path fixo');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END || ':' || a.privilege_type,
                         ',' ORDER BY CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END)
       FROM pg_proc p, aclexplode(p.proacl) a
       WHERE p.oid = 'public.portal_search_product_ids(text, uuid, integer)'::regprocedure$q$,
    'ptmarket_app:EXECUTE,ptmarket_search:EXECUTE', 'proacl da função: só a dona e ptmarket_app (sem PUBLIC)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc WHERE proowner = 'ptmarket_search'::regrole$q$,
    1, 'ptmarket_search é dono de uma só função');
SELECT pg_temp.expect_count(
    $q$SELECT (SELECT count(*) FROM pg_class WHERE relowner = 'ptmarket_search'::regrole)
            + (SELECT count(*) FROM pg_namespace WHERE nspowner = 'ptmarket_search'::regrole)
            + (SELECT count(*) FROM pg_type WHERE typowner = 'ptmarket_search'::regrole)$q$,
    0, 'ptmarket_search não é dono de tabelas, views, schemas nem tipos');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'public.f_unaccent(text)'::regprocedure AND NOT prosecdef AND provolatile = 'i'
         AND proparallel = 's' AND proisstrict AND proconfig = ARRAY['search_path=pg_catalog']$q$,
    1, 'f_unaccent: IMMUTABLE PARALLEL SAFE STRICT, INVOKER, search_path = pg_catalog');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(a.grantee::regrole::text, ',' ORDER BY a.grantee::regrole::text)
       FROM pg_proc p, aclexplode(p.proacl) a
       WHERE p.oid = 'public.f_unaccent(text)'::regprocedure AND a.grantee <> p.proowner$q$,
    'ptmarket_app,ptmarket_search', 'f_unaccent: EXECUTE só ptmarket_app e ptmarket_search (sem PUBLIC)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['public.portal_search_product_ids(text, uuid, integer)',
                                         'public.f_unaccent(text)']) AS f(sig)
       WHERE has_function_privilege('public', f.sig, 'EXECUTE')$q$,
    0, 'PUBLIC sem EXECUTE nas duas funções');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) WHERE has_function_privilege(current_user,
                                                    'public.portal_search_product_ids(text, uuid, integer)', 'EXECUTE')$q$,
    0, 'migrator (sem INHERIT) sem EXECUTE na função');
SELECT pg_temp.expect_error(
    $q$SELECT public.portal_search_product_ids('pao', NULL, 10)$q$,
    '42501', 'migrator: executar a função → 42501');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_am am ON am.oid = c.relam
       WHERE c.relname = 'products_search_idx' AND i.indrelid = 'public.products'::regclass AND am.amname = 'gin'
         AND i.indexprs IS NOT NULL AND pg_get_expr(i.indpred, i.indrelid) = 'is_published'$q$,
    1, 'products_search_idx: GIN de expressão WHERE is_published');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_attribute
       WHERE attrelid = 'public.products'::regclass AND attnum > 0 AND NOT attisdropped
         AND (attgenerated <> '' OR attname = 'search_tsv')$q$,
    0, 'products sem colunas geradas (nada para o L1 gravar)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid = 'public.products'::regclass AND polname = 'search_read' AND polcmd = 'r' AND polpermissive
         AND polroles = ARRAY['ptmarket_search'::regrole::oid] AND pg_get_expr(polqual, polrelid) = 'true'$q$,
    1, 'policy search_read FOR SELECT TO ptmarket_search USING (true) em products');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy p
       WHERE 'ptmarket_search'::regrole::oid = ANY (p.polroles)
         AND NOT (p.polrelid = 'public.products'::regclass AND p.polname = 'search_read')$q$,
    0, 'ptmarket_search não tem policies noutras tabelas');
-- tenants sem RLS: app_is_national_portal() (INVOKER) lê-a como ptmarket_search sem policy própria.
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class WHERE oid = 'public.tenants'::regclass AND NOT relrowsecurity$q$,
    1, 'tenants sem RLS (não bloqueia ptmarket_search; prova funcional no canal nacional abaixo)');

-- Privilégios de ptmarket_search: exatamente estes (catálogo direto: o information_schema esconde os grants de
-- ptmarket_portal ao migrator sem INHERIT).
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(c.relname || '.' || a.attname || ':' || x.privilege_type, ','
                         ORDER BY c.relname, a.attname, x.privilege_type)
       FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid, aclexplode(a.attacl) x
       WHERE x.grantee = 'ptmarket_search'::regrole$q$,
    'products.id:SELECT,products.is_published:SELECT,products.tenant_id:SELECT,products.title:SELECT,'
    'tenants.id:SELECT,tenants.is_active:SELECT,tenants.tenant_type:SELECT',
    'ptmarket_search: por coluna só SELECT em products(id, is_published, tenant_id, title) e '
    'tenants(id, is_active, tenant_type)');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(c.relname || ':' || x.privilege_type, ',' ORDER BY c.relname, x.privilege_type)
       FROM pg_class c, aclexplode(c.relacl) x
       WHERE x.grantee = 'ptmarket_search'::regrole$q$,
    'portal_products:SELECT', 'ptmarket_search: ao nível da tabela só SELECT na view portal_products');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(p.oid::regprocedure::text, ',' ORDER BY p.oid::regprocedure::text)
       FROM pg_proc p, aclexplode(p.proacl) a
       WHERE a.grantee = 'ptmarket_search'::regrole AND p.proowner <> 'ptmarket_search'::regrole$q$,
    'app_is_national_portal(),f_unaccent(text)', 'ptmarket_search: EXECUTE explícito só em app_is_national_portal e f_unaccent');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_namespace n, aclexplode(n.nspacl) a
       WHERE a.grantee = 'ptmarket_search'::regrole AND (n.nspname <> 'public' OR a.privilege_type <> 'USAGE')$q$,
    0, 'ptmarket_search: só USAGE no schema public');
-- ptmarket_portal: sem grants novos (lista igual à da 0039 + 0033/0021).
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(c.relname || '.' || a.attname, ',' ORDER BY c.relname, a.attname)
       FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid, aclexplode(a.attacl) x
       WHERE x.grantee = 'ptmarket_portal'::regrole AND x.privilege_type = 'SELECT'
         AND c.relname IN ('products', 'tenants') AND c.relnamespace = 'public'::regnamespace$q$,
    'products.attributes,products.category_id,products.created_at,products.description,products.id,products.images,'
    'products.is_perishable,products.is_published,products.store_id,products.tenant_id,products.title,'
    'products.updated_at,products.vat_rate_bps,tenants.country_code,tenants.id,tenants.is_active',
    'ptmarket_portal: products e tenants sem colunas novas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a WHERE a.grantee = 'ptmarket_portal'::regrole$q$,
    0, 'ptmarket_portal sem EXECUTE explícito em funções');

-- ---------------------------------------------------------------------------
-- 1. Dados (migrator: tenants, entidades; app: lojas, produtos, variantes, patrocínios).
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code, is_active) VALUES
    ('00000000-0000-7000-8000-0000000040a0', 'ps-npt', 'ps-npt.teste.invalid', 'Nacional PT 40', 'national_portal', 'PT', true),
    ('00000000-0000-7000-8000-0000000040c1', 'ps-ca', 'ps-ca.teste.invalid', 'Canal A 40', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-0000000040c2', 'ps-cb', 'ps-cb.teste.invalid', 'Canal B 40', 'municipal', 'PT', true);

INSERT INTO sponsor_entities (id, kind, country_code, name, slug, channel_tenant_id) VALUES
    ('00000000-0000-7000-8000-0000000040e1', 'association', 'PT', 'Associação A 40', 'ps-assoc-a',
     '00000000-0000-7000-8000-0000000040c1'),
    ('00000000-0000-7000-8000-0000000040e2', 'association', 'PT', 'Associação B 40', 'ps-assoc-b',
     '00000000-0000-7000-8000-0000000040c2');

SET ROLE ptmarket_app;
SELECT pg_temp.ctx('admin', '');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000040a0', true);

INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, is_active)
SELECT format('00000000-0000-7000-8000-0000000040b%s', n)::uuid, '00000000-0000-7000-8000-0000000040a0',
       format('Loja S%s', n), format('ps-s%s', n), format('S%s Lda', n), format('5000040%s', lpad(n::text, 2, '0')),
       format('PT500000000000000000040%s', lpad(n::text, 2, '0')), format('s%s@teste.invalid', n), n <> 4
FROM generate_series(1, 4) AS n;

INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps, is_published) VALUES
    ('00000000-0000-7000-8000-00000040f101', '00000000-0000-7000-8000-0000000040a0',
     '00000000-0000-7000-8000-0000000040b1', '{"pt":"Pão de Mafra"}', 600, true),
    ('00000000-0000-7000-8000-00000040f102', '00000000-0000-7000-8000-0000000040a0',
     '00000000-0000-7000-8000-0000000040b1', '{"pt":"Pão de ló"}', 600, false),
    ('00000000-0000-7000-8000-00000040f103', '00000000-0000-7000-8000-0000000040a0',
     '00000000-0000-7000-8000-0000000040b1', '{"pt":"Pão com chouriço"}', 600, true),
    ('00000000-0000-7000-8000-00000040f201', '00000000-0000-7000-8000-0000000040a0',
     '00000000-0000-7000-8000-0000000040b2', '{"pt":"PÃO caseiro"}', 600, true),
    ('00000000-0000-7000-8000-00000040f301', '00000000-0000-7000-8000-0000000040a0',
     '00000000-0000-7000-8000-0000000040b3', '{"pt":"Queijo da Serra","es":"Queso de la Sierra"}', 600, true),
    ('00000000-0000-7000-8000-00000040f302', '00000000-0000-7000-8000-0000000040a0',
     '00000000-0000-7000-8000-0000000040b3', '{"pt":"Bolo de mel"}', 600, true),
    ('00000000-0000-7000-8000-00000040f401', '00000000-0000-7000-8000-0000000040a0',
     '00000000-0000-7000-8000-0000000040b4', '{"pt":"Pão alentejano"}', 600, true);

INSERT INTO product_variants (tenant_id, product_id, price_cents, stock_qty, is_active)
SELECT '00000000-0000-7000-8000-0000000040a0', p.id, 250, 3, p.id <> '00000000-0000-7000-8000-00000040f103'
FROM (VALUES ('00000000-0000-7000-8000-00000040f101'::uuid), ('00000000-0000-7000-8000-00000040f102'),
             ('00000000-0000-7000-8000-00000040f103'), ('00000000-0000-7000-8000-00000040f201'),
             ('00000000-0000-7000-8000-00000040f301'), ('00000000-0000-7000-8000-00000040f302'),
             ('00000000-0000-7000-8000-00000040f401')) AS p(id);

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('00000000-0000-7000-8000-000000040101', '00000000-0000-7000-8000-0000000040b1',
         '00000000-0000-7000-8000-0000000040e1'),
        ('00000000-0000-7000-8000-000000040102', '00000000-0000-7000-8000-0000000040b2',
         '00000000-0000-7000-8000-0000000040e2'),
        ('00000000-0000-7000-8000-000000040104', '00000000-0000-7000-8000-0000000040b4',
         '00000000-0000-7000-8000-0000000040e1')
    ) AS v(id, store_id, sponsor_entity_id) LOOP
        PERFORM set_config('app.store_id', r.store_id, true);
        INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id)
        VALUES (r.id::uuid, '00000000-0000-7000-8000-0000000040a0', r.store_id::uuid, r.sponsor_entity_id::uuid);
    END LOOP;
    PERFORM set_config('app.store_id', '', true);
END
$$;
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
WHERE id IN ('00000000-0000-7000-8000-000000040101', '00000000-0000-7000-8000-000000040102',
             '00000000-0000-7000-8000-000000040104');

-- ---------------------------------------------------------------------------
-- 2. Caixa negra: INSERT/UPDATE de products não gravam nada de pesquisa no evento L1.
-- ---------------------------------------------------------------------------
UPDATE products SET title = '{"pt":"Bolo do caco"}' WHERE id = '00000000-0000-7000-8000-00000040f302';
SELECT set_config('app.impersonator_id', '', true);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'products.insert' AND target_id = '00000000-0000-7000-8000-00000040f101'
         AND changes->'after'->'title'->>'pt' = 'Pão de Mafra'$q$,
    1, 'L1: products.insert de F101 gravado');
SELECT pg_temp.expect_count(
    $q$SELECT count(*)
       FROM audit.audit_events e
       CROSS JOIN LATERAL (VALUES (e.changes->'before'), (e.changes->'after')) AS s(obj)
       CROSS JOIN LATERAL jsonb_object_keys(CASE WHEN jsonb_typeof(s.obj) = 'object' THEN s.obj ELSE '{}' END) AS k
       WHERE e.action IN ('products.insert', 'products.update')
         AND e.target_id LIKE '00000000-0000-7000-8000-00000040f%'
         AND k NOT IN (SELECT a.attname FROM pg_attribute a
                       WHERE a.attrelid = 'public.products'::regclass AND a.attnum > 0 AND NOT a.attisdropped
                         AND a.attgenerated = '')$q$,
    0, 'L1: eventos de products só com colunas reais (nenhuma chave de pesquisa)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action IN ('products.insert', 'products.update')
         AND target_id LIKE '00000000-0000-7000-8000-00000040f%'
         AND (changes::text LIKE '%''mafra'':%' OR changes::text LIKE '%''caco'':%' OR changes::text LIKE '%tsv%')$q$,
    0, 'L1: nenhum tsvector nos eventos de products');
SELECT pg_temp.expect_text(
    $q$SELECT string_agg(k, ',' ORDER BY k) FROM audit.audit_events e, jsonb_object_keys(e.changes->'after') k
       WHERE e.action = 'products.update' AND e.target_id = '00000000-0000-7000-8000-00000040f302'$q$,
    'title', 'L1: products.update do título grava só title');

-- ---------------------------------------------------------------------------
-- 3. Pesquisa no canal nacional: acentos, maiúsculas, E, ES, texto vazio, operadores, injeção.
-- ---------------------------------------------------------------------------
SELECT pg_temp.ctx('customer', '');
SET app.portal_national = 'on';
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('pao')$q$, 'PÃO caseiro|Pão de Mafra',
    'nacional: "pao" encontra "Pão de Mafra" e "PÃO caseiro" (sem não publicado, só-variante-inativa, loja inativa)');
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('PÃO')$q$, 'PÃO caseiro|Pão de Mafra', 'nacional: "PÃO" = "pao"');
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('pão mafra')$q$, 'Pão de Mafra', 'dois termos = E');
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('mafra pao')$q$, 'Pão de Mafra', 'dois termos em qualquer ordem');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao queijo', NULL, 10)$q$, 0,
    'dois termos sem produto com ambos → 0');
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('queso sierra')$q$, 'Queijo da Serra', 'título es pesquisável');
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('"de mafra" -bolo')$q$, 'Pão de Mafra', 'frase e exclusão');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('"pao de" -mafra', NULL, 10)$q$, 0,
    '"pao de" -mafra → 0 (o "Pão de ló" não está publicado)');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('chourico', NULL, 10)$q$, 0,
    'produto só com variante inativa nunca sai');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('alentejano', NULL, 10)$q$, 0,
    'produto de loja inativa nunca sai');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('', NULL, 10)$q$, 0, 'texto vazio → 0');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('   ', NULL, 10)$q$, 0, 'só espaços → 0');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids(NULL, NULL, 10)$q$, 0, 'NULL → 0');
-- Só operadores/pontuação: tsquery vazia → NOTICE do PostgreSQL, sem erro.
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('!!! -- "" ()', NULL, 10)$q$, 0,
    'texto sem lexemas → 0 sem erro');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids($i$' OR 1=1$i$, NULL, 10)$q$, 0,
    $l$' OR 1=1 → 0 sem erro$l$);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM public.portal_search_product_ids($i$pao'); DROP TABLE products; --$i$, NULL, 10)$q$, 0,
    'injeção → só texto (0 linhas, sem erro)');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids(repeat('pão ', 5000), NULL, 10)$q$, 2,
    'texto longo cortado a 200 caracteres');
SELECT pg_temp.ctx('admin', '');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM products WHERE id = '00000000-0000-7000-8000-00000040f101'$q$, 1,
    'products intacta depois da tentativa de injeção');
SELECT pg_temp.ctx('customer', '');

RESET app.portal_national;
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, 10)$q$, 0,
    'nacional sem a flag → 0');
SET app.portal_national = 'on';

-- ---------------------------------------------------------------------------
-- 4. Canais white-label e sem contexto.
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000040c1', true);
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('pao')$q$, 'Pão de Mafra',
    'canal A: só lojas patrocinadas por A (S1; S4 inativa)');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('queijo', NULL, 10)$q$, 0,
    'canal A: loja sem patrocínio fora');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000040c2', true);
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('pao')$q$, 'PÃO caseiro', 'canal B: só S2');
SELECT set_config('app.current_tenant_id', '', true);
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, 10)$q$, 0,
    'contexto vazio → 0');
RESET app.current_tenant_id;
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, 10)$q$, 0,
    'sem contexto → 0');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000040a0', true);

-- A app não chega a products por ptmarket_search.
SELECT pg_temp.expect_error('SET ROLE ptmarket_search', '42501', 'ptmarket_app: SET ROLE ptmarket_search → 42501');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) WHERE pg_has_role('ptmarket_app', 'ptmarket_search', 'MEMBER')$q$, 0,
    'ptmarket_app não é membro de ptmarket_search');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'ptmarket_app em modo portal: products direto → 0');

-- ---------------------------------------------------------------------------
-- 5. Escala (5000+ produtos): limite, cursor, plano com o GIN (custom e genérico).
-- ---------------------------------------------------------------------------
SELECT pg_temp.ctx('admin', '');
INSERT INTO products (tenant_id, store_id, title, vat_rate_bps, is_published)
SELECT '00000000-0000-7000-8000-0000000040a0', '00000000-0000-7000-8000-0000000040b1',
       jsonb_build_object('pt', 'Massa ' || n), 600, true
FROM generate_series(1, 5000) AS n;
INSERT INTO products (tenant_id, store_id, title, vat_rate_bps, is_published)
SELECT '00000000-0000-7000-8000-0000000040a0', '00000000-0000-7000-8000-0000000040b1',
       jsonb_build_object('pt', 'Pão escala ' || n), 600, true
FROM generate_series(1, 60) AS n;
INSERT INTO product_variants (tenant_id, product_id, price_cents, stock_qty, is_active)
SELECT p.tenant_id, p.id, 100, 1, true FROM products p WHERE p.title->>'pt' LIKE 'Pão escala %';
SELECT pg_temp.ctx('customer', '');
RESET ROLE;
ANALYZE products;
ANALYZE product_variants;
ANALYZE stores;
ANALYZE store_sponsorships;
ANALYZE tenants;
SET ROLE ptmarket_app;

SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, 1000)$q$, 49,
    'p_limit 1000 → 49');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, 2147483647)$q$, 49,
    'p_limit máximo do int → 49');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, 0)$q$, 1, 'p_limit 0 → 1');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, -5)$q$, 1,
    'p_limit negativo → 1');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, NULL)$q$, 1,
    'p_limit NULL → 1');
SELECT pg_temp.expect_count(
    $q$WITH p1 AS (SELECT s.id FROM public.portal_search_product_ids('pao', NULL, 24) AS s(id)),
            p2 AS (SELECT s.id FROM public.portal_search_product_ids('pao', (SELECT id FROM p1 ORDER BY id LIMIT 1), 49) AS s(id))
       SELECT (SELECT count(*) FROM p1) * 1000 + (SELECT count(*) FROM p2) * 10
              + (SELECT count(*) FROM p2 WHERE id >= (SELECT id FROM p1 ORDER BY id LIMIT 1))$q$,
    24380, 'cursor: 24 + 38 (62 visíveis), a 2.ª página toda abaixo do cursor');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (SELECT s.id, lag(s.id) OVER (ORDER BY o) AS prev
                             FROM public.portal_search_product_ids('pao', NULL, 49) WITH ORDINALITY AS s(id, o)) x
       WHERE x.prev IS NOT NULL AND x.prev <= x.id$q$,
    0, 'ordem id DESC (mais recentes primeiro)');
SET plan_cache_mode = force_generic_plan;
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('pao', NULL, 49)$q$, 49,
    'plano genérico: mesmo resultado');
SELECT pg_temp.expect_text($q$SELECT pg_temp.titles('mafra')$q$, 'Pão de Mafra', 'plano genérico: termo raro');
SELECT pg_temp.expect_count($q$SELECT count(*) FROM public.portal_search_product_ids('', NULL, 49)$q$, 0,
    'plano genérico: texto vazio → 0');
RESET plan_cache_mode;

-- Plano da consulta da função, como a dona (DEFINER temporária de ptmarket_search que prepara o corpo real da
-- função com $1..$3 no lugar dos parâmetros). Só nesta transação (ROLLBACK): o migrator recebe SET em
-- ptmarket_search e ptmarket_search CREATE em public para o ALTER … OWNER (sem TEMP na BD, pg_temp não serve).
RESET ROLE;
DO $$
BEGIN
    EXECUTE format('GRANT ptmarket_search TO %I WITH INHERIT FALSE, SET TRUE', current_user);
END
$$;
CREATE FUNCTION public.zz_test_search_plan(p_query text, p_generic boolean)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $f$
DECLARE
    v_body text;
    v_line text;
    v_plan text := '';
BEGIN
    SELECT prosrc INTO v_body FROM pg_proc
    WHERE oid = 'public.portal_search_product_ids(text, uuid, integer)'::regprocedure;
    v_body := regexp_replace(v_body, '\mp_query\M', '$1', 'g');
    v_body := regexp_replace(v_body, '\mp_after\M', '$2', 'g');
    v_body := regexp_replace(v_body, '\mp_limit\M', '$3', 'g');
    EXECUTE 'PREPARE ps_search_plan(text, uuid, integer) AS ' || v_body;
    PERFORM set_config('plan_cache_mode',
                       CASE WHEN p_generic THEN 'force_generic_plan' ELSE 'force_custom_plan' END, true);
    FOR v_line IN EXECUTE format('EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF, BUFFERS OFF) '
                                 'EXECUTE ps_search_plan(%L, NULL, 24)', p_query) LOOP
        v_plan := v_plan || v_line || E'\n';
    END LOOP;
    DEALLOCATE ps_search_plan;
    PERFORM set_config('plan_cache_mode', 'auto', true);
    RETURN v_plan;
END
$f$;
GRANT CREATE ON SCHEMA public TO ptmarket_search;
ALTER FUNCTION public.zz_test_search_plan(text, boolean) OWNER TO ptmarket_search;
REVOKE CREATE ON SCHEMA public FROM ptmarket_search;

CREATE FUNCTION pg_temp.expect_gin(p_query text, p_generic boolean, p_max numeric, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_plan text := public.zz_test_search_plan(p_query, p_generic);
    v_rows numeric := substring(v_plan FROM 'Bitmap Index Scan on products_search_idx \(actual rows=([0-9.]+)')::numeric;
BEGIN
    IF v_plan LIKE '%Seq Scan on products %' OR v_plan NOT LIKE '%Bitmap Heap Scan on products ps %'
       OR v_plan LIKE '% Index Scan using % on products ps %' OR v_plan LIKE '%Index Only Scan using % on products ps %'
       OR v_rows IS NULL OR v_rows > p_max THEN
        RAISE EXCEPTION 'FALHOU: % (esperado Bitmap Index Scan em products_search_idx com <= % linhas, sem Seq Scan '
                        'em products; lidas %)%', p_label, p_max, v_rows, E'\n' || v_plan;
    END IF;
    RAISE NOTICE 'OK: % (% linhas do GIN)', p_label, v_rows;
END
$$;

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class WHERE oid = 'public.products'::regclass AND reltuples >= 5000$q$,
    1, 'escala: products com 5000+ linhas (estatísticas)');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000040a0', true);
SELECT set_config('app.portal_national', 'on', true);
SELECT pg_temp.expect_gin('pao', false, 70, 'plano custom: "pao" lê o GIN (~63 linhas), sem Seq Scan');
SELECT pg_temp.expect_gin('pao', true, 70, 'plano genérico (force_generic_plan): "pao" lê o GIN, sem Seq Scan');
SELECT pg_temp.expect_gin('mafra', false, 2, 'plano custom: termo raro lê 1 linha do GIN');
SELECT pg_temp.expect_gin('mafra', true, 2, 'plano genérico: termo raro lê 1 linha do GIN');

ROLLBACK;
