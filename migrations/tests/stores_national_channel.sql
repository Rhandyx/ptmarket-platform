-- Teste 0030: lojas para o canal nacional do país (spec 14 §1). O corpo da migration (bloco DO) está copiado tal e
-- qual em pg_temp.move_stores(), para correr com dados semeados depois da migration (as FKs já têm ON UPDATE CASCADE:
-- o bloco é idempotente e não as refaz).
-- Cenário: canal nacional PT (NPT) e municipais PT (MA, MB) e ES (MES). Lojas SA (MA, slug padaria), SB (MB), SN
-- (já no NPT), SES (MES, slug padaria: outro país, sem colisão). Produtos, variantes e histórico Omnibus em SA e SB.
-- Papéis: X merchant_owner de SA, Y merchant_staff de SB, T tenant_admin de MA.
-- Falhas (nada muda): país sem national_portal ativo (ES); slug repetido no mesmo canal (PT).
-- Seed das lojas/produtos com SET ROLE ptmarket_app; users/user_roles e asserções pelo dono das migrations com FORCE
-- RLS desligado só nesta transação. Tudo com ROLLBACK.
BEGIN;

SELECT set_config('app.actor_label', 'test', true);

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_state text, p_msg_like text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = p_state AND v_msg LIKE p_msg_like THEN
            RAISE NOTICE 'OK: % (%)', p_label, v_msg;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado % %, obtido %: %)', p_label, p_state, p_msg_like, v_state, v_msg;
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

CREATE FUNCTION pg_temp.as_actor(p_type text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', p_type, true);
END
$$;

-- FORCE RLS das tabelas do teste (o dono só vê as linhas com FORCE desligado).
CREATE FUNCTION pg_temp.force_rls(p_on boolean)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_t text;
BEGIN
    FOREACH v_t IN ARRAY ARRAY['stores', 'products', 'product_variants', 'product_price_history', 'user_roles', 'users']
    LOOP
        EXECUTE format('ALTER TABLE %I %s FORCE ROW LEVEL SECURITY', v_t, CASE WHEN p_on THEN '' ELSE 'NO' END);
    END LOOP;
END
$$;

-- Corpo da 0030 (copiado do bloco DO, sem alterações).
CREATE FUNCTION pg_temp.move_stores()
RETURNS void LANGUAGE plpgsql AS $mv$
DECLARE
    v_fk         record;
    v_ddl        text[] := '{}';
    v_tables     regclass[];
    v_forced     regclass[];
    v_t          regclass;
    v_bad        text;
    v_n          bigint;
    v_before     jsonb := '{}';
    v_after      jsonb := '{}';
    v_moved      bigint;
BEGIN
    -- -----------------------------------------------------------------------
    -- Descoberta (só catálogo): FKs que dependem de stores, direta ou indiretamente, por tenant_id.
    -- -----------------------------------------------------------------------
    FOR v_fk IN
        WITH RECURSIVE dep AS (
            SELECT c.oid, c.conrelid, c.confrelid
            FROM pg_constraint c
            WHERE c.contype = 'f' AND c.confrelid = 'public.stores'::regclass
            UNION
            SELECT c.oid, c.conrelid, c.confrelid
            FROM pg_constraint c
            JOIN dep d ON c.confrelid = d.conrelid
            JOIN LATERAL (
                -- só se desce por FKs ligadas pelo tenant_id
                SELECT 1 FROM pg_constraint p
                WHERE p.oid = d.oid
                  AND EXISTS (
                      SELECT 1 FROM unnest(p.conkey, p.confkey) AS k(ck, pk)
                      JOIN pg_attribute ca ON ca.attrelid = p.conrelid AND ca.attnum = k.ck
                      JOIN pg_attribute pa ON pa.attrelid = p.confrelid AND pa.attnum = k.pk
                      WHERE ca.attname = 'tenant_id' AND pa.attname = 'tenant_id')
            ) linked ON true
            WHERE c.contype = 'f'
        )
        SELECT c.oid, c.conname, c.conrelid::regclass AS child, c.confrelid::regclass AS parent,
               c.confupdtype, c.confdeltype, c.confmatchtype, c.condeferrable, c.convalidated, c.confdelsetcols,
               EXISTS (
                   SELECT 1 FROM unnest(c.conkey, c.confkey) AS k(ck, pk)
                   JOIN pg_attribute ca ON ca.attrelid = c.conrelid AND ca.attnum = k.ck
                   JOIN pg_attribute pa ON pa.attrelid = c.confrelid AND pa.attnum = k.pk
                   WHERE ca.attname = 'tenant_id' AND pa.attname = 'tenant_id') AS by_tenant,
               EXISTS (
                   SELECT 1 FROM pg_attribute a
                   WHERE a.attrelid = c.conrelid AND a.attname = 'tenant_id' AND NOT a.attisdropped) AS child_has_tenant,
               (SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY k.i)
                FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, i)
                JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum) AS child_cols,
               (SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY k.i)
                FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, i)
                JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum) AS parent_cols
        FROM (SELECT DISTINCT oid FROM dep) d
        JOIN pg_constraint c ON c.oid = d.oid
        ORDER BY c.conrelid::regclass::text, c.conname
    LOOP
        IF NOT v_fk.by_tenant THEN
            IF v_fk.child_has_tenant THEN
                RAISE EXCEPTION '0030: a FK % de % para % não leva tenant_id; a tabela ficaria com o tenant antigo',
                    v_fk.conname, v_fk.child, v_fk.parent;
            END IF;
            CONTINUE; -- tabela sem tenant_id: a mudança de tenant não a afeta
        END IF;

        v_tables := array_append(v_tables, v_fk.child);

        IF v_fk.confupdtype = 'c' THEN
            CONTINUE; -- já tem ON UPDATE CASCADE
        END IF;
        IF v_fk.confupdtype <> 'a' OR v_fk.confmatchtype <> 's' OR v_fk.condeferrable OR NOT v_fk.convalidated
           OR v_fk.confdelsetcols IS NOT NULL THEN
            RAISE EXCEPTION '0030: FK % em % com forma inesperada (update %, match %, deferrable %, validada %); refazer à mão',
                v_fk.conname, v_fk.child, v_fk.confupdtype, v_fk.confmatchtype, v_fk.condeferrable, v_fk.convalidated;
        END IF;

        v_ddl := v_ddl || format('ALTER TABLE %s DROP CONSTRAINT %I', v_fk.child, v_fk.conname);
        v_ddl := v_ddl || format(
            'ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (%s) REFERENCES %s (%s) ON UPDATE CASCADE ON DELETE %s',
            v_fk.child, v_fk.conname, v_fk.child_cols, v_fk.parent, v_fk.parent_cols,
            CASE v_fk.confdeltype
                WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE'
                WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT'
            END);
    END LOOP;

    SELECT array_agg(DISTINCT t ORDER BY t) INTO v_tables
    FROM unnest(array_prepend('public.stores'::regclass, v_tables)) AS t;

    -- -----------------------------------------------------------------------
    -- RLS: o dono passa a ver as linhas só nesta transação (reposto e verificado no fim).
    -- -----------------------------------------------------------------------
    SELECT array_agg(c.oid::regclass ORDER BY c.oid::regclass) INTO v_forced
    FROM pg_class c WHERE c.oid = ANY (v_tables) AND c.relforcerowsecurity;
    FOREACH v_t IN ARRAY COALESCE(v_forced, '{}') LOOP
        EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY', v_t);
    END LOOP;

    -- -----------------------------------------------------------------------
    -- 1. Pré-condições (nada mudou ainda nos dados).
    -- -----------------------------------------------------------------------
    SELECT string_agg(format('%s (%s national_portal ativos)', x.country_code, x.n), ', ' ORDER BY x.country_code)
    INTO v_bad
    FROM (
        SELECT t.country_code,
               (SELECT count(*) FROM tenants n
                WHERE n.tenant_type = 'national_portal' AND n.is_active AND n.country_code = t.country_code) AS n
        FROM stores s JOIN tenants t ON t.id = s.tenant_id
        GROUP BY t.country_code
    ) x
    WHERE x.n <> 1;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '0030: cada país com lojas precisa de exatamente um national_portal ativo; falha em: %', v_bad;
    END IF;

    SELECT string_agg(format('canal %s, slug %L: %s', x.national_slug, x.slug, x.stores), '; '
                      ORDER BY x.national_slug, x.slug)
    INTO v_bad
    FROM (
        SELECT n.slug AS national_slug, s.slug,
               string_agg(format('loja %s (tenant %s)', s.id, t.slug), ', ' ORDER BY t.slug, s.id) AS stores
        FROM stores s
        JOIN tenants t ON t.id = s.tenant_id
        JOIN tenants n ON n.tenant_type = 'national_portal' AND n.is_active AND n.country_code = t.country_code
        GROUP BY n.id, n.slug, s.slug
        HAVING count(*) > 1
    ) x;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '0030: slugs repetidos no mesmo canal nacional (renomear à mão antes): %', v_bad;
    END IF;

    FOREACH v_t IN ARRAY v_tables LOOP
        EXECUTE format('SELECT count(*) FROM %s', v_t) INTO v_n;
        v_before := v_before || jsonb_build_object(v_t::text, v_n);
    END LOOP;

    -- -----------------------------------------------------------------------
    -- 2-3. FKs com ON UPDATE CASCADE; depois o UPDATE em stores (filhas pela cascata).
    -- -----------------------------------------------------------------------
    FOR v_n IN 1 .. COALESCE(array_length(v_ddl, 1), 0) LOOP
        EXECUTE v_ddl[v_n];
    END LOOP;

    UPDATE stores s
    SET tenant_id = n.id
    FROM tenants t, tenants n
    WHERE t.id = s.tenant_id
      AND n.tenant_type = 'national_portal' AND n.is_active AND n.country_code = t.country_code
      AND s.tenant_id <> n.id;
    GET DIAGNOSTICS v_moved = ROW_COUNT;

    -- -----------------------------------------------------------------------
    -- 5. Verificação final.
    -- -----------------------------------------------------------------------
    SELECT count(*) INTO v_n
    FROM stores s JOIN tenants t ON t.id = s.tenant_id
    WHERE NOT (t.tenant_type = 'national_portal' AND t.is_active);
    IF v_n <> 0 THEN
        RAISE EXCEPTION '0030: % lojas ficaram fora de um national_portal ativo', v_n;
    END IF;

    FOREACH v_t IN ARRAY v_tables LOOP
        EXECUTE format('SELECT count(*) FROM %s', v_t) INTO v_n;
        v_after := v_after || jsonb_build_object(v_t::text, v_n);
    END LOOP;
    IF v_after IS DISTINCT FROM v_before THEN
        RAISE EXCEPTION '0030: contagens mudaram (antes %, depois %)', v_before, v_after;
    END IF;

    FOREACH v_t IN ARRAY COALESCE(v_forced, '{}') LOOP
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', v_t);
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = ANY (v_forced) AND NOT c.relforcerowsecurity) THEN
        RAISE EXCEPTION '0030: FORCE RLS não reposto';
    END IF;

    RAISE NOTICE '0030: % lojas movidas; % FKs refeitas; contagens antes % / depois %',
        v_moved, COALESCE(array_length(v_ddl, 1), 0) / 2, v_before, v_after;
END
$mv$;

-- ---------------------------------------------------------------------------
-- 0. A migration (já aplicada) só mudou as FKs: ON UPDATE CASCADE, mesmo nome, mesmo ON DELETE.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_constraint c
       WHERE c.contype = 'f' AND c.confupdtype = 'c'
         AND (c.conrelid, c.conname, c.confdeltype) IN (
             ('products'::regclass, 'products_tenant_id_store_id_fkey', 'c'),
             ('user_roles'::regclass, 'user_roles_store_fkey', 'c'),
             ('product_variants'::regclass, 'product_variants_tenant_id_product_id_fkey', 'c'),
             ('product_price_history'::regclass, 'product_price_history_tenant_id_variant_id_fkey', 'r'))$q$,
    4, 'FKs compostas com ON UPDATE CASCADE e o mesmo ON DELETE');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE relname IN ('stores', 'products', 'product_variants', 'product_price_history', 'user_roles')
         AND relnamespace = 'public'::regnamespace AND relrowsecurity AND relforcerowsecurity$q$,
    5, 'RLS e FORCE RLS intactos depois da migration');

-- ---------------------------------------------------------------------------
-- 1. Preparação.
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000030a0', 'snc-npt', 'snc-npt.teste.invalid', 'Nacional PT 30', 'national_portal', 'PT'),
    ('00000000-0000-7000-8000-0000000030a1', 'snc-ma', 'snc-ma.teste.invalid', 'Municipal A 30', 'municipal', 'PT'),
    ('00000000-0000-7000-8000-0000000030a2', 'snc-mb', 'snc-mb.teste.invalid', 'Municipal B 30', 'municipal', 'PT'),
    ('00000000-0000-7000-8000-0000000030a3', 'snc-mes', 'snc-mes.teste.invalid', 'Municipal ES 30', 'municipal', 'ES');

SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('system');

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000030a1', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000030b1', '00000000-0000-7000-8000-0000000030a1',
     'Loja SA', 'padaria', 'Loja SA Lda', '500003001', 'PT50000000000000000003001', 'sa@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000030c1', '00000000-0000-7000-8000-0000000030a1',
     '00000000-0000-7000-8000-0000000030b1', '{"pt":"Pão"}', 600);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-0000000030d1', '00000000-0000-7000-8000-0000000030a1',
     '00000000-0000-7000-8000-0000000030c1', 1000);
UPDATE product_variants SET price_cents = 1200 WHERE id = '00000000-0000-7000-8000-0000000030d1';
UPDATE product_variants SET price_cents = 900 WHERE id = '00000000-0000-7000-8000-0000000030d1';

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000030a2', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000030b2', '00000000-0000-7000-8000-0000000030a2',
     'Loja SB', 'talho', 'Loja SB Lda', '500003002', 'PT50000000000000000003002', 'sb@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000030c2', '00000000-0000-7000-8000-0000000030a2',
     '00000000-0000-7000-8000-0000000030b2', '{"pt":"Bife"}', 600);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-0000000030d2', '00000000-0000-7000-8000-0000000030a2',
     '00000000-0000-7000-8000-0000000030c2', 500);

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000030a0', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000030b3', '00000000-0000-7000-8000-0000000030a0',
     'Loja SN', 'ja-nacional', 'Loja SN Lda', '500003003', 'PT50000000000000000003003', 'sn@teste.invalid');

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000030a3', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000030b4', '00000000-0000-7000-8000-0000000030a3',
     'Loja SES', 'padaria', 'Loja SES SL', 'B30000004', 'ES9100000000000000003004', 'ses@teste.invalid');

SELECT pg_temp.as_actor('');
RESET ROLE;

SELECT pg_temp.force_rls(false);
INSERT INTO users (id, email, password_hash, full_name, totp_secret_enc, totp_enabled, is_active) VALUES
    ('00000000-0000-7000-8000-0000000030e1', 'x.30@teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$WDMw$WDMx',
     'Xico Dono', NULL, false, true),
    ('00000000-0000-7000-8000-0000000030e2', 'y.30@teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$WTMw$WTMx',
     'Yolanda Staff', NULL, false, true),
    ('00000000-0000-7000-8000-0000000030e3', 't.30@teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$VDMw$VDMx',
     'Teresa Camara', NULL, false, true);
INSERT INTO user_roles (id, user_id, role, tenant_id, store_id) VALUES
    ('00000000-0000-7000-8000-0000000030f1', '00000000-0000-7000-8000-0000000030e1', 'merchant_owner',
     '00000000-0000-7000-8000-0000000030a1', '00000000-0000-7000-8000-0000000030b1'),
    ('00000000-0000-7000-8000-0000000030f2', '00000000-0000-7000-8000-0000000030e2', 'merchant_staff',
     '00000000-0000-7000-8000-0000000030a2', '00000000-0000-7000-8000-0000000030b2'),
    ('00000000-0000-7000-8000-0000000030f3', '00000000-0000-7000-8000-0000000030e3', 'tenant_admin',
     '00000000-0000-7000-8000-0000000030a1', NULL);

-- Fotografia antes (histórico Omnibus, variantes, papéis e tenants).
CREATE TEMP TABLE snc_hist AS
    SELECT id, variant_id, price_cents, recorded_at FROM product_price_history
    WHERE variant_id IN ('00000000-0000-7000-8000-0000000030d1', '00000000-0000-7000-8000-0000000030d2');
CREATE TEMP TABLE snc_var AS
    SELECT id, product_id, price_cents, lowest_price_30d_cents, updated_at FROM product_variants
    WHERE id IN ('00000000-0000-7000-8000-0000000030d1', '00000000-0000-7000-8000-0000000030d2');
CREATE TEMP TABLE snc_tenants AS SELECT * FROM tenants;
CREATE TEMP TABLE snc_counts AS
    SELECT 'stores' AS t, count(*) AS n FROM stores
    UNION ALL SELECT 'products', count(*) FROM products
    UNION ALL SELECT 'product_variants', count(*) FROM product_variants
    UNION ALL SELECT 'product_price_history', count(*) FROM product_price_history
    UNION ALL SELECT 'user_roles', count(*) FROM user_roles;
SELECT pg_temp.expect_count('SELECT count(*) FROM snc_hist', 4, 'seed: 4 linhas de histórico (3 em SA, 1 em SB)');
SELECT pg_temp.force_rls(true);

-- Estado inicial (para provar que as falhas não mudam nada).
CREATE FUNCTION pg_temp.stores_state()
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v text;
BEGIN
    PERFORM pg_temp.force_rls(false);
    SELECT string_agg(s.id || '@' || s.tenant_id, ',' ORDER BY s.id) INTO v FROM stores s
    WHERE s.id::text LIKE '00000000-0000-7000-8000-0000000030b%';
    SELECT v || '|' || string_agg(p.id || '@' || p.tenant_id, ',' ORDER BY p.id) INTO v FROM products p
    WHERE p.id::text LIKE '00000000-0000-7000-8000-0000000030c%';
    SELECT v || '|' || string_agg(r.id || '@' || COALESCE(r.tenant_id::text, '-'), ',' ORDER BY r.id) INTO v
    FROM user_roles r WHERE r.id::text LIKE '00000000-0000-7000-8000-0000000030f%';
    PERFORM pg_temp.force_rls(true);
    RETURN v;
END
$$;
CREATE TEMP TABLE snc_state AS SELECT pg_temp.stores_state() AS s;

-- ---------------------------------------------------------------------------
-- 2. Falhas: abortam com mensagem clara e nada muda.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error('SELECT pg_temp.move_stores()', 'P0001',
    '%national_portal ativo; falha em: ES (0 national_portal ativos)%', 'país sem national_portal ativo aborta');
SELECT pg_temp.expect_count(
    'SELECT (pg_temp.stores_state() = (SELECT s FROM snc_state))::int', 1, 'sem national_portal: nada mudou');

-- ES: um national_portal inativo não conta; só o ativo.
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code, is_active) VALUES
    ('00000000-0000-7000-8000-0000000030a4', 'snc-nes-old', 'snc-nes-old.teste.invalid', 'Nacional ES antigo 30',
     'national_portal', 'ES', false);
SELECT pg_temp.expect_error('SELECT pg_temp.move_stores()', 'P0001',
    '%falha em: ES (0 national_portal ativos)%', 'national_portal inativo não conta');
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000030a5', 'snc-nes', 'snc-nes.teste.invalid', 'Nacional ES 30',
     'national_portal', 'ES');

-- Slug repetido no canal PT (SA e SC, ambos 'padaria'); SES ('padaria', ES) não colide.
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('system');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000030a2', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000030b9', '00000000-0000-7000-8000-0000000030a2',
     'Loja SC', 'padaria', 'Loja SC Lda', '500003009', 'PT50000000000000000003009', 'sc@teste.invalid');
SELECT pg_temp.as_actor('');
RESET ROLE;
SELECT pg_temp.expect_error('SELECT pg_temp.move_stores()', 'P0001',
    '%slugs repetidos%canal snc-npt, slug ''padaria'': loja 00000000-0000-7000-8000-0000000030b1 (tenant snc-ma), '
    || 'loja 00000000-0000-7000-8000-0000000030b9 (tenant snc-mb)', 'slug repetido no mesmo canal aborta e lista o par');
SELECT pg_temp.force_rls(false);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores WHERE id = '00000000-0000-7000-8000-0000000030b9'
         AND tenant_id = '00000000-0000-7000-8000-0000000030a2' AND slug = 'padaria'$q$,
    1, 'slug repetido: a loja não foi renomeada nem movida');
DELETE FROM stores WHERE id = '00000000-0000-7000-8000-0000000030b9';
SELECT pg_temp.force_rls(true);
SELECT pg_temp.expect_count(
    'SELECT (pg_temp.stores_state() = (SELECT s FROM snc_state))::int', 1, 'slug repetido: nada mudou');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE relname IN ('stores', 'products', 'product_variants', 'product_price_history', 'user_roles')
         AND relnamespace = 'public'::regnamespace AND relforcerowsecurity$q$,
    5, 'falhas: FORCE RLS continua ligado');

-- ---------------------------------------------------------------------------
-- 3. Sucesso.
-- ---------------------------------------------------------------------------
SELECT pg_temp.move_stores();

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE relname IN ('stores', 'products', 'product_variants', 'product_price_history', 'user_roles')
         AND relnamespace = 'public'::regnamespace AND relforcerowsecurity$q$,
    5, 'FORCE RLS reposto depois de mover');

SELECT pg_temp.force_rls(false);

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores
       WHERE (id IN ('00000000-0000-7000-8000-0000000030b1', '00000000-0000-7000-8000-0000000030b2',
                     '00000000-0000-7000-8000-0000000030b3')
              AND tenant_id = '00000000-0000-7000-8000-0000000030a0')
          OR (id = '00000000-0000-7000-8000-0000000030b4' AND tenant_id = '00000000-0000-7000-8000-0000000030a5')$q$,
    4, 'lojas PT no nacional PT, loja ES no nacional ES');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores s JOIN tenants t ON t.id = s.tenant_id
       WHERE NOT (t.tenant_type = 'national_portal' AND t.is_active)$q$,
    0, 'zero lojas fora de um national_portal ativo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores WHERE slug = 'padaria'$q$, 2, 'slugs intactos (padaria em PT e em ES)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE id::text LIKE '00000000-0000-7000-8000-0000000030c%'
         AND tenant_id = '00000000-0000-7000-8000-0000000030a0'$q$,
    2, 'produtos seguiram a loja');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants v JOIN snc_var b USING (id)
       WHERE v.tenant_id = '00000000-0000-7000-8000-0000000030a0'
         AND v.product_id = b.product_id AND v.price_cents = b.price_cents
         AND v.lowest_price_30d_cents IS NOT DISTINCT FROM b.lowest_price_30d_cents
         AND v.updated_at = b.updated_at$q$,
    2, 'variantes seguiram a loja; preço e lowest_price_30d intactos');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history h JOIN snc_hist b USING (id)
       WHERE h.tenant_id = '00000000-0000-7000-8000-0000000030a0'
         AND h.variant_id = b.variant_id AND h.price_cents = b.price_cents AND h.recorded_at = b.recorded_at$q$,
    4, 'histórico Omnibus intacto (mesmas linhas, preços e datas), no nacional');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history
       WHERE variant_id IN ('00000000-0000-7000-8000-0000000030d1', '00000000-0000-7000-8000-0000000030d2')$q$,
    4, 'mover não grava preços novos no histórico');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (
         SELECT 'stores' AS t, count(*) AS n FROM stores
         UNION ALL SELECT 'products', count(*) FROM products
         UNION ALL SELECT 'product_variants', count(*) FROM product_variants
         UNION ALL SELECT 'product_price_history', count(*) FROM product_price_history
         UNION ALL SELECT 'user_roles', count(*) FROM user_roles) a
       JOIN snc_counts b USING (t) WHERE a.n = b.n$q$,
    5, 'contagens por tabela iguais às de antes');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_roles
       WHERE (id = '00000000-0000-7000-8000-0000000030f1' AND role = 'merchant_owner'
              AND tenant_id = '00000000-0000-7000-8000-0000000030a0' AND store_id = '00000000-0000-7000-8000-0000000030b1')
          OR (id = '00000000-0000-7000-8000-0000000030f2' AND role = 'merchant_staff'
              AND tenant_id = '00000000-0000-7000-8000-0000000030a0' AND store_id = '00000000-0000-7000-8000-0000000030b2')
          OR (id = '00000000-0000-7000-8000-0000000030f3' AND role = 'tenant_admin'
              AND tenant_id = '00000000-0000-7000-8000-0000000030a1' AND store_id IS NULL)$q$,
    3, 'merchant_* seguem a loja; tenant_admin fica no seu tenant');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (TABLE snc_tenants EXCEPT TABLE tenants) d$q$, 0, 'tenants: nenhuma linha mudou');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM tenants WHERE id::text LIKE '00000000-0000-7000-8000-0000000030a%'$q$,
    6, 'tenants municipais continuam a existir');
SELECT pg_temp.force_rls(true);

-- Idempotente: segunda passagem não muda nada.
SELECT pg_temp.move_stores();
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE relname IN ('stores', 'products', 'product_variants', 'product_price_history', 'user_roles')
         AND relnamespace = 'public'::regnamespace AND relforcerowsecurity$q$,
    5, '2.ª passagem: FORCE RLS reposto');

-- A app, no contexto do canal nacional PT, vê a loja movida, o produto e o histórico.
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('system');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000030a0', true);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_price_history WHERE variant_id = '00000000-0000-7000-8000-0000000030d1'$q$,
    3, 'app no nacional PT: histórico da variante movida visível');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores WHERE id IN ('00000000-0000-7000-8000-0000000030b1',
                                                '00000000-0000-7000-8000-0000000030b2')$q$,
    2, 'app no nacional PT: lojas movidas visíveis');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000030a1', true);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores$q$, 0, 'app no municipal A: já não tem lojas');
RESET ROLE;

ROLLBACK;
