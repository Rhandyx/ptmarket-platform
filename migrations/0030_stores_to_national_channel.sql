-- 0030 — stores.tenant_id passa para o canal nacional (national_portal ativo) do país do tenant onde a loja estava
--   (cartão 03/05; spec 14 §1). Os tenants municipais continuam como canais; nenhuma linha de tenants muda.
-- Rollback mental (só em dev):
--   As FKs compostas descobertas (hoje: products_tenant_id_store_id_fkey, user_roles_store_fkey,
--   product_variants_tenant_id_product_id_fkey, product_price_history_tenant_id_variant_id_fkey) voltam a ser
--   DROP + ADD com o mesmo nome e o mesmo ON DELETE, SEM ON UPDATE CASCADE.
--   Os dados movidos NÃO voltam sozinhos (o tenant municipal de origem não fica guardado fora da caixa negra:
--   os eventos UPDATE da L1, ator 'db', têm o tenant_id antigo de cada linha). Em dev: recriar a BD.
--
-- Regras:
--   * Uma só transação (sqlx). Pré-condições primeiro (RAISE EXCEPTION, nada muda): cada país com lojas tem
--     exatamente um national_portal ativo; nenhum slug repetido entre lojas que vão para o mesmo canal (lista os
--     pares; nunca renomeia).
--   * FKs: descobertas em pg_constraint a partir de stores, seguindo só FKs que levam tenant_id -> tenant_id. Uma
--     FK para uma dessas tabelas SEM tenant_id, vinda de uma tabela que tem tenant_id, aborta (ficaria com o
--     tenant antigo). Cada FK é refeita com ON UPDATE CASCADE (mesmo nome, mesmo ON DELETE); as que já o têm ficam.
--   * UPDATE só em stores; filhas pela cascata (merchant_* de user_roles seguem a loja; tenant_admin tem
--     store_id NULL e não muda). Guardas Omnibus e caixa negra ficam ligadas: a L1 grava cada linha com ator 'db'.
--   * RLS: stores e filhas têm FORCE RLS sem policy para o dono, por isso o dono não as via. Só dentro desta
--     transação (ACCESS EXCLUSIVE, ninguém vê o intervalo) fica NO FORCE nas tabelas envolvidas e é reposto no fim
--     (verificado). Sem SET ROLE, sem session_replication_role, sem desligar triggers.
--   * Verificação final: zero lojas fora de um national_portal ativo; contagem de cada tabela igual à de antes.
--   * O bloco abaixo é idempotente e está copiado (corpo igual) em migrations/tests/stores_national_channel.sql.

DO $mv$
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
