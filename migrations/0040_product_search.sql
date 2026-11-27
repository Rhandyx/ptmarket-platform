-- 0040 — pesquisa de produtos por texto (FTS sem acentos): índice GIN de expressão + função DEFINER
--   portal_search_product_ids, dona do papel dedicado ptmarket_search (cartão 04/03; spec 11 D9).
-- Rollback mental (só em dev):
--   DROP FUNCTION portal_search_product_ids(text, uuid, integer);
--   DROP POLICY search_read ON products;
--   REVOKE SELECT ON portal_products FROM ptmarket_search (com INHERIT temporário em ptmarket_portal, como abaixo);
--   REVOKE ALL ON products, tenants FROM ptmarket_search;
--   REVOKE EXECUTE ON FUNCTION app_is_national_portal() FROM ptmarket_search;
--   REVOKE USAGE ON SCHEMA public FROM ptmarket_search; DROP ROLE ptmarket_search (o papel é do cluster: só se
--     nenhuma outra BD o usar);
--   DROP INDEX products_search_idx; DROP FUNCTION f_unaccent(text).
--   A extensão unaccent fica. Os eventos ddl.* gravados ficam (caixa negra só de acréscimo).
--
-- DESVIOS AO CARTÃO (aprovados pelo supervisor):
--   1. Sem coluna gerada products.search_tsv: o trigger L1 (audit.audit_row_trigger, 0010) grava to_jsonb(NEW)/
--      to_jsonb(OLD), que inclui colunas STORED geradas; cada products.insert e cada mudança de título levariam o
--      tsvector inteiro para a caixa negra (tirá-lo exigia mexer na máscara selada). Em vez da coluna: índice GIN de
--      EXPRESSÃO, com o texto da expressão igual ao da função (o planeador só usa o índice se coincidir).
--   2. Dona da função = papel dedicado ptmarket_search, não ptmarket_portal: products tem FORCE RLS e, para
--      ptmarket_portal, a policy portal_view (0039) é uma qual de segurança; o @@ e as funções da expressão
--      (to_tsvector, ->>, ||, f_unaccent) não são LEAKPROOF, por isso o planeador nunca os usa como condição de
--      índice por baixo de uma qual de RLS (restriction_is_securely_promotable): provado em dev, a pesquisa lia
--      products_pkey inteira. ptmarket_search tem em products uma policy USING (true) (sem qual de segurança → o GIN
--      é usável), só 4 colunas e nenhum membro; a visibilidade final continua a ser portal_products (view + RLS
--      portal_view de ptmarket_portal), por EXISTS.
--
-- Regras:
--   * Expressão de pesquisa (índice e função, iguais):
--       to_tsvector('simple'::regconfig,
--                   public.f_unaccent(COALESCE(title ->> 'pt', '') || ' ' || COALESCE(title ->> 'es', '')))
--     'simple': sem stemming nem stopwords (PT e ES no mesmo vetor); f_unaccent tira acentos dos dois lados.
--   * f_unaccent(text): wrapper IMMUTABLE de unaccent() (que é STABLE: procura o dicionário no search_path);
--     dicionário qualificado e search_path = pg_catalog fixos, logo o resultado não depende de quem chama. INVOKER.
--     EXECUTE só ptmarket_app (escreve products: a manutenção do índice avalia a expressão como quem escreve) e
--     ptmarket_search.
--   * products_search_idx: GIN parcial WHERE is_published. Exceção documentada a "índices compostos começam por
--     tenant_id": GIN de uma só expressão (a pesquisa não filtra por tenant: o canal resolve-se em portal_stores).
--   * ptmarket_search: NOLOGIN NOINHERIT, sem SUPERUSER/BYPASSRLS/CREATEDB/CREATEROLE/REPLICATION; não é membro de
--     nada e só tem como membro o migrator com o ADMIN implícito do CREATE ROLE (grantor superuser, sem INHERIT nem
--     SET). O SET que o migrator recebe para o ALTER … OWNER é revogado no fim (verificado). Privilégios (todos):
--       USAGE no schema public; SELECT (id, tenant_id, title, is_published) em products + policy search_read
--       FOR SELECT USING (true); SELECT em portal_products; EXECUTE em app_is_national_portal() e f_unaccent(text);
--       SELECT (id, tenant_type, is_active) em tenants (lidos por app_is_national_portal(), INVOKER, chamada dentro de
--       portal_stores: as funções de uma view correm como quem consulta = a dona da DEFINER). tenants não tem RLS.
--     É dono só de portal_search_product_ids.
--   * portal_search_product_ids(p_query, p_after, p_limit) → ids (o Rust lê o resto em portal_products):
--     LANGUAGE sql STABLE SECURITY DEFINER, search_path = pg_catalog, pg_temp; REVOKE ALL FROM PUBLIC; EXECUTE só
--     ptmarket_app. Candidatos pelo GIN numa CTE MATERIALIZED (publicados, texto, cursor id < p_after: o plano parte
--     sempre do índice, também com plano genérico do PG18), depois EXISTS em public.portal_products (publicado, loja
--     em portal_stores do canal, variante ativa). Ordem id DESC (mais recentes primeiro; relevância fica para o
--     motor externo, SearchBackend). Limite 1..49 (NULL, 0 e negativos = 1). Texto NULL, vazio ou só espaços → 0
--     linhas sem tocar no índice; texto só com operadores/pontuação → tsquery vazia (NOTICE do PostgreSQL, sem erro)
--     → 0 linhas. O texto entra só como valor (websearch_to_tsquery não dá erro de sintaxe; sem SQL dinâmico).
--   * Sem SET ROLE (lição L2): donos por ALTER … OWNER TO; CREATE no schema só durante o ALTER. O GRANT em
--     portal_products (dona ptmarket_portal) faz-se com INHERIT temporário em ptmarket_portal, reposto a INHERIT
--     FALSE, SET TRUE (padrão da 0039).

-- ---------------------------------------------------------------------------
-- A. Papel ptmarket_search (do cluster: IF NOT EXISTS + recusa se tiver atributos a mais).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ptmarket_search') THEN
        CREATE ROLE ptmarket_search
            NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'ptmarket_search'
          AND (rolsuper OR rolbypassrls OR rolcanlogin OR rolinherit OR rolcreatedb OR rolcreaterole OR rolreplication)
    ) THEN
        RAISE EXCEPTION '0040: o papel ptmarket_search já existe com atributos a mais (LOGIN, INHERIT, SUPERUSER, '
                        'BYPASSRLS, CREATEDB, CREATEROLE ou REPLICATION); recusado.';
    END IF;

    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_search TO %I WITH INHERIT FALSE, SET TRUE', current_user);
        EXECUTE format('GRANT ptmarket_portal TO %I WITH INHERIT TRUE', current_user);
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- B. unaccent + f_unaccent + índice GIN de expressão.
-- ---------------------------------------------------------------------------
-- unaccent é trusted (como btree_gist na 0031): o migrator (dono da BD) cria-a sem superuser.
CREATE EXTENSION IF NOT EXISTS unaccent WITH SCHEMA public;

CREATE FUNCTION public.f_unaccent(text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path = pg_catalog
AS $$
    SELECT public.unaccent('public.unaccent'::regdictionary, $1)
$$;

COMMENT ON FUNCTION public.f_unaccent(text) IS
    'unaccent() IMMUTABLE (dicionário qualificado, search_path fixo) para o índice products_search_idx (0040)';

REVOKE ALL ON FUNCTION public.f_unaccent(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f_unaccent(text) TO ptmarket_app, ptmarket_search;

CREATE INDEX products_search_idx ON products USING gin (
    (to_tsvector('simple'::regconfig,
                 public.f_unaccent(COALESCE(title ->> 'pt', '') || ' ' || COALESCE(title ->> 'es', ''))))
) WHERE is_published;

COMMENT ON INDEX products_search_idx IS
    'Pesquisa por texto do portal (0040): mesma expressão que portal_search_product_ids; só publicados';

-- ---------------------------------------------------------------------------
-- C. Privilégios de ptmarket_search (todos os que tem).
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO ptmarket_search;
GRANT SELECT (id, tenant_id, title, is_published) ON products TO ptmarket_search;
GRANT SELECT (id, tenant_type, is_active) ON tenants TO ptmarket_search;
GRANT EXECUTE ON FUNCTION public.app_is_national_portal() TO ptmarket_search;
GRANT SELECT ON portal_products TO ptmarket_search; -- como dona (INHERIT temporário em ptmarket_portal)

CREATE POLICY search_read ON products
    AS PERMISSIVE
    FOR SELECT TO ptmarket_search
    USING (true);

COMMENT ON POLICY search_read ON products IS
    'Dona da pesquisa (ptmarket_search, 0040): sem qual de segurança para o GIN ser usável (o @@ não é leakproof); '
    'só 4 colunas; a visibilidade vem do EXISTS em portal_products dentro de portal_search_product_ids';

-- ---------------------------------------------------------------------------
-- D. Função de pesquisa.
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.portal_search_product_ids(p_query text, p_after uuid, p_limit integer)
RETURNS SETOF uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH hits AS MATERIALIZED (
        SELECT ps.tenant_id, ps.id
        FROM public.products ps
        WHERE btrim(COALESCE(p_query, '')) <> ''
          AND to_tsvector('simple'::regconfig,
                          public.f_unaccent(COALESCE(ps.title ->> 'pt', '') || ' ' || COALESCE(ps.title ->> 'es', '')))
              @@ websearch_to_tsquery('simple'::regconfig, public.f_unaccent(left(p_query, 200)))
          AND ps.is_published
          AND (p_after IS NULL OR ps.id < p_after)
    )
    SELECT h.id
    FROM hits h
    WHERE EXISTS (
        SELECT 1
        FROM public.portal_products pp
        WHERE pp.tenant_id = h.tenant_id
          AND pp.id = h.id
    )
    ORDER BY h.id DESC
    LIMIT least(greatest(COALESCE(p_limit, 1), 1), 49)
$$;

COMMENT ON FUNCTION public.portal_search_product_ids(text, uuid, integer) IS
    'Pesquisa do portal (0040): ids de portal_products (canal do pedido) cujo título pt/es, sem acentos, casa com o '
    'texto (websearch); mais recentes primeiro; cursor id < p_after; limite 1..49';

REVOKE ALL ON FUNCTION public.portal_search_product_ids(text, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.portal_search_product_ids(text, uuid, integer) TO ptmarket_app;

-- Dona = ptmarket_search (depois dos GRANT: quem migra deixa de ter EXECUTE). CREATE no schema só durante o ALTER.
GRANT CREATE ON SCHEMA public TO ptmarket_search;
ALTER FUNCTION public.portal_search_product_ids(text, uuid, integer) OWNER TO ptmarket_search;
REVOKE CREATE ON SCHEMA public FROM ptmarket_search;

-- ---------------------------------------------------------------------------
-- E. Repor memberships do migrator e verificar.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_search oid := (SELECT oid FROM pg_roles WHERE rolname = 'ptmarket_search');
    v_me     oid := (SELECT oid FROM pg_roles WHERE rolname = current_user);
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('REVOKE ptmarket_search FROM %I', current_user); -- só o SET dado acima (grantor = migrator)
        EXECUTE format('GRANT ptmarket_portal TO %I WITH INHERIT FALSE, SET TRUE', current_user);
        IF pg_has_role(current_user, 'ptmarket_portal', 'USAGE') THEN
            RAISE EXCEPTION '0040: o migrator ficou com INHERIT em ptmarket_portal';
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = v_search) THEN
        RAISE EXCEPTION '0040: ptmarket_search é membro de outro papel; recusado.';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_auth_members m
        LEFT JOIN pg_roles g ON g.oid = m.grantor
        WHERE m.roleid = v_search
          AND NOT (m.member = v_me AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option
                   AND COALESCE(g.rolsuper, false))
    ) THEN
        RAISE EXCEPTION '0040: ptmarket_search tem membros (só o ADMIN implícito do CREATE ROLE é aceite); recusado.';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_proc
                   WHERE oid = 'public.portal_search_product_ids(text, uuid, integer)'::regprocedure
                     AND prosecdef AND proowner = v_search
                     AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']) THEN
        RAISE EXCEPTION '0040: portal_search_product_ids tem de ser DEFINER de ptmarket_search com search_path fixo';
    END IF;
    IF (SELECT count(*) FROM pg_proc WHERE proowner = v_search) <> 1
       OR EXISTS (SELECT 1 FROM pg_class WHERE relowner = v_search)
       OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner = v_search) THEN
        RAISE EXCEPTION '0040: ptmarket_search só pode ser dono de portal_search_product_ids';
    END IF;
    IF has_function_privilege('public', 'public.portal_search_product_ids(text, uuid, integer)', 'EXECUTE')
       OR has_function_privilege('public', 'public.f_unaccent(text)', 'EXECUTE') THEN
        RAISE EXCEPTION '0040: PUBLIC com EXECUTE nas funções de pesquisa';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_attribute
               WHERE attrelid = 'public.products'::regclass AND attnum > 0 AND NOT attisdropped
                 AND attgenerated <> '') THEN
        RAISE EXCEPTION '0040: products não pode ter colunas geradas (o trigger L1 gravá-las-ia nos eventos)';
    END IF;
END
$$;
