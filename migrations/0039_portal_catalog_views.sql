-- 0039 — catálogo público só por views de ptmarket_portal: portal_products, portal_product_variants,
--   portal_categories; fim da leitura pública direta de products/product_variants/product_price_history
--   (cartão 04/01; spec 14 §1.1; padrão das 0021/0033/0035).
-- Rollback mental (só em dev):
--   GRANT ptmarket_portal TO <migrator> WITH INHERIT TRUE;
--   ALTER POLICY store_scope_select ON products | product_variants | product_price_history USING (texto da 0035, com o
--     ramo público "publicado/ativo de loja em portal_stores");
--   CREATE POLICY portal_read ON products e ON product_variants (texto da 0033, FOR SELECT TO ptmarket_app);
--   DROP VIEW portal_categories; DROP VIEW portal_product_variants; DROP VIEW portal_products;
--   DROP POLICY portal_view ON product_variants; DROP POLICY portal_view ON products;
--   REVOKE SELECT ON products, product_variants, categories FROM ptmarket_portal;
--   DROP INDEX products_tenant_published_id_idx, products_tenant_category_published_idx,
--     products_tenant_store_published_idx, product_variants_tenant_product_active_price_idx;
--   ALTER TABLE categories DROP CONSTRAINT categories_slug_key;
--   GRANT ptmarket_portal TO <migrator> WITH INHERIT FALSE, SET TRUE.
--   (Sem tabelas novas; os eventos ddl.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * O catálogo público lê-se SÓ por três views WITH (security_barrier = false) (porquê: secção D), donas
--     ptmarket_portal (NOLOGIN, sem BYPASSRLS), REVOKE ALL FROM PUBLIC, GRANT SELECT só a ptmarket_app. "Loja
--     visível" = EXISTS em portal_stores (o canal nacional/white-label já vem resolvido aí; a condição do canal não se
--     repete):
--       portal_products          publicados, de loja visível, com pelo menos uma variante ativa;
--       portal_product_variants  ativas, de produto em portal_products; stock só como in_stock = (stock_qty > 0);
--       portal_categories        todas as categorias + has_direct_products (há produto em portal_products com esta
--                                categoria; os ascendentes resolvem-se no Rust).
--     Nunca nas views: stock_qty, sku, compare_at_price_cents, catalog_item_id, ai_enriched, taxonomy_code,
--     default_vat_rate_bps (verificado no fim). Dinheiro em BIGINT cêntimos (PVP com IVA incluído).
--   * ptmarket_portal: SELECT por coluna só do que as views e as policies leem. Exceção única ao "nunca nos grants":
--     stock_qty, porque in_stock = (stock_qty > 0) é calculado na view com os privilégios da dona; ptmarket_portal não
--     tem LOGIN e a quantidade nunca sai da view (só o booleano). Os outros seis nunca são concedidos (verificado).
--   * products e product_variants têm FORCE RLS: policy portal_view FOR SELECT TO ptmarket_portal em cada uma.
--     Mesma condição da view sem o EXISTS cruzado (produto ↔ variante): products leria product_variants e vice-versa
--     → recursão infinita nas policies. products: publicado AND loja visível; product_variants: ativa AND produto
--     publicado de loja visível (equivalente: uma variante ativa basta para o produto ter variante ativa). O EXISTS
--     "tem variante ativa" fica só na view portal_products.
--   * Fecho da leitura direta (como a 0021 fez a stores): DROP POLICY portal_read ON products/product_variants;
--     store_scope_select de products, product_variants e product_price_history fica só "loja do contexto OR
--     app_is_platform_admin()". Lojista e admin continuam a ler os seus; anónimo/cliente/system sem app.store_id
--     leem 0 linhas nas tabelas. O trigger Omnibus (ptmarket_price_writer) não muda.
--   * Índices parciais (começam por tenant_id) para as listagens por cursor (id DESC, id < $cursor): geral, por
--     categoria e por loja (WHERE is_published); variantes por produto e preço (WHERE is_active). Provado por EXPLAIN
--     em tests/portal_catalog.sql. O EXISTS de portal_stores em portal_products leva OFFSET 0 (impede a conversão em
--     semi-join): a estimativa de portal_stores é sempre ~1 linha (condição do canal opaca ao planeador) e, sem a
--     barreira, o plano partia das lojas e só usava products_tenant_store_published_idx em todas as listagens. A
--     semântica é a mesma (EXISTS ignora OFFSET 0).
--   * categories.slug passa a UNIQUE (categories_slug_key); duplicados existentes abortam a migration com a lista.
--   * Sem SET ROLE (lição L2: ptmarket_portal não grava na caixa negra): o migrator ganha INHERIT em ptmarket_portal só
--     durante o bloco e volta a INHERIT FALSE, SET TRUE (verificado). CREATE no schema só durante o ALTER … OWNER.
--   * Views não levam bloco L1 (tests/audit_l1.sql e a L2 só contam relkind r/p).

DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_portal TO %I WITH INHERIT TRUE', current_user);
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- A. categories.slug único.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_bad text;
BEGIN
    SELECT string_agg(format('%s (%s)', x.slug, x.n), '; ' ORDER BY x.slug)
    INTO v_bad
    FROM (
        SELECT c.slug, count(*) AS n
        FROM public.categories c
        GROUP BY c.slug
        HAVING count(*) > 1
    ) x;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '0039: categories.slug repetido; resolver à mão antes (renomear ou fundir): %', v_bad;
    END IF;
END
$$;

ALTER TABLE categories ADD CONSTRAINT categories_slug_key UNIQUE (slug);

-- ---------------------------------------------------------------------------
-- B. Índices parciais das listagens públicas.
-- ---------------------------------------------------------------------------
CREATE INDEX products_tenant_published_id_idx ON products (tenant_id, id DESC)
    WHERE is_published;
CREATE INDEX products_tenant_category_published_idx ON products (tenant_id, category_id, id DESC)
    WHERE is_published;
CREATE INDEX products_tenant_store_published_idx ON products (tenant_id, store_id, id DESC)
    WHERE is_published;
CREATE INDEX product_variants_tenant_product_active_price_idx ON product_variants (tenant_id, product_id, price_cents)
    WHERE is_active;

-- ---------------------------------------------------------------------------
-- C. Grants por coluna de ptmarket_portal + policies FOR SELECT (FORCE RLS em products e product_variants).
-- ---------------------------------------------------------------------------
GRANT SELECT (id, tenant_id, store_id, category_id, title, description, vat_rate_bps, is_perishable, attributes,
              images, created_at, updated_at, is_published)
    ON products TO ptmarket_portal;
-- stock_qty: só para calcular in_stock na view (ver cabeçalho).
GRANT SELECT (id, tenant_id, product_id, ean, attributes, price_cents, lowest_price_30d_cents, stock_qty, is_active)
    ON product_variants TO ptmarket_portal;
GRANT SELECT (id, parent_id, slug, name, is_featured, sort_order) ON categories TO ptmarket_portal;

CREATE POLICY portal_view ON products
    AS PERMISSIVE
    FOR SELECT TO ptmarket_portal
    USING (
        is_published
        AND EXISTS (
            SELECT 1
            FROM public.portal_stores s
            WHERE s.tenant_id = products.tenant_id
              AND s.id = products.store_id
        )
    );

CREATE POLICY portal_view ON product_variants
    AS PERMISSIVE
    FOR SELECT TO ptmarket_portal
    USING (
        is_active
        AND EXISTS (
            SELECT 1
            FROM public.products pr
            JOIN public.portal_stores s ON s.tenant_id = pr.tenant_id AND s.id = pr.store_id
            WHERE pr.tenant_id = product_variants.tenant_id
              AND pr.id = product_variants.product_id
              AND pr.is_published
        )
    );

COMMENT ON POLICY portal_view ON products IS
    'Dona das views do catálogo (ptmarket_portal): produto publicado de loja em portal_stores (0039)';
COMMENT ON POLICY portal_view ON product_variants IS
    'Dona das views do catálogo (ptmarket_portal): variante ativa de produto publicado de loja em portal_stores (0039)';

-- ---------------------------------------------------------------------------
-- D. Views do catálogo.
--    security_barrier = false (decisão do supervisor, cartão 04/01), ao contrário de portal_stores/portal_store_badges:
--    * a visibilidade NÃO depende do WHERE da view: é imposta pelas policies RLS portal_view da dona (ptmarket_portal)
--      em products e product_variants, e as quals de RLS são sempre barreira (avaliadas antes de qualquer predicado
--      não leakproof de quem consulta); categories é global (todas as linhas são públicas);
--    * as colunas privadas ficam fora por projeção (grants por coluna da dona; ptmarket_app só tem SELECT nas views);
--    * só o Rust consulta, com SQL estático (sem predicados do utilizador).
--    Com barreira, ORDER BY id DESC LIMIT 24 ficava por cima da subquery e cada página lia todos os publicados do
--    tenant; sem ela a página lê ~24 linhas do índice. Provado em tests/portal_catalog.sql (predicado arbitrário não
--    vê produtos não publicados nem de lojas invisíveis; EXPLAIN ANALYZE da página).
-- ---------------------------------------------------------------------------
CREATE VIEW portal_products WITH (security_barrier = false) AS
    SELECT p.id, p.tenant_id, p.store_id, p.category_id, p.title, p.description, p.vat_rate_bps, p.is_perishable,
           p.attributes, p.images, p.created_at, p.updated_at
    FROM public.products p
    WHERE p.is_published
      AND EXISTS (
          SELECT 1
          FROM public.portal_stores s
          WHERE s.tenant_id = p.tenant_id
            AND s.id = p.store_id
          OFFSET 0 -- barreira do planeador (ver cabeçalho): verificação por produto, nunca "lojas primeiro"
      )
      AND EXISTS (
          SELECT 1
          FROM public.product_variants v
          WHERE v.tenant_id = p.tenant_id
            AND v.product_id = p.id
            AND v.is_active
      );

CREATE VIEW portal_product_variants WITH (security_barrier = false) AS
    SELECT v.id, v.tenant_id, v.product_id, v.ean, v.attributes, v.price_cents, v.lowest_price_30d_cents,
           (v.stock_qty > 0) AS in_stock
    FROM public.product_variants v
    WHERE v.is_active
      AND EXISTS (
          SELECT 1
          FROM public.portal_products pp
          WHERE pp.tenant_id = v.tenant_id
            AND pp.id = v.product_id
      );

CREATE VIEW portal_categories WITH (security_barrier = false) AS
    SELECT c.id, c.parent_id, c.slug, c.name, c.is_featured, c.sort_order,
           EXISTS (SELECT 1 FROM public.portal_products pp WHERE pp.category_id = c.id) AS has_direct_products
    FROM public.categories c;

COMMENT ON VIEW portal_products IS
    'Catálogo do canal do pedido: produtos publicados de lojas em portal_stores com pelo menos uma variante ativa. '
    'Sem catalog_item_id nem ai_enriched';
COMMENT ON VIEW portal_product_variants IS
    'Variantes ativas de produtos em portal_products; PVP em cêntimos com IVA incluído; stock só como in_stock. '
    'Sem sku, stock_qty nem compare_at_price_cents';
COMMENT ON VIEW portal_categories IS
    'Todas as categorias (sem taxonomy_code nem default_vat_rate_bps); has_direct_products = há produto desta '
    'categoria em portal_products no canal do pedido (ascendentes resolvidos na app)';

REVOKE ALL ON portal_products, portal_product_variants, portal_categories FROM PUBLIC;
GRANT SELECT ON portal_products, portal_product_variants, portal_categories TO ptmarket_app;

-- Dono = ptmarket_portal. CREATE no schema só durante o ALTER (padrão da 0017/0021/0033).
GRANT CREATE ON SCHEMA public TO ptmarket_portal;
ALTER VIEW portal_products OWNER TO ptmarket_portal;
ALTER VIEW portal_product_variants OWNER TO ptmarket_portal;
ALTER VIEW portal_categories OWNER TO ptmarket_portal;
REVOKE CREATE ON SCHEMA public FROM ptmarket_portal;

-- ---------------------------------------------------------------------------
-- E. Fecho da leitura pública direta: sem portal_read; store_scope_select só loja do contexto OR admin.
-- ---------------------------------------------------------------------------
DROP POLICY portal_read ON products;
DROP POLICY portal_read ON product_variants;

ALTER POLICY store_scope_select ON products
    USING (store_id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()));

ALTER POLICY store_scope_select ON product_variants
    USING (
        EXISTS (
            SELECT 1
            FROM products p
            WHERE p.tenant_id = product_variants.tenant_id
              AND p.id = product_variants.product_id
              AND p.store_id = (SELECT app_store_id())
        )
        OR (SELECT app_is_platform_admin())
    );

ALTER POLICY store_scope_select ON product_price_history
    USING (
        EXISTS (
            SELECT 1
            FROM product_variants v
            JOIN products p ON p.tenant_id = v.tenant_id AND p.id = v.product_id
            WHERE v.tenant_id = product_price_history.tenant_id
              AND v.id = product_price_history.variant_id
              AND p.store_id = (SELECT app_store_id())
        )
        OR (SELECT app_is_platform_admin())
    );

-- ---------------------------------------------------------------------------
-- F. Repor a membership do migrator (sem INHERIT) e verificar donos, colunas e grants.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_bad text;
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_portal TO %I WITH INHERIT FALSE, SET TRUE', current_user);
        IF pg_has_role(current_user, 'ptmarket_portal', 'USAGE') THEN
            RAISE EXCEPTION '0039: o migrator ficou com INHERIT em ptmarket_portal';
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles
               WHERE rolname = 'ptmarket_portal' AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION '0039: ptmarket_portal com SUPERUSER, BYPASSRLS ou LOGIN';
    END IF;

    SELECT string_agg(v.n, ', ' ORDER BY v.n) INTO v_bad
    FROM unnest(ARRAY['portal_stores', 'portal_store_badges', 'portal_products', 'portal_product_variants',
                      'portal_categories']) AS v(n)
    WHERE (SELECT relowner FROM pg_class WHERE oid = ('public.' || v.n)::regclass) <> 'ptmarket_portal'::regrole;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '0039: as views do portal têm de ser de ptmarket_portal: %', v_bad;
    END IF;

    SELECT string_agg(c.relname || '.' || a.attname, ', ' ORDER BY c.relname, a.attname) INTO v_bad
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    WHERE c.oid IN ('public.portal_products'::regclass, 'public.portal_product_variants'::regclass,
                    'public.portal_categories'::regclass)
      AND a.attnum > 0 AND NOT a.attisdropped
      AND a.attname IN ('stock_qty', 'sku', 'compare_at_price_cents', 'catalog_item_id', 'ai_enriched',
                        'taxonomy_code', 'default_vat_rate_bps', 'is_published', 'is_active');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '0039: coluna privada numa view do catálogo: %', v_bad;
    END IF;

    SELECT string_agg(x.t || '.' || x.c, ', ' ORDER BY x.t, x.c) INTO v_bad
    FROM (VALUES ('products', 'catalog_item_id'), ('products', 'ai_enriched'),
                 ('product_variants', 'sku'), ('product_variants', 'compare_at_price_cents'),
                 ('categories', 'taxonomy_code'), ('categories', 'default_vat_rate_bps')) AS x(t, c)
    WHERE has_column_privilege('ptmarket_portal', ('public.' || x.t)::regclass, x.c, 'SELECT');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '0039: ptmarket_portal com SELECT em coluna privada: %', v_bad;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_policies
               WHERE schemaname = 'public' AND tablename IN ('products', 'product_variants')
                 AND policyname = 'portal_read') THEN
        RAISE EXCEPTION '0039: portal_read ainda existe em products/product_variants';
    END IF;
END
$$;
