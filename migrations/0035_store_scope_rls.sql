-- 0035 — isolamento entre lojas do mesmo tenant na RLS: app.store_id / app.sponsor_entity_id e policies RESTRICTIVE
--   para ptmarket_app (cartão 03/08b); um só national_portal por país (adenda do supervisor ao cartão 08b).
-- Rollback mental (só em dev):
--   DROP POLICY store_scope_select|store_scope_insert|store_scope_update|store_scope_delete
--     ON stores, products, product_variants, product_price_history, store_sponsorships;  (20 policies)
--   DROP FUNCTION app_store_id(); DROP FUNCTION app_sponsor_entity_id(); DROP FUNCTION app_is_platform_admin();
--   DROP INDEX tenants_one_national_portal_per_country;
--   (Sem tabelas novas; os eventos ddl.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * Todas as lojas de um país vivem no mesmo tenant (0030/0033): tenant_isolation já não separa lojistas. As policies
--     novas são AS RESTRICTIVE … TO ptmarket_app: somam-se por AND às permissivas (tenant_isolation, portal_read,
--     tenant_read, que ficam como estavam) e não tocam em ptmarket_portal, ptmarket_identity, ptmarket_worker,
--     ptmarket_price_writer nem no migrator.
--   * GUCs novos, postos pelo TenantTx com set_config(…, true) (locais à transação, como app.session_id da 0026):
--       app.store_id          — extractor de loja (backoffice do lojista);
--       app.sponsor_entity_id — extractor de entidade (backoffice da Câmara/Junta/associação).
--     Vazio ou ausente = sem âmbito. Ator da plataforma = app.actor_type = 'admin' (o GUC do ator da 0010).
--   * Defesa em profundidade contra um handler que se esqueça do filtro da loja, NÃO contra uma app comprometida: os
--     GUCs são postos pela app, com o mesmo nível de confiança de app.current_tenant_id.
--   * Exceções explícitas e únicas: o ator 'admin' (super_admin, admin.ptmarket.pt) e a leitura pública pelo portal
--     (view portal_stores, dona ptmarket_portal; ramos "publicado/ativo de loja em portal_stores" nos SELECT de
--     products, product_variants e product_price_history). Sem app.store_id, um ator merchant, municipal, customer ou
--     system não escreve em nenhuma loja.
--   * S = store_id = (SELECT app_store_id()); ADM = (SELECT app_is_platform_admin()) (initplans: uma avaliação por
--     consulta). Por tabela (uma policy por comando):
--       stores                escrita e SELECT: id = app_store_id() OR ADM (a leitura pública é só por portal_stores).
--       products              escrita: S OR ADM; SELECT: + is_published AND loja em portal_stores.
--       product_variants      pelo produto (p.store_id = app_store_id()) OR ADM; SELECT: + is_active AND produto
--                             publicado de loja em portal_stores.
--       product_price_history pela variante → produto (mesmo critério). A app não tem INSERT/UPDATE/DELETE (0007): as
--                             policies de escrita só fecham um GRANT futuro. O trigger Omnibus (DEFINER, dono
--                             ptmarket_price_writer) continua a gravar: writer_insert é de outro papel.
--       store_sponsorships    INSERT: S; UPDATE: sponsor_entity_id = app_sponsor_entity_id() OR ADM; SELECT: S OR
--                             sponsor_entity_id = app_sponsor_entity_id() OR ADM; DELETE: fechado (a app não tem
--                             DELETE, 0031; esta policy só fecha um GRANT futuro).
--     user_roles fica de fora (só own_select); store_verifications nasce no cartão 09 com a sua policy.
--     tests/store_scope_rls.sql chumba uma tabela de public com store_id ou FK para stores/products/product_variants
--     sem as 4 policies RESTRICTIVE (exceto essas duas).
--   * Índices: products_tenant_store_idx (0004) serve S em products; os EXISTS usam as PK/UNIQUE (tenant_id, id) —
--     provado por EXPLAIN no teste.
--   * Um só national_portal por país (ativo ou não): tenants_one_national_portal_per_country. Sem isto, dois nacionais
--     no mesmo país permitiam slugs de loja repetidos no mesmo canal. Duplicados existentes abortam a migration.

-- ---------------------------------------------------------------------------
-- A. Um national_portal por país.
-- ---------------------------------------------------------------------------
DO $$
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
        RAISE EXCEPTION '0035: mais de um tenant national_portal no mesmo país (ativos ou não); resolver à mão antes '
                        '(fundir ou mudar o tipo): %', v_bad;
    END IF;
END
$$;

CREATE UNIQUE INDEX tenants_one_national_portal_per_country ON tenants (country_code)
    WHERE tenant_type = 'national_portal';

-- ---------------------------------------------------------------------------
-- B. Funções do contexto (INVOKER, STABLE, search_path fixo; EXECUTE só para ptmarket_app).
-- ---------------------------------------------------------------------------
CREATE FUNCTION app_store_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT NULLIF(current_setting('app.store_id', true), '')::uuid
$$;

CREATE FUNCTION app_sponsor_entity_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT NULLIF(current_setting('app.sponsor_entity_id', true), '')::uuid
$$;

CREATE FUNCTION app_is_platform_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    -- Como a porta da timeline (0026): impersonação nunca herda a exceção do admin.
    SELECT COALESCE(current_setting('app.actor_type', true) = 'admin', false)
       AND NULLIF(current_setting('app.impersonator_id', true), '') IS NULL
$$;

COMMENT ON FUNCTION app_store_id() IS
    'Loja do contexto (app.store_id, posto pelo extractor de loja com set_config local); vazio/ausente = NULL. '
    'Defesa em profundidade contra um handler sem filtro, não contra uma app comprometida (confiança igual à de '
    'app.current_tenant_id)';
COMMENT ON FUNCTION app_sponsor_entity_id() IS
    'Entidade patrocinadora do contexto (app.sponsor_entity_id, posto pelo extractor de entidade com set_config '
    'local); vazio/ausente = NULL. Defesa em profundidade, não contra uma app comprometida';
COMMENT ON FUNCTION app_is_platform_admin() IS
    'true só se app.actor_type = admin (super_admin em admin.ptmarket.pt) e sem app.impersonator_id; exceção única '
    'ao âmbito por loja. '
    'GUC posto pela app: defesa em profundidade, não contra uma app comprometida';

REVOKE ALL ON FUNCTION app_store_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_sponsor_entity_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_is_platform_admin() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_store_id() TO ptmarket_app;
GRANT EXECUTE ON FUNCTION app_sponsor_entity_id() TO ptmarket_app;
GRANT EXECUTE ON FUNCTION app_is_platform_admin() TO ptmarket_app;

-- ---------------------------------------------------------------------------
-- C. stores: só a loja do contexto (ou o admin). Leitura pública só por portal_stores (dona ptmarket_portal).
-- ---------------------------------------------------------------------------
CREATE POLICY store_scope_select ON stores AS RESTRICTIVE FOR SELECT TO ptmarket_app
    USING (id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()));
CREATE POLICY store_scope_insert ON stores AS RESTRICTIVE FOR INSERT TO ptmarket_app
    WITH CHECK (id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()));
CREATE POLICY store_scope_update ON stores AS RESTRICTIVE FOR UPDATE TO ptmarket_app
    USING (id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()))
    WITH CHECK (id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()));
CREATE POLICY store_scope_delete ON stores AS RESTRICTIVE FOR DELETE TO ptmarket_app
    USING (id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()));

-- ---------------------------------------------------------------------------
-- D. products: escrita S OR ADM; SELECT também o publicado de loja visível no canal (mesmo texto da portal_read).
-- ---------------------------------------------------------------------------
CREATE POLICY store_scope_select ON products AS RESTRICTIVE FOR SELECT TO ptmarket_app
    USING (
        store_id = (SELECT app_store_id())
        OR (SELECT app_is_platform_admin())
        OR (is_published
            AND EXISTS (
                SELECT 1
                FROM portal_stores s
                WHERE s.tenant_id = products.tenant_id
                  AND s.id = products.store_id
            ))
    );
CREATE POLICY store_scope_insert ON products AS RESTRICTIVE FOR INSERT TO ptmarket_app
    WITH CHECK (store_id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()));
CREATE POLICY store_scope_update ON products AS RESTRICTIVE FOR UPDATE TO ptmarket_app
    USING (store_id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()))
    WITH CHECK (store_id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()));
CREATE POLICY store_scope_delete ON products AS RESTRICTIVE FOR DELETE TO ptmarket_app
    USING (store_id = (SELECT app_store_id()) OR (SELECT app_is_platform_admin()));

-- ---------------------------------------------------------------------------
-- E. product_variants: pelo produto.
-- ---------------------------------------------------------------------------
CREATE POLICY store_scope_select ON product_variants AS RESTRICTIVE FOR SELECT TO ptmarket_app
    USING (
        EXISTS (
            SELECT 1
            FROM products p
            WHERE p.tenant_id = product_variants.tenant_id
              AND p.id = product_variants.product_id
              AND p.store_id = (SELECT app_store_id())
        )
        OR (SELECT app_is_platform_admin())
        OR (is_active
            AND EXISTS (
                SELECT 1
                FROM products pr
                JOIN portal_stores s ON s.tenant_id = pr.tenant_id AND s.id = pr.store_id
                WHERE pr.tenant_id = product_variants.tenant_id
                  AND pr.id = product_variants.product_id
                  AND pr.is_published
            ))
    );
CREATE POLICY store_scope_insert ON product_variants AS RESTRICTIVE FOR INSERT TO ptmarket_app
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM products p
            WHERE p.tenant_id = product_variants.tenant_id
              AND p.id = product_variants.product_id
              AND p.store_id = (SELECT app_store_id())
        )
        OR (SELECT app_is_platform_admin())
    );
CREATE POLICY store_scope_update ON product_variants AS RESTRICTIVE FOR UPDATE TO ptmarket_app
    USING (
        EXISTS (
            SELECT 1
            FROM products p
            WHERE p.tenant_id = product_variants.tenant_id
              AND p.id = product_variants.product_id
              AND p.store_id = (SELECT app_store_id())
        )
        OR (SELECT app_is_platform_admin())
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM products p
            WHERE p.tenant_id = product_variants.tenant_id
              AND p.id = product_variants.product_id
              AND p.store_id = (SELECT app_store_id())
        )
        OR (SELECT app_is_platform_admin())
    );
CREATE POLICY store_scope_delete ON product_variants AS RESTRICTIVE FOR DELETE TO ptmarket_app
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

-- ---------------------------------------------------------------------------
-- F. product_price_history: pela variante → produto. A app só tem SELECT (0007); o Omnibus grava como
--    ptmarket_price_writer (writer_insert), fora destas policies.
-- ---------------------------------------------------------------------------
CREATE POLICY store_scope_select ON product_price_history AS RESTRICTIVE FOR SELECT TO ptmarket_app
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
        OR EXISTS (
            SELECT 1
            FROM product_variants v
            JOIN products pr ON pr.tenant_id = v.tenant_id AND pr.id = v.product_id
            JOIN portal_stores s ON s.tenant_id = pr.tenant_id AND s.id = pr.store_id
            WHERE v.tenant_id = product_price_history.tenant_id
              AND v.id = product_price_history.variant_id
              AND v.is_active
              AND pr.is_published
        )
    );
CREATE POLICY store_scope_insert ON product_price_history AS RESTRICTIVE FOR INSERT TO ptmarket_app
    WITH CHECK (
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
CREATE POLICY store_scope_update ON product_price_history AS RESTRICTIVE FOR UPDATE TO ptmarket_app
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
    )
    WITH CHECK (
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
CREATE POLICY store_scope_delete ON product_price_history AS RESTRICTIVE FOR DELETE TO ptmarket_app
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
-- G. store_sponsorships: a loja pede (INSERT); a entidade decide (UPDATE); ambas leem; DELETE fechado.
-- ---------------------------------------------------------------------------
CREATE POLICY store_scope_select ON store_sponsorships AS RESTRICTIVE FOR SELECT TO ptmarket_app
    USING (
        store_id = (SELECT app_store_id())
        OR sponsor_entity_id = (SELECT app_sponsor_entity_id())
        OR (SELECT app_is_platform_admin())
    );
-- A loja só faz pedidos (initiated_by = 'store'): nunca grava um "convite da entidade" em nome dela (auditoria 08b).
CREATE POLICY store_scope_insert ON store_sponsorships AS RESTRICTIVE FOR INSERT TO ptmarket_app
    WITH CHECK (store_id = (SELECT app_store_id()) AND initiated_by = 'store');
CREATE POLICY store_scope_update ON store_sponsorships AS RESTRICTIVE FOR UPDATE TO ptmarket_app
    USING (sponsor_entity_id = (SELECT app_sponsor_entity_id()) OR (SELECT app_is_platform_admin()))
    WITH CHECK (sponsor_entity_id = (SELECT app_sponsor_entity_id()) OR (SELECT app_is_platform_admin()));
CREATE POLICY store_scope_delete ON store_sponsorships AS RESTRICTIVE FOR DELETE TO ptmarket_app
    USING (false);

-- ---------------------------------------------------------------------------
-- H. Comentários (uma frase por tabela; o critério completo está no cabeçalho).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
    c text;
BEGIN
    FOREACH t IN ARRAY ARRAY['stores', 'products', 'product_variants', 'product_price_history',
                             'store_sponsorships'] LOOP
        FOREACH c IN ARRAY ARRAY['select', 'insert', 'update', 'delete'] LOOP
            EXECUTE format(
                'COMMENT ON POLICY %I ON public.%I IS %L',
                'store_scope_' || c, t,
                'Âmbito por loja/entidade (0035): RESTRICTIVE para ptmarket_app (app.store_id, app.sponsor_entity_id, '
                || 'ator admin). Defesa em profundidade contra um handler sem filtro, não contra uma app comprometida '
                || '(GUCs postos pela app, como app.current_tenant_id)');
        END LOOP;
    END LOOP;
END
$$;
