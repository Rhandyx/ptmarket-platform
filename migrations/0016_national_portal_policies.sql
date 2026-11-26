-- 0016 — portal nacional: leitura (só SELECT) de lojas/produtos/variantes publicadas de outros tenants.
-- Rollback mental: DROP POLICY portal_read ON product_variants; DROP POLICY portal_read ON products;
--   DROP POLICY portal_read ON stores; DROP FUNCTION app_is_national_portal();
--   (as policies tenant_isolation de 0003/0004 ficam intactas; nenhuma tabela nova, nenhum índice novo.)
--
-- Regras:
--   * A flag app.portal_national = 'on' sozinha não chega: o tenant do contexto (app.current_tenant_id)
--     tem de SER um tenant 'national_portal' ativo. Um tenant municipal com a flag continua isolado.
--   * Só lojas publish_to_national_portal AND is_active, de tenant ativo e do MESMO país do portal
--     (IVA de ES/ilhas ainda por decidir); produtos is_published dessas lojas; variantes is_active desses
--     produtos.
--   * Só FOR SELECT: INSERT/UPDATE/DELETE continuam a exigir tenant_id = contexto (tenant_isolation).
--   * product_price_history NÃO ganha policy de portal (Omnibus via product_variants.lowest_price_30d_cents).
--   * A policy é por linha; colunas sensíveis (iban, invoicing_credentials_enc, eupago_split_key,
--     stripe_account_id) nunca são selecionadas pela API em modo portal (regra da app, cartão 11).
--   * Nas policies a função vai em (SELECT app_is_national_portal()): InitPlan avaliado uma vez por query,
--     não por linha.
--   * Índices: stores_national_portal_idx (0003) serve a listagem de lojas; produtos por loja usam
--     products_tenant_store_idx (0004) — provado por EXPLAIN em tests/portal.sql.

CREATE FUNCTION app_is_national_portal()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT COALESCE(current_setting('app.portal_national', true) = 'on', false)
       AND EXISTS (
           SELECT 1
           FROM public.tenants t
           WHERE t.id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
             AND t.tenant_type = 'national_portal'
             AND t.is_active
       )
$$;

COMMENT ON FUNCTION app_is_national_portal() IS
    'true só se app.portal_national = on E o tenant do contexto for um national_portal ativo';

REVOKE ALL ON FUNCTION app_is_national_portal() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_is_national_portal() TO ptmarket_app;

CREATE POLICY portal_read ON stores
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        (SELECT app_is_national_portal())
        AND publish_to_national_portal
        AND is_active
        AND EXISTS (
            SELECT 1
            FROM tenants o, tenants p
            WHERE o.id = stores.tenant_id
              AND o.is_active
              AND p.id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
              AND o.country_code = p.country_code
        )
    );

-- A subconsulta repete as condições da loja de forma explícita (não depende só do RLS de stores,
-- que também se aplica aqui ao ptmarket_app e dá o mesmo resultado).
CREATE POLICY portal_read ON products
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        (SELECT app_is_national_portal())
        AND is_published
        AND EXISTS (
            SELECT 1
            FROM stores s, tenants o, tenants p
            WHERE s.tenant_id = products.tenant_id
              AND s.id = products.store_id
              AND s.publish_to_national_portal
              AND s.is_active
              AND o.id = s.tenant_id
              AND o.is_active
              AND p.id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
              AND o.country_code = p.country_code
        )
    );

CREATE POLICY portal_read ON product_variants
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        (SELECT app_is_national_portal())
        AND is_active
        AND EXISTS (
            SELECT 1
            FROM products pr, stores s, tenants o, tenants p
            WHERE pr.tenant_id = product_variants.tenant_id
              AND pr.id = product_variants.product_id
              AND pr.is_published
              AND s.tenant_id = pr.tenant_id
              AND s.id = pr.store_id
              AND s.publish_to_national_portal
              AND s.is_active
              AND o.id = s.tenant_id
              AND o.is_active
              AND p.id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
              AND o.country_code = p.country_code
        )
    );
