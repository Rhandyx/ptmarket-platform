-- 0033 — visibilidade por canal: portal_stores, portal_read de products/product_variants, selos e trinco de stores
--   (cartão 03/08; spec 14 §1.1).
-- Rollback mental (só em dev):
--   GRANT ptmarket_portal TO <migrator> WITH INHERIT TRUE;
--   DROP VIEW portal_store_badges;
--   DROP POLICY portal_read ON product_variants; DROP POLICY portal_read ON products; recriá-las com o texto da 0021
--     (com o gate (SELECT app_is_national_portal())).
--   CREATE OR REPLACE VIEW não tira colunas: DROP VIEW portal_stores (depois das portal_read) e recriá-la com o texto,
--     o COMMENT, os grants e o dono da 0021; ALTER POLICY portal_view ON stores USING (texto da 0021).
--   DROP POLICY portal_view ON store_sponsorships; DROP POLICY portal_view ON sponsor_entities;
--   REVOKE SELECT ON store_sponsorships, sponsor_entities FROM ptmarket_portal;
--   REVOKE SELECT (shipping_scope, storefront_address, storefront_dicofre) ON stores FROM ptmarket_portal;
--   GRANT SELECT (publish_to_national_portal) ON stores TO ptmarket_portal;
--   GRANT ptmarket_portal TO <migrator> WITH INHERIT FALSE, SET TRUE;
--   DROP TRIGGER stores_national_tenant_guard ON stores; DROP FUNCTION stores_national_tenant_guard().
--   (Sem tabelas novas; os eventos ddl.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * app.current_tenant_id = canal do pedido. Uma loja é visível se estiver ativa, o seu tenant estiver ativo e:
--       - o canal for o nacional (app_is_national_portal(), 0016, inalterada) e a loja for desse tenant (todas as
--         lojas ativas do país; sem opt-out, publish_to_national_portal deixa de ser lido); OU
--       - houver um patrocínio 'active' e vigente (now() <@ tstzrange(valid_from, valid_to), sem depender do job)
--         de uma entidade ativa cujo channel_tenant_id é o canal (ativo, do país da loja).
--     Mesma condição na view portal_stores e na policy portal_view de stores (TO ptmarket_portal).
--   * portal_stores: mesmas colunas e ordem da 0021 + shipping_scope, storefront_address, storefront_dicofre no fim
--     (shipping_scope não esconde a loja). Continua sem iban, chaves, credenciais, comissões, KYC.
--   * portal_store_badges: selos (patrocínios ativos e vigentes de entidades ativas) só das lojas em portal_stores.
--   * products/product_variants: portal_read sem o gate; "loja visível" = EXISTS em portal_stores (o gate vive na view).
--   * ptmarket_portal (NOLOGIN, sem BYPASSRLS): SELECT por coluna só do que a condição e as views leem; policies
--     FOR SELECT próprias em store_sponsorships (só active e vigente) e sponsor_entities (só is_active). Deixa de ler
--     stores.publish_to_national_portal (já não é lido).
--   * Views substituídas/alteradas sem SET ROLE (lição L2: ptmarket_portal não grava na caixa negra): o migrator
--     ganha INHERIT em ptmarket_portal só durante o bloco e volta a INHERIT FALSE, SET TRUE (verificado).
--   * Trinco: stores só em tenants national_portal (INSERT ou UPDATE OF tenant_id; 23514; ENABLE ALWAYS).
--   * Views não levam bloco L1 (tests/audit_l1.sql e a L2 só contam relkind r/p).

DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_portal TO %I WITH INHERIT TRUE', current_user);
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- A. Grants por coluna de ptmarket_portal + policies FOR SELECT nas tabelas de patrocínio.
-- ---------------------------------------------------------------------------
GRANT SELECT (shipping_scope, storefront_address, storefront_dicofre) ON stores TO ptmarket_portal;
REVOKE SELECT (publish_to_national_portal) ON stores FROM ptmarket_portal;
GRANT SELECT (store_id, sponsor_entity_id, status, valid_from, valid_to) ON store_sponsorships TO ptmarket_portal;
GRANT SELECT (id, kind, name, slug, logo_key, channel_tenant_id, is_active) ON sponsor_entities TO ptmarket_portal;

CREATE POLICY portal_view ON store_sponsorships
    AS PERMISSIVE
    FOR SELECT TO ptmarket_portal
    USING (status = 'active' AND now() <@ tstzrange(valid_from, valid_to));

CREATE POLICY portal_view ON sponsor_entities
    AS PERMISSIVE
    FOR SELECT TO ptmarket_portal
    USING (is_active);

-- ---------------------------------------------------------------------------
-- B. Condição de visibilidade: policy portal_view de stores e view portal_stores (texto igual).
-- ---------------------------------------------------------------------------
ALTER POLICY portal_view ON stores
    USING (
        stores.is_active
        AND EXISTS (SELECT 1 FROM public.tenants o WHERE o.id = stores.tenant_id AND o.is_active)
        AND (
            ((SELECT public.app_is_national_portal())
             AND stores.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            OR EXISTS (
                SELECT 1
                FROM public.store_sponsorships sp
                JOIN public.sponsor_entities e ON e.id = sp.sponsor_entity_id AND e.is_active
                JOIN public.tenants c ON c.id = e.channel_tenant_id AND c.is_active
                JOIN public.tenants o ON o.id = stores.tenant_id AND o.country_code = c.country_code
                WHERE sp.store_id = stores.id
                  AND sp.status = 'active'
                  AND now() <@ tstzrange(sp.valid_from, sp.valid_to)
                  AND e.channel_tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
        )
    );

CREATE OR REPLACE VIEW portal_stores WITH (security_barrier = true) AS
    SELECT s.id, s.tenant_id, s.name, s.slug, s.legal_name, s.nif, s.email, s.phone, s.address_json, s.geo_lat,
           s.geo_lng, s.business_hours, s.is_vacation_mode, s.vacation_message, s.supports_click_collect,
           s.supports_local_courier, s.supports_national_shipping, s.vat_exempt_art53,
           s.shipping_scope, s.storefront_address, s.storefront_dicofre
    FROM public.stores s
    WHERE s.is_active
      AND EXISTS (SELECT 1 FROM public.tenants o WHERE o.id = s.tenant_id AND o.is_active)
      AND (
          ((SELECT public.app_is_national_portal())
           AND s.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
          OR EXISTS (
              SELECT 1
              FROM public.store_sponsorships sp
              JOIN public.sponsor_entities e ON e.id = sp.sponsor_entity_id AND e.is_active
              JOIN public.tenants c ON c.id = e.channel_tenant_id AND c.is_active
              JOIN public.tenants o ON o.id = s.tenant_id AND o.country_code = c.country_code
              WHERE sp.store_id = s.id
                AND sp.status = 'active'
                AND now() <@ tstzrange(sp.valid_from, sp.valid_to)
                AND e.channel_tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
          )
      );

COMMENT ON VIEW portal_stores IS
    'Lojas visíveis no canal do pedido (app.current_tenant_id): nacional = todas as lojas ativas do tenant nacional; white-label = lojas com patrocínio ativo e vigente de uma entidade ativa desse canal. Só colunas de exibição (sem IBAN, chaves, credenciais, comissões, KYC)';

-- ---------------------------------------------------------------------------
-- C. Selos: portal_store_badges.
-- ---------------------------------------------------------------------------
CREATE VIEW portal_store_badges WITH (security_barrier = true) AS
    SELECT sp.store_id, sp.sponsor_entity_id, e.kind, e.name, e.slug, e.logo_key
    FROM public.store_sponsorships sp
    JOIN public.sponsor_entities e ON e.id = sp.sponsor_entity_id AND e.is_active
    WHERE sp.status = 'active'
      AND now() <@ tstzrange(sp.valid_from, sp.valid_to)
      AND EXISTS (SELECT 1 FROM public.portal_stores ps WHERE ps.id = sp.store_id)
    ORDER BY sp.store_id,
             CASE e.kind WHEN 'municipality' THEN 1 WHEN 'parish' THEN 2 WHEN 'association' THEN 3 ELSE 4 END,
             e.name;

COMMENT ON VIEW portal_store_badges IS
    'Selos das lojas em portal_stores (patrocínios ativos e vigentes de entidades ativas). Ordem fixa por loja: municipality → parish → association; no mesmo tipo, por nome';

REVOKE ALL ON portal_store_badges FROM PUBLIC;
GRANT SELECT ON portal_store_badges TO ptmarket_app;

-- Dono = ptmarket_portal. CREATE no schema só durante o ALTER (padrão da 0017/0021).
GRANT CREATE ON SCHEMA public TO ptmarket_portal;
ALTER VIEW portal_store_badges OWNER TO ptmarket_portal;
REVOKE CREATE ON SCHEMA public FROM ptmarket_portal;

-- ---------------------------------------------------------------------------
-- D. products e product_variants: portal_read sem o gate (o gate vive na view).
-- ---------------------------------------------------------------------------
DROP POLICY portal_read ON products;
CREATE POLICY portal_read ON products
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        is_published
        AND EXISTS (
            SELECT 1
            FROM portal_stores s
            WHERE s.tenant_id = products.tenant_id
              AND s.id = products.store_id
        )
    );

DROP POLICY portal_read ON product_variants;
CREATE POLICY portal_read ON product_variants
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        is_active
        AND EXISTS (
            SELECT 1
            FROM products pr
            JOIN portal_stores s ON s.tenant_id = pr.tenant_id AND s.id = pr.store_id
            WHERE pr.tenant_id = product_variants.tenant_id
              AND pr.id = product_variants.product_id
              AND pr.is_published
        )
    );

-- ---------------------------------------------------------------------------
-- E. Trinco: uma loja só vive num tenant national_portal.
-- ---------------------------------------------------------------------------
CREATE FUNCTION stores_national_tenant_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS
$$
DECLARE
    v_type text;
BEGIN
    SELECT t.tenant_type INTO v_type FROM public.tenants t WHERE t.id = NEW.tenant_id;
    -- Falha fechado: tenant inexistente OU invisível ao chamador (RLS futura em tenants) → 23503, como a FK.
    IF NOT FOUND THEN
        RAISE EXCEPTION 'stores: tenant % inexistente ou invisível', NEW.tenant_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF v_type IS DISTINCT FROM 'national_portal' THEN
        RAISE EXCEPTION 'stores: uma loja só pode pertencer a um tenant national_portal'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

COMMENT ON FUNCTION stores_national_tenant_guard() IS
    'BEFORE INSERT OR UPDATE OF tenant_id em stores: tenant que não seja national_portal → 23514';

REVOKE ALL ON FUNCTION stores_national_tenant_guard() FROM PUBLIC;

CREATE TRIGGER stores_national_tenant_guard
    BEFORE INSERT OR UPDATE OF tenant_id ON stores
    FOR EACH ROW EXECUTE FUNCTION stores_national_tenant_guard();
ALTER TABLE stores ENABLE ALWAYS TRIGGER stores_national_tenant_guard;

-- ---------------------------------------------------------------------------
-- F. Repor a membership do migrator (sem INHERIT) e verificar.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_portal TO %I WITH INHERIT FALSE, SET TRUE', current_user);
        IF pg_has_role(current_user, 'ptmarket_portal', 'USAGE') THEN
            RAISE EXCEPTION '0033: o migrator ficou com INHERIT em ptmarket_portal';
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles
               WHERE rolname = 'ptmarket_portal' AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION '0033: ptmarket_portal com SUPERUSER, BYPASSRLS ou LOGIN';
    END IF;
    IF (SELECT relowner FROM pg_class WHERE oid = 'public.portal_stores'::regclass) <> 'ptmarket_portal'::regrole
       OR (SELECT relowner FROM pg_class WHERE oid = 'public.portal_store_badges'::regclass)
          <> 'ptmarket_portal'::regrole THEN
        RAISE EXCEPTION '0033: as views do portal têm de ser de ptmarket_portal';
    END IF;
END
$$;
