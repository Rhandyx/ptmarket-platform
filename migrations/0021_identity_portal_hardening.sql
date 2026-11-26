-- 0021 — identidade e portal endurecidos (cartão 02/10b; achados 5, 6 e 9 da auditoria ASVS da onda 4 + códigos de
-- recuperação da 0019).
-- Rollback mental (só em dev):
--   D. GRANT ptmarket_identity TO <migrator> WITH INHERIT TRUE; CREATE OR REPLACE das 4 funções com
--      SET search_path = pg_catalog, public (corpo igual); GRANT ... WITH INHERIT FALSE, SET TRUE.
--   C. DROP POLICY portal_read ON product_variants; DROP POLICY portal_read ON products;
--      recriá-las com o EXISTS sobre stores/tenants da 0016; CREATE POLICY portal_read ON stores (texto da 0016);
--      DROP VIEW portal_stores; DROP POLICY portal_view ON stores; REVOKE ALL ON stores, tenants FROM ptmarket_portal;
--      REVOKE USAGE ON SCHEMA public FROM ptmarket_portal; DROP ROLE ptmarket_portal (o papel pode ser partilhado
--      por outras BDs do cluster).
--   B. DROP TRIGGER user_recovery_codes_use_once ON user_recovery_codes;
--      DROP FUNCTION user_recovery_codes_use_once().
--   A. DROP TRIGGER customers_email_unverify ON customers; DROP FUNCTION customers_email_unverify().
--   (Nenhuma tabela nova; os eventos ddl.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   A. Mudar o email de um cliente anula email_verified_at, a não ser que o MESMO UPDATE defina a coluna (fluxo
--      futuro de confirmação do email novo; a app não tem UPDATE em email_verified_at). Função INVOKER.
--   B. user_recovery_codes: um código usado nunca volta a servir, para TODOS os papéis (dono incluído; trigger
--      ENABLE ALWAYS, como a L1). used_at só passa de NULL a valor, e o valor é sempre now() (a app não escolhe a
--      data); id, user_id, code_hash e created_at nunca mudam. Violação = 23514 com mensagem fixa. DELETE continua
--      permitido (regenerar a lista). Consumo certo (cartão 20):
--        UPDATE user_recovery_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL  → 1 linha;
--      com duas transações em paralelo a segunda reavalia o WHERE depois do lock e afeta 0 linhas.
--   C. Portal: o RLS é por linha, por isso a leitura de lojas de outros tenants deixa de ser feita em stores
--      (DROP POLICY portal_read ON stores) e passa a ser feita na VIEW portal_stores (security_barrier), dona
--      ptmarket_portal (NOLOGIN, sem SUPERUSER/BYPASSRLS), que só tem as colunas de exibição obrigatória (DSA art.
--      30.º, DL 7/2004 art. 10.º, menção do Art. 53.º). iban, eupago_split_key, invoicing_credentials_enc,
--      stripe_account_id, custom_commission_bps, kyc_verified, invoicing_provider e shipping_config ficam fora da view
--      e fora dos grants de ptmarket_portal. A condição (view e policy portal_view de ptmarket_portal em stores) é a
--      da 0016. A função app_is_national_portal() corre como quem consulta (ptmarket_app), como antes.
--      products/product_variants: "loja visível" = EXISTS em portal_stores. tenant_isolation fica como está.
--      Uma view não é tabela: sem bloco L1 (tests/audit_l1.sql e a L2 da 0013 só contam relkind r/p).
--   D. As 4 DEFINER de identidade passam a SET search_path = pg_catalog, pg_temp (todas as relações já qualificadas
--      com public.). Mesma assinatura, retorno, corpo, dono (ptmarket_identity) e GRANT/REVOKE. CREATE OR REPLACE
--      feito pelo migrator com INHERIT ligado só durante o bloco (o bootstrap dá-lhe ADMIN sobre ptmarket_identity;
--      fica outra vez INHERIT FALSE, SET TRUE, como na 0017). Não é SET ROLE: a L2 (event triggers) corre como
--      current_user e ptmarket_identity não pode gravar na caixa negra (42501, falha fechada da 0013).

-- ---------------------------------------------------------------------------
-- A. customers: mudar o email anula a verificação.
-- ---------------------------------------------------------------------------
CREATE FUNCTION customers_email_unverify()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.email IS DISTINCT FROM OLD.email
       AND NEW.email_verified_at IS NOT DISTINCT FROM OLD.email_verified_at THEN
        NEW.email_verified_at := NULL;
    END IF;
    RETURN NEW;
END
$$;

COMMENT ON FUNCTION customers_email_unverify() IS
    'BEFORE UPDATE OF email: email novo sem email_verified_at definido no mesmo UPDATE → email_verified_at = NULL';

REVOKE ALL ON FUNCTION customers_email_unverify() FROM PUBLIC;

CREATE TRIGGER customers_email_unverify
    BEFORE UPDATE OF email ON customers
    FOR EACH ROW EXECUTE FUNCTION customers_email_unverify();
ALTER TABLE customers ENABLE ALWAYS TRIGGER customers_email_unverify;

-- ---------------------------------------------------------------------------
-- B. user_recovery_codes: uso único.
-- ---------------------------------------------------------------------------
CREATE FUNCTION user_recovery_codes_use_once()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.code_hash IS DISTINCT FROM OLD.code_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'user_recovery_codes: só used_at pode mudar'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.used_at IS NOT NULL THEN
        RAISE EXCEPTION 'user_recovery_codes: código de recuperação já usado'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.used_at IS NOT NULL THEN
        NEW.used_at := now();
    END IF;
    RETURN NEW;
END
$$;

COMMENT ON FUNCTION user_recovery_codes_use_once() IS
    'BEFORE UPDATE: código usado não volta a mudar (23514); used_at NULL → now(); id/user_id/code_hash/created_at fixos';

REVOKE ALL ON FUNCTION user_recovery_codes_use_once() FROM PUBLIC;

CREATE TRIGGER user_recovery_codes_use_once
    BEFORE UPDATE ON user_recovery_codes
    FOR EACH ROW EXECUTE FUNCTION user_recovery_codes_use_once();
ALTER TABLE user_recovery_codes ENABLE ALWAYS TRIGGER user_recovery_codes_use_once;

-- ---------------------------------------------------------------------------
-- C. Portal: papel ptmarket_portal + VIEW portal_stores.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ptmarket_portal') THEN
        CREATE ROLE ptmarket_portal
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'ptmarket_portal' AND (rolsuper OR rolbypassrls OR rolcanlogin)
    ) THEN
        RAISE EXCEPTION 'O papel ptmarket_portal já existe com SUPERUSER, BYPASSRLS ou LOGIN; recusado.';
    END IF;

    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       AND NOT pg_has_role(current_user, 'ptmarket_portal', 'SET') THEN
        EXECUTE format('GRANT ptmarket_portal TO %I WITH INHERIT FALSE, SET TRUE', current_user);
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO ptmarket_portal;

-- Só as colunas da view + as do filtro (tenant_id já está na view; publish_to_national_portal, is_active).
GRANT SELECT (id, tenant_id, name, slug, legal_name, nif, email, phone, address_json, geo_lat, geo_lng,
              business_hours, is_vacation_mode, vacation_message, supports_click_collect, supports_local_courier,
              supports_national_shipping, vat_exempt_art53, publish_to_national_portal, is_active)
    ON stores TO ptmarket_portal;
-- tenants: só o que a condição lê (o tenant_type é lido por app_is_national_portal(), INVOKER, como ptmarket_app).
GRANT SELECT (id, is_active, country_code) ON tenants TO ptmarket_portal;

-- Mesma condição da view (defesa em profundidade: nem o dono da view vê lojas fora do portal).
CREATE POLICY portal_view ON stores
    AS PERMISSIVE
    FOR SELECT TO ptmarket_portal
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

-- A app deixa de ler linhas de stores de outros tenants (só tenant_isolation).
DROP POLICY portal_read ON stores;

CREATE VIEW portal_stores WITH (security_barrier = true) AS
    SELECT s.id, s.tenant_id, s.name, s.slug, s.legal_name, s.nif, s.email, s.phone, s.address_json, s.geo_lat,
           s.geo_lng, s.business_hours, s.is_vacation_mode, s.vacation_message, s.supports_click_collect,
           s.supports_local_courier, s.supports_national_shipping, s.vat_exempt_art53
    FROM public.stores s
    WHERE (SELECT public.app_is_national_portal())
      AND s.publish_to_national_portal
      AND s.is_active
      AND EXISTS (
          SELECT 1
          FROM public.tenants o, public.tenants p
          WHERE o.id = s.tenant_id
            AND o.is_active
            AND p.id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            AND o.country_code = p.country_code
      );

COMMENT ON VIEW portal_stores IS
    'Portal nacional: lojas publicadas e ativas de tenants ativos do país do portal; só colunas de exibição (sem IBAN, chaves, credenciais, comissões, KYC)';

REVOKE ALL ON portal_stores FROM PUBLIC;
GRANT SELECT ON portal_stores TO ptmarket_app;

-- Dono = ptmarket_portal (depois do GRANT). CREATE no schema só durante o ALTER (padrão da 0017).
GRANT CREATE ON SCHEMA public TO ptmarket_portal;
ALTER VIEW portal_stores OWNER TO ptmarket_portal;
REVOKE CREATE ON SCHEMA public FROM ptmarket_portal;

-- products e product_variants: "loja visível" = EXISTS em portal_stores.
DROP POLICY portal_read ON products;
CREATE POLICY portal_read ON products
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        (SELECT app_is_national_portal())
        AND is_published
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
        (SELECT app_is_national_portal())
        AND is_active
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
-- D. search_path das DEFINER de identidade (corpo, retorno, dono e grants iguais).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_identity TO %I WITH INHERIT TRUE', current_user);
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION identity_customer_credentials(p_email text)
RETURNS TABLE (id uuid, password_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT c.id, c.password_hash
    FROM public.customers c
    WHERE lower(c.email) = lower(p_email)
      AND c.anonymized_at IS NULL
    LIMIT 1
$$;

CREATE OR REPLACE FUNCTION identity_user_credentials(p_email text)
RETURNS TABLE (id uuid, password_hash text, totp_enabled boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT u.id, u.password_hash, u.totp_enabled
    FROM public.users u
    WHERE lower(u.email) = lower(p_email)
      AND u.is_active
    LIMIT 1
$$;

CREATE OR REPLACE FUNCTION identity_session_lookup(p_token_hash bytea)
RETURNS TABLE (
    id                   uuid,
    subject_type         varchar,
    subject_id           uuid,
    tenant_id            uuid,
    mfa_verified_at      timestamptz,
    impersonator_user_id uuid,
    created_at           timestamptz,
    expires_at           timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.id, s.subject_type, s.subject_id, s.tenant_id, s.mfa_verified_at, s.impersonator_user_id,
           s.created_at, s.expires_at
    FROM public.sessions s
    WHERE s.token_hash = p_token_hash
      AND s.revoked_at IS NULL
      AND s.expires_at > now()
      AND CASE s.subject_type
              WHEN 'user' THEN EXISTS (SELECT 1 FROM public.users u WHERE u.id = s.subject_id AND u.is_active)
              WHEN 'customer' THEN EXISTS (SELECT 1 FROM public.customers c
                                           WHERE c.id = s.subject_id AND c.anonymized_at IS NULL)
              ELSE false
          END
    LIMIT 1
$$;

CREATE OR REPLACE FUNCTION identity_passkey_lookup(p_credential_id bytea)
RETURNS TABLE (id uuid, user_id uuid, credential jsonb, sign_count bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT p.id, p.user_id, p.credential, p.sign_count
    FROM public.user_passkeys p
    JOIN public.users u ON u.id = p.user_id
    WHERE p.credential_id = p_credential_id
      AND u.is_active
    LIMIT 1
$$;

DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_identity TO %I WITH INHERIT FALSE, SET TRUE', current_user);
    END IF;
    IF pg_has_role(current_user, 'ptmarket_identity', 'USAGE')
       AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0021: o migrator ficou com INHERIT em ptmarket_identity';
    END IF;
END
$$;
