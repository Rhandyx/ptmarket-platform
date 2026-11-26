-- 0018 — users e user_roles: contas de backoffice (lojista, Câmara, super_admin) e papéis com âmbito (cartão 02/13).
-- Rollback mental (só em dev):
--   DROP FUNCTION identity_user_credentials(text);
--   DROP TABLE user_roles; DROP TABLE users;   (policies, índices, grants e zz_audit_* caem com as tabelas;
--   os eventos ddl.* e users.*/user_roles.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras (spec 07 §1 e §4 adaptada, spec 12 §3):
--   * users é global (uma conta pode ter papéis em várias lojas/Câmaras): sem tenant_id; email único sem
--     distinção de maiúsculas. password_hash = Argon2id PHC (NULL = só passkey); totp_secret_enc = AES-256-GCM
--     com a chave fora da BD; totp_enabled exige o segredo.
--   * user_roles: âmbito por papel (CHECK): super_admin → global (tenant e loja NULL); tenant_admin → tenant, sem
--     loja; merchant_owner/merchant_staff → tenant + loja, e a loja tem de ser desse tenant (FK composta para
--     stores (tenant_id, id)). Par repetido, NULLs incluídos, = 23505.
--   * U := o actor_id SÓ quando app.actor_type ∈ {merchant, municipal, admin} (super_admin → admin, tenant_admin →
--     municipal, merchant_* → merchant). customer/system/anonymous com o mesmo uuid não leem nada.
--   * Conta inativa (is_active = false): nem lê nem altera a sua linha (self_select e self_update exigem is_active;
--     decisão do supervisor, 26/11: o cartão não pedia is_active no self_update).
--   * A app lê a sua conta (ativa) e os seus papéis, e altera só full_name, password_hash, totp_secret_enc,
--     totp_enabled, last_login_at, updated_at da sua conta. ZERO INSERT/DELETE em users e ZERO escrita em
--     user_roles: criar contas, convites e atribuir papéis é do épico backoffice; o 1.º super_admin nasce pelo
--     CLI do cartão 20 (ligação do migrator, ator 'db': L1 + pgaudit). Não há escalada para super_admin pela API.
--   * identity_user_credentials é a ÚNICA leitura por email: id + password_hash + totp_enabled, no máximo 1 linha,
--     nunca de conta inativa. Dono ptmarket_identity (0017: NOLOGIN, sem SUPERUSER/BYPASSRLS), que só lê
--     (id, email, password_hash, totp_enabled, is_active) — nunca nome nem segredo TOTP — e não escreve.
--     Não existe função que liste utilizadores.
--   * Caixa negra: zz_audit_row + zz_audit_truncate (L1, ENABLE ALWAYS). Com os event triggers da L2 ativos (BD de
--     dev, produção) o CREATE TABLE já os cria (0013) e o bloco abaixo não faz nada; numa BD limpa as migrations
--     correm ANTES de infra/postgres/bootstrap/event-triggers.sql (migrations/tests/run.sh, deploy), por isso o
--     bloco cria-os como a 0010. A máscara (0010/0014) cobre users(email, full_name), *_enc e *_hash.
--     PADRÃO para as tabelas novas (aprovado pelo supervisor, 26/11): enquanto o run.sh/deploy instalar os event
--     triggers DEPOIS das migrations, cada migration que cria tabelas inclui este bloco condicional (IF NOT EXISTS,
--     CREATE TRIGGER + ENABLE ALWAYS só quando falta), nunca um CREATE TRIGGER incondicional (dá 42710 com a L2).

-- ---------------------------------------------------------------------------
-- Tabelas.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuidv7(),
    email           VARCHAR(255) NOT NULL,
    password_hash   TEXT, -- Argon2id PHC; NULL = só passkey
    full_name       VARCHAR(255) NOT NULL,
    totp_secret_enc TEXT, -- AES-256-GCM, chave fora da BD
    totp_enabled    BOOLEAN      NOT NULL DEFAULT false,
    is_active       BOOLEAN      NOT NULL DEFAULT true,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT users_totp_needs_secret CHECK (NOT totp_enabled OR totp_secret_enc IS NOT NULL)
);

CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

CREATE TABLE user_roles (
    id         UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       VARCHAR(32) NOT NULL
        CHECK (role IN ('super_admin', 'tenant_admin', 'merchant_owner', 'merchant_staff')),
    tenant_id  UUID REFERENCES tenants (id) ON DELETE CASCADE,
    store_id   UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_roles_store_fkey
        FOREIGN KEY (tenant_id, store_id) REFERENCES stores (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT user_roles_scope CHECK (
        CASE role
            WHEN 'super_admin'  THEN tenant_id IS NULL AND store_id IS NULL
            WHEN 'tenant_admin' THEN tenant_id IS NOT NULL AND store_id IS NULL
            ELSE tenant_id IS NOT NULL AND store_id IS NOT NULL
        END
    ),
    CONSTRAINT user_roles_unique UNIQUE NULLS NOT DISTINCT (user_id, role, tenant_id, store_id)
);

CREATE INDEX user_roles_user_id_idx ON user_roles (user_id);
CREATE INDEX user_roles_tenant_store_idx ON user_roles (tenant_id, store_id); -- FKs tenant_id e (tenant_id, store_id)

-- ---------------------------------------------------------------------------
-- Caixa negra L1 (só se a L2 ainda não os criou: ver o cabeçalho).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['users', 'user_roles'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                       WHERE tgrelid = format('public.%I', t)::regclass AND tgname = 'zz_audit_row') THEN
            EXECUTE format('CREATE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE ON %I '
                           'FOR EACH ROW EXECUTE FUNCTION audit.audit_row_trigger()', t);
            EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER zz_audit_row', t);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                       WHERE tgrelid = format('public.%I', t)::regclass AND tgname = 'zz_audit_truncate') THEN
            EXECUTE format('CREATE TRIGGER zz_audit_truncate BEFORE TRUNCATE ON %I '
                           'FOR EACH STATEMENT EXECUTE FUNCTION audit.audit_row_trigger()', t);
            EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER zz_audit_truncate', t);
        END IF;
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- RLS (FORCE: nem o dono escreve sem o desligar explicitamente).
-- ---------------------------------------------------------------------------
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;

CREATE POLICY self_select ON users
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                  THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
        AND is_active
    );

CREATE POLICY self_update ON users
    AS PERMISSIVE
    FOR UPDATE TO ptmarket_app
    USING (
        id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                  THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
        AND is_active
    )
    WITH CHECK (
        id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                  THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

-- Só para o dono da DEFINER de lookup; o filtro (email + ativo) está na função.
CREATE POLICY identity_lookup ON users
    AS PERMISSIVE
    FOR SELECT TO ptmarket_identity
    USING (true);

CREATE POLICY own_select ON user_roles
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

-- ---------------------------------------------------------------------------
-- Grants (sem INSERT/DELETE em users e sem escrita em user_roles para ninguém da app).
-- ---------------------------------------------------------------------------
GRANT SELECT ON users TO ptmarket_app;
GRANT UPDATE (full_name, password_hash, totp_secret_enc, totp_enabled, last_login_at, updated_at)
    ON users TO ptmarket_app;
GRANT SELECT ON user_roles TO ptmarket_app;
GRANT SELECT (id, email, password_hash, totp_enabled, is_active) ON users TO ptmarket_identity;

-- ---------------------------------------------------------------------------
-- Lookup de login de backoffice: a única leitura por email. Nada de listar nem pesquisar utilizadores.
-- ---------------------------------------------------------------------------
CREATE FUNCTION identity_user_credentials(p_email text)
RETURNS TABLE (id uuid, password_hash text, totp_enabled boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT u.id, u.password_hash, u.totp_enabled
    FROM public.users u
    WHERE lower(u.email) = lower(p_email)
      AND u.is_active
    LIMIT 1
$$;

COMMENT ON FUNCTION identity_user_credentials(text) IS
    'Login de backoffice: id + password_hash + totp_enabled da conta ativa com este email (sem distinção de maiúsculas); 0 ou 1 linha';

REVOKE ALL ON FUNCTION identity_user_credentials(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity_user_credentials(text) TO ptmarket_app;

-- Dono = ptmarket_identity (depois dos GRANT: quem migra deixa de ter EXECUTE). O novo dono precisa de CREATE no
-- schema só durante o ALTER; retira-se logo a seguir (padrão de 0017).
GRANT CREATE ON SCHEMA public TO ptmarket_identity;
ALTER FUNCTION identity_user_credentials(text) OWNER TO ptmarket_identity;
REVOKE CREATE ON SCHEMA public FROM ptmarket_identity;
