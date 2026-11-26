-- 0019 — sessions, user_passkeys e user_recovery_codes: sessões com token só em hash, passkeys de staff e códigos de
-- recuperação do 2FA, cada linha legível só pelo próprio titular (cartão 02/14).
-- Rollback mental (só em dev):
--   DROP FUNCTION identity_passkey_lookup(bytea); DROP FUNCTION identity_session_lookup(bytea);
--   DROP TABLE user_recovery_codes; DROP TABLE user_passkeys; DROP TABLE sessions;
--   (policies, índices, grants e zz_audit_* caem com as tabelas; os eventos ddl.* e sessions.*/user_passkeys.*/
--   user_recovery_codes.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras (spec 12 §3; durações decididas pelo owner a 25/11):
--   * sessions: o token NUNCA é gravado, só o sha256 (32 bytes, UNIQUE). subject_id sem FK (dois alvos: customers ou
--     users). tenant_id = Host onde nasceu; NULL = consola de plataforma. Sem last_seen: a inatividade vive no Redis
--     (cartão 16: staff 30 min, plataforma 15 min), para não haver uma mutação (e um evento L1) por pedido.
--   * Duração ABSOLUTA máxima (CHECK sessions_max_lifetime, decisão do owner 25/11): cliente ≤ 7 dias (168 h);
--     utilizador com tenant_id (staff) ≤ 12 h; utilizador sem tenant_id (plataforma) ≤ 8 h. Em horas, para o CHECK
--     não depender do fuso (DST). created_at fica fora do GRANT INSERT da app (vale sempre o DEFAULT now()), senão um
--     created_at no futuro esticava a validade efetiva.
--   * S := (tipo, actor_id) do contexto: 'customer' ↔ subject_type 'customer'; 'merchant'|'municipal'|'admin' ↔
--     'user'; qualquer outro tipo → nada. Cliente e utilizador com o MESMO uuid não se veem (anti-IDOR por tipo).
--     U := actor_id só quando app.actor_type ∈ {merchant, municipal, admin} (como na 0018).
--   * A app cria a sua sessão (nunca já revogada nem com impersonator_user_id: impersonation = épico admin), lê-a e
--     revoga-a (revoked_at) ou marca o 2FA (mfa_verified_at). SEM DELETE: revogar deixa o rasto. Uma sessão já
--     revogada não volta a ser alterada (own_update exige revoked_at IS NULL: sem "des-revogar"; reforço desta
--     migration, além do cartão).
--   * Passkeys e códigos de recuperação: só do próprio utilizador (U) para SELECT/INSERT/DELETE; UPDATE só de
--     (sign_count, last_used_at, label) e (used_at).
--   * identity_session_lookup / identity_passkey_lookup: DEFINER, STABLE, dono ptmarket_identity (0017: NOLOGIN, sem
--     SUPERUSER/BYPASSRLS), search_path fixo, EXECUTE só ptmarket_app. O dono só lê as colunas de que precisa (grants
--     por coluna + policy identity_lookup USING (true)). A sessão só sai se não revogada, não expirada e o titular
--     estiver ativo (users.is_active / customers.anonymized_at IS NULL: reforço desta migration, além do cartão);
--     a passkey só de utilizador ativo. Nenhuma lista: 0 ou 1 linha por hash/credential_id (ambos UNIQUE).
--   * Caixa negra: zz_audit_row + zz_audit_truncate (L1, ALWAYS) pelo bloco condicional (padrão da 0018: com a L2
--     ativa o CREATE TABLE já os cria). Máscara (0014, audit._redact_key): token_hash, code_hash, user_agent_hash,
--     credential, credential_id → "[redacted]"; ip → "[pii]".

-- ---------------------------------------------------------------------------
-- Tabelas.
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id                   UUID PRIMARY KEY DEFAULT uuidv7(),
    subject_type         VARCHAR(8)  NOT NULL CHECK (subject_type IN ('customer', 'user')),
    subject_id           UUID        NOT NULL, -- sem FK: customers ou users
    token_hash           BYTEA       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32), -- sha256; token nunca gravado
    tenant_id            UUID REFERENCES tenants (id) ON DELETE CASCADE, -- Host onde nasceu; NULL = plataforma
    mfa_verified_at      TIMESTAMPTZ,
    impersonator_user_id UUID REFERENCES users (id) ON DELETE RESTRICT,
    ip                   INET,
    user_agent_hash      BYTEA,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at           TIMESTAMPTZ NOT NULL,
    revoked_at           TIMESTAMPTZ,
    CONSTRAINT sessions_max_lifetime CHECK (
        expires_at > created_at
        AND expires_at <= created_at + CASE
            WHEN subject_type = 'customer' THEN interval '168 hours'
            WHEN tenant_id IS NOT NULL     THEN interval '12 hours'
            ELSE interval '8 hours'
        END
    )
);

CREATE INDEX sessions_subject_idx ON sessions (subject_type, subject_id);
CREATE INDEX sessions_tenant_id_idx ON sessions (tenant_id);
CREATE INDEX sessions_impersonator_user_id_idx ON sessions (impersonator_user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE user_passkeys (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id       UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id BYTEA       NOT NULL UNIQUE,
    credential    JSONB       NOT NULL, -- credencial pública serializada pela biblioteca WebAuthn; sem segredos
    sign_count    BIGINT      NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    label         VARCHAR(64) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX user_passkeys_user_id_idx ON user_passkeys (user_id);

CREATE TABLE user_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  BYTEA       NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX user_recovery_codes_user_id_idx ON user_recovery_codes (user_id);

-- ---------------------------------------------------------------------------
-- Caixa negra L1 (só se a L2 ainda não os criou: padrão da 0018).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sessions', 'user_passkeys', 'user_recovery_codes'] LOOP
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
-- RLS (FORCE: nem o dono lê ou escreve sem o desligar explicitamente).
-- ---------------------------------------------------------------------------
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE user_passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_passkeys FORCE ROW LEVEL SECURITY;
ALTER TABLE user_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_recovery_codes FORCE ROW LEVEL SECURITY;

-- sessions: subject = S.
CREATE POLICY own_insert ON sessions
    AS PERMISSIVE
    FOR INSERT TO ptmarket_app
    WITH CHECK (
        subject_type = CASE WHEN current_setting('app.actor_type', true) = 'customer' THEN 'customer'
                            WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                            THEN 'user' END
        AND subject_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
        AND revoked_at IS NULL
        AND impersonator_user_id IS NULL
    );

CREATE POLICY own_select ON sessions
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        subject_type = CASE WHEN current_setting('app.actor_type', true) = 'customer' THEN 'customer'
                            WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                            THEN 'user' END
        AND subject_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    );

CREATE POLICY own_update ON sessions
    AS PERMISSIVE
    FOR UPDATE TO ptmarket_app
    USING (
        subject_type = CASE WHEN current_setting('app.actor_type', true) = 'customer' THEN 'customer'
                            WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                            THEN 'user' END
        AND subject_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
        AND revoked_at IS NULL
    )
    WITH CHECK (
        subject_type = CASE WHEN current_setting('app.actor_type', true) = 'customer' THEN 'customer'
                            WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                            THEN 'user' END
        AND subject_id = NULLIF(current_setting('app.actor_id', true), '')::uuid
    );

-- Só para o dono da DEFINER de lookup; o filtro (hash + válida + titular ativo) está na função.
CREATE POLICY identity_lookup ON sessions
    AS PERMISSIVE
    FOR SELECT TO ptmarket_identity
    USING (true);

-- user_passkeys e user_recovery_codes: user_id = U.
CREATE POLICY own_select ON user_passkeys
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

CREATE POLICY own_insert ON user_passkeys
    AS PERMISSIVE
    FOR INSERT TO ptmarket_app
    WITH CHECK (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

CREATE POLICY own_update ON user_passkeys
    AS PERMISSIVE
    FOR UPDATE TO ptmarket_app
    USING (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    )
    WITH CHECK (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

CREATE POLICY own_delete ON user_passkeys
    AS PERMISSIVE
    FOR DELETE TO ptmarket_app
    USING (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

CREATE POLICY identity_lookup ON user_passkeys
    AS PERMISSIVE
    FOR SELECT TO ptmarket_identity
    USING (true);

CREATE POLICY own_select ON user_recovery_codes
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

CREATE POLICY own_insert ON user_recovery_codes
    AS PERMISSIVE
    FOR INSERT TO ptmarket_app
    WITH CHECK (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

CREATE POLICY own_update ON user_recovery_codes
    AS PERMISSIVE
    FOR UPDATE TO ptmarket_app
    USING (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    )
    WITH CHECK (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

CREATE POLICY own_delete ON user_recovery_codes
    AS PERMISSIVE
    FOR DELETE TO ptmarket_app
    USING (
        user_id = CASE WHEN current_setting('app.actor_type', true) IN ('merchant', 'municipal', 'admin')
                       THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

-- ---------------------------------------------------------------------------
-- Grants (por coluna onde há escrita parcial; nada para worker/price_writer; sem DELETE em sessions).
-- ---------------------------------------------------------------------------
GRANT SELECT ON sessions TO ptmarket_app;
GRANT INSERT (id, subject_type, subject_id, token_hash, tenant_id, mfa_verified_at, impersonator_user_id, ip,
              user_agent_hash, expires_at, revoked_at)
    ON sessions TO ptmarket_app; -- sem created_at: vale sempre o DEFAULT now() (ver o cabeçalho)
GRANT UPDATE (revoked_at, mfa_verified_at) ON sessions TO ptmarket_app;

GRANT SELECT, INSERT, DELETE ON user_passkeys TO ptmarket_app;
GRANT UPDATE (sign_count, last_used_at, label) ON user_passkeys TO ptmarket_app;

GRANT SELECT, INSERT, DELETE ON user_recovery_codes TO ptmarket_app;
GRANT UPDATE (used_at) ON user_recovery_codes TO ptmarket_app;

GRANT SELECT (id, subject_type, subject_id, token_hash, tenant_id, mfa_verified_at, impersonator_user_id,
              created_at, expires_at, revoked_at)
    ON sessions TO ptmarket_identity;
GRANT SELECT (id, user_id, credential_id, credential, sign_count) ON user_passkeys TO ptmarket_identity;

-- ---------------------------------------------------------------------------
-- Lookups (0 ou 1 linha; nada de listar).
-- ---------------------------------------------------------------------------
CREATE FUNCTION identity_session_lookup(p_token_hash bytea)
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
SET search_path = pg_catalog, public
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

COMMENT ON FUNCTION identity_session_lookup(bytea) IS
    'Sessão válida (não revogada, não expirada, titular ativo) com este sha256 do token; 0 ou 1 linha';

CREATE FUNCTION identity_passkey_lookup(p_credential_id bytea)
RETURNS TABLE (id uuid, user_id uuid, credential jsonb, sign_count bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT p.id, p.user_id, p.credential, p.sign_count
    FROM public.user_passkeys p
    JOIN public.users u ON u.id = p.user_id
    WHERE p.credential_id = p_credential_id
      AND u.is_active
    LIMIT 1
$$;

COMMENT ON FUNCTION identity_passkey_lookup(bytea) IS
    'Passkey de utilizador ativo com este credential_id: id, user_id, credencial pública e sign_count; 0 ou 1 linha';

REVOKE ALL ON FUNCTION identity_session_lookup(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity_passkey_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity_session_lookup(bytea) TO ptmarket_app;
GRANT EXECUTE ON FUNCTION identity_passkey_lookup(bytea) TO ptmarket_app;

-- Dono = ptmarket_identity (depois dos GRANT: quem migra deixa de ter EXECUTE). CREATE no schema só durante o ALTER
-- (padrão de 0017/0018).
GRANT CREATE ON SCHEMA public TO ptmarket_identity;
ALTER FUNCTION identity_session_lookup(bytea) OWNER TO ptmarket_identity;
ALTER FUNCTION identity_passkey_lookup(bytea) OWNER TO ptmarket_identity;
REVOKE CREATE ON SCHEMA public FROM ptmarket_identity;
