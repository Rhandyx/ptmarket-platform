-- 0017 — customers deixa de estar fechada: policies por ator, grants por coluna e lookup de login (cartão 02/12).
-- Rollback mental (só em dev):
--   DROP FUNCTION identity_customer_credentials(text);
--   DROP POLICY identity_lookup ON customers; DROP POLICY customer_register ON customers;
--   DROP POLICY customer_self_update ON customers; DROP POLICY customer_self_select ON customers;
--   REVOKE ALL ON customers FROM ptmarket_app, ptmarket_identity;
--   ALTER TABLE customers DROP COLUMN email_verified_at;
--   REVOKE USAGE ON SCHEMA public FROM ptmarket_identity; DROP ROLE ptmarket_identity;
--   (o papel pode ser partilhado por outras BDs do cluster; os eventos ddl.* gravados ficam.)
--
-- Regras:
--   * customers é global (uma conta para todas as Câmaras): sem tenant_id; o dono da linha é o ator.
--   * A := o actor_id SÓ quando app.actor_type = 'customer'. merchant/admin/system com o mesmo uuid não leem nada.
--   * O registo é do ator 'anonymous': INSERT sem RETURNING e sem ON CONFLICT (não passa na policy de SELECT);
--     email repetido = 23505. Não nasce anonimizado nem com o email verificado.
--   * Sem DELETE e sem UPDATE de id, created_at, anonymized_at, email_verified_at (verificação de email e
--     esquecimento RGPD são de outros épicos; o esquecimento mantém os dados fiscais).
--   * identity_customer_credentials é a ÚNICA leitura por email: devolve só id + password_hash, no máximo 1 linha,
--     nunca de conta anonimizada. Dono ptmarket_identity (NOLOGIN, sem SUPERUSER/BYPASSRLS), que só tem SELECT
--     em (id, email, password_hash, anonymized_at) — nunca nome, telefone nem NIF — e nenhuma escrita.
--   * Nenhuma tabela nova: os eventos customers.insert/update saem do zz_audit_row (L1, 0010) com o ator do
--     contexto e email/nome/telefone/NIF mascarados; o DDL desta migration fica na L2 (0013).

ALTER TABLE customers ADD COLUMN email_verified_at TIMESTAMPTZ;

-- ---------------------------------------------------------------------------
-- Papel dono da função de lookup (padrão de 0007: quem migra recebe SET sem INHERIT para o ALTER ... OWNER).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ptmarket_identity') THEN
        CREATE ROLE ptmarket_identity
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'ptmarket_identity' AND (rolsuper OR rolbypassrls OR rolcanlogin)
    ) THEN
        RAISE EXCEPTION 'O papel ptmarket_identity já existe com SUPERUSER, BYPASSRLS ou LOGIN; recusado.';
    END IF;

    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       AND NOT pg_has_role(current_user, 'ptmarket_identity', 'SET') THEN
        EXECUTE format('GRANT ptmarket_identity TO %I WITH INHERIT FALSE, SET TRUE', current_user);
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO ptmarket_identity;

-- ---------------------------------------------------------------------------
-- Policies (RLS FORCE desde 0005).
-- ---------------------------------------------------------------------------
CREATE POLICY customer_self_select ON customers
    AS PERMISSIVE
    FOR SELECT TO ptmarket_app
    USING (
        id = CASE WHEN current_setting('app.actor_type', true) = 'customer'
                  THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
        AND anonymized_at IS NULL
    );

CREATE POLICY customer_self_update ON customers
    AS PERMISSIVE
    FOR UPDATE TO ptmarket_app
    USING (
        id = CASE WHEN current_setting('app.actor_type', true) = 'customer'
                  THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
        AND anonymized_at IS NULL
    )
    WITH CHECK (
        id = CASE WHEN current_setting('app.actor_type', true) = 'customer'
                  THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
    );

CREATE POLICY customer_register ON customers
    AS PERMISSIVE
    FOR INSERT TO ptmarket_app
    WITH CHECK (
        current_setting('app.actor_type', true) = 'anonymous'
        AND anonymized_at IS NULL
        AND email_verified_at IS NULL
    );

-- Só para o dono da DEFINER de lookup; o filtro (email + não anonimizado) está na função.
CREATE POLICY identity_lookup ON customers
    AS PERMISSIVE
    FOR SELECT TO ptmarket_identity
    USING (true);

-- ---------------------------------------------------------------------------
-- Grants (sem DELETE para ninguém).
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON customers TO ptmarket_app;
GRANT UPDATE (email, name, phone, nif, password_hash, passkeys, consents, updated_at) ON customers TO ptmarket_app;
GRANT SELECT (id, email, password_hash, anonymized_at) ON customers TO ptmarket_identity;

-- ---------------------------------------------------------------------------
-- Lookup de login: a única leitura por email. Nada de listar nem pesquisar clientes.
-- ---------------------------------------------------------------------------
CREATE FUNCTION identity_customer_credentials(p_email text)
RETURNS TABLE (id uuid, password_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT c.id, c.password_hash
    FROM public.customers c
    WHERE lower(c.email) = lower(p_email)
      AND c.anonymized_at IS NULL
    LIMIT 1
$$;

COMMENT ON FUNCTION identity_customer_credentials(text) IS
    'Login: id + password_hash da conta não anonimizada com este email (sem distinção de maiúsculas); 0 ou 1 linha';

REVOKE ALL ON FUNCTION identity_customer_credentials(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity_customer_credentials(text) TO ptmarket_app;

-- Dono = ptmarket_identity (depois dos GRANT: quem migra deixa de ter EXECUTE). O novo dono precisa de CREATE no
-- schema só durante o ALTER; retira-se logo a seguir.
GRANT CREATE ON SCHEMA public TO ptmarket_identity;
ALTER FUNCTION identity_customer_credentials(text) OWNER TO ptmarket_identity;
REVOKE CREATE ON SCHEMA public FROM ptmarket_identity;
