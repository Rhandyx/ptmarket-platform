-- 0024 — 1.º super_admin (e os seguintes) por uma DEFINER dedicada, já com TOTP ativo e 10 códigos de recuperação
-- (cartão 02/20b; achados médios 3 e 4 da auditoria L3 do cartão 20).
-- Rollback mental (só em dev):
--   D. DROP FUNCTION identity_create_superadmin(uuid, text, text, text, text, bytea[]);
--   C. DROP POLICY bootstrap_insert ON users; DROP POLICY bootstrap_insert ON user_roles;
--      DROP POLICY bootstrap_insert ON user_recovery_codes;
--      REVOKE ALL ON users, user_roles, user_recovery_codes FROM ptmarket_bootstrap;
--      REVOKE USAGE ON SCHEMA public FROM ptmarket_bootstrap, ptmarket_operator;
--   A. REVOKE ptmarket_operator FROM <migrator>; DROP ROLE ptmarket_operator (papel do cluster: pode servir outras BDs).
--      ptmarket_bootstrap é do bootstrap da caixa negra (infra/postgres/init/03-audit-bootstrap.sh): fica.
--   B. nada (o bloco só lê pg_auth_members).
--   (Nenhuma tabela nova; os eventos ddl.* e users.*/user_roles.*/user_recovery_codes.* gravados ficam: a caixa negra
--   é só de acréscimo.)
--
-- Regras:
--   * O CLI deixa de fazer DDL (NO FORCE RLS com a credencial do dono = lock ACCESS EXCLUSIVE sem lock_timeout em
--     users/user_roles, DDL de rotina na L2, super_admin sem TOTP). Caminho do CLI (ligado como migrator), uma só
--     transação: BEGIN; SET LOCAL ROLE ptmarket_operator; SELECT public.identity_create_superadmin(…); COMMIT.
--   * ptmarket_bootstrap (criado pelo bootstrap da caixa negra, com USAGE em audit e EXECUTE em audit_append_db, na
--     allowlist de grants da audit_seal): dono da função. Os seus INSERT passam pela L1 (INVOKER) → evento com ator
--     'db' e actor_label = session_user (quem ligou; o SET ROLE não o muda). Só INSERT nas colunas que a função usa;
--     ZERO SELECT/UPDATE/DELETE: o email repetido é recusado pelo índice único users_email_lower_key (23505 apanhado
--     e relançado com mensagem fixa), sem ler users.
--     Políticas FOR INSERT TO ptmarket_bootstrap: users sem restrição extra; user_roles só super_admin global
--     (tenant e loja NULL; o INSERT por coluna nem deixa escrever tenant_id/store_id); user_recovery_codes livre.
--   * ptmarket_operator: o ÚNICO com EXECUTE (REVOKE de PUBLIC, app e worker). O migrator é membro com INHERIT FALSE,
--     SET TRUE: sem SET ROLE não executa. Produção: o owner pode criar um login próprio, membro de ptmarket_operator
--     (depois desta migration: a guarda B recusa memberships estranhas que já existam ao aplicá-la).
--   * Guarda B = a da 0022, para os dois papéis novos: nenhum é membro de outro papel; o migrator sem INHERIT; nenhum
--     membro além do migrator (ADMIN implícito do CREATE ROLE com grantor superuser, ou SET sem INHERIT nem ADMIN).
--   * LIÇÃO L2: nada de SET ROLE aqui (a L2 corre como current_user; ptmarket_bootstrap não grava em audit por DDL).
--     O dono muda com ALTER FUNCTION … OWNER TO (o migrator tem SET em ptmarket_bootstrap, dado pelo bootstrap; o
--     novo dono precisa de CREATE no schema só durante o ALTER, padrão da 0017).
--   * Validação (22023, mensagem fixa, sem ecoar valores), antes de qualquer escrita: id não NULL; email =
--     lower(btrim(email)), 3–255 caracteres, com '@'; nome 1–255; PHC '$argon2id$…'; segredo 'v1:…'; exatamente 10
--     hashes de 32 bytes, sem NULL nem repetidos. Email já existente (sem distinção de maiúsculas) → 23505; id já
--     existente → 23505 (outra mensagem fixa).

-- ---------------------------------------------------------------------------
-- A. Papéis: ptmarket_bootstrap tem de vir do bootstrap; ptmarket_operator nasce aqui.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regrole('ptmarket_bootstrap') IS NULL
       OR NOT has_schema_privilege('ptmarket_bootstrap', 'audit', 'USAGE')
       OR NOT has_function_privilege('ptmarket_bootstrap',
                                     'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)', 'EXECUTE') THEN
        RAISE EXCEPTION '0024: ptmarket_bootstrap em falta ou sem USAGE em audit/EXECUTE em audit_append_db: reaplicar infra/postgres/init/03-audit-bootstrap.sh (superuser) antes desta migration.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ptmarket_bootstrap'
               AND (rolsuper OR rolbypassrls OR rolcanlogin OR rolcreatedb OR rolcreaterole OR rolreplication)) THEN
        RAISE EXCEPTION '0024: ptmarket_bootstrap tem LOGIN, SUPERUSER, BYPASSRLS, CREATEDB, CREATEROLE ou REPLICATION; recusado.';
    END IF;
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       AND NOT pg_has_role(current_user, 'ptmarket_bootstrap', 'SET') THEN
        RAISE EXCEPTION '0024: o migrator não tem SET em ptmarket_bootstrap (dado pelo bootstrap da caixa negra); recusado.';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ptmarket_operator') THEN
        CREATE ROLE ptmarket_operator
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ptmarket_operator'
               AND (rolsuper OR rolbypassrls OR rolcanlogin OR rolcreatedb OR rolcreaterole OR rolreplication)) THEN
        RAISE EXCEPTION '0024: ptmarket_operator já existe com LOGIN, SUPERUSER, BYPASSRLS, CREATEDB, CREATEROLE ou REPLICATION; recusado.';
    END IF;
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
       AND NOT pg_has_role(current_user, 'ptmarket_operator', 'SET') THEN
        EXECUTE format('GRANT ptmarket_operator TO %I WITH INHERIT FALSE, SET TRUE', current_user);
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- B. Guarda da 0022 para os dois papéis novos: nenhuma membership além das do migrator.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_role text;
    v_oid  oid;
    v_me   oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
    FOREACH v_role IN ARRAY ARRAY['ptmarket_bootstrap', 'ptmarket_operator'] LOOP
        v_oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = v_role);

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = v_oid) THEN
            RAISE EXCEPTION '0024: o papel % é membro de outro papel (herdaria os privilégios dele); recusado.', v_role;
        END IF;

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                   WHERE m.roleid = v_oid AND m.member = v_me AND m.inherit_option) THEN
            RAISE EXCEPTION '0024: o migrator tem INHERIT no papel %; recusado.', v_role;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members m
            LEFT JOIN pg_catalog.pg_roles g ON g.oid = m.grantor
            WHERE m.roleid = v_oid
              AND NOT (m.member = v_me
                       AND NOT m.inherit_option
                       AND ((m.admin_option AND COALESCE(g.rolsuper, false))
                            OR (m.set_option AND NOT m.admin_option)))
        ) THEN
            RAISE EXCEPTION '0024: o papel % tem membros além do migrator (só ADMIN do bootstrap ou SET sem INHERIT); recusado.',
                v_role;
        END IF;
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- C. Grants e políticas de ptmarket_bootstrap (só INSERT, só as colunas usadas).
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO ptmarket_bootstrap, ptmarket_operator;

GRANT INSERT (id, email, password_hash, full_name, totp_secret_enc, totp_enabled, is_active)
    ON users TO ptmarket_bootstrap;
GRANT INSERT (user_id, role) ON user_roles TO ptmarket_bootstrap;
GRANT INSERT (user_id, code_hash) ON user_recovery_codes TO ptmarket_bootstrap;

CREATE POLICY bootstrap_insert ON users
    AS PERMISSIVE
    FOR INSERT TO ptmarket_bootstrap
    WITH CHECK (true);

CREATE POLICY bootstrap_insert ON user_roles
    AS PERMISSIVE
    FOR INSERT TO ptmarket_bootstrap
    WITH CHECK (role = 'super_admin' AND tenant_id IS NULL AND store_id IS NULL);

CREATE POLICY bootstrap_insert ON user_recovery_codes
    AS PERMISSIVE
    FOR INSERT TO ptmarket_bootstrap
    WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- D. A função.
-- ---------------------------------------------------------------------------
CREATE FUNCTION identity_create_superadmin(
    p_id              uuid,
    p_email           text,
    p_full_name       text,
    p_phc             text,
    p_totp_secret_enc text,
    p_recovery_hashes bytea[]
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_constraint text;
BEGIN
    IF p_id IS NULL THEN
        RAISE EXCEPTION 'identity_create_superadmin: id obrigatório' USING ERRCODE = '22023';
    END IF;
    IF p_email IS NULL OR p_email <> lower(btrim(p_email))
       OR char_length(p_email) NOT BETWEEN 3 AND 255 OR strpos(p_email, '@') = 0 THEN
        RAISE EXCEPTION 'identity_create_superadmin: email inválido (minúsculas, sem espaços nas pontas, 3–255, com @)'
            USING ERRCODE = '22023';
    END IF;
    IF p_full_name IS NULL OR char_length(p_full_name) NOT BETWEEN 1 AND 255 THEN
        RAISE EXCEPTION 'identity_create_superadmin: nome inválido (1–255 caracteres)' USING ERRCODE = '22023';
    END IF;
    IF p_phc IS NULL OR p_phc NOT LIKE '$argon2id$%' THEN
        RAISE EXCEPTION 'identity_create_superadmin: hash da password tem de ser Argon2id (PHC)' USING ERRCODE = '22023';
    END IF;
    IF p_totp_secret_enc IS NULL OR p_totp_secret_enc NOT LIKE 'v1:%' THEN
        RAISE EXCEPTION 'identity_create_superadmin: segredo TOTP tem de ser cifrado no formato v1:' USING ERRCODE = '22023';
    END IF;
    IF p_recovery_hashes IS NULL
       OR array_ndims(p_recovery_hashes) IS DISTINCT FROM 1
       OR array_length(p_recovery_hashes, 1) IS DISTINCT FROM 10
       OR EXISTS (SELECT 1 FROM unnest(p_recovery_hashes) AS h(v) WHERE h.v IS NULL OR octet_length(h.v) <> 32)
       OR (SELECT count(DISTINCT h.v) FROM unnest(p_recovery_hashes) AS h(v)) <> 10 THEN
        RAISE EXCEPTION 'identity_create_superadmin: são precisos 10 hashes de códigos de recuperação, de 32 bytes, distintos'
            USING ERRCODE = '22023';
    END IF;

    -- Email repetido: o índice único (lower(email)) recusa; sem SELECT em users.
    BEGIN
        INSERT INTO public.users (id, email, password_hash, full_name, totp_secret_enc, totp_enabled, is_active)
        VALUES (p_id, p_email, p_phc, p_full_name, p_totp_secret_enc, true, true);
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
        IF v_constraint = 'users_pkey' THEN
            RAISE EXCEPTION 'identity_create_superadmin: id já existe' USING ERRCODE = '23505';
        END IF;
        RAISE EXCEPTION 'identity_create_superadmin: email já existe' USING ERRCODE = '23505';
    END;

    INSERT INTO public.user_roles (user_id, role) VALUES (p_id, 'super_admin');

    INSERT INTO public.user_recovery_codes (user_id, code_hash)
    SELECT p_id, h.v FROM unnest(p_recovery_hashes) AS h(v);
END
$fn$;

COMMENT ON FUNCTION identity_create_superadmin(uuid, text, text, text, text, bytea[]) IS
    'Cria um super_admin ativo com TOTP ligado, papel global e 10 códigos de recuperação (só ptmarket_operator); 22023 validação, 23505 repetido';

REVOKE ALL ON FUNCTION identity_create_superadmin(uuid, text, text, text, text, bytea[])
    FROM PUBLIC, ptmarket_app, ptmarket_worker;
GRANT EXECUTE ON FUNCTION identity_create_superadmin(uuid, text, text, text, text, bytea[]) TO ptmarket_operator;

-- Dono = ptmarket_bootstrap (depois dos GRANT: quem migra deixa de ter EXECUTE). CREATE no schema só durante o ALTER.
GRANT CREATE ON SCHEMA public TO ptmarket_bootstrap;
ALTER FUNCTION identity_create_superadmin(uuid, text, text, text, text, bytea[]) OWNER TO ptmarket_bootstrap;
REVOKE CREATE ON SCHEMA public FROM ptmarket_bootstrap;

-- ---------------------------------------------------------------------------
-- Verificação final.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_fn regprocedure := 'public.identity_create_superadmin(uuid,text,text,text,text,bytea[])'::regprocedure;
    v_r  text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
                   WHERE p.oid = v_fn AND p.prosecdef
                     AND p.proowner = 'ptmarket_bootstrap'::regrole
                     AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']) THEN
        RAISE EXCEPTION '0024: identity_create_superadmin sem DEFINER, dono ptmarket_bootstrap ou search_path fixo';
    END IF;
    FOREACH v_r IN ARRAY ARRAY['ptmarket_app', 'ptmarket_worker', current_user::text] LOOP
        IF has_function_privilege(v_r, v_fn, 'EXECUTE') THEN
            RAISE EXCEPTION '0024: % tem EXECUTE em identity_create_superadmin', v_r;
        END IF;
    END LOOP;
    IF NOT has_function_privilege('ptmarket_operator', v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0024: ptmarket_operator sem EXECUTE em identity_create_superadmin';
    END IF;
    IF has_schema_privilege('ptmarket_bootstrap', 'public', 'CREATE') THEN
        RAISE EXCEPTION '0024: ptmarket_bootstrap ficou com CREATE em public';
    END IF;
END
$$;
