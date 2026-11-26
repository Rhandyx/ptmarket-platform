-- run.sh: superuser
-- Teste da 0024 (cartão 02/20b): identity_create_superadmin cria utilizador + papel + 10 códigos numa chamada, como
-- ptmarket_operator (SET ROLE); eventos L1 com ator 'db'; validação 22023 e repetidos 23505 sem nada criado; só o
-- operator executa; ptmarket_bootstrap só insere super_admin global; guarda de memberships nos dois papéis novos.
-- Superuser só para contar linhas (RLS FORCE) e ler audit.*; cada asserção de acesso faz SET ROLE do papel em causa.
-- Tudo numa transação com ROLLBACK.

BEGIN;

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_state text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = p_state THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado %, obtido %: %)', p_label, p_state, v_state, v_msg;
    END;
    RAISE EXCEPTION 'FALHOU: % (esperado erro %, mas passou)', p_label, p_state;
END
$$;

CREATE FUNCTION pg_temp.expect_count(p_sql text, p_expected bigint, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_n bigint;
BEGIN
    EXECUTE p_sql INTO v_n;
    IF v_n IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'FALHOU: % (esperado %, obtido %)', p_label, p_expected, v_n;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Mensagem de erro sem ecoar valores (email, hash, segredo).
CREATE FUNCTION pg_temp.expect_error_msg(p_sql text, p_state text, p_forbidden text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
    v_det   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT, v_det = PG_EXCEPTION_DETAIL;
        IF v_state <> p_state THEN
            RAISE EXCEPTION 'FALHOU: % (esperado %, obtido %: %)', p_label, p_state, v_state, v_msg;
        END IF;
        IF strpos(v_msg || COALESCE(v_det, ''), p_forbidden) > 0 THEN
            RAISE EXCEPTION 'FALHOU: % (a mensagem ecoa o valor)', p_label;
        END IF;
        RAISE NOTICE 'OK: %', p_label;
        RETURN;
    END;
    RAISE EXCEPTION 'FALHOU: % (esperado erro %, mas passou)', p_label, p_state;
END
$$;

-- Chamada com argumentos por omissão válidos; cada caso troca um.
CREATE FUNCTION pg_temp.call_sql(
    p_id      text DEFAULT '00000000-0000-7000-8000-0000000b0002',
    p_email   text DEFAULT 'segundo@ptmarket.test',
    p_name    text DEFAULT 'Segundo',
    p_phc     text DEFAULT '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA',
    p_secret  text DEFAULT 'v1:k1:QUJD',
    p_hashes  text DEFAULT 'ARRAY(SELECT sha256(convert_to(''s'' || g, ''UTF8'')) FROM generate_series(1, 10) g)'
)
RETURNS text LANGUAGE sql AS $$
    SELECT format('SELECT public.identity_create_superadmin(%L::uuid, %L, %L, %L, %L, %s)',
                  p_id, p_email, p_name, p_phc, p_secret, p_hashes)
$$;

-- ---------------------------------------------------------------------------
-- 1. Catálogo: função, papéis, memberships.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'public.identity_create_superadmin(uuid,text,text,text,text,bytea[])'::regprocedure
         AND p.prosecdef AND p.proowner = 'ptmarket_bootstrap'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']
         AND p.prorettype = 'void'::regtype$q$,
    1, 'identity_create_superadmin: DEFINER, dono ptmarket_bootstrap, search_path = pg_catalog, pg_temp, void');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a
       WHERE p.oid = 'public.identity_create_superadmin(uuid,text,text,text,text,bytea[])'::regprocedure
         AND a.grantee NOT IN ('ptmarket_bootstrap'::regrole, 'ptmarket_operator'::regrole)$q$,
    0, 'EXECUTE só do dono e de ptmarket_operator (nem PUBLIC)');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname IN ('ptmarket_bootstrap', 'ptmarket_operator')
         AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcanlogin AND NOT rolcreatedb AND NOT rolcreaterole
         AND NOT rolreplication$q$,
    2, 'ptmarket_bootstrap e ptmarket_operator: NOLOGIN, sem SUPERUSER/BYPASSRLS/CREATEDB/CREATEROLE/REPLICATION');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_auth_members m
       WHERE m.member IN ('ptmarket_bootstrap'::regrole, 'ptmarket_operator'::regrole)
          OR (m.roleid IN ('ptmarket_bootstrap'::regrole, 'ptmarket_operator'::regrole)
              AND (m.member <> 'ptmarket_migrator'::regrole OR m.inherit_option))$q$,
    0, 'memberships: os dois papéis não são membros de nada; só o migrator é membro, sem INHERIT');

SELECT pg_temp.expect_count(
    $q$SELECT (pg_has_role('ptmarket_migrator', 'ptmarket_operator', 'SET')
               AND NOT pg_has_role('ptmarket_migrator', 'ptmarket_operator', 'USAGE')
               AND pg_has_role('ptmarket_migrator', 'ptmarket_bootstrap', 'SET')
               AND NOT pg_has_role('ptmarket_migrator', 'ptmarket_bootstrap', 'USAGE'))::int$q$,
    1, 'migrator: SET nos dois papéis, sem herdar privilégios');

SELECT pg_temp.expect_count(
    $q$SELECT (has_function_privilege('ptmarket_bootstrap',
                   'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)', 'EXECUTE')
               AND has_schema_privilege('ptmarket_bootstrap', 'audit', 'USAGE')
               AND NOT has_schema_privilege('ptmarket_bootstrap', 'public', 'CREATE')
               AND NOT has_table_privilege('ptmarket_bootstrap', 'public.users', 'SELECT')
               AND NOT has_any_column_privilege('ptmarket_bootstrap', 'public.users', 'SELECT')
               AND NOT has_any_column_privilege('ptmarket_bootstrap', 'public.user_roles', 'SELECT')
               AND NOT has_any_column_privilege('ptmarket_bootstrap', 'public.user_recovery_codes', 'SELECT')
               AND NOT has_column_privilege('ptmarket_bootstrap', 'public.user_roles', 'tenant_id', 'INSERT')
               AND NOT has_column_privilege('ptmarket_bootstrap', 'public.user_roles', 'store_id', 'INSERT'))::int$q$,
    1, 'ptmarket_bootstrap: EXECUTE em audit_append_db; sem SELECT; INSERT sem tenant_id/store_id em user_roles');

-- Nenhum DDL nem NO FORCE no caminho do CLI: o FORCE RLS continua ligado nas três tabelas.
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE oid IN ('public.users'::regclass, 'public.user_roles'::regclass, 'public.user_recovery_codes'::regclass)
         AND relrowsecurity AND relforcerowsecurity$q$,
    3, 'users, user_roles e user_recovery_codes com RLS ENABLE + FORCE');

-- ---------------------------------------------------------------------------
-- 2. Quem não é operator não executa.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error(pg_temp.call_sql(), '42501', 'ptmarket_app sem EXECUTE');
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error(pg_temp.call_sql(), '42501', 'ptmarket_worker sem EXECUTE');
RESET ROLE;
SET ROLE ptmarket_migrator;
SELECT pg_temp.expect_error(pg_temp.call_sql(), '42501', 'ptmarket_migrator (sem SET ROLE) sem EXECUTE');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 3. Caminho feliz como operator: utilizador + papel + 10 códigos, eventos L1 com ator 'db'.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_operator;
SELECT public.identity_create_superadmin(
    '00000000-0000-7000-8000-0000000b0001'::uuid, 'primeiro@ptmarket.test', 'Primeiro Admin',
    '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA', 'v1:k1:QUJD',
    ARRAY(SELECT sha256(convert_to('p' || g, 'UTF8')) FROM generate_series(1, 10) g));
RESET ROLE;

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM public.users
       WHERE id = '00000000-0000-7000-8000-0000000b0001' AND email = 'primeiro@ptmarket.test'
         AND full_name = 'Primeiro Admin' AND password_hash LIKE '$argon2id$%'
         AND totp_secret_enc = 'v1:k1:QUJD' AND totp_enabled AND is_active$q$,
    1, 'utilizador criado ativo, com TOTP ligado');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM public.user_roles
       WHERE user_id = '00000000-0000-7000-8000-0000000b0001' AND role = 'super_admin'
         AND tenant_id IS NULL AND store_id IS NULL$q$,
    1, 'papel super_admin global');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM public.user_roles WHERE user_id = '00000000-0000-7000-8000-0000000b0001'$q$,
    1, 'só um papel');
SELECT pg_temp.expect_count(
    $q$SELECT count(DISTINCT code_hash) FROM public.user_recovery_codes
       WHERE user_id = '00000000-0000-7000-8000-0000000b0001' AND used_at IS NULL
         AND code_hash = ANY (ARRAY(SELECT sha256(convert_to('p' || g, 'UTF8')) FROM generate_series(1, 10) g))$q$,
    10, '10 códigos de recuperação gravados, por usar');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE actor_type = 'db' AND actor_label = session_user
         AND ((action = 'users.insert' AND target_id = '00000000-0000-7000-8000-0000000b0001')
           OR (action = 'user_roles.insert' AND changes -> 'after' ->> 'user_id' = '00000000-0000-7000-8000-0000000b0001')
           OR (action = 'user_recovery_codes.insert'
               AND changes -> 'after' ->> 'user_id' = '00000000-0000-7000-8000-0000000b0001'))$q$,
    12, 'L1: 1 users.insert + 1 user_roles.insert + 10 user_recovery_codes.insert, ator db (session_user)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action IN ('users.insert', 'user_roles.insert', 'user_recovery_codes.insert')
         AND actor_type <> 'db'
         AND (target_id = '00000000-0000-7000-8000-0000000b0001'
              OR changes -> 'after' ->> 'user_id' = '00000000-0000-7000-8000-0000000b0001')$q$,
    0, 'L1: nenhum evento com outro ator');

-- ---------------------------------------------------------------------------
-- 4. Repetidos → 23505, mensagem fixa, nada criado.
-- ---------------------------------------------------------------------------
-- Conta antiga com maiúsculas no email (criada por fora; superuser): o índice lower(email) também a apanha.
INSERT INTO public.users (id, email, full_name) VALUES ('00000000-0000-7000-8000-0000000b00aa', 'Antigo@PTMarket.test', 'Antigo');

SET ROLE ptmarket_operator;
SELECT pg_temp.expect_error_msg(pg_temp.call_sql(p_email => 'primeiro@ptmarket.test'), '23505', 'primeiro@',
    'mesmo email → 23505, sem ecoar o email');
SELECT pg_temp.expect_error_msg(pg_temp.call_sql(p_email => 'antigo@ptmarket.test'), '23505', 'antigo@',
    'email igual a uma conta com maiúsculas → 23505, sem ecoar o email');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_email => 'Primeiro@PTMarket.test'), '22023',
    'mesmo email com maiúsculas no argumento → 22023 (tem de vir já em minúsculas)');
SELECT pg_temp.expect_error_msg(pg_temp.call_sql(p_id => '00000000-0000-7000-8000-0000000b0001'), '23505',
    '0000000b0001', 'id repetido → 23505, sem ecoar o id');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 5. Validação → 22023, nada criado.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_operator;
SELECT pg_temp.expect_error_msg(pg_temp.call_sql(p_phc => '$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA'), '22023',
    'argon2i$', 'PHC argon2i (não id) → 22023, sem ecoar o hash');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_phc => '$2b$12$abcdefghijklmnopqrstuv'), '22023', 'PHC bcrypt → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_phc => NULL), '22023', 'PHC NULL → 22023');
SELECT pg_temp.expect_error_msg(pg_temp.call_sql(p_secret => 'k1:QUJD'), '22023', 'QUJD',
    'segredo sem v1: → 22023, sem ecoar o segredo');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_secret => 'v2:k1:QUJD'), '22023', 'segredo v2: → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(
    p_hashes => 'ARRAY(SELECT sha256(convert_to(''s'' || g, ''UTF8'')) FROM generate_series(1, 9) g)'),
    '22023', '9 hashes → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(
    p_hashes => 'ARRAY(SELECT sha256(convert_to(''s'' || g, ''UTF8'')) FROM generate_series(1, 11) g)'),
    '22023', '11 hashes → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(
    p_hashes => 'ARRAY(SELECT CASE WHEN g = 5 THEN substring(sha256(''x''::bytea) FROM 1 FOR 31)
                                   ELSE sha256(convert_to(''s'' || g, ''UTF8'')) END
                       FROM generate_series(1, 10) g)'),
    '22023', 'um hash com 31 bytes → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(
    p_hashes => 'ARRAY(SELECT sha256(convert_to(''s'' || least(g, 9), ''UTF8'')) FROM generate_series(1, 10) g)'),
    '22023', 'hashes repetidos → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(
    p_hashes => 'ARRAY(SELECT CASE WHEN g = 3 THEN NULL ELSE sha256(convert_to(''s'' || g, ''UTF8'')) END
                       FROM generate_series(1, 10) g)'),
    '22023', 'hash NULL → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_hashes => 'NULL'), '22023', 'array NULL → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_email => ' segundo@ptmarket.test'), '22023', 'email com espaço → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_email => 'sem-arroba.test'), '22023', 'email sem @ → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_email => 'a@'), '22023', 'email com 2 caracteres → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_email => repeat('a', 250) || '@x.test'), '22023',
    'email com 257 caracteres → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_name => ''), '22023', 'nome vazio → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_name => repeat('n', 256)), '22023', 'nome com 256 → 22023');
SELECT pg_temp.expect_error(pg_temp.call_sql(p_id => NULL), '22023', 'id NULL → 22023');
RESET ROLE;

SELECT pg_temp.expect_count(
    $q$SELECT (SELECT count(*) FROM public.users
               WHERE id IN ('00000000-0000-7000-8000-0000000b0001', '00000000-0000-7000-8000-0000000b0002')
                  OR email = 'segundo@ptmarket.test')
             + (SELECT count(*) FROM public.user_roles WHERE user_id = '00000000-0000-7000-8000-0000000b0002')
             + (SELECT count(*) FROM public.user_recovery_codes
                WHERE user_id = '00000000-0000-7000-8000-0000000b0002')$q$,
    1, 'depois das recusas: só o primeiro utilizador existe; nada do segundo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM public.user_recovery_codes WHERE user_id = '00000000-0000-7000-8000-0000000b0001'$q$,
    10, 'o primeiro continua com 10 códigos (as recusas não acrescentaram nada)');

-- ---------------------------------------------------------------------------
-- 6. ptmarket_bootstrap diretamente: só super_admin global; sem leitura nem outras escritas.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_bootstrap;
SELECT pg_temp.expect_error($q$INSERT INTO public.user_roles (user_id, role)
    VALUES ('00000000-0000-7000-8000-0000000b00aa', 'tenant_admin')$q$, '42501',
    'bootstrap: papel que não é super_admin → 42501 (política)');
SELECT pg_temp.expect_error($q$INSERT INTO public.user_roles (user_id, role)
    VALUES ('00000000-0000-7000-8000-0000000b00aa', 'merchant_owner')$q$, '42501',
    'bootstrap: merchant_owner → 42501 (política)');
SELECT pg_temp.expect_error($q$INSERT INTO public.user_roles (user_id, role, tenant_id)
    VALUES ('00000000-0000-7000-8000-0000000b00aa', 'super_admin', '00000000-0000-7000-8000-00000000c001')$q$, '42501',
    'bootstrap: papel com tenant → 42501');
SELECT pg_temp.expect_error($q$INSERT INTO public.users (id, email, full_name, last_login_at)
    VALUES ('00000000-0000-7000-8000-0000000b00bb', 'x@ptmarket.test', 'X', now())$q$, '42501',
    'bootstrap: coluna fora do GRANT (last_login_at) → 42501');
SELECT pg_temp.expect_error($q$SELECT count(*) FROM public.users$q$, '42501', 'bootstrap: sem SELECT em users');
SELECT pg_temp.expect_error($q$UPDATE public.users SET is_active = false$q$, '42501', 'bootstrap: sem UPDATE em users');
SELECT pg_temp.expect_error($q$DELETE FROM public.user_roles$q$, '42501', 'bootstrap: sem DELETE em user_roles');
SELECT pg_temp.expect_error($q$DELETE FROM public.user_recovery_codes$q$, '42501',
    'bootstrap: sem DELETE em user_recovery_codes');
RESET ROLE;

ROLLBACK;
