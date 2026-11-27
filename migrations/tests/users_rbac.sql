-- Teste de users e user_roles (0018): RLS por ator, grants por coluna, CHECK de âmbito, lookup de login e
-- eventos da caixa negra.
-- Preparação pelo dono das migrations (a app não cria contas nem papéis): RLS FORCE desligado só durante o seed e
-- reposto logo a seguir. Asserções de acesso sempre com SET ROLE ptmarket_app (ou ptmarket_worker onde se prova
-- que não pode), nunca como superuser. Os eventos L1 ficam no tenant do contexto (app.current_tenant_id), que a
-- app lê pela policy tenant_read. Tudo numa transação com ROLLBACK: a BD fica como estava.

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

-- Linhas afetadas por um UPDATE (sem RETURNING).
CREATE FUNCTION pg_temp.expect_rows(p_sql text, p_expected bigint, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_n bigint;
BEGIN
    EXECUTE p_sql;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'FALHOU: % (esperado % linhas, obtido %)', p_label, p_expected, v_n;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

CREATE FUNCTION pg_temp.as_actor(p_type text, p_id text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', p_type, true);
    PERFORM set_config('app.actor_id', p_id, true);
END
$$;

-- Tenants TA, TB, TC; lojas SA (TA), SB (TC).
-- Utilizadores: X = merchant_owner de SA · Y = tenant_admin de TB · S = super_admin · Z = merchant_staff de SA, INATIVO
-- · W = sponsor_admin da entidade E (0028).
SELECT set_config('app.actor_label', 'test', true);
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000013a0', true);

-- ---------------------------------------------------------------------------
-- 0. Preparação.
-- ---------------------------------------------------------------------------
-- Desde a 0033 as lojas só vivem em tenants national_portal: TA = nacional PT (loja SA), TC = nacional ES (loja SB);
-- TB = municipal PT, só para o papel tenant_admin de Y.
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000013a0', 'rbac-a', 'rbac-a.teste.invalid', 'Tenant RBAC A', 'national_portal', 'PT'),
    ('00000000-0000-7000-8000-0000000013b0', 'rbac-b', 'rbac-b.teste.invalid', 'Tenant RBAC B', 'municipal', 'PT'),
    ('00000000-0000-7000-8000-0000000013c0', 'rbac-c', 'rbac-c.teste.invalid', 'Tenant RBAC C', 'national_portal', 'ES');

SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('system', '');
SELECT set_config('app.store_id', '00000000-0000-7000-8000-0000000013a1', true); -- âmbito da loja (0035)
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000013a1', '00000000-0000-7000-8000-0000000013a0',
     'Loja SA', 'loja-sa', 'Loja SA Lda', '500001301', 'PT50000000000000000001301', 'sa@teste.invalid');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000013c0', true);
SELECT set_config('app.store_id', '00000000-0000-7000-8000-0000000013b1', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000013b1', '00000000-0000-7000-8000-0000000013c0',
     'Loja SB', 'loja-sb', 'Loja SB Lda', '500001302', 'PT50000000000000000001302', 'sb@teste.invalid');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000013a0', true);
SELECT set_config('app.store_id', '', true);
SELECT pg_temp.as_actor('', '');
RESET ROLE;

ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
ALTER TABLE user_roles NO FORCE ROW LEVEL SECURITY;

INSERT INTO users (id, email, password_hash, full_name, totp_secret_enc, totp_enabled, is_active) VALUES
    ('00000000-0000-7000-8000-0000000013e1', 'Lojista.X@Teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$UVgx$UVgy',
     'Xavier Lojista', 'ZW5jLXRvdHAteA', true, true),
    ('00000000-0000-7000-8000-0000000013e2', 'camara.y@teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$UVkx$UVky',
     'Yara Camara', 'ZW5jLXRvdHAteQ', true, true),
    ('00000000-0000-7000-8000-0000000013e5', 'segjar.s@teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$UVMx$UVMy',
     'Sofia Segjar', 'ZW5jLXRvdHAtcw', true, true),
    ('00000000-0000-7000-8000-0000000013e9', 'inativo.z@teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$UVox$UVoy',
     'Zeca Inativo', NULL, false, false);

INSERT INTO user_roles (id, user_id, role, tenant_id, store_id) VALUES
    ('00000000-0000-7000-8000-0000000013f1', '00000000-0000-7000-8000-0000000013e1', 'merchant_owner',
     '00000000-0000-7000-8000-0000000013a0', '00000000-0000-7000-8000-0000000013a1'),
    ('00000000-0000-7000-8000-0000000013f2', '00000000-0000-7000-8000-0000000013e2', 'tenant_admin',
     '00000000-0000-7000-8000-0000000013b0', NULL),
    ('00000000-0000-7000-8000-0000000013f5', '00000000-0000-7000-8000-0000000013e5', 'super_admin', NULL, NULL),
    ('00000000-0000-7000-8000-0000000013f9', '00000000-0000-7000-8000-0000000013e9', 'merchant_staff',
     '00000000-0000-7000-8000-0000000013a0', '00000000-0000-7000-8000-0000000013a1');

-- ---------------------------------------------------------------------------
-- 1. Invariantes (CHECK, FK, UNIQUE), ainda como dono sem FORCE.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id) VALUES
       ('00000000-0000-7000-8000-0000000013e5', 'super_admin', '00000000-0000-7000-8000-0000000013a0')$q$,
    '23514', 'super_admin com tenant_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id, store_id) VALUES
       ('00000000-0000-7000-8000-0000000013e5', 'super_admin', '00000000-0000-7000-8000-0000000013a0',
        '00000000-0000-7000-8000-0000000013a1')$q$,
    '23514', 'super_admin com tenant_id + store_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role) VALUES ('00000000-0000-7000-8000-0000000013e2', 'tenant_admin')$q$,
    '23514', 'tenant_admin sem tenant_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id, store_id) VALUES
       ('00000000-0000-7000-8000-0000000013e2', 'tenant_admin', '00000000-0000-7000-8000-0000000013c0',
        '00000000-0000-7000-8000-0000000013b1')$q$,
    '23514', 'tenant_admin com store_id falha (mesmo com o par tenant/loja coerente)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id) VALUES
       ('00000000-0000-7000-8000-0000000013e1', 'merchant_owner', '00000000-0000-7000-8000-0000000013a0')$q$,
    '23514', 'merchant_owner sem store_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, store_id) VALUES
       ('00000000-0000-7000-8000-0000000013e1', 'merchant_staff', '00000000-0000-7000-8000-0000000013a1')$q$,
    '23514', 'merchant_staff sem tenant_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id, store_id) VALUES
       ('00000000-0000-7000-8000-0000000013e1', 'merchant_owner', '00000000-0000-7000-8000-0000000013a0',
        '00000000-0000-7000-8000-0000000013b1')$q$,
    '23503', 'merchant_owner com loja de outro tenant falha (FK composta)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id, store_id) VALUES
       ('00000000-0000-7000-8000-0000000013e1', 'merchant_owner', '00000000-0000-7000-8000-0000000013a0',
        '00000000-0000-7000-8000-0000000013ff')$q$,
    '23503', 'merchant_owner com loja inexistente falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role) VALUES ('00000000-0000-7000-8000-0000000013e5', 'root')$q$,
    '23514', 'papel fora da lista fechada falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role) VALUES ('00000000-0000-7000-8000-0000000013e5', 'super_admin')$q$,
    '23505', 'super_admin repetido (tenant/loja NULL) = 23505 (NULLS NOT DISTINCT)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id) VALUES
       ('00000000-0000-7000-8000-0000000013e2', 'tenant_admin', '00000000-0000-7000-8000-0000000013b0')$q$,
    '23505', 'tenant_admin repetido (loja NULL) = 23505');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role) VALUES ('00000000-0000-7000-8000-0000000013ee', 'super_admin')$q$,
    '23503', 'papel de utilizador inexistente falha');
-- 0028: sponsor_admin com âmbito de entidade patrocinadora (W = sponsor_admin da entidade E).
INSERT INTO sponsor_entities (id, kind, name, slug) VALUES
    ('00000000-0000-7000-8000-0000000013d1', 'association', 'Associação RBAC', 'assoc-rbac');
INSERT INTO users (id, email, full_name) VALUES
    ('00000000-0000-7000-8000-0000000013e7', 'patrocinio.w@teste.invalid', 'Wanda Patrocinio');
INSERT INTO user_roles (id, user_id, role, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-0000000013f7', '00000000-0000-7000-8000-0000000013e7', 'sponsor_admin',
     '00000000-0000-7000-8000-0000000013d1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_roles WHERE id = '00000000-0000-7000-8000-0000000013f7'$q$,
    1, 'sponsor_admin com entidade passa');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role) VALUES ('00000000-0000-7000-8000-0000000013e7', 'sponsor_admin')$q$,
    '23514', 'sponsor_admin sem entidade falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, sponsor_entity_id, tenant_id) VALUES
       ('00000000-0000-7000-8000-0000000013e7', 'sponsor_admin', '00000000-0000-7000-8000-0000000013d1',
        '00000000-0000-7000-8000-0000000013a0')$q$,
    '23514', 'sponsor_admin com tenant_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, sponsor_entity_id, tenant_id, store_id) VALUES
       ('00000000-0000-7000-8000-0000000013e7', 'sponsor_admin', '00000000-0000-7000-8000-0000000013d1',
        '00000000-0000-7000-8000-0000000013a0', '00000000-0000-7000-8000-0000000013a1')$q$,
    '23514', 'sponsor_admin com tenant_id + store_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id) VALUES
       ('00000000-0000-7000-8000-0000000013e7', 'sponsor_admin', '00000000-0000-7000-8000-0000000013a0')$q$,
    '23514', 'sponsor_admin só com tenant_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id, store_id, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000013e1', 'merchant_owner', '00000000-0000-7000-8000-0000000013a0',
        '00000000-0000-7000-8000-0000000013a1', '00000000-0000-7000-8000-0000000013d1')$q$,
    '23514', 'merchant_owner com entidade falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000013e2', 'tenant_admin', '00000000-0000-7000-8000-0000000013b0',
        '00000000-0000-7000-8000-0000000013d1')$q$,
    '23514', 'tenant_admin com entidade falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000013e5', 'super_admin', '00000000-0000-7000-8000-0000000013d1')$q$,
    '23514', 'super_admin com entidade falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000013e7', 'sponsor_admin', '00000000-0000-7000-8000-0000000013d1')$q$,
    '23505', 'sponsor_admin duplicado exato = 23505');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000013e7', 'sponsor_admin', '00000000-0000-7000-8000-0000000013dd')$q$,
    '23503', 'sponsor_admin com entidade inexistente falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO users (email, full_name, totp_enabled) VALUES ('t@teste.invalid', 'T', true)$q$,
    '23514', 'totp_enabled sem totp_secret_enc falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO users (email, full_name) VALUES ('LOJISTA.x@teste.INVALID', 'Outro')$q$,
    '23505', 'email repetido (maiúsculas ignoradas) = 23505');

ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE oid IN ('users'::regclass, 'user_roles'::regclass) AND relrowsecurity AND relforcerowsecurity$q$,
    2, 'users e user_roles: RLS ENABLE + FORCE');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid IN ('users'::regclass, 'user_roles'::regclass) AND tgenabled = 'A'
         AND tgfoid = 'audit.audit_row_trigger()'::regprocedure
         AND ((tgname = 'zz_audit_row' AND tgtype = 29) OR (tgname = 'zz_audit_truncate' AND tgtype = 34))$q$,
    4, 'users e user_roles: zz_audit_row + zz_audit_truncate (L1, ALWAYS)');

SET ROLE ptmarket_app;

-- ---------------------------------------------------------------------------
-- 2. Cada um lê a sua conta e os seus papéis, e nada mais (anti-IDOR).
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000013e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM users', 1, 'X vê exatamente uma conta');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM users WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$, 1, 'X lê a sua conta');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM users WHERE id = '00000000-0000-7000-8000-0000000013e2'$q$, 0, 'X não lê a conta de Y');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM users WHERE lower(email) = 'segjar.s@teste.invalid'$q$, 0, 'X não encontra S por email');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_roles
       WHERE user_id = '00000000-0000-7000-8000-0000000013e1' AND role = 'merchant_owner'$q$,
    1, 'X lê o seu papel');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_roles', 1, 'X vê só os seus papéis');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_roles WHERE user_id <> '00000000-0000-7000-8000-0000000013e1'$q$,
    0, 'X não lê papéis de Y, S nem Z (nem os da sua loja)');

SELECT pg_temp.as_actor('municipal', '00000000-0000-7000-8000-0000000013e2');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM users WHERE id = '00000000-0000-7000-8000-0000000013e2'$q$, 1, 'Y (municipal) lê a sua conta');
SELECT pg_temp.expect_count('SELECT count(*) FROM users', 1, 'Y vê só a sua conta');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_roles WHERE role = 'tenant_admin'$q$, 1, 'Y lê o seu papel tenant_admin');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_roles', 1, 'Y vê só os seus papéis');

SELECT pg_temp.as_actor('municipal', '00000000-0000-7000-8000-0000000013e7');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_roles
       WHERE role = 'sponsor_admin' AND sponsor_entity_id = '00000000-0000-7000-8000-0000000013d1'$q$,
    1, 'W (sponsor_admin) lê o seu papel com a entidade');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_roles', 1, 'W vê só os seus papéis');
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000013e1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_roles WHERE user_id = '00000000-0000-7000-8000-0000000013e7'$q$,
    0, 'X não lê o papel sponsor_admin de W');

SELECT pg_temp.as_actor('admin', '00000000-0000-7000-8000-0000000013e5');
SELECT pg_temp.expect_count('SELECT count(*) FROM users', 1, 'S (admin) vê só a sua conta (sem listagem global)');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_roles', 1, 'S vê só o seu papel');

SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000013e9');
SELECT pg_temp.expect_count('SELECT count(*) FROM users', 0, 'conta inativa: Z não lê a sua conta');
SELECT pg_temp.expect_rows(
    $q$UPDATE users SET full_name = 'volta' WHERE id = '00000000-0000-7000-8000-0000000013e9'$q$,
    0, 'conta inativa: Z não altera a sua conta (por id)');
SELECT pg_temp.expect_rows($q$UPDATE users SET full_name = 'volta'$q$, 0, 'conta inativa: UPDATE sem WHERE → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM users WHERE id = '00000000-0000-7000-8000-0000000013e9'$q$,
    0, 'conta inativa: SELECT por id → 0 linhas');

-- O tipo de ator conta: o mesmo uuid como customer/system/anonymous/sem tipo não vê nem altera nada.
SELECT pg_temp.as_actor('customer', '00000000-0000-7000-8000-0000000013e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM users', 0, 'customer com o actor_id de X não lê users');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_roles', 0, 'customer com o actor_id de X não lê user_roles');
SELECT pg_temp.expect_rows($q$UPDATE users SET full_name = 'c'$q$, 0, 'customer com o actor_id de X não altera');
SELECT pg_temp.as_actor('system', '00000000-0000-7000-8000-0000000013e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM users', 0, 'system com o actor_id de X não lê users');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_roles', 0, 'system com o actor_id de X não lê user_roles');
SELECT pg_temp.as_actor('anonymous', '00000000-0000-7000-8000-0000000013e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM users', 0, 'anonymous com o actor_id de X não lê users');
SELECT pg_temp.as_actor('', '00000000-0000-7000-8000-0000000013e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM users', 0, 'sem actor_type (só actor_id) → 0 linhas');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_roles', 0, 'sem actor_type → 0 papéis');

-- ---------------------------------------------------------------------------
-- 3. Escrita: só a própria conta e só as colunas concedidas; papéis nunca.
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000013e1');
SELECT pg_temp.expect_rows(
    $q$UPDATE users SET full_name = 'Xavier Novo', last_login_at = now(), updated_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$,
    1, 'X altera a sua conta (nome, último login)');
SELECT pg_temp.expect_rows(
    $q$UPDATE users SET password_hash = '$argon2id$v=19$m=19456,t=2,p=1$Tk9WTw$Tk9WTzI',
                        totp_secret_enc = 'Tk9WTy1zZWdyZWRvLXRvdHA', totp_enabled = true, updated_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$,
    1, 'X troca a password e o segredo TOTP');
SELECT pg_temp.expect_rows(
    $q$UPDATE users SET full_name = 'pirata' WHERE id = '00000000-0000-7000-8000-0000000013e2'$q$,
    0, 'X não altera a conta de Y (0 linhas)');
SELECT pg_temp.expect_rows($q$UPDATE users SET full_name = 'Xavier Final'$q$, 1, 'UPDATE sem WHERE só afeta X');
SELECT pg_temp.expect_error(
    $q$UPDATE users SET totp_enabled = true, totp_secret_enc = NULL
       WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$,
    '23514', 'app não liga TOTP sem segredo');
SELECT pg_temp.expect_error(
    $q$UPDATE users SET is_active = true WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$,
    '42501', 'UPDATE de is_active falha');
SELECT pg_temp.expect_error(
    $q$UPDATE users SET email = 'novo@teste.invalid' WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$,
    '42501', 'UPDATE de email falha');
SELECT pg_temp.expect_error(
    $q$UPDATE users SET id = '00000000-0000-7000-8000-0000000013e5' WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$,
    '42501', 'UPDATE de id falha');
SELECT pg_temp.expect_error(
    $q$UPDATE users SET created_at = now() WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$,
    '42501', 'UPDATE de created_at falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO users (email, full_name) VALUES ('novo@teste.invalid', 'Novo')$q$,
    '42501', 'app não cria contas (INSERT em users = 42501)');
SELECT pg_temp.expect_error(
    $q$DELETE FROM users WHERE id = '00000000-0000-7000-8000-0000000013e1'$q$,
    '42501', 'app não apaga contas (DELETE em users = 42501)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role) VALUES ('00000000-0000-7000-8000-0000000013e1', 'super_admin')$q$,
    '42501', 'sem escalada: app não se dá super_admin (INSERT em user_roles = 42501)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, tenant_id) VALUES
       ('00000000-0000-7000-8000-0000000013e1', 'tenant_admin', '00000000-0000-7000-8000-0000000013a0')$q$,
    '42501', 'app não se dá tenant_admin');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_roles (user_id, role, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000013e1', 'sponsor_admin', '00000000-0000-7000-8000-0000000013d1')$q$,
    '42501', 'app não se dá sponsor_admin');
SELECT pg_temp.expect_error(
    $q$UPDATE user_roles SET sponsor_entity_id = NULL WHERE id = '00000000-0000-7000-8000-0000000013f7'$q$,
    '42501', 'app não altera o âmbito de sponsor_admin');
SELECT pg_temp.expect_error(
    $q$UPDATE user_roles SET role = 'super_admin', tenant_id = NULL, store_id = NULL
       WHERE id = '00000000-0000-7000-8000-0000000013f1'$q$,
    '42501', 'app não promove o seu papel (UPDATE em user_roles = 42501)');
SELECT pg_temp.expect_error(
    $q$UPDATE user_roles SET user_id = '00000000-0000-7000-8000-0000000013e1'
       WHERE id = '00000000-0000-7000-8000-0000000013f5'$q$,
    '42501', 'app não rouba o papel de S');
SELECT pg_temp.expect_error(
    $q$DELETE FROM user_roles WHERE id = '00000000-0000-7000-8000-0000000013f1'$q$,
    '42501', 'app não apaga papéis (DELETE em user_roles = 42501)');
SELECT pg_temp.expect_error('TRUNCATE user_roles', '42501', 'app não faz TRUNCATE de user_roles');
SELECT pg_temp.expect_error('TRUNCATE users', '42501', 'app não faz TRUNCATE de users');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM users
       WHERE id = '00000000-0000-7000-8000-0000000013e1' AND full_name = 'Xavier Final' AND totp_enabled
         AND last_login_at IS NOT NULL$q$,
    1, 'alterações de X gravadas');
RESET ROLE;

-- Privilégios no catálogo (independentes de policy).
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', 'user_roles', p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE', 'REFERENCES')
              AND has_any_column_privilege('ptmarket_app', 'user_roles', p.priv))$q$,
    0, 'app: só SELECT em user_roles');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['INSERT', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', 'users', p.priv)
          OR (p.priv IN ('INSERT', 'REFERENCES') AND has_any_column_privilege('ptmarket_app', 'users', p.priv))$q$,
    0, 'app sem INSERT/DELETE/TRUNCATE em users');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['id', 'email', 'is_active', 'created_at']) AS c(col)
       WHERE has_column_privilege('ptmarket_app', 'users', c.col, 'UPDATE')$q$,
    0, 'app sem UPDATE de id/email/is_active/created_at');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_worker', 'ptmarket_price_writer']) AS r(rol),
                            unnest(ARRAY['users', 'user_roles']) AS t(tab),
                            unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) AS p(priv)
       WHERE has_table_privilege(r.rol, t.tab, p.priv)
          OR (p.priv <> 'DELETE' AND has_any_column_privilege(r.rol, t.tab, p.priv))$q$,
    0, 'worker e price_writer sem nenhum privilégio em users/user_roles');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['full_name', 'totp_secret_enc', 'last_login_at', 'created_at', 'updated_at']) AS c(col)
       WHERE has_column_privilege('ptmarket_identity', 'users', c.col, 'SELECT')$q$,
    0, 'ptmarket_identity não lê nome, segredo TOTP nem datas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['id', 'email', 'password_hash', 'totp_enabled', 'is_active']) AS c(col)
       WHERE has_column_privilege('ptmarket_identity', 'users', c.col, 'SELECT')$q$,
    5, 'ptmarket_identity lê só (id, email, password_hash, totp_enabled, is_active)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_identity', 'users', p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE') AND has_any_column_privilege('ptmarket_identity', 'users', p.priv))$q$,
    0, 'ptmarket_identity sem escrita em users');
-- 0025: a porta da timeline do Super-Admin lê user_roles (só as colunas do papel), nunca escreve.
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_identity', 'user_roles', p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE') AND has_any_column_privilege('ptmarket_identity', 'user_roles', p.priv))$q$,
    0, 'ptmarket_identity sem escrita em user_roles (nem SELECT na tabela inteira)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_attribute a
       WHERE a.attrelid = 'user_roles'::regclass AND a.attnum > 0 AND NOT a.attisdropped
         AND has_column_privilege('ptmarket_identity', 'user_roles', a.attname, 'SELECT')
             IS DISTINCT FROM (a.attname IN ('user_id', 'role', 'tenant_id', 'store_id'))$q$,
    0, 'ptmarket_identity lê só (user_id, role, tenant_id, store_id) de user_roles');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid IN ('users'::regclass, 'user_roles'::regclass) AND a.grantee = 0$q$,
    0, 'users/user_roles sem privilégios para PUBLIC');

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error('SELECT count(*) FROM users', '42501', 'worker não lê users');
SELECT pg_temp.expect_error('SELECT count(*) FROM user_roles', '42501', 'worker não lê user_roles');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM identity_user_credentials('lojista.x@teste.invalid')$q$,
    '42501', 'worker não executa o lookup');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. Lookup de login.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('anonymous', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_user_credentials('LOJISTA.x@teste.INVALID')
       WHERE id = '00000000-0000-7000-8000-0000000013e1' AND totp_enabled
         AND password_hash = '$argon2id$v=19$m=19456,t=2,p=1$Tk9WTw$Tk9WTzI'$q$,
    1, 'lookup devolve id + hash + totp_enabled de X (maiúsculas ignoradas)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_user_credentials('lojista.x@teste.invalid')$q$, 1, 'lookup: no máximo 1 linha');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_user_credentials('inativo.z@teste.invalid')$q$, 0, 'lookup: conta inativa → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_user_credentials('ninguem@teste.invalid')$q$, 0, 'lookup: email inexistente → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_user_credentials('%')$q$, 0, 'lookup: sem padrões (% não pesquisa)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_user_credentials($e$x' OR '1'='1$e$)$q$, 0, 'lookup: texto com SQL injetado → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_user_credentials(NULL)$q$, 0, 'lookup: NULL → 0 linhas');
RESET ROLE;

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'identity_user_credentials(text)'::regprocedure
         AND p.prosecdef AND p.provolatile = 's' AND p.proowner = 'ptmarket_identity'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']
         AND pg_get_function_result(p.oid) = 'TABLE(id uuid, password_hash text, totp_enabled boolean)'$q$,
    1, 'lookup: DEFINER, STABLE, dono ptmarket_identity, search_path fixo, só id + hash + totp_enabled');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_worker', 'ptmarket_price_writer']) AS r(rol)
       WHERE has_function_privilege(r.rol, 'identity_user_credentials(text)', 'EXECUTE')$q$,
    0, 'só ptmarket_app executa o lookup (worker/price_writer não)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a
       WHERE p.oid = 'identity_user_credentials(text)'::regprocedure AND a.grantee = 0$q$,
    0, 'lookup sem EXECUTE para PUBLIC');
-- Proibida função que liste utilizadores: ptmarket_identity só é dono dos lookups (0 ou 1 linha cada) e de uma
-- exceção na allowlist: identity_admin_read_events (0025/0026), até 100 linhas de EVENTOS da caixa negra (nunca
-- utilizadores), só para super_admin com TOTP e sessão da plataforma com 2FA; e as 3 de revisão das verificações
-- de loja (0037: até 100 verificações, nunca utilizadores), com a mesma porta.
-- 14: lookups de sessão e passkey
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (SELECT array_agg(p.oid::regprocedure::text ORDER BY p.oid::regprocedure::text) AS fns
                             FROM pg_proc p WHERE p.proowner = 'ptmarket_identity'::regrole) s
       WHERE s.fns = ARRAY['identity_admin_read_events(timestamp with time zone,timestamp with time zone,uuid,uuid,uuid,uuid,text,text,timestamp with time zone,uuid,integer)',
                           'identity_admin_verification_decide(uuid,boolean,text)',
                           'identity_admin_verification_secret(uuid)',
                           'identity_admin_verifications_list(text,timestamp with time zone,uuid,integer)',
                           'identity_customer_credentials(text)', 'identity_passkey_lookup(bytea)',
                           'identity_session_lookup(bytea)', 'identity_user_credentials(text)']$q$,
    1, 'ptmarket_identity não é dono de mais nenhuma função (allowlist exata de 8)');

-- ---------------------------------------------------------------------------
-- 5. Caixa negra: o UPDATE de password_hash / totp_secret_enc deixou evento com o ator, sem os valores.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000013e1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'users.update' AND target_type = 'users' AND actor_type = 'merchant'
         AND actor_id = '00000000-0000-7000-8000-0000000013e1'
         AND target_id = '00000000-0000-7000-8000-0000000013e1'
         AND tenant_id = '00000000-0000-7000-8000-0000000013a0' AND outcome = 'success'
         AND changes->'after'->>'password_hash' = '[redacted]'
         AND changes->'after'->>'totp_secret_enc' = '[redacted]'
         AND changes->'before'->>'password_hash' = '[redacted]'
         AND changes->'before'->>'totp_secret_enc' = '[redacted]'$q$,
    1, 'users.update da password/TOTP de X: ator merchant X, hash e segredo = [redacted] (antes e depois)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'users.update' AND target_type = 'users' AND actor_type = 'merchant'
         AND actor_id = '00000000-0000-7000-8000-0000000013e1'
         AND tenant_id = '00000000-0000-7000-8000-0000000013a0'$q$,
    3, 'três UPDATE de X com efeito → três eventos (as tentativas recusadas não gravaram)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE target_type = 'users' AND actor_type = 'db' AND action = 'users.insert'
         AND tenant_id = '00000000-0000-7000-8000-0000000013a0'
         AND changes->'after'->>'email' = '[pii]' AND changes->'after'->>'full_name' = '[pii]'$q$,
    5, 'seed do dono em users ficou na caixa negra (ator db), email/nome = [pii]');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE target_type IN ('users', 'user_roles')
         AND changes::text ~* '(argon2id|ZW5jLXRvdHA|Tk9WTy|Lojista|teste\.invalid|Xavier|Yara|Sofia|Zeca|Wanda|Patrocinio)'$q$,
    0, 'eventos de users/user_roles sem hash, segredo TOTP, email nem nome em claro');
RESET ROLE;

ROLLBACK;
