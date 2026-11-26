-- Teste da 0022 (cartão 02/10c): a app regista clientes sem poder escolher email_verified_at nem anonymized_at; os
-- papéis donos de DEFINER/views (ptmarket_identity, ptmarket_portal) sem memberships além das do migrator.
-- Corre como o migrator (o bloco B da 0022 compara com current_user). Asserções de acesso com SET ROLE ptmarket_app.
-- O bloco B não fica na BD (é um DO): pg_temp.roles_guard() é uma CÓPIA LITERAL do corpo do DO da 0022 — mudar
-- um sem o outro invalida este teste. O papel de teste é criado e largado dentro da transação (ROLLBACK).

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

-- Erro do bloco B com a mensagem esperada (P0001 + texto): prova qual das regras recusou.
CREATE FUNCTION pg_temp.expect_raise(p_sql text, p_msg text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = 'P0001' AND v_msg = p_msg THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado P0001 "%", obtido %: %)', p_label, p_msg, v_state, v_msg;
    END;
    RAISE EXCEPTION 'FALHOU: % (esperado "%", mas passou)', p_label, p_msg;
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

-- Linhas afetadas por um INSERT (sem RETURNING: não depende da policy de SELECT).
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

-- Cópia literal do DO do bloco B da 0022.
CREATE FUNCTION pg_temp.roles_guard()
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_role text;
    v_oid  oid;
    v_me   oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
    FOREACH v_role IN ARRAY ARRAY['ptmarket_identity', 'ptmarket_portal'] LOOP
        v_oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = v_role);
        IF v_oid IS NULL THEN
            RAISE EXCEPTION '0022: o papel % não existe (aplicar a 0017 e a 0021 primeiro); recusado.', v_role;
        END IF;

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = v_oid) THEN
            RAISE EXCEPTION '0022: o papel % é membro de outro papel (herdaria os privilégios dele); recusado.', v_role;
        END IF;

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                   WHERE m.roleid = v_oid AND m.member = v_me AND m.inherit_option) THEN
            RAISE EXCEPTION '0022: o migrator tem INHERIT no papel %; recusado.', v_role;
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
            RAISE EXCEPTION '0022: o papel % tem membros além do migrator (só ADMIN do bootstrap ou SET sem INHERIT); recusado.',
                v_role;
        END IF;
    END LOOP;
END
$$;

SELECT set_config('app.actor_label', 'test', true);
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-00000000cc0a', true);

-- ---------------------------------------------------------------------------
-- A. INSERT de customers pela app.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_attribute a
       WHERE a.attrelid = 'public.customers'::regclass AND a.attnum > 0 AND NOT a.attisdropped
         AND has_column_privilege('ptmarket_app', 'public.customers', a.attnum, 'INSERT')
             = (a.attname IN ('email_verified_at', 'anonymized_at'))$q$,
    0, 'app tem INSERT em todas as colunas de customers exceto email_verified_at e anonymized_at');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_attribute a
       WHERE a.attrelid = 'public.customers'::regclass AND a.attnum > 0 AND NOT a.attisdropped$q$,
    12, 'customers tem as 12 colunas conhecidas (0005 + email_verified_at da 0017)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid = 'public.customers'::regclass AND a.grantee = 'ptmarket_app'::regrole
         AND a.privilege_type = 'INSERT'$q$,
    0, 'app sem INSERT na tabela customers inteira');

SET ROLE ptmarket_app;
SELECT set_config('app.actor_type', 'anonymous', true);
SELECT set_config('app.actor_id', '', true);

SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email, email_verified_at) VALUES ('v1@teste.invalid', now())$q$,
    '42501', 'app: INSERT com email_verified_at = 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email, anonymized_at) VALUES ('v2@teste.invalid', now())$q$,
    '42501', 'app: INSERT com anonymized_at = 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email, email_verified_at, anonymized_at) VALUES ('v3@teste.invalid', NULL, NULL)$q$,
    '42501', 'app: INSERT que menciona as colunas de estado, mesmo com NULL = 42501');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers SELECT '00000000-0000-7000-8000-0000000000d4', 'v4@teste.invalid', NULL, NULL, NULL,
       NULL, '[]', '{}', NULL, now(), now(), now()$q$,
    '42501', 'app: INSERT sem lista de colunas (todas) = 42501');
SELECT pg_temp.expect_rows(
    $q$INSERT INTO customers (id, email, name, phone, nif, password_hash, passkeys, consents, created_at, updated_at)
       VALUES ('00000000-0000-7000-8000-0000000000d1', 'registo.d1@teste.invalid', 'Registo D1', '+351912000444',
               '233333333', '$argon2id$v=19$m=19456,t=2,p=1$RDE$RDI', '[]',
               '{"terms": {"version": "2026-11", "at": "2026-11-26T10:00:00Z"}}', now(), now())$q$,
    1, 'app: registo com todas as outras colunas funciona (ator anonymous)');
SELECT pg_temp.expect_rows(
    $q$INSERT INTO customers (email, password_hash)
       VALUES ('registo.d2@teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$RDM$RDQ')$q$,
    1, 'app: registo mínimo (email + hash) funciona');
RESET ROLE;

-- Nasceram por verificar e não anonimizadas (lido pelo dono sem FORCE; reposto logo a seguir).
ALTER TABLE customers NO FORCE ROW LEVEL SECURITY;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers
       WHERE lower(email) IN ('registo.d1@teste.invalid', 'registo.d2@teste.invalid')
         AND email_verified_at IS NULL AND anonymized_at IS NULL$q$,
    2, 'contas registadas pela app: email por verificar, não anonimizadas');
ALTER TABLE customers FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- B. Memberships de ptmarket_identity / ptmarket_portal (lógica do DO da 0022, como o migrator).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles WHERE rolname = current_user AND NOT rolsuper$q$,
    1, 'o teste corre como o migrator (não superuser)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_auth_members m
       WHERE m.member IN ('ptmarket_identity'::regrole, 'ptmarket_portal'::regrole)$q$,
    0, 'ptmarket_identity e ptmarket_portal não são membros de nenhum papel');
SELECT pg_temp.roles_guard();

CREATE ROLE ptm_test_10c_x NOLOGIN;

-- Membro estranho em ptmarket_identity.
GRANT ptmarket_identity TO ptm_test_10c_x WITH INHERIT TRUE;
SELECT pg_temp.expect_raise(
    'SELECT pg_temp.roles_guard()',
    '0022: o papel ptmarket_identity tem membros além do migrator (só ADMIN do bootstrap ou SET sem INHERIT); recusado.',
    'membro estranho (INHERIT) em ptmarket_identity → recusado');
REVOKE ptmarket_identity FROM ptm_test_10c_x;
GRANT ptmarket_identity TO ptm_test_10c_x WITH INHERIT FALSE, SET FALSE;
SELECT pg_temp.expect_raise(
    'SELECT pg_temp.roles_guard()',
    '0022: o papel ptmarket_identity tem membros além do migrator (só ADMIN do bootstrap ou SET sem INHERIT); recusado.',
    'membro estranho (sem INHERIT nem SET) em ptmarket_identity → recusado');
REVOKE ptmarket_identity FROM ptm_test_10c_x;
SELECT pg_temp.roles_guard();

-- ptmarket_portal membro de outro papel (herdaria privilégios dele; ex.: GRANT ptmarket_app TO ptmarket_portal).
GRANT ptm_test_10c_x TO ptmarket_portal;
SELECT pg_temp.expect_raise(
    'SELECT pg_temp.roles_guard()',
    '0022: o papel ptmarket_portal é membro de outro papel (herdaria os privilégios dele); recusado.',
    'ptmarket_portal membro de outro papel → recusado');
REVOKE ptm_test_10c_x FROM ptmarket_portal;
GRANT ptm_test_10c_x TO ptmarket_identity WITH INHERIT FALSE, SET FALSE;
SELECT pg_temp.expect_raise(
    'SELECT pg_temp.roles_guard()',
    '0022: o papel ptmarket_identity é membro de outro papel (herdaria os privilégios dele); recusado.',
    'ptmarket_identity membro de outro papel (mesmo sem INHERIT) → recusado');
REVOKE ptm_test_10c_x FROM ptmarket_identity;
SELECT pg_temp.roles_guard();

-- Migrator com INHERIT (o estado que a 0021 D liga só durante o bloco).
GRANT ptmarket_identity TO CURRENT_USER WITH INHERIT TRUE;
SELECT pg_temp.expect_raise(
    'SELECT pg_temp.roles_guard()',
    '0022: o migrator tem INHERIT no papel ptmarket_identity; recusado.',
    'migrator com INHERIT em ptmarket_identity → recusado');
GRANT ptmarket_identity TO CURRENT_USER WITH INHERIT FALSE;
GRANT ptmarket_portal TO CURRENT_USER WITH INHERIT TRUE;
SELECT pg_temp.expect_raise(
    'SELECT pg_temp.roles_guard()',
    '0022: o migrator tem INHERIT no papel ptmarket_portal; recusado.',
    'migrator com INHERIT em ptmarket_portal → recusado');
GRANT ptmarket_portal TO CURRENT_USER WITH INHERIT FALSE;
SELECT pg_temp.roles_guard();

DROP ROLE ptm_test_10c_x;

ROLLBACK;
