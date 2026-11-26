-- Teste de sessions, user_passkeys e user_recovery_codes (0019): RLS por titular (anti-IDOR por tipo), grants por
-- coluna, CHECK de tamanho do hash e de duração máxima (owner 25/11), lookups DEFINER e máscara na caixa negra.
-- Preparação pelo dono das migrations (contas, e linhas que a app não consegue criar: sessão expirada, de conta
-- inativa/anonimizada): RLS FORCE desligado só durante o seed e reposto logo a seguir. Asserções de acesso sempre
-- com SET ROLE ptmarket_app (ou ptmarket_worker onde se prova que não pode), nunca como superuser. Os eventos L1 da
-- app ficam no tenant do contexto (app.current_tenant_id), que a app lê pela policy tenant_read.
-- Tudo numa transação com ROLLBACK: a BD fica como estava.

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

-- Linhas afetadas por um UPDATE/DELETE (sem RETURNING).
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

-- Tenants TA, TB. Utilizadores: X = 14e1 (ativo) · Y = 14e2 (ativo) · Z = 14e9 (INATIVO).
-- Clientes: C = 14e1 (o MESMO uuid de X: anti-IDOR por tipo) · K = 14c9 (anonimizado).
-- Tokens: sha256('tok-<nome>'). Sessões: sx1, sx2 (X, staff TA) · sc (C) · sy (Y, staff TB) · syp (Y, plataforma)
--   · sexp (X, expirada) · sz (Z inativo) · sk (K anonimizado) — as três últimas preparadas pelo dono.
SELECT set_config('app.actor_label', 'test', true);
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000014a0', true);

-- ---------------------------------------------------------------------------
-- 0. Preparação.
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, slug, custom_domain, name) VALUES
    ('00000000-0000-7000-8000-0000000014a0', 'sess-a', 'sess-a.teste.invalid', 'Tenant Sessões A'),
    ('00000000-0000-7000-8000-0000000014b0', 'sess-b', 'sess-b.teste.invalid', 'Tenant Sessões B');

ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
INSERT INTO users (id, email, full_name, is_active) VALUES
    ('00000000-0000-7000-8000-0000000014e1', 'sess.x@teste.invalid', 'Xavier Sessao', true),
    ('00000000-0000-7000-8000-0000000014e2', 'sess.y@teste.invalid', 'Yara Sessao', true),
    ('00000000-0000-7000-8000-0000000014e9', 'sess.z@teste.invalid', 'Zeca Sessao', false);
ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE customers NO FORCE ROW LEVEL SECURITY;
INSERT INTO customers (id, email, anonymized_at) VALUES
    ('00000000-0000-7000-8000-0000000014e1', 'sess.c@teste.invalid', NULL),
    ('00000000-0000-7000-8000-0000000014c9', NULL, now());
ALTER TABLE customers FORCE ROW LEVEL SECURITY;

ALTER TABLE sessions NO FORCE ROW LEVEL SECURITY;
INSERT INTO sessions (id, subject_type, subject_id, token_hash, tenant_id, created_at, expires_at) VALUES
    ('00000000-0000-7000-8000-0000000014d7', 'user', '00000000-0000-7000-8000-0000000014e1',
     sha256('tok-sexp'::bytea), '00000000-0000-7000-8000-0000000014a0', now() - interval '2 hours',
     now() - interval '1 hour'),
    ('00000000-0000-7000-8000-0000000014d8', 'user', '00000000-0000-7000-8000-0000000014e9',
     sha256('tok-sz'::bytea), '00000000-0000-7000-8000-0000000014a0', now(), now() + interval '1 hour'),
    ('00000000-0000-7000-8000-0000000014d9', 'customer', '00000000-0000-7000-8000-0000000014c9',
     sha256('tok-sk'::bytea), '00000000-0000-7000-8000-0000000014a0', now(), now() + interval '1 hour');
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;

ALTER TABLE user_passkeys NO FORCE ROW LEVEL SECURITY;
INSERT INTO user_passkeys (id, user_id, credential_id, credential, label) VALUES
    ('00000000-0000-7000-8000-0000000014f9', '00000000-0000-7000-8000-0000000014e9', '\xc0ffee09'::bytea,
     '{"public_key": "cGstWg", "alg": -7}', 'Chave Z');
ALTER TABLE user_passkeys FORCE ROW LEVEL SECURITY;

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE oid IN ('sessions'::regclass, 'user_passkeys'::regclass, 'user_recovery_codes'::regclass)
         AND relrowsecurity AND relforcerowsecurity$q$,
    3, 'sessions, user_passkeys, user_recovery_codes: RLS ENABLE + FORCE');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid IN ('sessions'::regclass, 'user_passkeys'::regclass, 'user_recovery_codes'::regclass)
         AND tgenabled = 'A' AND tgfoid = 'audit.audit_row_trigger()'::regprocedure
         AND ((tgname = 'zz_audit_row' AND tgtype = 29) OR (tgname = 'zz_audit_truncate' AND tgtype = 34))$q$,
    6, 'as três tabelas: zz_audit_row + zz_audit_truncate (L1, ALWAYS)');

SET ROLE ptmarket_app;

-- ---------------------------------------------------------------------------
-- 1. Criar a própria sessão; CHECK de hash e de duração.
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000014e1');
INSERT INTO sessions (id, subject_type, subject_id, token_hash, tenant_id, ip, user_agent_hash, expires_at) VALUES
    ('00000000-0000-7000-8000-0000000014d1', 'user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-sx1'::bytea),
     '00000000-0000-7000-8000-0000000014a0', '203.0.113.71', sha256('ua-x'::bytea), now() + interval '12 hours'),
    ('00000000-0000-7000-8000-0000000014d2', 'user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-sx2'::bytea),
     '00000000-0000-7000-8000-0000000014a0', '203.0.113.72', NULL, now() + interval '1 hour');

SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e2', sha256('tok-o1'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 hour')$q$,
    '42501', 'X não cria sessão para outro subject_id');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('customer', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o2'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 hour')$q$,
    '42501', 'X (merchant) não cria sessão de cliente com o mesmo uuid');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, impersonator_user_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o3'::bytea),
        '00000000-0000-7000-8000-0000000014a0', '00000000-0000-7000-8000-0000000014e2', now() + interval '1 hour')$q$,
    '42501', 'INSERT com impersonator_user_id falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at, revoked_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o4'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 hour', now())$q$,
    '42501', 'INSERT de sessão já revogada falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, created_at, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o5'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 year', now() + interval '1 year 1 hour')$q$,
    '42501', 'app não escolhe created_at (sem GRANT INSERT na coluna)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', '\x0102'::bytea,
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 hour')$q$,
    '23514', 'token_hash com 2 bytes falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', sha512('tok-o6'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 hour')$q$,
    '23514', 'token_hash com 64 bytes falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-sx1'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 hour')$q$,
    '23505', 'token_hash repetido falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o7'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '12 hours 1 second')$q$,
    '23514', 'staff (com tenant): mais de 12 h falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o8'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now())$q$,
    '23514', 'expires_at = created_at falha');

SELECT pg_temp.as_actor('customer', '00000000-0000-7000-8000-0000000014e1');
INSERT INTO sessions (id, subject_type, subject_id, token_hash, tenant_id, ip, expires_at) VALUES
    ('00000000-0000-7000-8000-0000000014d3', 'customer', '00000000-0000-7000-8000-0000000014e1',
     sha256('tok-sc'::bytea), '00000000-0000-7000-8000-0000000014a0', '198.51.100.33', now() + interval '7 days');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('customer', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o9'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '7 days 1 second')$q$,
    '23514', 'cliente: mais de 7 dias falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o10'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 hour')$q$,
    '42501', 'cliente C não cria sessão de utilizador com o mesmo uuid');

SELECT pg_temp.as_actor('municipal', '00000000-0000-7000-8000-0000000014e2');
INSERT INTO sessions (id, subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
    ('00000000-0000-7000-8000-0000000014d4', 'user', '00000000-0000-7000-8000-0000000014e2', sha256('tok-sy'::bytea),
     '00000000-0000-7000-8000-0000000014b0', now() + interval '2 hours');

SELECT pg_temp.as_actor('admin', '00000000-0000-7000-8000-0000000014e2');
INSERT INTO sessions (id, subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
    ('00000000-0000-7000-8000-0000000014d5', 'user', '00000000-0000-7000-8000-0000000014e2', sha256('tok-syp'::bytea),
     NULL, now() + interval '8 hours');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('user', '00000000-0000-7000-8000-0000000014e2', sha256('tok-o11'::bytea), NULL,
        now() + interval '8 hours 1 second')$q$,
    '23514', 'plataforma (sem tenant): mais de 8 h falha');

SELECT pg_temp.as_actor('anonymous', '');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sessions (subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
       ('customer', '00000000-0000-7000-8000-0000000014e1', sha256('tok-o12'::bytea),
        '00000000-0000-7000-8000-0000000014a0', now() + interval '1 hour')$q$,
    '42501', 'anonymous não cria sessões');

-- ---------------------------------------------------------------------------
-- 2. Ler e revogar: só as próprias (anti-IDOR, também por tipo); sem DELETE.
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM sessions', 3, 'X vê as suas 3 sessões (sx1, sx2, expirada)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM sessions WHERE id IN ('00000000-0000-7000-8000-0000000014d3',
                                                  '00000000-0000-7000-8000-0000000014d4',
                                                  '00000000-0000-7000-8000-0000000014d5')$q$,
    0, 'X não lê a sessão de C (mesmo uuid, tipo cliente) nem as de Y');
SELECT pg_temp.expect_rows(
    $q$UPDATE sessions SET revoked_at = now() WHERE id = '00000000-0000-7000-8000-0000000014d2'$q$,
    1, 'X revoga a sua sessão sx2');
SELECT pg_temp.expect_rows(
    $q$UPDATE sessions SET revoked_at = NULL WHERE id = '00000000-0000-7000-8000-0000000014d2'$q$,
    0, 'X não "des-revoga" sx2 (0 linhas)');
SELECT pg_temp.expect_rows(
    $q$UPDATE sessions SET mfa_verified_at = now() WHERE id = '00000000-0000-7000-8000-0000000014d1'$q$,
    1, 'X marca o 2FA na sua sessão sx1');
SELECT pg_temp.expect_rows(
    $q$UPDATE sessions SET revoked_at = now() WHERE id = '00000000-0000-7000-8000-0000000014d3'$q$,
    0, 'X não revoga a sessão de C (mesmo uuid, tipo cliente)');
SELECT pg_temp.expect_rows(
    $q$UPDATE sessions SET revoked_at = now() WHERE id = '00000000-0000-7000-8000-0000000014d4'$q$,
    0, 'X não revoga a sessão de Y');
SELECT pg_temp.expect_error(
    $q$UPDATE sessions SET expires_at = now() + interval '1 hour' WHERE id = '00000000-0000-7000-8000-0000000014d1'$q$,
    '42501', 'UPDATE de expires_at falha');
SELECT pg_temp.expect_error(
    $q$UPDATE sessions SET subject_id = '00000000-0000-7000-8000-0000000014e2'
       WHERE id = '00000000-0000-7000-8000-0000000014d1'$q$,
    '42501', 'UPDATE de subject_id falha');
SELECT pg_temp.expect_error(
    $q$UPDATE sessions SET token_hash = sha256('novo'::bytea) WHERE id = '00000000-0000-7000-8000-0000000014d1'$q$,
    '42501', 'UPDATE de token_hash falha');
SELECT pg_temp.expect_error(
    $q$UPDATE sessions SET impersonator_user_id = '00000000-0000-7000-8000-0000000014e2'
       WHERE id = '00000000-0000-7000-8000-0000000014d1'$q$,
    '42501', 'UPDATE de impersonator_user_id falha');
SELECT pg_temp.expect_error(
    $q$DELETE FROM sessions WHERE id = '00000000-0000-7000-8000-0000000014d1'$q$,
    '42501', 'DELETE da própria sessão falha (revogar = revoked_at)');
SELECT pg_temp.expect_error('TRUNCATE sessions', '42501', 'app não faz TRUNCATE de sessions');

SELECT pg_temp.as_actor('customer', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM sessions', 1, 'C vê só a sua sessão (não as de X, mesmo uuid)');
SELECT pg_temp.expect_rows(
    $q$UPDATE sessions SET revoked_at = now() WHERE id = '00000000-0000-7000-8000-0000000014d1'$q$,
    0, 'C não revoga a sessão de X (mesmo uuid, tipo utilizador)');

SELECT pg_temp.as_actor('municipal', '00000000-0000-7000-8000-0000000014e2');
SELECT pg_temp.expect_count('SELECT count(*) FROM sessions', 2, 'Y vê as suas 2 sessões (staff + plataforma)');

SELECT pg_temp.as_actor('system', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM sessions', 0, 'system com o uuid de X não lê sessões');
SELECT pg_temp.as_actor('anonymous', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM sessions', 0, 'anonymous com o uuid de X não lê sessões');
SELECT pg_temp.as_actor('', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM sessions', 0, 'sem actor_type não lê sessões');

-- ---------------------------------------------------------------------------
-- 3. identity_session_lookup.
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('anonymous', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('tok-sx1'::bytea))
       WHERE id = '00000000-0000-7000-8000-0000000014d1' AND subject_type = 'user'
         AND subject_id = '00000000-0000-7000-8000-0000000014e1'
         AND tenant_id = '00000000-0000-7000-8000-0000000014a0' AND mfa_verified_at IS NOT NULL
         AND impersonator_user_id IS NULL AND expires_at = created_at + interval '12 hours'$q$,
    1, 'lookup devolve a sessão válida sx1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('tok-sc'::bytea))
       WHERE subject_type = 'customer' AND subject_id = '00000000-0000-7000-8000-0000000014e1'$q$,
    1, 'lookup devolve a sessão válida de cliente sc');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('tok-syp'::bytea)) WHERE tenant_id IS NULL$q$,
    1, 'lookup devolve a sessão de plataforma syp');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('tok-sx2'::bytea))$q$, 0, 'lookup: revogada → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('tok-sexp'::bytea))$q$, 0, 'lookup: expirada → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('tok-nada'::bytea))$q$, 0, 'lookup: hash desconhecido → 0');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(NULL)$q$, 0, 'lookup: NULL → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('tok-sz'::bytea))$q$, 0, 'lookup: utilizador inativo → 0');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('tok-sk'::bytea))$q$, 0, 'lookup: cliente anonimizado → 0');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error(
    $q$SELECT * FROM identity_session_lookup(sha256('tok-sx1'::bytea))$q$, '42501', 'worker não executa o lookup de sessão');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM identity_passkey_lookup('\xc0ffee01'::bytea)$q$, '42501', 'worker não executa o lookup de passkey');
SELECT pg_temp.expect_error('SELECT count(*) FROM sessions', '42501', 'worker não lê sessions');
SELECT pg_temp.expect_error('SELECT count(*) FROM user_passkeys', '42501', 'worker não lê user_passkeys');
SELECT pg_temp.expect_error('SELECT count(*) FROM user_recovery_codes', '42501', 'worker não lê user_recovery_codes');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. Passkeys.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000014e1');
INSERT INTO user_passkeys (id, user_id, credential_id, credential, label) VALUES
    ('00000000-0000-7000-8000-0000000014f1', '00000000-0000-7000-8000-0000000014e1', '\xc0ffee01'::bytea,
     '{"public_key": "cGstWA", "alg": -7}', 'Portátil X');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_passkeys (user_id, credential_id, credential, label) VALUES
       ('00000000-0000-7000-8000-0000000014e2', '\xc0ffee0a'::bytea, '{}', 'pirata')$q$,
    '42501', 'X não cria passkey para Y');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_passkeys (user_id, credential_id, credential, sign_count, label) VALUES
       ('00000000-0000-7000-8000-0000000014e1', '\xc0ffee0b'::bytea, '{}', -1, 'neg')$q$,
    '23514', 'sign_count negativo falha');

SELECT pg_temp.as_actor('municipal', '00000000-0000-7000-8000-0000000014e2');
INSERT INTO user_passkeys (id, user_id, credential_id, credential, label) VALUES
    ('00000000-0000-7000-8000-0000000014f2', '00000000-0000-7000-8000-0000000014e2', '\xc0ffee02'::bytea,
     '{"public_key": "cGstWQ", "alg": -7}', 'Telemóvel Y');
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_passkeys (user_id, credential_id, credential, label) VALUES
       ('00000000-0000-7000-8000-0000000014e2', '\xc0ffee01'::bytea, '{}', 'copia')$q$,
    '23505', 'credential_id repetido falha');

SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_passkeys', 1, 'X vê só a sua passkey');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_passkeys WHERE id = '00000000-0000-7000-8000-0000000014f2'$q$, 0, 'X não vê a de Y');
SELECT pg_temp.expect_rows(
    $q$DELETE FROM user_passkeys WHERE id = '00000000-0000-7000-8000-0000000014f2'$q$, 0, 'X não apaga a de Y');
SELECT pg_temp.expect_rows(
    $q$UPDATE user_passkeys SET label = 'pirata' WHERE id = '00000000-0000-7000-8000-0000000014f2'$q$,
    0, 'X não altera a de Y');
SELECT pg_temp.expect_rows(
    $q$UPDATE user_passkeys SET sign_count = 5, last_used_at = now(), label = 'Portátil X2'
       WHERE id = '00000000-0000-7000-8000-0000000014f1'$q$,
    1, 'X atualiza sign_count, last_used_at e label da sua');
SELECT pg_temp.expect_error(
    $q$UPDATE user_passkeys SET credential = '{}' WHERE id = '00000000-0000-7000-8000-0000000014f1'$q$,
    '42501', 'UPDATE de credential falha');
SELECT pg_temp.expect_error(
    $q$UPDATE user_passkeys SET user_id = '00000000-0000-7000-8000-0000000014e2'
       WHERE id = '00000000-0000-7000-8000-0000000014f1'$q$,
    '42501', 'UPDATE de user_id falha');
SELECT pg_temp.as_actor('customer', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_passkeys', 0, 'cliente com o uuid de X não vê passkeys');

SELECT pg_temp.as_actor('anonymous', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_passkey_lookup('\xc0ffee01'::bytea)
       WHERE id = '00000000-0000-7000-8000-0000000014f1' AND user_id = '00000000-0000-7000-8000-0000000014e1'
         AND credential->>'public_key' = 'cGstWA' AND sign_count = 5$q$,
    1, 'lookup de passkey devolve a de X');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_passkey_lookup('\xc0ffee09'::bytea)$q$, 0, 'lookup: passkey de inativo → 0');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_passkey_lookup('\xdead'::bytea)$q$, 0, 'lookup: credential_id desconhecido → 0');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_passkey_lookup(NULL)$q$, 0, 'lookup: NULL → 0');

SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_rows(
    $q$DELETE FROM user_passkeys WHERE id = '00000000-0000-7000-8000-0000000014f1'$q$, 1, 'X apaga a sua passkey');

-- ---------------------------------------------------------------------------
-- 5. Códigos de recuperação.
-- ---------------------------------------------------------------------------
INSERT INTO user_recovery_codes (id, user_id, code_hash) VALUES
    ('00000000-0000-7000-8000-000000001481', '00000000-0000-7000-8000-0000000014e1', sha256('rc-x1'::bytea)),
    ('00000000-0000-7000-8000-000000001482', '00000000-0000-7000-8000-0000000014e1', sha256('rc-x2'::bytea));
SELECT pg_temp.expect_error(
    $q$INSERT INTO user_recovery_codes (user_id, code_hash) VALUES
       ('00000000-0000-7000-8000-0000000014e2', sha256('rc-pirata'::bytea))$q$,
    '42501', 'X não cria códigos para Y');
SELECT pg_temp.as_actor('municipal', '00000000-0000-7000-8000-0000000014e2');
INSERT INTO user_recovery_codes (id, user_id, code_hash) VALUES
    ('00000000-0000-7000-8000-000000001483', '00000000-0000-7000-8000-0000000014e2', sha256('rc-y1'::bytea));

SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_recovery_codes', 2, 'X vê só os seus 2 códigos');
SELECT pg_temp.expect_rows(
    $q$DELETE FROM user_recovery_codes WHERE id = '00000000-0000-7000-8000-000000001483'$q$, 0, 'X não apaga o de Y');
SELECT pg_temp.expect_rows(
    $q$UPDATE user_recovery_codes SET used_at = now() WHERE id = '00000000-0000-7000-8000-000000001483'$q$,
    0, 'X não gasta o código de Y');
SELECT pg_temp.expect_rows(
    $q$UPDATE user_recovery_codes SET used_at = now() WHERE id = '00000000-0000-7000-8000-000000001481'$q$,
    1, 'X gasta o seu código');
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET code_hash = sha256('novo'::bytea) WHERE id = '00000000-0000-7000-8000-000000001482'$q$,
    '42501', 'UPDATE de code_hash falha');
SELECT pg_temp.expect_rows(
    $q$DELETE FROM user_recovery_codes WHERE id = '00000000-0000-7000-8000-000000001482'$q$, 1, 'X apaga o seu código');
SELECT pg_temp.as_actor('municipal', '00000000-0000-7000-8000-0000000014e2');
SELECT pg_temp.expect_count('SELECT count(*) FROM user_recovery_codes', 1, 'Y vê só o seu código (intacto)');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 6. Privilégios no catálogo e funções.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_worker', 'ptmarket_price_writer']) AS r(rol),
                            unnest(ARRAY['sessions', 'user_passkeys', 'user_recovery_codes']) AS t(tab),
                            unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) AS p(priv)
       WHERE has_table_privilege(r.rol, t.tab, p.priv)
          OR (p.priv <> 'DELETE' AND has_any_column_privilege(r.rol, t.tab, p.priv))$q$,
    0, 'worker e price_writer sem nenhum privilégio nas três tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', 'sessions', p.priv)$q$,
    0, 'app sem DELETE/TRUNCATE em sessions');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['id', 'subject_type', 'subject_id', 'token_hash', 'tenant_id',
                                         'impersonator_user_id', 'ip', 'user_agent_hash', 'created_at',
                                         'expires_at']) AS c(col)
       WHERE has_column_privilege('ptmarket_app', 'sessions', c.col, 'UPDATE')$q$,
    0, 'app: UPDATE em sessions só de revoked_at e mfa_verified_at');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['id', 'user_id', 'credential_id', 'credential', 'created_at']) AS c(col)
       WHERE has_column_privilege('ptmarket_app', 'user_passkeys', c.col, 'UPDATE')$q$,
    0, 'app: UPDATE em user_passkeys só de sign_count, last_used_at, label');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['id', 'user_id', 'code_hash', 'created_at']) AS c(col)
       WHERE has_column_privilege('ptmarket_app', 'user_recovery_codes', c.col, 'UPDATE')$q$,
    0, 'app: UPDATE em user_recovery_codes só de used_at');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['ip', 'user_agent_hash']) AS c(col)
       WHERE has_column_privilege('ptmarket_identity', 'sessions', c.col, 'SELECT')$q$,
    0, 'ptmarket_identity não lê ip nem user_agent_hash');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['label', 'created_at', 'last_used_at']) AS c(col)
       WHERE has_column_privilege('ptmarket_identity', 'user_passkeys', c.col, 'SELECT')$q$,
    0, 'ptmarket_identity não lê label nem datas das passkeys');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['sessions', 'user_passkeys', 'user_recovery_codes']) AS t(tab),
                            unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_identity', t.tab, p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE') AND has_any_column_privilege('ptmarket_identity', t.tab, p.priv))$q$,
    0, 'ptmarket_identity sem escrita nas três tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE']) AS p(priv)
       WHERE has_any_column_privilege('ptmarket_identity', 'user_recovery_codes', p.priv)$q$,
    0, 'ptmarket_identity sem acesso a user_recovery_codes');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid IN ('sessions'::regclass, 'user_passkeys'::regclass, 'user_recovery_codes'::regclass)
         AND a.grantee = 0$q$,
    0, 'sem privilégios para PUBLIC nas três tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid IN ('identity_session_lookup(bytea)'::regprocedure, 'identity_passkey_lookup(bytea)'::regprocedure)
         AND p.prosecdef AND p.provolatile = 's' AND p.proowner = 'ptmarket_identity'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    2, 'lookups: DEFINER, STABLE, dono ptmarket_identity, search_path fixo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'identity_passkey_lookup(bytea)'::regprocedure
         AND pg_get_function_result(p.oid) = 'TABLE(id uuid, user_id uuid, credential jsonb, sign_count bigint)'$q$,
    1, 'lookup de passkey: só id, user_id, credential, sign_count');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['identity_session_lookup(bytea)', 'identity_passkey_lookup(bytea)']) AS f(fn),
                            unnest(ARRAY['ptmarket_worker', 'ptmarket_price_writer']) AS r(rol)
       WHERE has_function_privilege(r.rol, f.fn, 'EXECUTE')$q$,
    0, 'só ptmarket_app executa os lookups');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a
       WHERE p.oid IN ('identity_session_lookup(bytea)'::regprocedure, 'identity_passkey_lookup(bytea)'::regprocedure)
         AND a.grantee = 0$q$,
    0, 'lookups sem EXECUTE para PUBLIC');

-- ---------------------------------------------------------------------------
-- 7. Caixa negra: eventos com o ator, sem token/hash, IP, credencial nem chave pública em claro.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000014e1');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'sessions.insert' AND target_type = 'sessions' AND actor_type = 'merchant'
         AND actor_id = '00000000-0000-7000-8000-0000000014e1'
         AND target_id = '00000000-0000-7000-8000-0000000014d1'
         AND changes->'after'->>'token_hash' = '[redacted]'
         AND changes->'after'->>'user_agent_hash' = '[redacted]'
         AND changes->'after'->>'ip' = '[pii]'$q$,
    1, 'sessions.insert de sx1: token_hash e user_agent_hash = [redacted], ip = [pii]');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'sessions.update' AND target_type = 'sessions'
         AND target_id = '00000000-0000-7000-8000-0000000014d2' AND changes->'after'->>'revoked_at' IS NOT NULL$q$,
    1, 'revogação de sx2 ficou na caixa negra');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'user_passkeys.insert' AND target_id = '00000000-0000-7000-8000-0000000014f1'
         AND changes->'after'->>'credential' = '[redacted]'
         AND changes->'after'->>'credential_id' = '[redacted]'$q$,
    1, 'user_passkeys.insert de X: credential e credential_id = [redacted]');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'user_passkeys.delete' AND target_id = '00000000-0000-7000-8000-0000000014f1'
         AND changes->'before'->>'credential' = '[redacted]'$q$,
    1, 'user_passkeys.delete de X: credential = [redacted]');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'user_recovery_codes.insert' AND target_type = 'user_recovery_codes'
         AND changes->'after'->>'code_hash' = '[redacted]'$q$,
    3, 'user_recovery_codes.insert (3): code_hash = [redacted]');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events e,
              unnest(ARRAY['tok-sx1', 'tok-sx2', 'tok-sc', 'tok-sy', 'tok-syp', 'tok-sexp', 'tok-sz', 'tok-sk',
                           'ua-x', 'rc-x1', 'rc-x2', 'rc-y1']) AS s(src)
       WHERE e.target_type IN ('sessions', 'user_passkeys', 'user_recovery_codes')
         AND strpos(e.changes::text, encode(sha256(convert_to(s.src, 'UTF8')), 'hex')) > 0$q$,
    0, 'nenhum evento contém um token_hash, user_agent_hash ou code_hash (hex) em claro');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE target_type IN ('sessions', 'user_passkeys', 'user_recovery_codes')
         AND changes::text ~* '(203\.0\.113|198\.51\.100|c0ffee|cGstW|public_key)'$q$,
    0, 'nenhum evento contém IP, credential_id nem chave pública em claro');
RESET ROLE;

ROLLBACK;
