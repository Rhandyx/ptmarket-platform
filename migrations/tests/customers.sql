-- Teste de customers (0017): policies por ator, grants por coluna, lookup de login e eventos da caixa negra.
-- Asserções sempre com SET ROLE ptmarket_app (ou ptmarket_worker onde se prova que não pode), nunca como superuser.
-- Única preparação feita pelo dono das migrations: uma conta já anonimizada (a app não consegue criá-la).
-- Os eventos L1 ficam no tenant do contexto (app.current_tenant_id), que a app lê pela policy tenant_read.
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

-- Linhas afetadas por um INSERT/UPDATE/DELETE (sem RETURNING: não depende da policy de SELECT).
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

-- X = 0c1, Y = 0c2 (registados pela app); Z = 0c9 (anonimizada, preparada pelo dono).
SELECT set_config('app.actor_label', 'test', true);
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-00000000cc0a', true);

-- ---------------------------------------------------------------------------
-- 0. Preparação: conta anonimizada (o dono só escreve sem FORCE; reposto logo a seguir).
-- ---------------------------------------------------------------------------
ALTER TABLE customers NO FORCE ROW LEVEL SECURITY;
INSERT INTO customers (id, email, password_hash, anonymized_at) VALUES
    ('00000000-0000-7000-8000-0000000000c9', 'anon.z@teste.invalid', '$argon2id$v=19$m=19456,t=2,p=1$WjE$WjI', now());
ALTER TABLE customers FORCE ROW LEVEL SECURITY;

SET ROLE ptmarket_app;

-- ---------------------------------------------------------------------------
-- 1. Registo pelo ator anónimo: insere e não lê.
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('anonymous', '');
SELECT pg_temp.expect_rows(
    $q$INSERT INTO customers (id, email, name, phone, nif, password_hash, consents) VALUES
       ('00000000-0000-7000-8000-0000000000c1', 'Cliente.X@Teste.invalid', 'Xavier Confidencial', '+351912000111',
        '211111111', '$argon2id$v=19$m=19456,t=2,p=1$WDE$WDI',
        '{"terms": {"version": "2026-11", "at": "2026-11-26T10:00:00Z"}}')$q$,
    1, 'anónimo regista o cliente X');
SELECT pg_temp.expect_rows(
    $q$INSERT INTO customers (id, email, name, phone, nif, password_hash) VALUES
       ('00000000-0000-7000-8000-0000000000c2', 'cliente.y@teste.invalid', 'Yolanda Confidencial', '+351912000222',
        '222222222', '$argon2id$v=19$m=19456,t=2,p=1$WTE$WTI')$q$,
    1, 'anónimo regista o cliente Y');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 0, 'anónimo não lê nenhuma linha (nem as que inseriu)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email) VALUES ('ret@teste.invalid') RETURNING id$q$,
    '42501', 'anónimo: INSERT ... RETURNING falha (policy de SELECT)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email) VALUES ('CLIENTE.x@teste.INVALID')$q$,
    '23505', 'email repetido (maiúsculas ignoradas) = 23505');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email, anonymized_at) VALUES ('a1@teste.invalid', now())$q$,
    '42501', 'anónimo não regista conta já anonimizada');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email, email_verified_at) VALUES ('a2@teste.invalid', now())$q$,
    '42501', 'anónimo não regista conta com email já verificado');
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET name = 'anónimo' WHERE id = '00000000-0000-7000-8000-0000000000c1'$q$,
    0, 'anónimo não altera nenhuma linha');

-- ---------------------------------------------------------------------------
-- 2. Cliente X: lê e altera só a sua linha (anti-IDOR).
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('customer', '00000000-0000-7000-8000-0000000000c1');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 1, 'X vê exatamente uma linha');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers WHERE id = '00000000-0000-7000-8000-0000000000c1'$q$,
    1, 'X lê a sua linha');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers WHERE id = '00000000-0000-7000-8000-0000000000c2'$q$,
    0, 'X não lê a linha de Y (0 linhas)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers WHERE lower(email) = 'cliente.y@teste.invalid'$q$,
    0, 'X não encontra Y por email');
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET name = 'Xavier Novo', updated_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000000c1'$q$,
    1, 'X altera a sua linha');
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET name = 'pirata' WHERE id = '00000000-0000-7000-8000-0000000000c2'$q$,
    0, 'X não altera a linha de Y (0 linhas)');
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET phone = '+351912000333'$q$,
    1, 'UPDATE sem WHERE só afeta a linha de X');
SELECT pg_temp.expect_error(
    $q$UPDATE customers SET anonymized_at = now() WHERE id = '00000000-0000-7000-8000-0000000000c1'$q$,
    '42501', 'UPDATE de anonymized_at falha');
SELECT pg_temp.expect_error(
    $q$UPDATE customers SET email_verified_at = now() WHERE id = '00000000-0000-7000-8000-0000000000c1'$q$,
    '42501', 'UPDATE de email_verified_at falha');
SELECT pg_temp.expect_error(
    $q$UPDATE customers SET id = '00000000-0000-7000-8000-0000000000c3' WHERE id = '00000000-0000-7000-8000-0000000000c1'$q$,
    '42501', 'UPDATE de id falha');
SELECT pg_temp.expect_error(
    $q$UPDATE customers SET created_at = now() WHERE id = '00000000-0000-7000-8000-0000000000c1'$q$,
    '42501', 'UPDATE de created_at falha');
SELECT pg_temp.expect_error(
    $q$DELETE FROM customers WHERE id = '00000000-0000-7000-8000-0000000000c1'$q$,
    '42501', 'DELETE falha (42501)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email) VALUES ('x2@teste.invalid')$q$,
    '42501', 'cliente autenticado não regista contas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers
       WHERE id = '00000000-0000-7000-8000-0000000000c1' AND name = 'Xavier Novo' AND phone = '+351912000333'$q$,
    1, 'alterações de X gravadas');

-- Conta anonimizada: invisível e intocável mesmo para o próprio.
SELECT pg_temp.as_actor('customer', '00000000-0000-7000-8000-0000000000c9');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 0, 'cliente anonimizado não lê a sua linha');
SELECT pg_temp.expect_rows($q$UPDATE customers SET name = 'volta'$q$, 0, 'cliente anonimizado não altera a sua linha');

-- ---------------------------------------------------------------------------
-- 3. O tipo de ator conta: o mesmo uuid como merchant/admin/system/anonymous não vê nada; sem ator → 0.
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000000c1');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 0, 'merchant com o actor_id de X não lê');
SELECT pg_temp.expect_rows($q$UPDATE customers SET name = 'm'$q$, 0, 'merchant com o actor_id de X não altera');
SELECT pg_temp.as_actor('admin', '00000000-0000-7000-8000-0000000000c1');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 0, 'admin com o actor_id de X não lê');
SELECT pg_temp.as_actor('system', '00000000-0000-7000-8000-0000000000c1');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 0, 'system com o actor_id de X não lê');
SELECT pg_temp.as_actor('anonymous', '00000000-0000-7000-8000-0000000000c1');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 0, 'anonymous com o actor_id de X não lê');
SELECT pg_temp.as_actor('', '00000000-0000-7000-8000-0000000000c1');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 0, 'sem actor_type (só actor_id) → 0 linhas');
SELECT pg_temp.as_actor('', '');
SELECT pg_temp.expect_count('SELECT count(*) FROM customers', 0, 'sem ator → 0 linhas');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email) VALUES ('semator@teste.invalid')$q$,
    '42501', 'sem ator não regista');

-- ---------------------------------------------------------------------------
-- 4. Lookup de login.
-- ---------------------------------------------------------------------------
SELECT pg_temp.as_actor('anonymous', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_customer_credentials('CLIENTE.x@teste.INVALID')
       WHERE id = '00000000-0000-7000-8000-0000000000c1'
         AND password_hash = '$argon2id$v=19$m=19456,t=2,p=1$WDE$WDI'$q$,
    1, 'lookup devolve id + hash de X (maiúsculas ignoradas)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_customer_credentials('cliente.x@teste.invalid')$q$,
    1, 'lookup: no máximo 1 linha');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_customer_credentials('ninguem@teste.invalid')$q$,
    0, 'lookup: email inexistente → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_customer_credentials('anon.z@teste.invalid')$q$,
    0, 'lookup: conta anonimizada → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_customer_credentials('%')$q$,
    0, 'lookup: sem padrões (% não pesquisa)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_customer_credentials($e$x' OR '1'='1$e$)$q$,
    0, 'lookup: texto com SQL injetado → 0 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'identity_customer_credentials(text)'::regprocedure
         AND p.prosecdef AND p.provolatile = 's' AND p.proowner = 'ptmarket_identity'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, public']
         AND pg_get_function_result(p.oid) = 'TABLE(id uuid, password_hash text)'$q$,
    1, 'lookup: DEFINER, STABLE, dono ptmarket_identity, search_path fixo, só id + password_hash');
-- 13: segunda função de lookup · 14: lookups de sessão e passkey
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (SELECT array_agg(p.oid::regprocedure::text ORDER BY p.oid::regprocedure::text) AS fns
                             FROM pg_proc p WHERE p.proowner = 'ptmarket_identity'::regrole) s
       WHERE s.fns = ARRAY['identity_customer_credentials(text)', 'identity_passkey_lookup(bytea)',
                           'identity_session_lookup(bytea)', 'identity_user_credentials(text)']$q$,
    1, 'ptmarket_identity é dono exatamente de {identity_customer_credentials, identity_passkey_lookup, '
       'identity_session_lookup, identity_user_credentials}');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname = 'ptmarket_identity'
         AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcanlogin AND NOT rolcreaterole AND NOT rolcreatedb$q$,
    1, 'ptmarket_identity: NOLOGIN, sem SUPERUSER/BYPASSRLS');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_identity', 'customers', p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE')
              AND has_any_column_privilege('ptmarket_identity', 'customers', p.priv))$q$,
    0, 'ptmarket_identity sem INSERT/UPDATE/DELETE em customers');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['name', 'phone', 'nif', 'passkeys', 'consents']) AS c(col)
       WHERE has_column_privilege('ptmarket_identity', 'customers', c.col, 'SELECT')$q$,
    0, 'ptmarket_identity não lê nome, telefone, NIF, passkeys nem consents');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_worker', 'ptmarket_price_writer']) AS r(rol)
       WHERE has_function_privilege(r.rol, 'identity_customer_credentials(text)', 'EXECUTE')$q$,
    0, 'só ptmarket_app executa o lookup (worker/price_writer não)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a
       WHERE p.oid = 'identity_customer_credentials(text)'::regprocedure AND a.grantee = 0$q$,
    0, 'lookup sem EXECUTE para PUBLIC');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', 'customers', p.priv)$q$,
    0, 'app sem DELETE/TRUNCATE em customers');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['id', 'created_at', 'anonymized_at', 'email_verified_at']) AS c(col)
       WHERE has_column_privilege('ptmarket_app', 'customers', c.col, 'UPDATE')$q$,
    0, 'app sem UPDATE de id/created_at/anonymized_at/email_verified_at');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error(
    $q$SELECT * FROM identity_customer_credentials('cliente.x@teste.invalid')$q$,
    '42501', 'ptmarket_worker não executa o lookup');
SELECT pg_temp.expect_error('SELECT count(*) FROM customers', '42501', 'worker continua sem ler customers');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 5. Caixa negra: cada INSERT/UPDATE da app deixou evento com o ator do contexto, sem PII em claro.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('anonymous', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'customers.insert' AND actor_type = 'anonymous' AND actor_id IS NULL
         AND tenant_id = '00000000-0000-7000-8000-00000000cc0a' AND outcome = 'success'
         AND target_id IN ('00000000-0000-7000-8000-0000000000c1', '00000000-0000-7000-8000-0000000000c2')
         AND changes->'after'->>'email' = '[pii]' AND changes->'after'->>'name' = '[pii]'
         AND changes->'after'->>'phone' = '[pii]' AND changes->'after'->>'nif' = '[pii]'
         AND changes->'after'->>'password_hash' = '[redacted]'$q$,
    2, 'customers.insert de X e Y: ator anonymous, PII = [pii], hash = [redacted]');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'customers.update' AND actor_type = 'customer'
         AND actor_id = '00000000-0000-7000-8000-0000000000c1'
         AND target_id = '00000000-0000-7000-8000-0000000000c1'
         AND tenant_id = '00000000-0000-7000-8000-00000000cc0a' AND outcome = 'success'$q$,
    2, 'customers.update de X (nome, telefone): ator customer X');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE target_type = 'customers' AND tenant_id = '00000000-0000-7000-8000-00000000cc0a'
         AND actor_type <> 'db'$q$,
    4, 'nenhum outro evento da app em customers (as tentativas recusadas não gravaram)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE target_type = 'customers' AND tenant_id = '00000000-0000-7000-8000-00000000cc0a'
         AND actor_type = 'db' AND action = 'customers.insert'
         AND target_id = '00000000-0000-7000-8000-0000000000c9'
         AND changes->'after'->>'email' = '[pii]'$q$,
    1, 'preparação do dono (conta anonimizada Z) também ficou na caixa negra, email = [pii]');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE target_type = 'customers'
         AND changes::text ~* '(cliente\.|anon\.z|Teste\.invalid|Xavier|Yolanda|Confidencial|9120|211111111|222222222|argon2id)'$q$,
    0, 'eventos de customers sem email/nome/telefone/NIF/hash em claro');
RESET ROLE;

ROLLBACK;
