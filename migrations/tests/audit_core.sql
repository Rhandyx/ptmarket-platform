-- run.sh: superuser
-- Teste da caixa negra (0008): audit.audit_events só de acréscimo, encadeada por hash, escrita só por
-- audit_append. Corre como superuser só para poder assumir papéis NOLOGIN (ptmarket_audit_writer para ler tudo,
-- ptmarket_audit_owner para a montagem que exige ser dono: DETACH, re-GRANT a si próprio para provar os
-- triggers); cada asserção é feita com SET ROLE do papel em causa. O que o migrator (LOGIN) não consegue
-- prova-se em audit_seal.sql, numa sessão dele. Tudo numa transação com ROLLBACK.

BEGIN;

-- Base: eventos que já existiam antes deste teste (ex.: os do sqlx em _sqlx_migrations, L1 da 0010).
-- As asserções contam só o que este teste grava (id fora da base).
CREATE TEMP TABLE audit_base AS
SELECT id, chain_key, retention_class::text AS retention_class, chain_seq FROM audit.audit_events;
GRANT SELECT ON audit_base TO ptmarket_app, ptmarket_worker, ptmarket_audit_writer, ptmarket_audit_owner;

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

CREATE FUNCTION pg_temp.expect_value(p_sql text, p_expected bigint, p_label text)
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

-- Hash recalculado em SQL, independente de audit._event_hash (fórmula do cartão; ip::text com máscara).
CREATE TEMP VIEW audit_hash_check WITH (security_invoker = true) AS
SELECT e.*, sha256(e.prev_hash || convert_to(jsonb_build_array(
        e.id, e.tenant_id, e.store_id, e.actor_type, e.actor_id, e.actor_label, e.impersonator_id,
        e.action, e.target_type, e.target_id, e.outcome, e.reason, e.changes, e.request_id, e.ip::text,
        encode(e.user_agent_hash, 'hex'), e.retention_class,
        (extract(epoch FROM e.occurred_at) * 1000000)::bigint,
        (extract(epoch FROM e.created_at) * 1000000)::bigint,
        e.chain_seq)::text, 'UTF8')) AS recomputed
FROM audit.audit_events e;
GRANT SELECT ON audit_hash_check TO ptmarket_app, ptmarket_audit_writer;

-- ---------------------------------------------------------------------------
-- Papéis e donos.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname IN ('ptmarket_audit_owner', 'ptmarket_audit_writer', 'ptmarket_audit_retention')
         AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcanlogin AND NOT rolcreaterole$q$,
    3, 'papéis de auditoria sem super/bypassrls/login/createrole');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
       WHERE p.oid = 'audit.audit_append(text,text,text,text,text,jsonb,uuid,uuid)'::regprocedure
         AND p.prosecdef AND r.rolname = 'ptmarket_audit_writer'
         AND p.proconfig @> ARRAY['lock_timeout=2s']$q$,
    1, 'audit_append é DEFINER, pertence a ptmarket_audit_writer e tem lock_timeout = 2s');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
       WHERE p.oid = 'audit._chain_insert(audit.audit_events,boolean)'::regprocedure
         AND r.rolname = 'ptmarket_audit_writer'
         AND NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee <> p.proowner)$q$,
    1, '_chain_insert: dono ptmarket_audit_writer, sem EXECUTE para mais ninguém');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'audit.audit_ensure_partitions(int)'::regprocedure
         AND p.prosecdef AND p.proowner = (SELECT relowner FROM pg_class WHERE oid = 'audit.audit_events'::regclass)
         AND p.proowner = 'ptmarket_audit_owner'::regrole$q$,
    1, 'audit_ensure_partitions é DEFINER e pertence ao dono da tabela (ptmarket_audit_owner)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
       WHERE a.grantee = 'ptmarket_audit_writer'::regrole AND c.relkind IN ('r', 'p', 'v')
         AND c.relpersistence <> 't'$q$,
    6, 'ptmarket_audit_writer só tem 6 privilégios em tabelas (fora as temporárias deste teste)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
       WHERE a.grantee = 'ptmarket_audit_writer'::regrole
         AND ((c.oid = 'audit.audit_events'::regclass AND a.privilege_type IN ('INSERT', 'SELECT'))
           OR (c.oid = 'audit.audit_alerts'::regclass AND a.privilege_type = 'INSERT')
           OR (c.oid = 'audit.audit_chain_heads'::regclass AND a.privilege_type IN ('SELECT', 'INSERT', 'UPDATE')))$q$,
    6, 'INSERT+SELECT em audit_events, INSERT em audit_alerts, SELECT/INSERT/UPDATE em audit_chain_heads');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
       WHERE c.oid = 'audit.audit_chain_heads'::regclass AND r.rolname = 'ptmarket_audit_owner'
         AND c.relrowsecurity AND c.relforcerowsecurity$q$,
    1, 'audit_chain_heads: dono ptmarket_audit_owner, RLS ENABLE + FORCE');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
       WHERE c.oid = 'audit.audit_chain_heads'::regclass
         AND (a.grantee NOT IN ('ptmarket_audit_writer'::regrole, 'ptmarket_audit_owner'::regrole)
              OR (a.grantee = 'ptmarket_audit_owner'::regrole
                  AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')))$q$,
    0, 'audit_chain_heads: só o escritor escreve; o dono sem INSERT/UPDATE/DELETE/TRUNCATE; mais ninguém');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
       WHERE a.grantee = 'ptmarket_audit_retention'::regrole$q$,
    0, 'ptmarket_audit_retention sem privilégios');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
       WHERE c.oid IN (SELECT relid FROM pg_partition_tree('audit.audit_events'))
         AND a.privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')$q$,
    0, 'ninguém (o dono ptmarket_audit_owner incluído) tem UPDATE/DELETE/TRUNCATE em audit_events e partições');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
       WHERE c.oid = 'audit.audit_alerts'::regclass AND a.privilege_type IN ('DELETE', 'TRUNCATE')$q$,
    0, 'audit_alerts: ninguém tem DELETE/TRUNCATE');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_roles r
       WHERE r.rolname IN ('ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer', 'ptmarket_migrator')
         AND (pg_has_role(r.oid, 'ptmarket_audit_writer', 'MEMBER')
              OR pg_has_role(r.oid, 'ptmarket_audit_owner', 'MEMBER'))$q$,
    0, 'app, worker, price_writer e migrator não são membros de ptmarket_audit_writer/_owner');

-- ---------------------------------------------------------------------------
-- Sem ator no contexto: PTA01.
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00a';
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, NULL, NULL)$q$,
    'PTA01', 'sem app.actor_type ⇒ PTA01');

-- ---------------------------------------------------------------------------
-- Tenant A, merchant: 3 eventos standard encadeados + 1 fiscal + 1 denied (cadeias independentes).
-- ---------------------------------------------------------------------------
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-00000000a0a1';
SET app.request_id = '00000000-0000-7000-8000-00000000a0f1';
SET app.ip = '203.0.113.7';
SET app.user_agent_hash = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, '{"name":["x","y"]}', NULL);
SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, NULL, NULL);
SELECT audit.audit_append('stores.update', 'store', 's1', 'error', 'timeout', NULL, NULL);
SELECT audit.audit_append('orders.create', 'order', 'o1', 'success', NULL, NULL, NULL);
SELECT audit.audit_append('stores.delete', 'store', 's1', 'denied', 'sem permissão', NULL, NULL);

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE retention_class = 'standard'
       AND chain_key = '00000000-0000-7000-8000-00000000a00a'::uuid
       AND tenant_id = chain_key AND chain_seq IN (1, 2, 3)$q$,
    3, 'A standard: seq 1..3');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE retention_class = 'standard' AND chain_seq = 1
       AND prev_hash = decode(repeat('00', 32), 'hex')
       AND tenant_id = '00000000-0000-7000-8000-00000000a00a'$q$,
    1, 'A standard: génese com prev_hash a zeros');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events cur JOIN audit.audit_events prv
         ON prv.tenant_id = cur.tenant_id AND prv.retention_class = cur.retention_class
        AND prv.chain_seq = cur.chain_seq - 1
       WHERE cur.retention_class = 'standard' AND cur.prev_hash = prv.hash
         AND cur.created_at > prv.created_at
         AND cur.tenant_id = '00000000-0000-7000-8000-00000000a00a'$q$,
    2, 'A standard: prev_hash = hash do anterior (seq 2 e 3)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE retention_class = 'fiscal' AND chain_seq = 1
       AND action = 'orders.create' AND prev_hash = decode(repeat('00', 32), 'hex')$q$,
    1, 'A fiscal: cadeia própria (seq 1)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE retention_class = 'security' AND chain_seq = 1
       AND action = 'stores.delete' AND outcome = 'denied'$q$,
    1, 'A denied ⇒ security, cadeia própria (seq 1)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE actor_type = 'merchant' AND actor_id = '00000000-0000-7000-8000-00000000a0a1'
         AND request_id = '00000000-0000-7000-8000-00000000a0f1' AND host(ip) = '203.0.113.7'
         AND octet_length(user_agent_hash) = 32 AND occurred_at = created_at$q$,
    5, 'A: ator, pedido, IP e UA vêm do contexto');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE uuid_extract_version(id) = 7 AND octet_length(hash) = 32$q$,
    5, 'A: ids uuidv7 e hash de 32 bytes');

-- Hash: ip::text inclui a máscara — o mesmo evento com /8 em vez de /32 dá outro hash (host() era igual).
RESET ROLE;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events e
       WHERE e.ip::text = '203.0.113.7/32' AND audit._event_hash(e) = e.hash
         AND audit._event_hash(jsonb_populate_record(e, '{"ip": "203.0.113.7/8"}')) <> e.hash
         AND host((jsonb_populate_record(e, '{"ip": "203.0.113.7/8"}')).ip) = host(e.ip)$q$,
    5, 'ip /32 → /8 muda o hash (5/5); _event_hash = hash gravado');

-- Retenção (função só do escritor; chamada aqui pelo superuser do teste).
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES
        (audit.audit_retention_class('payments.capture', 'success'), 'fiscal'),
        (audit.audit_retention_class('price.change', 'error'), 'fiscal'),
        (audit.audit_retention_class('product_variants.update', 'success'), 'fiscal'),
        (audit.audit_retention_class('payments.capture', 'denied'), 'security'),
        (audit.audit_retention_class('subXorders.update', 'success'), 'standard'),
        (audit.audit_retention_class('orderly.update', 'success'), 'standard'),
        (audit.audit_retention_class('stores.update', 'success'), 'standard')) v(got, want)
       WHERE got = want$q$,
    7, 'audit_retention_class: denied ⇒ security; prefixos fiscais; resto standard');
SET ROLE ptmarket_app;

-- ---------------------------------------------------------------------------
-- Tenant B: cadeia independente; mismatch de tenant recusado.
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00b';
SELECT audit.audit_append('stores.update', 'store', 's2', 'success', NULL, NULL, NULL);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE retention_class = 'standard' AND chain_seq = 1
       AND prev_hash = decode(repeat('00', 32), 'hex')$q$,
    1, 'B standard: cadeia própria (seq 1)');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update', 'store', 's2', 'success', NULL, NULL, NULL,
                           '00000000-0000-7000-8000-00000000a00a')$q$,
    'P0001', 'merchant com p_tenant_id (outro tenant) ⇒ recusado');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update', 'store', 's2', 'success', NULL, NULL, NULL,
                           '00000000-0000-7000-8000-00000000a00b')$q$,
    'P0001', 'merchant com p_tenant_id (o próprio tenant) ⇒ recusado: p_tenant_id só para system');
SET app.actor_type = 'system';
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('jobs.run', 'job', 'j0', 'success', NULL, NULL, NULL,
                           '00000000-0000-7000-8000-00000000a00a')$q$,
    'P0001', 'system com p_tenant_id ≠ app.current_tenant_id ⇒ recusado');
SET app.actor_type = 'merchant';

-- ---------------------------------------------------------------------------
-- Anti-IDOR e app sem contexto.
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00a';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE tenant_id = '00000000-0000-7000-8000-00000000a00b'$q$,
    0, 'tenant A não lê eventos do B');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE tenant_id IS DISTINCT FROM '00000000-0000-7000-8000-00000000a00a'$q$,
    0, 'tenant A só vê eventos do próprio tenant');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_hash_check WHERE hash = recomputed$q$,
    5, 'A: hash recalculado em SQL = hash gravado (5/5)');

-- Plataforma (sem tenant): a app sem contexto grava com p_tenant_id NULL mas lê 0 linhas.
SET app.current_tenant_id = '';
SET app.actor_type = 'system';
SET app.actor_label = 'job:teste';
RESET app.actor_id;
SELECT audit.audit_append('jobs.run', 'job', 'j1', 'success', NULL, NULL, NULL);
-- system sem contexto com p_tenant_id: grava na cadeia desse tenant.
SELECT audit.audit_append('jobs.run', 'job', 'j2', 'success', NULL, NULL, NULL,
                          '00000000-0000-7000-8000-00000000a00d');
SET app.actor_type = 'merchant';
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update', 'store', 's9', 'success', NULL, NULL, NULL,
                                 '00000000-0000-7000-8000-00000000a00d')$q$,
    'P0001', 'app sem contexto, ator ≠ system, com p_tenant_id ⇒ recusado (não injeta na cadeia de outro tenant)');
SET app.actor_type = 'system';
SELECT pg_temp.expect_value($q$SELECT count(*) FROM audit.audit_events$q$, 0, 'app sem contexto lê 0 linhas');
SELECT pg_temp.expect_value($q$SELECT count(*) FROM audit_hash_check$q$, 0, 'app sem contexto lê 0 linhas (vista)');
RESET ROLE;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE tenant_id IS NULL AND action = 'jobs.run'
       AND chain_key = '00000000-0000-0000-0000-000000000000'
       AND chain_seq = 1 + (SELECT count(*) FROM audit_base
                            WHERE chain_key = '00000000-0000-0000-0000-000000000000'
                              AND retention_class = 'standard')
       AND actor_label = 'job:teste'$q$,
    1, 'evento de plataforma: tenant NULL, chain_key zero, seq 1');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE tenant_id = '00000000-0000-7000-8000-00000000a00d'
       AND chain_key = tenant_id AND chain_seq = 1 AND actor_type = 'system' AND target_id = 'j2'$q$,
    1, 'system com p_tenant_id ⇒ grava na cadeia do tenant D (seq 1)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_hash_check WHERE hash = recomputed AND id NOT IN (SELECT id FROM audit_base)$q$,
    8, 'todas as linhas: hash recalculado = gravado (8/8)');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Admin e impersonação ⇒ 1 alerta audit.superadmin_action em audit.audit_alerts; merchant simples não.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SET app.actor_type = 'admin';
SET app.actor_id = '00000000-0000-7000-8000-00000000adad';
RESET app.actor_label;
SELECT audit.audit_append('tenants.suspend', 'tenant', 't1', 'success', NULL, NULL, NULL) AS admin_id \gset
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00a';
SET app.actor_type = 'merchant';
SET app.impersonator_id = '00000000-0000-7000-8000-00000000adad';
SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, NULL, NULL) AS imp_id \gset
RESET app.impersonator_id;
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_alerts$q$, '42501', 'app não lê audit_alerts');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_alerts (id, created_at, event_type, payload) VALUES (uuidv7(), now(), 'x', '{}')$q$,
    '42501', 'app não insere em audit_alerts');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND event_type = 'audit.superadmin_action' AND published_at IS NULL
         AND payload->>'tenant_id' IS NULL AND payload->>'actor_type' = 'admin'
         AND payload->>'hash' ~ '^[0-9a-f]{64}$' AND payload->>'prev_hash' ~ '^[0-9a-f]{64}$'$q$,
        :'admin_id'),
    1, 'ator admin ⇒ 1 alerta audit.superadmin_action (hashes em hex)');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND event_type = 'audit.superadmin_action'
         AND payload->>'impersonator_id' = '00000000-0000-7000-8000-00000000adad'$q$,
        :'imp_id'),
    1, 'impersonação ⇒ 1 alerta audit.superadmin_action');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts$q$, 2, 'eventos sem admin/impersonação não geram alerta');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM outbox_events WHERE aggregate = 'audit'$q$, 0, 'a caixa negra não escreve no outbox');

-- Worker: marca published_at de NULL para um valor, uma vez; nada mais.
SELECT pg_temp.expect_value(
    format($q$WITH u AS (UPDATE audit.audit_alerts SET published_at = now() WHERE id = %L RETURNING 1)
              SELECT count(*) FROM u$q$, :'admin_id'),
    1, 'worker publica (published_at NULL → now())');
SELECT pg_temp.expect_value(
    format($q$WITH u AS (UPDATE audit.audit_alerts SET published_at = now() WHERE id = %L RETURNING 1)
              SELECT count(*) FROM u$q$, :'admin_id'),
    0, 'já publicado: o worker não o volta a mudar (0 linhas)');
SELECT pg_temp.expect_error(
    format($q$UPDATE audit.audit_alerts SET published_at = NULL WHERE id = %L$q$, :'imp_id'),
    'P0001', 'worker não grava published_at = NULL (o trigger recusa antes do WITH CHECK do RLS)');
SELECT pg_temp.expect_error(
    format($q$UPDATE audit.audit_alerts SET payload = '{}' WHERE id = %L$q$, :'imp_id'),
    '42501', 'worker não altera outras colunas (só UPDATE em published_at)');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_alerts$q$, '42501', 'worker não apaga alertas');
SELECT pg_temp.expect_error($q$TRUNCATE audit.audit_alerts$q$, '42501', 'worker não trunca alertas');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_alerts (id, created_at, event_type, payload) VALUES (uuidv7(), now(), 'x', '{}')$q$,
    '42501', 'worker não insere alertas');
RESET ROLE;

-- Mesmo o dono (NOLOGIN), sem FORCE e com privilégios re-concedidos a si próprio: o trigger recusa.
SET ROLE ptmarket_audit_owner;
ALTER TABLE audit.audit_alerts NO FORCE ROW LEVEL SECURITY;
GRANT UPDATE, DELETE, TRUNCATE ON audit.audit_alerts TO ptmarket_audit_owner;
SELECT pg_temp.expect_error(
    format($q$UPDATE audit.audit_alerts SET payload = '{}', published_at = now() WHERE id = %L$q$, :'imp_id'),
    'P0001', 'trigger: alterar o payload é recusado');
SELECT pg_temp.expect_error(
    format($q$UPDATE audit.audit_alerts SET published_at = NULL WHERE id = %L$q$, :'admin_id'),
    'P0001', 'trigger: voltar published_at a NULL é recusado');
SELECT pg_temp.expect_error(
    format($q$UPDATE audit.audit_alerts SET published_at = now() + interval '1 day' WHERE id = %L$q$, :'admin_id'),
    'P0001', 'trigger: mudar um published_at já gravado é recusado');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_alerts$q$, 'P0001', 'trigger: DELETE de alertas recusado');
SELECT pg_temp.expect_error($q$TRUNCATE audit.audit_alerts$q$, 'P0001', 'trigger: TRUNCATE de alertas recusado');
REVOKE UPDATE, DELETE, TRUNCATE ON audit.audit_alerts FROM ptmarket_audit_owner;
ALTER TABLE audit.audit_alerts FORCE ROW LEVEL SECURITY;
RESET ROLE;

-- Ninguém cria eventos 'audit' no outbox; a app mantém os outros eventos globais.
SET ROLE ptmarket_app;
SET app.current_tenant_id = '';
SELECT pg_temp.expect_error(
    $q$INSERT INTO outbox_events (aggregate, aggregate_id, event_type, payload)
       VALUES ('audit', uuidv7(), 'audit.superadmin_action', '{}')$q$,
    '42501', 'app sem contexto não forja eventos audit globais no outbox');
INSERT INTO outbox_events (aggregate, aggregate_id, event_type, payload)
VALUES ('tenant', uuidv7(), 'tenant.created', '{}');
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00a';
SELECT pg_temp.expect_error(
    $q$INSERT INTO outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
       VALUES ('00000000-0000-7000-8000-00000000a00a', 'audit', uuidv7(), 'audit.superadmin_action', '{}')$q$,
    '42501', 'app com contexto não forja eventos audit do tenant no outbox');
INSERT INTO outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
VALUES ('00000000-0000-7000-8000-00000000a00a', 'order', uuidv7(), 'order.created', '{}');
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM outbox_events
       WHERE (aggregate = 'tenant' AND tenant_id IS NULL)
          OR (aggregate = 'order' AND tenant_id = '00000000-0000-7000-8000-00000000a00a')$q$,
    2, 'app continua a inserir eventos globais e de tenant que não são audit');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Cabeças das cadeias: batem com a última linha; chain_seq contíguo; app/worker sem acesso.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chain_heads$q$,
    6, '6 cadeias: A standard/fiscal/security, B standard, D standard, plataforma standard');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chain_heads h
       JOIN LATERAL (
           SELECT e.chain_seq, e.hash FROM audit.audit_events e
           WHERE e.chain_key = h.chain_key AND e.retention_class = h.retention_class
           ORDER BY e.chain_seq DESC LIMIT 1) l ON true
       WHERE h.last_seq = l.chain_seq AND h.last_hash = l.hash$q$,
    6, 'cada cabeça = (chain_seq, hash) da última linha da cadeia');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (
           SELECT chain_key, retention_class FROM audit.audit_events
           GROUP BY chain_key, retention_class
           HAVING min(chain_seq) = 1 AND max(chain_seq) = count(*) AND count(DISTINCT chain_seq) = count(*)) c$q$,
    6, 'chain_seq contíguo de 1 a N em todas as cadeias');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events cur JOIN audit.audit_events prv
         ON prv.chain_key = cur.chain_key AND prv.retention_class = cur.retention_class
        AND prv.chain_seq = cur.chain_seq - 1
       WHERE cur.prev_hash <> prv.hash$q$,
    0, 'nenhum elo partido (prev_hash = hash do anterior)');
SELECT pg_temp.expect_error(
    $q$DELETE FROM audit.audit_chain_heads$q$, '42501', 'nem o escritor apaga cabeças');
RESET ROLE;

SET ROLE ptmarket_app;
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_chain_heads$q$, '42501', 'app não lê audit_chain_heads');
SELECT pg_temp.expect_error(
    $q$UPDATE audit.audit_chain_heads SET last_seq = 0$q$, '42501', 'app não altera audit_chain_heads');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_chain_heads VALUES (uuidv7(), 'standard', 0, decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'app não insere em audit_chain_heads');
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_chain_heads$q$, '42501', 'worker não lê audit_chain_heads');
SELECT pg_temp.expect_error(
    $q$UPDATE audit.audit_chain_heads SET last_seq = 0$q$, '42501', 'worker não altera audit_chain_heads');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_chain_heads VALUES (uuidv7(), 'standard', 0, decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'worker não insere em audit_chain_heads');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Escrita direta, UPDATE, DELETE e TRUNCATE: app, worker e dono das tabelas (o migrator: audit_seal.sql).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00a';
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_events SELECT * FROM audit.audit_events LIMIT 1$q$,
    '42501', 'app: INSERT direto falha');
SELECT pg_temp.expect_error($q$UPDATE audit.audit_events SET reason = 'x'$q$, '42501', 'app: UPDATE falha');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_events$q$, '42501', 'app: DELETE falha');
SELECT pg_temp.expect_error($q$TRUNCATE audit.audit_events$q$, '42501', 'app: TRUNCATE falha');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_ensure_partitions(3)$q$, '42501', 'app: não executa audit_ensure_partitions');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_events (id, chain_key, actor_type, action, outcome, retention_class, occurred_at,
                                 created_at, chain_seq, prev_hash, hash)
       VALUES (uuidv7(), uuidv7(), 'system', 'x.y', 'success', 'standard', now(), now(), 1,
               decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'worker: INSERT direto falha');
SELECT pg_temp.expect_error($q$UPDATE audit.audit_events SET reason = 'x'$q$, '42501', 'worker: UPDATE falha');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_events$q$, '42501', 'worker: DELETE falha');
SELECT pg_temp.expect_error($q$TRUNCATE audit.audit_events$q$, '42501', 'worker: TRUNCATE falha');
SELECT pg_temp.expect_error(
    $q$TRUNCATE audit.audit_events_standard_default$q$, '42501', 'worker: TRUNCATE de partição falha');
RESET ROLE;

-- Dono das tabelas (ptmarket_audit_owner, NOLOGIN).
SET ROLE ptmarket_audit_owner;
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_events (id, chain_key, actor_type, action, outcome, retention_class, occurred_at,
                                 created_at, chain_seq, prev_hash, hash)
       VALUES (uuidv7(), uuidv7(), 'db', 'x.y', 'success', 'standard', now(), now(), 1,
               decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'dono: INSERT direto falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_events_standard_default (id, chain_key, actor_type, action, outcome, retention_class,
                                 occurred_at, created_at, chain_seq, prev_hash, hash)
       VALUES (uuidv7(), uuidv7(), 'db', 'x.y', 'success', 'standard', now(), now(), 1,
               decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'dono: INSERT direto numa partição falha');
SELECT pg_temp.expect_error($q$UPDATE audit.audit_events SET reason = 'x'$q$, '42501', 'dono: UPDATE falha');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_events$q$, '42501', 'dono: DELETE falha');
SELECT pg_temp.expect_error($q$TRUNCATE audit.audit_events$q$, '42501', 'dono: TRUNCATE falha');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, NULL, NULL)$q$,
    '42501', 'dono das tabelas não executa audit_append');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_chain_heads VALUES (uuidv7(), 'standard', 0, decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'dono: INSERT em audit_chain_heads falha');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_chain_heads$q$, '42501', 'dono: DELETE em audit_chain_heads falha');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Partições: idempotência, triggers nas novas, DEFAULT.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value($q$SELECT audit.audit_ensure_partitions(3)$q$, 0, 'audit.audit_ensure_partitions(3) idempotente (0 novas)');
SELECT pg_temp.expect_value($q$SELECT audit.audit_ensure_partitions(5)$q$, 6, 'audit.audit_ensure_partitions(5) cria 2 meses × 3 classes');
SELECT pg_temp.expect_value($q$SELECT audit.audit_ensure_partitions(5)$q$, 0, 'audit.audit_ensure_partitions(5) idempotente');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_ensure_partitions(-1)$q$, '22023', 'audit_ensure_partitions recusa N negativo');
RESET ROLE;

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_partition_tree('audit.audit_events') t
       WHERE t.isleaf AND t.relid::text ~ '^audit\.audit_events_(fiscal|standard|security)_y[0-9]{4}m[0-9]{2}$'$q$,
    18, '6 meses × 3 classes de partições mensais');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_partition_tree('audit.audit_events') t
       WHERE NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = t.relid
                           AND g.tgname = 'audit_events_no_truncate' AND NOT g.tgisinternal)
          OR NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = t.relid
                           AND g.tgname = 'audit_events_no_update_delete')$q$,
    0, 'pai e todas as partições (também as novas) têm os triggers de imutabilidade');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
       WHERE c.oid IN (SELECT relid FROM pg_partition_tree('audit.audit_events') WHERE level > 0)
         AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')$q$,
    0, 'partições (também as novas) sem INSERT/UPDATE/DELETE/TRUNCATE para ninguém');

-- ---------------------------------------------------------------------------
-- Triggers: mesmo que o dono re-conceda a si próprio os privilégios, UPDATE/DELETE/TRUNCATE falham.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_owner;
ALTER TABLE audit.audit_events NO FORCE ROW LEVEL SECURITY;
DO $$
DECLARE
    r regclass;
BEGIN
    FOR r IN SELECT relid FROM pg_partition_tree('audit.audit_events') LOOP
        EXECUTE format('GRANT UPDATE, DELETE, TRUNCATE ON %s TO %I', r, current_user);
    END LOOP;
END
$$;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE id NOT IN (SELECT id FROM audit_base)$q$,
    10, 'dono sem FORCE vê as 10 linhas');
SELECT pg_temp.expect_error($q$UPDATE audit.audit_events SET reason = 'x'$q$, 'P0001', 'trigger: UPDATE recusado ao dono');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_events$q$, 'P0001', 'trigger: DELETE recusado ao dono');
SELECT pg_temp.expect_error($q$TRUNCATE audit.audit_events$q$, 'P0001', 'trigger: TRUNCATE do pai recusado ao dono');
SELECT pg_temp.expect_error(
    $q$TRUNCATE audit.audit_events_standard_default$q$, 'P0001', 'trigger: TRUNCATE de partição recusado ao dono');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE id NOT IN (SELECT id FROM audit_base)$q$,
    10, 'as 10 linhas continuam lá');


-- DEFAULT: sem a partição do mês corrente, o evento cai na DEFAULT (o INSERT não falha).
DO $$
BEGIN
    EXECUTE format('ALTER TABLE audit.audit_events_standard DETACH PARTITION audit.%I',
                   'audit_events_standard_' || to_char(now() AT TIME ZONE 'UTC', '"y"YYYY"m"MM'));
    EXECUTE format('DROP TABLE audit.%I',
                   'audit_events_standard_' || to_char(now() AT TIME ZONE 'UTC', '"y"YYYY"m"MM'));
END
$$;
RESET ROLE;
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00c';
SELECT audit.audit_append('stores.update', 'store', 's3', 'success', NULL, NULL, NULL);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE tableoid = 'audit.audit_events_standard_default'::regclass AND chain_seq = 1$q$,
    1, 'data fora das partições mensais cai na DEFAULT');
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT audit.audit_ensure_partitions(3)$q$, 0,
    'DEFAULT com linhas desse mês: partição não criada, sem erro (WARNING)');
RESET ROLE;


ROLLBACK;
