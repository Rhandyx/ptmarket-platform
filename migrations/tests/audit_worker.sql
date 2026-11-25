-- run.sh: superuser
-- Teste das funções do worker da caixa negra (0009): audit_append_event, audit_verify_chain, audit_day_root,
-- audit_chains, audit_default_partition_rows. Chamadas sempre com SET ROLE ptmarket_worker; leituras de
-- controlo com SET ROLE ptmarket_audit_writer. Corre como superuser só para assumir papéis NOLOGIN: o dono
-- das tabelas (ptmarket_audit_owner) adultera a cadeia (trigger desligado, só nesta transação) e desanexa uma
-- partição. Tudo com ROLLBACK.

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

-- Evento do contrato do Redis Stream (occurred_at RFC 3339, UTC, há p_age).
CREATE FUNCTION pg_temp.ev(
    p_id uuid, p_tenant uuid, p_actor_type text, p_action text, p_outcome text DEFAULT 'success',
    p_age interval DEFAULT interval '1 minute')
RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'id', p_id, 'tenant_id', p_tenant, 'store_id', NULL, 'actor_type', p_actor_type,
        'actor_id', '00000000-0000-7000-8000-00000000b0a1', 'actor_label', NULL, 'impersonator_id', NULL,
        'action', p_action, 'target_type', 'store', 'target_id', 's1', 'outcome', p_outcome,
        'reason', NULL, 'changes', jsonb_build_object('name', jsonb_build_array('x', 'y')),
        'request_id', '00000000-0000-7000-8000-00000000b0f1', 'ip', '198.51.100.9',
        'user_agent_hash', 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
        'occurred_at', to_char((now() - p_age) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
$$;

-- Hash recalculado em SQL, independente das funções (fórmula do cartão 01; ip::text com máscara, cartão 01b).
CREATE TEMP VIEW audit_hash_check WITH (security_invoker = true) AS
SELECT e.*, sha256(e.prev_hash || convert_to(jsonb_build_array(
        e.id, e.tenant_id, e.store_id, e.actor_type, e.actor_id, e.actor_label, e.impersonator_id,
        e.action, e.target_type, e.target_id, e.outcome, e.reason, e.changes, e.request_id, e.ip::text,
        encode(e.user_agent_hash, 'hex'), e.retention_class,
        (extract(epoch FROM e.occurred_at) * 1000000)::bigint,
        (extract(epoch FROM e.created_at) * 1000000)::bigint,
        e.chain_seq)::text, 'UTF8')) AS recomputed
FROM audit.audit_events e;
GRANT SELECT ON audit_hash_check TO ptmarket_audit_writer;

-- ---------------------------------------------------------------------------
-- Catálogo: DEFINER, search_path fixo, dono ptmarket_audit_writer, EXECUTE só worker (+ dono).
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE worker_fns (sig regprocedure);
INSERT INTO worker_fns VALUES
    ('audit.audit_append_event(jsonb)'),
    ('audit.audit_verify_chain(uuid,text,timestamptz,timestamptz)'),
    ('audit.audit_day_root(date)'),
    ('audit.audit_chains()'),
    ('audit.audit_default_partition_rows()');

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM worker_fns f JOIN pg_proc p ON p.oid = f.sig JOIN pg_roles r ON r.oid = p.proowner
       WHERE p.prosecdef AND r.rolname = 'ptmarket_audit_writer'
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    5, '5 funções DEFINER, dono ptmarket_audit_writer, search_path = pg_catalog, pg_temp');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM worker_fns f JOIN pg_proc p ON p.oid = f.sig,
            aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
       WHERE a.privilege_type = 'EXECUTE'
         AND (a.grantee = 0 OR a.grantee NOT IN ('ptmarket_worker'::regrole, 'ptmarket_audit_writer'::regrole))$q$,
    0, 'nenhuma é executável por PUBLIC nem por outro papel além de worker e dono');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM worker_fns f WHERE has_function_privilege('ptmarket_worker', f.sig, 'EXECUTE')$q$,
    5, 'ptmarket_worker executa as 5');

-- ---------------------------------------------------------------------------
-- A app não executa nenhuma (42501); o worker não lê audit_events diretamente.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'))$q$,
    '42501', 'app: audit_append_event ⇒ 42501');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM audit.audit_verify_chain(uuidv7(), 'standard', now() - interval '1 day', now())$q$,
    '42501', 'app: audit_verify_chain ⇒ 42501');
SELECT pg_temp.expect_error($q$SELECT * FROM audit.audit_day_root(current_date)$q$, '42501', 'app: audit_day_root ⇒ 42501');
SELECT pg_temp.expect_error($q$SELECT * FROM audit.audit_chains()$q$, '42501', 'app: audit_chains ⇒ 42501');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_default_partition_rows()$q$, '42501', 'app: audit_default_partition_rows ⇒ 42501');
RESET ROLE;
SET ROLE ptmarket_migrator;
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'))$q$,
    '42501', 'migrator: audit_append_event ⇒ 42501');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_events$q$, '42501', 'worker sem SELECT direto em audit_events');

-- ---------------------------------------------------------------------------
-- Raiz diária: 3 eventos em 2 cadeias (C standard ×2, D standard ×1) ⇒ 2 linhas.
-- ---------------------------------------------------------------------------
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), '00000000-0000-7000-8000-00000000c00c', 'merchant', 'stores.update'));
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), '00000000-0000-7000-8000-00000000c00c', 'merchant', 'stores.update'));
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), '00000000-0000-7000-8000-00000000d00d', 'customer', 'customers.login'));
RESET ROLE;
SET ROLE ptmarket_audit_writer;
SELECT (created_at AT TIME ZONE 'UTC')::date AS root_day FROM audit.audit_events ORDER BY created_at LIMIT 1 \gset
CREATE TEMP TABLE expected_root AS
SELECT DISTINCT ON (chain_key, retention_class) chain_key, retention_class::text, chain_seq, hash
FROM audit.audit_events ORDER BY chain_key, retention_class, chain_seq DESC;
GRANT SELECT ON expected_root TO ptmarket_worker;
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_day_root(%L::date)$q$, :'root_day'), 2, 'audit_day_root: 2 cadeias');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_day_root(%L::date) r JOIN expected_root x
         ON x.chain_key = r.chain_key AND x.retention_class = r.retention_class
       WHERE r.last_hash = x.hash AND r.last_seq = x.chain_seq AND r.first_seq = 1
         AND r.events = x.chain_seq$q$, :'root_day'),
    2, 'audit_day_root: last_hash/last_seq da última linha de cada cadeia, first_seq 1, events certos');
SELECT pg_temp.expect_value(
    format($q$SELECT sum(events) FROM audit.audit_day_root(%L::date)$q$, :'root_day'), 3, 'audit_day_root: 3 eventos');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_day_root(%L::date - 1)$q$, :'root_day'), 0, 'dia anterior: 0 linhas');

-- ---------------------------------------------------------------------------
-- audit_append_event: grava, encadeia, idempotente; partilha a cabeça com audit_append.
-- ---------------------------------------------------------------------------
SELECT uuidv7() AS ev1 \gset
SELECT pg_temp.expect_value(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L, '00000000-0000-7000-8000-00000000a00a', 'merchant', 'stores.update'))::int$q$,
        :'ev1'),
    1, 'grava ⇒ true');
SELECT pg_temp.expect_value(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L, '00000000-0000-7000-8000-00000000a00a', 'merchant', 'stores.update'))::int$q$,
        :'ev1'),
    0, 'mesmo id ⇒ false');
SELECT pg_temp.expect_value(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L, '00000000-0000-7000-8000-00000000a00a', 'merchant', 'stores.update',
                                                   'success', interval '2 days'))::int$q$,
        :'ev1'),
    0, 'mesmo id com occurred_at mais antigo (dentro da janela) ⇒ false');
RESET ROLE;

-- audit_append (app, contexto do tenant A) na mesma cadeia: continua a sequência.
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00a';
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-00000000a0a1';
SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, NULL, NULL);
RESET app.current_tenant_id;
RESET app.actor_type;
RESET app.actor_id;
RESET ROLE;

SET ROLE ptmarket_worker;
-- Evento mínimo: chaves "|null" ausentes; contexto app.* ignorado.
SET app.actor_type = 'admin';
SELECT uuidv7() AS minimal \gset
SELECT audit.audit_append_event(jsonb_build_object(
    'id', :'minimal'::uuid, 'tenant_id', '00000000-0000-7000-8000-00000000a00a', 'actor_type', 'merchant',
    'action', 'stores.update', 'outcome', 'success', 'request_id', '00000000-0000-7000-8000-00000000b0f2',
    'occurred_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"+00:00"')));
RESET app.actor_type;
RESET ROLE;

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L$q$, :'ev1'), 1, 'mesmo id: uma só linha');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE tenant_id = '00000000-0000-7000-8000-00000000a00a'
       AND retention_class = 'standard' AND chain_seq IN (1, 2, 3)$q$,
    3, 'A standard: worker (1), audit_append (2), worker (3) na mesma cadeia');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events cur JOIN audit.audit_events prv
         ON prv.chain_key = cur.chain_key AND prv.retention_class = cur.retention_class
        AND prv.chain_seq = cur.chain_seq - 1
       WHERE cur.prev_hash = prv.hash AND cur.created_at > prv.created_at$q$,
    3, 'elos certos: C seq 2, A seq 2 e 3');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE chain_seq = 1 AND prev_hash = decode(repeat('00', 32), 'hex')$q$,
    3, 'génese a zeros nas cadeias C, D e A');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_hash_check WHERE hash = recomputed$q$, 6, 'hash recalculado = gravado (6/6)');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L
       AND actor_type = 'merchant' AND actor_id = '00000000-0000-7000-8000-00000000b0a1'
       AND request_id = '00000000-0000-7000-8000-00000000b0f1' AND host(ip) = '198.51.100.9'
       AND octet_length(user_agent_hash) = 32 AND changes = '{"name":["x","y"]}'
       AND occurred_at < created_at AND tenant_id = chain_key$q$, :'ev1'),
    1, 'ator, pedido, IP, UA, changes e occurred_at vêm do JSON');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L AND actor_type = 'merchant'
       AND actor_id IS NULL AND ip IS NULL AND changes IS NULL AND chain_seq = 3$q$, :'minimal'),
    1, 'evento mínimo (nulos ausentes) grava; app.actor_type ignorado');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chain_heads h
       JOIN LATERAL (SELECT e.chain_seq, e.hash FROM audit.audit_events e
                     WHERE e.chain_key = h.chain_key AND e.retention_class = h.retention_class
                     ORDER BY e.chain_seq DESC LIMIT 1) l ON true
       WHERE h.last_seq = l.chain_seq AND h.last_hash = l.hash$q$,
    3, 'cabeças = última linha de cada cadeia');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Contrato inválido ⇒ PTA02.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error($q$SELECT audit.audit_append_event('[]')$q$, 'PTA02', 'não objeto ⇒ PTA02');
SELECT pg_temp.expect_error($q$SELECT audit.audit_append_event(NULL)$q$, 'PTA02', 'NULL ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'db', 'jobs.run'))$q$, 'PTA02', 'actor_type db ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'root', 'jobs.run'))$q$, 'PTA02', 'actor_type fora da lista ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run', 'maybe'))$q$, 'PTA02', 'outcome inválido ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run') || '{"extra": 1}')$q$,
    'PTA02', 'chave desconhecida ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run') - 'request_id')$q$,
    'PTA02', 'request_id em falta ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{action}', 'null'))$q$,
    'PTA02', 'action null ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{id}', '42'))$q$,
    'PTA02', 'id numérico ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(gen_random_uuid(), NULL, 'system', 'jobs.run'))$q$,
    'PTA02', 'id uuid v4 ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{tenant_id}', '"x"'))$q$,
    'PTA02', 'tenant_id não uuid ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{actor_id}', 'true'))$q$,
    'PTA02', 'actor_id booleano ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{changes}', '[1]'))$q$,
    'PTA02', 'changes array ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{ip}', '"999.1.1.1"'))$q$,
    'PTA02', 'ip inválido ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{user_agent_hash}', '"zz"'))$q$,
    'PTA02', 'user_agent_hash não hex ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{occurred_at}', '"yesterday"'))$q$,
    'PTA02', 'occurred_at não RFC 3339 ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(jsonb_set(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run'), '{occurred_at}', '"2026-01-01T00:00:00"'))$q$,
    'PTA02', 'occurred_at sem fuso ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run', 'success', interval '-10 minutes'))$q$,
    'PTA02', 'occurred_at > now() + 5 min ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', 'jobs.run', 'success', interval '8 days'))$q$,
    'PTA02', 'occurred_at < now() - 7 dias ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', repeat('a', 97)))$q$,
    'PTA02', 'action > 96 ⇒ PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', ''))$q$, 'PTA02', 'action vazia ⇒ PTA02');

-- ---------------------------------------------------------------------------
-- Ator admin ⇒ alerta audit.superadmin_action em audit.audit_alerts (mesma regra de audit_append).
-- ---------------------------------------------------------------------------
SELECT uuidv7() AS adm \gset
SELECT audit.audit_append_event(pg_temp.ev(:'adm', NULL, 'admin', 'tenants.suspend'));
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND event_type = 'audit.superadmin_action' AND published_at IS NULL
         AND payload->>'tenant_id' IS NULL AND payload->>'actor_type' = 'admin'
         AND payload->>'hash' ~ '^[0-9a-f]{64}$' AND payload->>'prev_hash' ~ '^[0-9a-f]{64}$'$q$, :'adm'),
    1, 'ator admin ⇒ 1 alerta audit.superadmin_action');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts$q$, 1, 'merchant/customer não geram alerta');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM outbox_events WHERE aggregate = 'audit'$q$, 0, 'nada da caixa negra no outbox');

-- ---------------------------------------------------------------------------
-- audit_chains e verificação de cadeias íntegras.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value($q$SELECT count(*) FROM audit.audit_chains()$q$, 4, 'audit_chains: C, D, A, plataforma');
SELECT pg_temp.expect_value(
    $q$SELECT last_seq FROM audit.audit_chains() WHERE chain_key = '00000000-0000-7000-8000-00000000a00a'
       AND retention_class = 'standard'$q$,
    3, 'audit_chains: last_seq da cabeça de A');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chains() c,
            audit.audit_verify_chain(c.chain_key, c.retention_class, now() - interval '1 day', now() + interval '1 day')$q$,
    0, 'audit_verify_chain: 0 quebras em todas as cadeias íntegras');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM audit.audit_verify_chain(uuidv7(), 'other', now() - interval '1 day', now())$q$,
    '22023', 'audit_verify_chain: classe inválida ⇒ 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM audit.audit_verify_chain(uuidv7(), 'standard', now(), now() - interval '1 day')$q$,
    '22023', 'audit_verify_chain: p_from ≥ p_to ⇒ 22023');

-- Cadeia E (5 eventos) para adulterar; cadeia F (3 eventos) para o salto.
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), '00000000-0000-7000-8000-00000000e00e', 'merchant', 'stores.update'))
FROM generate_series(1, 5);
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), '00000000-0000-7000-8000-00000000f00f', 'merchant', 'stores.update'))
FROM generate_series(1, 3);
RESET ROLE;

-- A 1.ª linha do intervalo aceita o prev_hash gravado (âncora).
SET ROLE ptmarket_audit_writer;
SELECT created_at AS e_seq2_at FROM audit.audit_events
WHERE chain_key = '00000000-0000-7000-8000-00000000e00e' AND chain_seq = 2 \gset
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-00000000e00e', 'standard',
                                                      %L::timestamptz, now() + interval '1 day')$q$, :'e_seq2_at'),
    0, 'intervalo a começar no seq 2: âncora aceite, 0 quebras');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Adulteração (dono NOLOGIN, trigger desligado SÓ nesta transação, BD descartável): hash, link e gap.
-- ---------------------------------------------------------------------------
RESET ROLE;
SET ROLE ptmarket_audit_owner;
ALTER TABLE audit.audit_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_events DISABLE TRIGGER audit_events_no_update_delete;
GRANT UPDATE, DELETE ON audit.audit_events TO CURRENT_USER;
-- E: seq 2 muda o reason (⇒ 'hash' no 2); seq 4 muda o hash (⇒ 'hash' no 4 e 'link' no 5).
UPDATE audit.audit_events SET reason = 'adulterado'
WHERE chain_key = '00000000-0000-7000-8000-00000000e00e' AND retention_class = 'standard' AND chain_seq = 2;
UPDATE audit.audit_events SET hash = sha256('x'::bytea)
WHERE chain_key = '00000000-0000-7000-8000-00000000e00e' AND retention_class = 'standard' AND chain_seq = 4;
-- F: apaga o seq 2 (⇒ 'gap' no 3).
DELETE FROM audit.audit_events
WHERE chain_key = '00000000-0000-7000-8000-00000000f00f' AND retention_class = 'standard' AND chain_seq = 2;
ALTER TABLE audit.audit_events ENABLE TRIGGER audit_events_no_update_delete;
REVOKE UPDATE, DELETE ON audit.audit_events FROM CURRENT_USER;
ALTER TABLE audit.audit_events FORCE ROW LEVEL SECURITY;
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-00000000e00e', 'standard',
                                               now() - interval '1 day', now() + interval '1 day')$q$,
    3, 'E adulterada: 3 quebras');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-00000000e00e', 'standard',
                                               now() - interval '1 day', now() + interval '1 day') v
       WHERE (v.broken_seq, v.problem) IN ((2, 'hash'), (4, 'hash'), (5, 'link'))
         AND v.broken_id IS NOT NULL$q$,
    3, 'E: hash no seq 2 e 4, link no seq 5');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-00000000f00f', 'standard',
                                               now() - interval '1 day', now() + interval '1 day') v
       WHERE v.broken_seq = 3 AND v.problem = 'gap'$q$,
    1, 'F: gap no seq 3');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-00000000f00f', 'standard',
                                               now() - interval '1 day', now() + interval '1 day')$q$,
    1, 'F: só essa quebra');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chains() c,
            audit.audit_verify_chain(c.chain_key, c.retention_class, now() - interval '1 day', now() + interval '1 day')
       WHERE c.chain_key NOT IN ('00000000-0000-7000-8000-00000000e00e', '00000000-0000-7000-8000-00000000f00f')$q$,
    0, 'as outras cadeias continuam íntegras');

-- ---------------------------------------------------------------------------
-- Partições DEFAULT: 0 com as mensais criadas; > 0 quando falta a do mês (o evento cai na DEFAULT).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value($q$SELECT audit.audit_default_partition_rows()$q$, 0, 'DEFAULT vazias ⇒ 0');
RESET ROLE;
SET ROLE ptmarket_audit_owner;
DO $$
BEGIN
    EXECUTE format('ALTER TABLE audit.audit_events_standard DETACH PARTITION audit.%I',
                   'audit_events_standard_' || to_char(now() AT TIME ZONE 'UTC', '"y"YYYY"m"MM'));
END
$$;
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), '00000000-0000-7000-8000-00000000a00a', 'merchant', 'stores.update'));
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL, 'system', 'payments.reconcile'));
SELECT pg_temp.expect_value(
    $q$SELECT audit.audit_default_partition_rows()$q$, 1, 'sem a partição standard do mês: 1 linha na DEFAULT');
RESET ROLE;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE tableoid = 'audit.audit_events_standard_default'::regclass
       AND chain_seq = 4 AND chain_key = '00000000-0000-7000-8000-00000000a00a'$q$,
    1, 'o evento continua a cadeia A (seq 4) a partir da cabeça, não das partições');
RESET ROLE;

ROLLBACK;
