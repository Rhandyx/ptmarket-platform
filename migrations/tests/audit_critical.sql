-- run.sh: superuser
-- Teste da 0015 (cartão 02/09a): audit.critical_kind, alertas de eventos críticos em audit.audit_alerts (kind),
-- índices da timeline (EXPLAIN sem Seq Scan) e selagem dos objetos novos.
-- Corre como superuser só para assumir papéis NOLOGIN e ler catálogos; cada asserção de dados é feita com
-- SET ROLE do papel em causa. Tudo numa transação com ROLLBACK.

BEGIN;
SET LOCAL event_triggers = off; -- L2 (0013) desligada só nesta transação: este teste não é sobre DDL

CREATE TEMP TABLE alert_base AS SELECT id FROM audit.audit_alerts;
GRANT SELECT ON alert_base TO ptmarket_worker;

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

-- EXPLAIN (FORMAT JSON) de p_sql: sem Seq Scan em nenhum nó e cada índice de p_roots usado (em pelo menos uma
-- partição; raiz da árvore de partições). Partições vazias podem ir por outro índice (custo ~0): não conta.
CREATE FUNCTION pg_temp.expect_index_plan(p_sql text, p_roots text[], p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_plan    jsonb;
    v_seq     bigint;
    v_missing text;
BEGIN
    EXECUTE 'EXPLAIN (FORMAT JSON) ' || p_sql INTO v_plan;
    SELECT count(*) INTO v_seq
    FROM jsonb_path_query(v_plan, 'strict $.**."Node Type"') AS n(t)
    WHERE n.t #>> '{}' = 'Seq Scan';
    SELECT string_agg(r.root, ', ') INTO v_missing
    FROM unnest(p_roots) AS r(root)
    WHERE NOT EXISTS (
        SELECT 1 FROM jsonb_path_query(v_plan, 'strict $.**."Index Name"') AS i(t)
        WHERE pg_partition_root(('audit.' || quote_ident(i.t #>> '{}'))::regclass)::text = r.root);
    IF v_seq > 0 OR v_missing IS NOT NULL THEN
        RAISE EXCEPTION 'FALHOU: % (seq scans %, índices em falta: %) plano: %',
            p_label, v_seq, v_missing, left(v_plan::text, 2000);
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- ---------------------------------------------------------------------------
-- 1. audit.critical_kind: tabela de casos (ação, outcome, ator → kind esperado; NULL = não crítico).
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE kind_cases (action text, outcome text, actor_type text, expected text);
INSERT INTO kind_cases VALUES
    ('stores.iban_update',     'success', 'merchant', 'iban_change'),
    ('stores.iban',            'denied',  'merchant', 'iban_change'),
    ('payout_accounts.create', 'success', 'merchant', 'iban_change'),
    ('payout_accounts.update', 'error',   'db',       'iban_change'),
    ('merchants.iban_change',  'success', 'admin',    'iban_change'),
    ('payments.capture',       'error',   'customer', 'payment_failure'),
    ('refunds.create',         'error',   'merchant', 'payment_failure'),
    ('payments.failed',        'success', 'system',   'payment_failure'),
    ('payments.capture',       'success', 'customer', NULL),
    ('payments.capture',       'denied',  'customer', NULL),
    ('refunds.create',         'success', 'merchant', NULL),
    ('invoices.issue',         'error',   'system',   'invoice_failure'),
    ('invoices.failed',        'success', 'system',   'invoice_failure'),
    ('invoices.issue',         'success', 'system',   NULL),
    ('auth.login',             'success', 'admin',    'superadmin_login'),
    ('auth.login',             'denied',  'admin',    'superadmin_login'),
    ('auth.login',             'success', 'customer', NULL),
    ('auth.login',             'denied',  'merchant', NULL),
    ('audit.verify_failed',    'error',   'system',   'verify_failure'),
    ('audit.verify',           'success', 'system',   NULL),
    ('stores.update',          'success', 'merchant', NULL),
    ('stores.ibanx',           'success', 'merchant', 'iban_change'), -- prefixo stores.iban (regra do cartão)
    ('store.iban_update',      'success', 'merchant', NULL),
    ('payment.capture',        'error',   'customer', NULL),
    ('orders.create',          'error',   'customer', NULL),
    ('tenants.suspend',        'success', 'admin',    NULL);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM kind_cases
       WHERE audit.critical_kind(action, outcome, actor_type) IS DISTINCT FROM expected$q$,
    0, 'critical_kind devolve o kind certo em todos os casos da tabela (e NULL nas ações normais)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES (audit.critical_kind(NULL, NULL, NULL)),
                                    (audit.critical_kind('auth.login', NULL, NULL))) v(k) WHERE k IS NOT NULL$q$,
    0, 'critical_kind com NULL → NULL');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'audit.critical_kind(text, text, text)'::regprocedure
         AND provolatile = 'i' AND NOT prosecdef$q$,
    1, 'critical_kind é IMMUTABLE e SECURITY INVOKER');

-- ---------------------------------------------------------------------------
-- 2. Alertas: crítico (customer/merchant/system) → 1 linha com kind; admin não crítico → kind NULL;
--    normal → nenhuma.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000c0a01';
SET app.actor_type = 'customer';
SET app.actor_id = '00000000-0000-7000-8000-0000000c0c01';
SELECT audit.audit_append('payments.capture', 'payment', 'p1', 'error', 'cartão recusado',
    '{"order_id": "o-1", "email": "cliente@example.com"}'::jsonb, NULL) AS pay_id \gset
SELECT audit.audit_append('payments.capture', 'payment', 'p2', 'success', NULL, NULL, NULL) AS pay_ok_id \gset
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-0000000c0c02';
SELECT audit.audit_append('stores.iban_update', 'store', 's1', 'success', 'novo IBAN PT50000201231234567890154',
    '{"before": {"iban": "PT50000201231234567890154"}, "after": {"iban": "PT50003506510000000000033"}}'::jsonb,
    NULL) AS iban_id \gset
SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, '{"title": "x"}'::jsonb, NULL) AS norm_id \gset
SET app.actor_type = 'system';
RESET app.actor_id;
SELECT audit.audit_append('invoices.issue', 'invoice', 'i1', 'error', NULL, NULL, NULL) AS inv_id \gset
RESET app.current_tenant_id;
SELECT audit.audit_append('audit.verify_failed', 'chain', 'c1', 'error', NULL, NULL, NULL) AS ver_id \gset
SET app.actor_type = 'admin';
SET app.actor_id = '00000000-0000-7000-8000-00000000adad';
SELECT audit.audit_append('auth.login', 'admin', 'a1', 'denied', NULL, NULL, NULL) AS login_id \gset
SELECT audit.audit_append('tenants.suspend', 'tenant', 't1', 'success', NULL, NULL, NULL) AS adm_id \gset
SET app.actor_type = 'customer';
SELECT audit.audit_append('auth.login', 'customer', 'c1', 'success', NULL, NULL, NULL) AS clogin_id \gset
RESET app.actor_type;
RESET app.actor_id;
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND kind = 'payment_failure' AND event_type = 'audit.critical' AND published_at IS NULL
         AND payload->>'actor_type' = 'customer'
         AND payload->'changes'->>'email' = '[pii]' AND payload->'changes'->>'order_id' = 'o-1'
         AND payload->>'hash' ~ '^[0-9a-f]{64}$'$q$, :'pay_id'),
    1, 'customer payments.* com error ⇒ 1 alerta payment_failure (payload = linha mascarada)');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND kind = 'iban_change' AND event_type = 'audit.critical'
         AND payload->>'actor_type' = 'merchant'
         AND NOT payload ? 'changes' AND NOT payload ? 'reason'
         AND strpos(payload::text, '****') = 0 AND strpos(payload::text, 'PT50') = 0
         AND strpos(payload::text, '1234567890154') = 0 AND strpos(payload::text, '0000000000033') = 0$q$,
        :'iban_id'),
    1, 'merchant stores.iban* ⇒ 1 alerta iban_change sem IBAN (nem mascarado: sem changes nem reason)');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts WHERE id = %L AND kind = 'invoice_failure'$q$, :'inv_id'),
    1, 'system invoices.* com error ⇒ 1 alerta invoice_failure');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND kind = 'verify_failure' AND payload->>'tenant_id' IS NULL$q$, :'ver_id'),
    1, 'audit.verify_failed ⇒ 1 alerta verify_failure');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND kind = 'superadmin_login' AND event_type = 'audit.critical'$q$, :'login_id'),
    1, 'auth.login de admin (recusa) ⇒ 1 alerta superadmin_login');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND kind IS NULL AND event_type = 'audit.superadmin_action'$q$, :'adm_id'),
    1, 'ação admin não crítica ⇒ 1 alerta com kind NULL');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts WHERE id IN (%L, %L, %L)$q$,
        :'pay_ok_id', :'norm_id', :'clogin_id'),
    0, 'ações normais (pagamento ok, stores.update, login de customer) ⇒ nenhum alerta');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts WHERE id NOT IN (SELECT id FROM alert_base)$q$,
    6, 'exatamente 6 alertas novos');
SELECT pg_temp.expect_error(
    format($q$UPDATE audit.audit_alerts SET kind = NULL WHERE id = %L$q$, :'pay_id'),
    '42501', 'worker não altera kind (só published_at)');
RESET ROLE;

-- O evento continua na cadeia com o IBAN mascarado (só o alerta o omite).
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events
       WHERE id = %L AND changes->'after'->>'iban' = '****0033'$q$, :'iban_id'),
    1, 'evento iban_change na cadeia com IBAN mascarado');
RESET ROLE;

-- Guard: só published_at muda (agora também protege kind), mesmo para o superuser.
SELECT pg_temp.expect_error(
    format($q$UPDATE audit.audit_alerts SET kind = 'verify_failure', published_at = now() WHERE id = %L$q$,
        :'pay_id'),
    'P0001', 'guard recusa mudar kind');
SELECT pg_temp.expect_error(
    format($q$UPDATE audit.audit_alerts SET published_at = now(), kind = 'nao_existe' WHERE id = %L$q$, :'adm_id'),
    'P0001', 'guard corre antes do CHECK de kind');

-- ---------------------------------------------------------------------------
-- 3. Timeline: as 4 consultas (tenant, loja, utilizador, encomenda; intervalo de datas, ORDER BY created_at
--    DESC LIMIT 50) usam índice, sem Seq Scan em nenhuma partição. enable_seqscan = off: a BD de teste tem
--    poucas linhas (o planeador preferiria Seq Scan); com ele desligado, um Seq Scan só aparece se nenhum índice
--    servir a consulta. Lidas como ptmarket_audit_writer (política writer_select).
-- ---------------------------------------------------------------------------
SET LOCAL enable_seqscan = off;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_index_plan(
    $q$SELECT * FROM audit.audit_events
       WHERE tenant_id = '00000000-0000-7000-8000-0000000c0a01'
         AND created_at >= now() - interval '30 days' AND created_at < now() + interval '1 day'
       ORDER BY created_at DESC LIMIT 50$q$,
    ARRAY['audit.audit_events_tenant_created_idx'], 'timeline por tenant usa (tenant_id, created_at)');
SELECT pg_temp.expect_index_plan(
    $q$SELECT * FROM audit.audit_events
       WHERE store_id = '00000000-0000-7000-8000-0000000c0501'
         AND created_at >= now() - interval '30 days' AND created_at < now() + interval '1 day'
       ORDER BY created_at DESC LIMIT 50$q$,
    ARRAY['audit.audit_events_store_created_idx'], 'timeline por loja usa (store_id, created_at)');
SELECT pg_temp.expect_index_plan(
    $q$SELECT * FROM audit.audit_events
       WHERE actor_id = '00000000-0000-7000-8000-0000000c0c01'
         AND created_at >= now() - interval '30 days' AND created_at < now() + interval '1 day'
       ORDER BY created_at DESC LIMIT 50$q$,
    ARRAY['audit.audit_events_actor_created_idx'], 'timeline por utilizador usa (actor_id, created_at)');
SELECT pg_temp.expect_index_plan(
    $q$SELECT * FROM audit.audit_events
       WHERE ((target_type = 'order' AND target_id = 'o-1')
              OR (changes ? 'order_id' AND changes ->> 'order_id' = 'o-1'))
         AND created_at >= now() - interval '30 days' AND created_at < now() + interval '1 day'
       ORDER BY created_at DESC LIMIT 50$q$,
    ARRAY['audit.audit_events_target_created_idx', 'audit.audit_events_order_created_idx'],
    'timeline por encomenda usa (target_type, target_id, created_at) + ((changes->>order_id), created_at)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (
           SELECT * FROM audit.audit_events
           WHERE ((target_type = 'order' AND target_id = 'o-1')
                  OR (changes ? 'order_id' AND changes ->> 'order_id' = 'o-1'))
             AND created_at >= now() - interval '30 days' AND created_at < now() + interval '1 day'
           ORDER BY created_at DESC LIMIT 50) t$q$,
    1, 'timeline por encomenda encontra o pagamento correlacionado por changes.order_id');
RESET ROLE;
RESET enable_seqscan;

-- ---------------------------------------------------------------------------
-- 4. Selagem: objetos novos de ptmarket_audit_owner; o migrator sem privilégios; audit_seal() passa.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied WHERE name = '0015_critical_timeline'$q$,
    1, 'alteração aprovada 0015_critical_timeline aplicada');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (
           SELECT proowner AS owner FROM pg_proc WHERE oid = 'audit.critical_kind(text, text, text)'::regprocedure
           UNION ALL
           SELECT c.relowner FROM pg_class c
           WHERE c.oid IN (SELECT relid FROM pg_partition_tree('audit.audit_events_store_created_idx')
                           UNION ALL SELECT relid FROM pg_partition_tree('audit.audit_events_actor_created_idx')
                           UNION ALL SELECT relid FROM pg_partition_tree('audit.audit_events_order_created_idx'))) o
       WHERE o.owner <> 'ptmarket_audit_owner'::regrole$q$,
    0, 'critical_kind e os índices novos (pai e partições) com dono ptmarket_audit_owner');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
       WHERE p.oid = 'audit.critical_kind(text, text, text)'::regprocedure
         AND a.grantee <> 'ptmarket_audit_owner'::regrole
         AND NOT (a.grantee = 'ptmarket_audit_writer'::regrole AND a.privilege_type = 'EXECUTE')$q$,
    0, 'critical_kind: EXECUTE só para ptmarket_audit_writer (nem PUBLIC, nem migrator, nem app)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) v(p)
       WHERE has_column_privilege('ptmarket_migrator', 'audit.audit_alerts', 'kind', v.p)$q$,
    0, 'migrator sem privilégios em audit_alerts.kind');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES ('ptmarket_migrator'), ('ptmarket_app'), ('ptmarket_worker')) v(r)
       WHERE has_function_privilege(v.r, 'audit.critical_kind(text, text, text)', 'EXECUTE')$q$,
    0, 'migrator, app e worker sem EXECUTE em critical_kind');
SET ROLE ptmarket_migrator;
SELECT audit_admin.audit_seal();
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit.critical_kind(p_action text, p_outcome text, p_actor_type text)
       RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT NULL::text'$q$,
    '42501', 'migrator não substitui critical_kind (selada)');
SELECT pg_temp.expect_error(
    $q$DROP INDEX audit.audit_events_store_created_idx$q$, '42501', 'migrator não apaga os índices novos');
RESET ROLE;
DO $$ BEGIN RAISE NOTICE 'OK: audit_seal() continua a passar'; END $$;

ROLLBACK;
