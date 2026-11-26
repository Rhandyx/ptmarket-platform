-- run.sh: superuser
-- Teste da 0026 (achados da auditoria do cartão 02/23a): session_user = ptmarket_app (o SET ROLE do migrator não
-- passa), só sessões da plataforma, 24 h sem filtro seletivo, a leitura grava 'admin.audit_timeline.read' na cadeia
-- (ator, filtros, linhas; nada gravado quando falha), chain_ok da cauda, EXPLAIN sem Seq Scan sem filtro seletivo,
-- VOLATILE e migrator sem INHERIT em ptmarket_identity. O resto (filtros, cursor, porta, adulteração do meio,
-- índices) está em audit_admin_read_events.sql.
-- Superuser só para semear, adulterar (dono NOLOGIN, trigger desligado só nesta transação) e ler catálogos/audit.*;
-- as chamadas fazem SET SESSION AUTHORIZATION ptmarket_app. Tudo numa transação com ROLLBACK.

BEGIN;
SET LOCAL event_triggers = off; -- L2 (0013) desligada só nesta transação: este teste não é sobre DDL

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

CREATE FUNCTION pg_temp.expect_no_seqscan(p_sql text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_plan jsonb;
    v_seq  text;
BEGIN
    EXECUTE 'EXPLAIN (FORMAT JSON) ' || p_sql INTO v_plan;
    SELECT string_agg(n.node ->> 'Relation Name', ', ') INTO v_seq
    FROM jsonb_path_query(v_plan, 'strict $.** ? (@."Node Type" == "Seq Scan")') AS n(node);
    IF v_seq IS NOT NULL THEN
        RAISE EXCEPTION 'FALHOU: % (Seq Scan em %)', p_label, v_seq;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

CREATE TEMP TABLE res (
    label text, id uuid, created_at timestamptz, tenant_id uuid, store_id uuid, actor_type text, actor_id uuid,
    actor_label text, impersonator_id uuid, action text, target_type text, target_id text, outcome text,
    reason text, changes jsonb, chain_seq bigint, chain_ok boolean);
GRANT SELECT, INSERT ON res TO ptmarket_app;

-- ---------------------------------------------------------------------------
-- 0. Super_admin A (TOTP); sessão da plataforma (5101) e sessão de um tenant (5102), ambas com 2FA.
--    Eventos: T4 com 3 (cauda).
-- ---------------------------------------------------------------------------
INSERT INTO public.tenants (id, slug, custom_domain, name) VALUES
    ('00000000-0000-7000-8000-0000002b0a01', 'adm-0026', 'adm-0026.teste.invalid', 'Adm 0026');
INSERT INTO public.users (id, email, full_name, totp_secret_enc, totp_enabled) VALUES
    ('00000000-0000-7000-8000-0000002b0001', 'a@ptm26.test', 'A', 'v1:a', true);
INSERT INTO public.user_roles (user_id, role) VALUES ('00000000-0000-7000-8000-0000002b0001', 'super_admin');
INSERT INTO public.sessions (id, subject_type, subject_id, token_hash, tenant_id, mfa_verified_at, expires_at) VALUES
    ('00000000-0000-7000-8000-0000002b5101', 'user', '00000000-0000-7000-8000-0000002b0001', sha256('t1'::bytea),
     NULL, now(), now() + interval '8 hours'),
    ('00000000-0000-7000-8000-0000002b5102', 'user', '00000000-0000-7000-8000-0000002b0001', sha256('t2'::bytea),
     '00000000-0000-7000-8000-0000002b0a01', now(), now() + interval '8 hours');

SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-0000002b0a04';
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-0000002b0c04';
SELECT count(audit.audit_append('stores.update', 'store', 's4', 'success', NULL, NULL, NULL))
FROM generate_series(1, 3);
RESET app.current_tenant_id;
RESET ROLE;

SET app.actor_type = 'admin';
SET app.actor_id = '00000000-0000-7000-8000-0000002b0001';
SET app.session_id = '00000000-0000-7000-8000-0000002b5101';
SET app.request_id = '00000000-0000-7000-8000-0000002b0e01';

CREATE TEMP TABLE reads_before AS
SELECT count(*) AS n FROM audit.audit_events WHERE action = 'admin.audit_timeline.read';

-- ---------------------------------------------------------------------------
-- 1. session_user: SET ROLE ptmarket_app (superuser ou migrator ligados) não lê pela porta.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 hour', now(),
           '00000000-0000-7000-8000-0000002b0a04', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 10)$q$,
    '42501', 'SET ROLE ptmarket_app com session_user postgres → 42501');
RESET ROLE;
SET SESSION AUTHORIZATION ptmarket_migrator;
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 hour', now(),
           '00000000-0000-7000-8000-0000002b0a04', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 10)$q$,
    '42501', 'migrator com SET ROLE ptmarket_app → 42501 (session_user = ptmarket_migrator)');
RESET ROLE;
RESET SESSION AUTHORIZATION;

-- ---------------------------------------------------------------------------
-- 2. Como ptmarket_app (session_user): sessão de tenant recusada; janela de 24 h sem filtro seletivo.
-- ---------------------------------------------------------------------------
SET SESSION AUTHORIZATION ptmarket_app;
SET app.session_id = '00000000-0000-7000-8000-0000002b5102';
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 hour', now(),
           '00000000-0000-7000-8000-0000002b0a04', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 10)$q$,
    '42501', 'sessão de tenant (tenant_id não NULL) → 42501');
SET app.session_id = '00000000-0000-7000-8000-0000002b5101';

SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '25 hours', now(), NULL, NULL, NULL, NULL,
           NULL, NULL, NULL, NULL, 10)$q$,
    '22023', 'sem filtro seletivo: janela de 25 h → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '2 days', now(), NULL, NULL, NULL, NULL,
           'stores.', 'success', NULL, NULL, 10)$q$,
    '22023', 'prefixo e outcome não são seletivos: 2 dias → 22023');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM public.identity_admin_read_events(now() - interval '23 hours', now() + interval '1 hour',
           NULL, NULL, NULL, NULL, 'stores.', NULL, NULL, NULL, 100) WHERE tenant_id = '00000000-0000-7000-8000-0000002b0a04'$q$,
    3, 'sem filtro seletivo: 24 h exatas aceites');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM public.identity_admin_read_events(now() - interval '30 days', now() + interval '1 day',
           NULL, NULL, '00000000-0000-7000-8000-0000002b0c04', NULL, NULL, NULL, NULL, NULL, 100)$q$,
    3, 'com ator: 31 dias exatos aceites');

-- Uma leitura conhecida (tenant T4, com cursor no futuro): 3 linhas, todas com chain_ok (cauda = cabeça).
INSERT INTO res
SELECT 'tail_ok', f.* FROM public.identity_admin_read_events(now() - interval '1 hour', now() + interval '1 minute',
    '00000000-0000-7000-8000-0000002b0a04', NULL, NULL, NULL, NULL, NULL, now() + interval '1 minute',
    'ffffffff-ffff-7fff-bfff-ffffffffffff', 10) f;
RESET SESSION AUTHORIZATION;

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label = 'tail_ok' AND chain_ok$q$, 3, 'T4 intacta: 3 linhas com chain_ok (incluindo a cauda)');

-- ---------------------------------------------------------------------------
-- 3. Cada leitura com sucesso gravou 'admin.audit_timeline.read' (as recusas e os 22023 não gravaram nada).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) - (SELECT n FROM reads_before) FROM audit.audit_events WHERE action = 'admin.audit_timeline.read'$q$,
    3, '3 leituras com sucesso → 3 eventos admin.audit_timeline.read (recusas e 22023 → 0)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events e
       WHERE e.action = 'admin.audit_timeline.read'
         AND e.actor_type = 'admin' AND e.actor_id = '00000000-0000-7000-8000-0000002b0001'
         AND e.request_id = '00000000-0000-7000-8000-0000002b0e01'
         AND e.outcome = 'success' AND e.target_type = 'audit_events' AND e.db_user = 'ptmarket_app'
         AND e.tenant_id IS NULL
         AND e.changes ->> 'tenant_id' = '00000000-0000-7000-8000-0000002b0a04'
         AND e.changes ->> 'cursor' = 'true' AND e.changes ->> 'limit' = '10' AND e.changes ->> 'rows' = '3'
         AND e.changes ? 'from' AND e.changes ? 'to'
         AND NOT e.changes ? 'cursor_at' AND NOT e.changes ? 'cursor_id' AND NOT e.changes ? 'store_id'$q$,
    1, 'evento: ator do contexto, request_id, db_user ptmarket_app, changes = filtros + cursor booleano + linhas');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts a
       JOIN audit.audit_events e ON e.id = a.id
       WHERE e.action = 'admin.audit_timeline.read' AND a.event_type = 'audit.superadmin_action'$q$,
    3, 'cada leitura também gerou o alerta audit.superadmin_action');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events e,
           LATERAL audit.audit_verify_chain(e.chain_key, e.retention_class, now() - interval '1 day',
                                            now() + interval '1 day') v
       WHERE e.action = 'admin.audit_timeline.read' AND e.request_id = '00000000-0000-7000-8000-0000002b0e01'$q$,
    0, 'cadeia dos eventos de leitura válida (audit_verify_chain sem quebras)');

-- ---------------------------------------------------------------------------
-- 4. Cauda: apagar o último de T4 (dono NOLOGIN, trigger desligado só aqui) deixa o anterior com chain_ok = false.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_owner;
ALTER TABLE audit.audit_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_events DISABLE TRIGGER audit_events_no_update_delete;
GRANT DELETE ON audit.audit_events TO CURRENT_USER;
DELETE FROM audit.audit_events WHERE tenant_id = '00000000-0000-7000-8000-0000002b0a04' AND chain_seq = 3;
ALTER TABLE audit.audit_events ENABLE TRIGGER audit_events_no_update_delete;
REVOKE DELETE ON audit.audit_events FROM CURRENT_USER;
ALTER TABLE audit.audit_events FORCE ROW LEVEL SECURITY;
RESET ROLE;

SET SESSION AUTHORIZATION ptmarket_app;
INSERT INTO res
SELECT 'tail_cut', f.* FROM public.identity_admin_read_events(now() - interval '1 hour', now() + interval '1 minute',
    '00000000-0000-7000-8000-0000002b0a04', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 10) f;
RESET SESSION AUTHORIZATION;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label = 'tail_cut' AND chain_ok IS DISTINCT FROM (chain_seq = 1)$q$,
    0, 'T4 sem o último: seq 2 com chain_ok = false (sem seguinte e não é a cabeça), seq 1 true');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label = 'tail_cut'$q$, 2, 'T4: 2 linhas depois do DELETE');

-- ---------------------------------------------------------------------------
-- 5. EXPLAIN sem filtro seletivo (só a janela de 24 h) e com prefixo + outcome: sem Seq Scan.
-- ---------------------------------------------------------------------------
SELECT audit._admin_read_events_sql(false, false, false, false, false, false, false) AS q_none,
       audit._admin_read_events_sql(false, false, false, false, true, true, true) AS q_none_po \gset
SET LOCAL enable_seqscan = off;
SET ROLE ptmarket_audit_writer;
PREPARE q_none(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer) AS :q_none;
PREPARE q_none_po(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer) AS :q_none_po;
SELECT pg_temp.expect_no_seqscan(
    $q$EXECUTE q_none(now() - interval '24 hours', now(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 100)$q$,
    'sem filtro seletivo (24 h): sem Seq Scan');
SELECT pg_temp.expect_no_seqscan(
    $q$EXECUTE q_none_po(now() - interval '24 hours', now(), NULL, NULL, NULL, NULL, 'stores.%', 'success', now(),
                         '00000000-0000-7000-8000-0000002bffff', 100)$q$,
    'sem filtro seletivo, com prefixo, outcome e cursor: sem Seq Scan');
DEALLOCATE q_none;
DEALLOCATE q_none_po;
RESET ROLE;
RESET enable_seqscan;

-- ---------------------------------------------------------------------------
-- 6. Catálogo: alteração aplicada; as duas funções VOLATILE; migrator sem INHERIT em ptmarket_identity.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied WHERE name = '0026_admin_read_events_v2'$q$,
    1, 'alteração aprovada 0026_admin_read_events_v2 aplicada');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid IN ('audit.admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)'::regprocedure,
                     'public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)'::regprocedure)
         AND provolatile = 'v' AND prosecdef AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    2, 'selada e porta: VOLATILE, DEFINER, search_path fixo');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)'::regprocedure
         AND proowner = 'ptmarket_identity'::regrole$q$,
    1, 'porta continua com dono ptmarket_identity');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) WHERE pg_has_role('ptmarket_migrator', 'ptmarket_identity', 'USAGE')$q$,
    0, 'migrator sem INHERIT em ptmarket_identity depois da 0026');
SET ROLE ptmarket_migrator;
SELECT audit_admin.audit_seal();
RESET ROLE;
DO $$ BEGIN RAISE NOTICE 'OK: audit_seal() continua a passar'; END $$;

ROLLBACK;
