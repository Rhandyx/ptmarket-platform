-- run.sh: superuser
-- Teste da caixa negra L2 (0013 + infra/postgres/bootstrap/event-triggers.sql, cartão 02/04): DDL → ddl.* na
-- cadeia da plataforma, L1 automática em tabelas novas, máscara de PASSWORD/SECRET, guarda dos zz_audit_*.
-- Corre como superuser só para: ler a cadeia da plataforma (SET ROLE ptmarket_audit_writer), mudar o session_user
-- (SET SESSION AUTHORIZATION ptmarket_migrator = "ligado como migrator", como nas migrations) e dar uma tabela de
-- prova à app. Cada DDL a provar corre como o papel em causa. Tudo numa transação com ROLLBACK.
-- Falha se os event triggers não existirem ou não estiverem em ENABLE ALWAYS.

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

-- Eventos da cadeia da plataforma (standard) gravados depois da marca. Ler com SET ROLE ptmarket_audit_writer.
CREATE FUNCTION pg_temp.mark()
RETURNS void LANGUAGE sql AS $$
    SELECT set_config('ptm.ddl_seq', (SELECT COALESCE(max(chain_seq), 0) FROM audit.audit_events
                                      WHERE chain_key = '00000000-0000-0000-0000-000000000000'
                                        AND retention_class = 'standard')::text, false);
$$;
CREATE FUNCTION pg_temp.new_ev()
RETURNS SETOF audit.audit_events LANGUAGE sql AS $$
    SELECT * FROM audit.audit_events
    WHERE chain_key = '00000000-0000-0000-0000-000000000000' AND retention_class = 'standard'
      AND chain_seq > current_setting('ptm.ddl_seq')::bigint;
$$;

-- Triggers L1 corretos (função, tipo, ALWAYS) numa tabela.
CREATE FUNCTION pg_temp.l1_ok(p_rel regclass)
RETURNS bigint LANGUAGE sql AS $$
    SELECT count(*) FROM pg_trigger t
    WHERE t.tgrelid = p_rel AND t.tgenabled = 'A' AND t.tgfoid = 'audit.audit_row_trigger()'::regprocedure
      AND ((t.tgname = 'zz_audit_row' AND t.tgtype = 29) OR (t.tgname = 'zz_audit_truncate' AND t.tgtype = 34));
$$;

-- ---------------------------------------------------------------------------
-- 0. Instalação: os dois event triggers existem, ENABLE ALWAYS, sem filtro; funções seladas; GUC ligado.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_event_trigger e
       WHERE e.evtenabled = 'A' AND e.evttags IS NULL
         AND ((e.evtname = 'audit_ddl_end' AND e.evtevent = 'ddl_command_end'
               AND e.evtfoid = 'audit.audit_ddl_end()'::regprocedure::oid)
           OR (e.evtname = 'audit_ddl_drop' AND e.evtevent = 'sql_drop'
               AND e.evtfoid = 'audit.audit_ddl_drop()'::regprocedure::oid))$q$,
    2, 'event triggers audit_ddl_end/audit_ddl_drop instalados e em ENABLE ALWAYS (event-triggers.sql)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_event_trigger e JOIN pg_roles r ON r.oid = e.evtowner WHERE NOT r.rolsuper$q$,
    0, 'event triggers pertencem a um superuser');
SELECT pg_temp.expect_value(
    $q$SELECT (current_setting('event_triggers') = 'on')::int$q$, 1, 'GUC event_triggers ligado');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
       WHERE p.oid IN ('audit.audit_ddl_end()'::regprocedure, 'audit.audit_ddl_drop()'::regprocedure)
         AND NOT p.prosecdef AND r.rolname = 'ptmarket_audit_owner'
         AND NOT has_function_privilege('ptmarket_migrator', p.oid, 'EXECUTE')
         AND NOT has_function_privilege('ptmarket_app', p.oid, 'EXECUTE')$q$,
    2, 'audit_ddl_end/audit_ddl_drop: INVOKER, dono ptmarket_audit_owner, sem EXECUTE para migrator/app');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied WHERE name = '0013_ddl_owner_exec'$q$,
    1, 'alteração aprovada 0013_ddl_owner_exec aplicada');
SELECT pg_temp.expect_value(
    $q$SELECT has_function_privilege('ptmarket_audit_owner',
              'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)', 'EXECUTE')::int$q$,
    1, 'ptmarket_audit_owner tem EXECUTE em audit_append_db (partições)');

-- ---------------------------------------------------------------------------
-- 1. CREATE TABLE → 1 ddl.create_table + L1 automática; INSERT → t_probe.insert; DROP → ddl.drop_table.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.mark();
RESET ROLE;
SET SESSION AUTHORIZATION ptmarket_migrator;
CREATE TABLE public.t_probe (id uuid PRIMARY KEY);
RESET SESSION AUTHORIZATION;
SELECT pg_temp.expect_value(
    $q$SELECT pg_temp.l1_ok('public.t_probe')$q$, 2, 't_probe: zz_audit_row + zz_audit_truncate ativos (ALWAYS) sozinhos');
SET SESSION AUTHORIZATION ptmarket_migrator;
INSERT INTO public.t_probe VALUES ('00000000-0000-7000-8000-0000000dd001');
DROP TABLE public.t_probe;
RESET SESSION AUTHORIZATION;

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev()
       WHERE action = 'ddl.create_table' AND target_type = 'table' AND target_id = 'public.t_probe'
         AND actor_type = 'db' AND actor_label = 'ptmarket_migrator' AND tenant_id IS NULL
         AND changes->>'query_sha256' ~ '^[0-9a-f]{64}$' AND changes->>'truncated' = 'false'
         AND changes->>'query' LIKE 'CREATE TABLE public.t_probe%'$q$,
    1, 'CREATE TABLE t_probe: 1 evento ddl.create_table (db/ptmarket_migrator, plataforma, query + sha256)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev() WHERE target_id = 'zz_audit_row on public.t_probe'
         AND action = 'ddl.create_trigger'$q$,
    1, 'a L1 automática também fica em ddl.create_trigger');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev()
       WHERE action = 't_probe.insert' AND target_id = '00000000-0000-7000-8000-0000000dd001' AND actor_type = 'db'$q$,
    1, 'INSERT em t_probe gera t_probe.insert (L1)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev()
       WHERE action = 'ddl.drop_table' AND target_id = 'public.t_probe' AND actor_type = 'db'$q$,
    1, 'DROP TABLE t_probe: ddl.drop_table');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 2. CREATE POLICY, GRANT, REVOKE, ALTER TABLE … ADD COLUMN, CREATE FUNCTION, CREATE TABLE AS.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.mark();
RESET ROLE;
SET SESSION AUTHORIZATION ptmarket_migrator;
CREATE TABLE public.ptm_ddl_t2 (id int);
CREATE POLICY ptm_ddl_pol ON public.ptm_ddl_t2 USING (true);
GRANT SELECT ON TABLE public.ptm_ddl_t2 TO ptmarket_app;
REVOKE SELECT ON TABLE public.ptm_ddl_t2 FROM ptmarket_app;
ALTER TABLE public.ptm_ddl_t2 ADD COLUMN note text;
CREATE FUNCTION public.ptm_ddl_fn() RETURNS int LANGUAGE sql AS 'SELECT 1';
CREATE TABLE public.ptm_ddl_ctas AS SELECT 1 AS id;
RESET SESSION AUTHORIZATION;
SELECT pg_temp.expect_value(
    $q$SELECT pg_temp.l1_ok('public.ptm_ddl_ctas')$q$, 2, 'CREATE TABLE AS também recebe a L1');

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev() WHERE actor_type = 'db' AND actor_label = 'ptmarket_migrator' AND (
           (action = 'ddl.create_policy'   AND target_type = 'policy'   AND target_id = 'ptm_ddl_pol on public.ptm_ddl_t2')
        OR (action = 'ddl.grant'           AND target_type = 'table'    AND target_id IS NULL
                                           AND changes->>'query' LIKE 'GRANT SELECT ON TABLE public.ptm_ddl_t2%')
        OR (action = 'ddl.revoke'          AND target_type = 'table'    AND target_id IS NULL
                                           AND changes->>'query' LIKE 'REVOKE SELECT ON TABLE public.ptm_ddl_t2%')
        OR (action = 'ddl.alter_table'     AND target_type = 'table'    AND target_id = 'public.ptm_ddl_t2'
                                           AND changes->>'query' LIKE '%ADD COLUMN note%')
        OR (action = 'ddl.create_function' AND target_type = 'function' AND target_id = 'public.ptm_ddl_fn()')
        OR (action = 'ddl.create_table_as' AND target_type = 'table'    AND target_id = 'public.ptm_ddl_ctas'))$q$,
    6, 'CREATE POLICY, GRANT, REVOKE, ALTER TABLE ADD COLUMN, CREATE FUNCTION, CREATE TABLE AS: um ddl.* cada, actor db');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 3. Máscara: PASSWORD/SECRET nunca gravados (bloco com outro DDL; várias formas de literal); corte a 4096.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.mark();
RESET ROLE;
SET SESSION AUTHORIZATION ptmarket_migrator;
CREATE ROLE ptm_ddl_pw NOLOGIN \; ALTER ROLE ptm_ddl_pw PASSWORD 'S3gr3do-Um' \; CREATE TABLE public.ptm_ddl_pw1 (id int);
ALTER ROLE ptm_ddl_pw ENCRYPTED PASSWORD E'Esc\'S3gr3do-Dois' \; ALTER ROLE ptm_ddl_pw PASSWORD $pw$S3gr3do-Tres$pw$ \; ALTER ROLE ptm_ddl_pw password /* c */ 'S3gr3do''Quatro' \; CREATE TABLE public.ptm_ddl_pw2 (id int);
DO $do$ BEGIN EXECUTE 'ALTER ROLE ptm_ddl_pw PASSWORD ''S3gr3do-Cinco'''; CREATE TABLE public.ptm_ddl_pw3 (id int); END $do$;
COMMENT ON TABLE public.ptm_ddl_pw3 IS 'host=x password=S3gr3do-Seis dbname=y';
COMMENT ON TABLE public.ptm_ddl_pw2 IS '{"secret": "S3gr3do Sete", "a": 1}';
ALTER ROLE ptm_ddl_pw PASSWORD 'S3gr3do-Oito' \; CREATE TABLE public.ptm_ddl_h (id int);
DROP TABLE public.ptm_ddl_h;
ALTER ROLE ptm_ddl_pw PASSWORD 'S3gr3do-Nove-outra-mais-longa' \; CREATE TABLE public.ptm_ddl_h (id int);
SELECT format('CREATE TABLE public.ptm_ddl_long (id int /* %s */)', repeat('x', 5000)) AS long_q \gset
SELECT :'long_q' \gexec
RESET SESSION AUTHORIZATION;

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev() WHERE action LIKE 'ddl.%'
         AND target_id IN ('public.ptm_ddl_pw1', 'public.ptm_ddl_pw2', 'public.ptm_ddl_pw3')
         AND action IN ('ddl.create_table', 'ddl.comment')$q$,
    5, 'os DDL dos blocos com password foram gravados (3 create_table + 2 comment)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev() WHERE changes::text LIKE '%S3gr3do%'$q$,
    0, 'nenhum evento grava a password/secret (literal, E, $$, comentário, aninhado, conninfo, JSON)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev()
       WHERE action = 'ddl.create_table' AND target_id = 'public.ptm_ddl_pw1'
         AND changes->>'query' LIKE '%ALTER ROLE ptm_ddl_pw PASSWORD ''[redacted]''%'
         AND changes->>'query' LIKE '%CREATE TABLE public.ptm_ddl_pw1%'$q$,
    1, 'PASSWORD ''…'' → PASSWORD ''[redacted]'' e o resto da query fica');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev()
       WHERE action = 'ddl.create_table' AND target_id = 'public.ptm_ddl_h'
         AND changes->>'truncated' = 'false'
         AND changes->>'query_sha256' = encode(sha256(convert_to(changes->>'query', 'UTF8')), 'hex')$q$,
    2, 'query_sha256 = sha256 do texto já mascarado (nunca do original)');
SELECT pg_temp.expect_value(
    $q$SELECT count(DISTINCT changes->>'query_sha256') + count(DISTINCT changes->>'query') FROM pg_temp.new_ev()
       WHERE action = 'ddl.create_table' AND target_id = 'public.ptm_ddl_h'$q$,
    2, 'duas queries que só diferem na password: mesmo texto e mesmo query_sha256');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM pg_temp.new_ev()
       WHERE action = 'ddl.create_table' AND target_id = 'public.ptm_ddl_long'
         AND changes->>'truncated' = 'true' AND length(changes->>'query') = 4096
         AND changes->>'query_sha256' = %L$q$, encode(sha256(convert_to(:'long_q', 'UTF8')), 'hex')),
    1, 'query longa (sem segredos: mascarado = original): cortada a 4096, truncated = true, sha256 do texto inteiro');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. Guarda: o migrator (dono de stores) não desliga, troca, renomeia nem apaga os zz_audit_* (PTA04).
-- ---------------------------------------------------------------------------
SET SESSION AUTHORIZATION ptmarket_migrator;
CREATE FUNCTION public.ptm_ddl_noop() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END';
SELECT pg_temp.expect_error($q$ALTER TABLE public.stores DISABLE TRIGGER zz_audit_row$q$,
    'PTA04', 'migrator: DISABLE TRIGGER zz_audit_row recusado');
SELECT pg_temp.expect_error($q$DROP TRIGGER zz_audit_truncate ON public.stores$q$,
    'PTA04', 'migrator: DROP TRIGGER zz_audit_truncate recusado');
SELECT pg_temp.expect_error($q$ALTER TABLE public.stores ENABLE REPLICA TRIGGER zz_audit_row$q$,
    'PTA04', 'migrator: ENABLE REPLICA TRIGGER zz_audit_row recusado');
SELECT pg_temp.expect_error($q$ALTER TABLE public.stores ENABLE TRIGGER zz_audit_row$q$,
    'PTA04', 'migrator: ENABLE (sem ALWAYS) recusado');
SELECT pg_temp.expect_error($q$ALTER TABLE public.stores DISABLE TRIGGER USER$q$,
    'PTA04', 'migrator: DISABLE TRIGGER USER recusado');
SELECT pg_temp.expect_error($q$ALTER TRIGGER zz_audit_row ON public.stores RENAME TO zz_audit_row_x$q$,
    'PTA04', 'migrator: RENAME de zz_audit_row recusado');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE ON public.stores
       FOR EACH ROW EXECUTE FUNCTION audit.audit_row_trigger()$q$,
    'PTA04', 'migrator: CREATE OR REPLACE TRIGGER igual (volta a ENABLE sem ALWAYS) recusado');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE TRIGGER zz_audit_row AFTER INSERT ON public.stores
       FOR EACH ROW EXECUTE FUNCTION audit.audit_row_trigger()$q$,
    'PTA04', 'migrator: CREATE OR REPLACE TRIGGER com outro tipo recusado');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE TRIGGER zz_audit_truncate BEFORE TRUNCATE ON public.stores
       FOR EACH STATEMENT EXECUTE FUNCTION public.ptm_ddl_noop()$q$,
    'PTA04', 'migrator: CREATE OR REPLACE TRIGGER com outra função recusado');
SELECT pg_temp.expect_error(
    $q$CREATE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE ON public.ptm_ddl_t2
       FOR EACH ROW EXECUTE FUNCTION audit.audit_row_trigger()$q$,
    '42710', 'tabela nova já tem zz_audit_row (CREATE TRIGGER manual dá duplicado)');
ALTER TABLE public.stores ENABLE ALWAYS TRIGGER zz_audit_row;
RESET SESSION AUTHORIZATION;
SELECT pg_temp.expect_value(
    $q$SELECT pg_temp.l1_ok('public.stores')$q$, 2, 'stores: zz_audit_* intactos depois das recusas');

-- ---------------------------------------------------------------------------
-- 5. App: em stores falha por não ser dona; numa tabela de que é dona, o event trigger recusa (com ou sem ator).
-- ---------------------------------------------------------------------------
SET SESSION AUTHORIZATION ptmarket_migrator;
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error($q$ALTER TABLE public.stores DISABLE TRIGGER zz_audit_row$q$,
    '42501', 'app: DISABLE TRIGGER em stores falha (não é dona)');
RESET ROLE;
CREATE TABLE public.ptm_ddl_app (id int);
RESET SESSION AUTHORIZATION;
ALTER TABLE public.ptm_ddl_app OWNER TO ptmarket_app; -- superuser: a app não tem CREATE em public
SET SESSION AUTHORIZATION ptmarket_migrator;
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error($q$ALTER TABLE public.ptm_ddl_app DISABLE TRIGGER zz_audit_row$q$,
    'PTA04', 'app dona sem ator: DISABLE TRIGGER recusado pelo event trigger');
SELECT set_config('app.actor_type', 'merchant', true);
SELECT pg_temp.expect_error($q$ALTER TABLE public.ptm_ddl_app DISABLE TRIGGER zz_audit_row$q$,
    'PTA04', 'app dona com ator: DISABLE TRIGGER recusado pelo event trigger');
SELECT pg_temp.expect_error($q$DROP TRIGGER zz_audit_row ON public.ptm_ddl_app$q$,
    'PTA04', 'app dona com ator: DROP TRIGGER recusado');
SELECT pg_temp.expect_error($q$ALTER TABLE public.ptm_ddl_app ENABLE REPLICA TRIGGER zz_audit_truncate$q$,
    'PTA04', 'app dona com ator: ENABLE REPLICA recusado');
SELECT set_config('app.actor_type', '', true);
-- DDL da app sem ator falha fechado (PTA01); com ator grava pelo audit_append, na cadeia da plataforma.
-- (Na tabela de que é dona: desde a 0020 a app não tem TEMPORARY, já não cria tabelas temporárias.)
SELECT pg_temp.expect_error($q$ALTER TABLE public.ptm_ddl_app ADD COLUMN c1 int$q$, 'PTA01', 'app: DDL sem ator → PTA01');
RESET ROLE;
RESET SESSION AUTHORIZATION;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.mark();
RESET ROLE;
SET SESSION AUTHORIZATION ptmarket_migrator;
SET ROLE ptmarket_app;
SELECT set_config('app.actor_type', 'merchant', true);
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000dd0aa', true);
ALTER TABLE public.ptm_ddl_app ADD COLUMN c2 int;
SELECT pg_temp.expect_value(
    $q$SELECT (current_setting('app.current_tenant_id') = '00000000-0000-7000-8000-0000000dd0aa')::int$q$,
    1, 'app.current_tenant_id reposto depois da escrita do evento');
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.current_tenant_id', '', true);
RESET ROLE;
RESET SESSION AUTHORIZATION;
SELECT pg_temp.expect_value(
    $q$SELECT pg_temp.l1_ok('public.ptm_ddl_app')$q$, 2, 'ptm_ddl_app: zz_audit_* intactos');
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev()
       WHERE action = 'ddl.alter_table' AND target_id = 'public.ptm_ddl_app' AND actor_type = 'merchant'
         AND tenant_id IS NULL$q$,
    1, 'DDL da app com ator: ddl.alter_table como merchant, tenant NULL (cadeia da plataforma)');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 6. Partições: audit_ensure_partitions (DEFINER, dono ptmarket_audit_owner) grava ddl.create_table na mesma
--    transação do CREATE TABLE … PARTITION OF, sem bloqueio.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.mark();
SET ROLE ptmarket_worker;
SET LOCAL lock_timeout = '5s';
SELECT audit.audit_ensure_partitions(12) AS n_parts \gset
RESET lock_timeout;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT 1$q$, CASE WHEN :n_parts > 0 THEN 1 ELSE 0 END, 'audit_ensure_partitions(12) criou partições');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.new_ev()
       WHERE action = 'ddl.create_table' AND target_id LIKE 'audit.audit_events_%' AND actor_type = 'db'$q$,
    :n_parts, 'cada partição criada fica em ddl.create_table');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 7. A selagem continua a funcionar com os event triggers ativos; cobertura L1 de public intacta.
-- ---------------------------------------------------------------------------
SET SESSION AUTHORIZATION ptmarket_migrator;
SELECT audit_admin.audit_seal();
RESET SESSION AUTHORIZATION;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c
       WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p') AND NOT c.relispartition
         AND c.relname NOT IN ('audit_events', 'audit_chain_heads', 'outbox_events')
         AND pg_temp.l1_ok(c.oid) <> 2$q$,
    0, 'cobertura: todas as tabelas de public (incluindo as criadas aqui) com L1 sem CREATE TRIGGER manual');

ROLLBACK;
