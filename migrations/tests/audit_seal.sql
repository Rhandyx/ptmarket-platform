-- Teste da selagem da caixa negra (cartão 01b). Corre como ptmarket_migrator (LOGIN), numa sessão própria:
-- assim SET ROLE é avaliado contra o migrator e não contra um superuser.
-- Prova: o migrator não se torna escritor/dono, não escreve nem mexe na estrutura de audit.*; um trigger
-- plantado por ele em public.outbox_events (de que é dono) não tem efeito em audit.*; o CREATE que mantém no
-- schema audit só lhe deixa criar objetos novos, que a selagem lhe tira (e recusa DEFINER fora da allowlist e
-- sobrecargas). Tudo com ROLLBACK.

BEGIN;

-- Base: eventos que já existiam antes deste teste (ex.: os do sqlx em _sqlx_migrations, L1 da 0010).
-- O migrator não lê audit.*: a soma das cabeças vem de audit_chains() como worker.
SET ROLE ptmarket_worker;
SELECT set_config('ptm.base_seq_sum', (SELECT COALESCE(sum(last_seq), 0) FROM audit.audit_chains())::text, false);
RESET ROLE;

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

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_roles WHERE rolname = session_user AND rolname = 'ptmarket_migrator'
       AND rolcanlogin AND NOT rolsuper$q$,
    1, 'sessão = ptmarket_migrator (LOGIN, não superuser)');

-- ---------------------------------------------------------------------------
-- Selagem idempotente (já correu no fim da 0009).
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_seal();
SELECT audit_admin.audit_seal();
SELECT pg_temp.expect_value($q$SELECT 1$q$, 1, 'audit_seal() repetida duas vezes sem erro');
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_seal()$q$, '42501', 'audit_seal() só para o migrator (a app não a executa)');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Papéis: o migrator não assume, não concede nem altera os papéis de auditoria.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error($q$SET ROLE ptmarket_audit_writer$q$, '42501', 'SET ROLE ptmarket_audit_writer falha');
SELECT pg_temp.expect_error($q$SET ROLE ptmarket_audit_owner$q$, '42501', 'SET ROLE ptmarket_audit_owner falha');
SELECT pg_temp.expect_error($q$SET ROLE ptmarket_audit_retention$q$, '42501', 'SET ROLE ptmarket_audit_retention falha');
SELECT pg_temp.expect_error(
    $q$GRANT ptmarket_audit_writer TO ptmarket_migrator$q$, '42501', 'GRANT ptmarket_audit_writer a si próprio falha');
SELECT pg_temp.expect_error(
    $q$GRANT ptmarket_audit_owner TO ptmarket_app$q$, '42501', 'GRANT ptmarket_audit_owner a outro papel falha');
SELECT pg_temp.expect_error(
    $q$ALTER ROLE ptmarket_audit_writer LOGIN PASSWORD 'x'$q$, '42501', 'ALTER ROLE ptmarket_audit_writer LOGIN falha');
SELECT pg_temp.expect_error($q$DROP ROLE ptmarket_audit_owner$q$, '42501', 'DROP ROLE ptmarket_audit_owner falha');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_roles r CROSS JOIN unnest(ARRAY['ptmarket_audit_owner', 'ptmarket_audit_writer',
                                                              'ptmarket_audit_retention']::regrole[]) a(oid)
       WHERE r.rolcanlogin AND NOT r.rolsuper AND pg_has_role(r.oid, a.oid, 'MEMBER')$q$,
    0, 'nenhum papel com LOGIN (não superuser) é membro de owner/writer/retention');

-- ---------------------------------------------------------------------------
-- Dados: nem lê, nem escreve, nem executa.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_events$q$, '42501', 'migrator não lê audit_events');
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_chain_heads$q$, '42501', 'migrator não lê audit_chain_heads');
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_alerts$q$, '42501', 'migrator não lê audit_alerts');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_events (id, chain_key, actor_type, action, outcome, retention_class, occurred_at,
                                       created_at, chain_seq, prev_hash, hash)
       VALUES (uuidv7(), uuidv7(), 'db', 'x.y', 'success', 'standard', now(), now(), 1,
               decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'INSERT direto em audit_events falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_events_standard_default (id, chain_key, actor_type, action, outcome, retention_class,
                                       occurred_at, created_at, chain_seq, prev_hash, hash)
       VALUES (uuidv7(), uuidv7(), 'db', 'x.y', 'success', 'standard', now(), now(), 1,
               decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'INSERT direto numa partição falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_chain_heads VALUES (uuidv7(), 'standard', 0, decode(repeat('00', 32), 'hex'))$q$,
    '42501', 'INSERT em audit_chain_heads falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit.audit_alerts (id, created_at, event_type, payload) VALUES (uuidv7(), now(), 'x', '{}')$q$,
    '42501', 'INSERT em audit_alerts falha');
SELECT pg_temp.expect_error($q$UPDATE audit.audit_events SET reason = 'x'$q$, '42501', 'UPDATE em audit_events falha');
SELECT pg_temp.expect_error($q$UPDATE audit.audit_chain_heads SET last_seq = 0$q$, '42501', 'UPDATE em audit_chain_heads falha');
SELECT pg_temp.expect_error($q$UPDATE audit.audit_alerts SET published_at = now()$q$, '42501', 'UPDATE em audit_alerts falha');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_events$q$, '42501', 'DELETE em audit_events falha');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_chain_heads$q$, '42501', 'DELETE em audit_chain_heads falha');
SELECT pg_temp.expect_error($q$DELETE FROM audit.audit_alerts$q$, '42501', 'DELETE em audit_alerts falha');
SELECT pg_temp.expect_error($q$TRUNCATE audit.audit_events$q$, '42501', 'TRUNCATE de audit_events falha');
SELECT pg_temp.expect_error(
    $q$TRUNCATE audit.audit_events_standard_default$q$, '42501', 'TRUNCATE de partição falha');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, NULL, NULL)$q$,
    '42501', 'migrator não executa audit_append');
SELECT pg_temp.expect_error(
    $q$SELECT audit._chain_insert(NULL::audit.audit_events, false)$q$, '42501', 'migrator não executa _chain_insert');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event('{}')$q$, '42501', 'migrator não executa audit_append_event');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_ensure_partitions(3)$q$, '42501', 'migrator não executa audit_ensure_partitions');
SELECT pg_temp.expect_error(
    $q$SELECT audit._event_hash(NULL::audit.audit_events)$q$, '42501', 'migrator não executa _event_hash');

-- ---------------------------------------------------------------------------
-- Estrutura: nada se apaga, desanexa, desliga, substitui ou acrescenta.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error($q$DROP TABLE audit.audit_events$q$, '42501', 'DROP TABLE audit_events falha');
SELECT pg_temp.expect_error(
    $q$DROP TABLE audit.audit_events_standard_default$q$, '42501', 'DROP TABLE de partição falha');
SELECT pg_temp.expect_error($q$DROP TABLE audit.audit_chain_heads$q$, '42501', 'DROP TABLE audit_chain_heads falha');
SELECT pg_temp.expect_error(
    $q$ALTER TABLE audit.audit_events_standard DETACH PARTITION audit.audit_events_standard_default$q$,
    '42501', 'DETACH PARTITION falha');
SELECT pg_temp.expect_error(
    $q$ALTER TABLE audit.audit_events DISABLE TRIGGER audit_events_no_update_delete$q$,
    '42501', 'DISABLE TRIGGER falha');
SELECT pg_temp.expect_error(
    $q$ALTER TABLE audit.audit_alerts DISABLE TRIGGER audit_alerts_publish_only$q$,
    '42501', 'DISABLE TRIGGER em audit_alerts falha');
SELECT pg_temp.expect_error(
    $q$ALTER TABLE audit.audit_events NO FORCE ROW LEVEL SECURITY$q$, '42501', 'NO FORCE ROW LEVEL SECURITY falha');
SELECT pg_temp.expect_error(
    $q$CREATE POLICY evil ON audit.audit_chain_heads FOR ALL TO ptmarket_migrator USING (true)$q$,
    '42501', 'CREATE POLICY em audit_chain_heads falha');
SELECT pg_temp.expect_error(
    $q$DROP POLICY writer_insert ON audit.audit_events$q$, '42501', 'DROP POLICY falha');
SELECT pg_temp.expect_error(
    $q$CREATE TRIGGER evil BEFORE INSERT ON audit.audit_events FOR EACH ROW
       EXECUTE FUNCTION audit.audit_alerts_guard()$q$,
    '42501', 'CREATE TRIGGER em audit_events falha');
SELECT pg_temp.expect_error(
    $q$ALTER TABLE audit.audit_events ALTER COLUMN reason SET DEFAULT 'x'$q$, '42501', 'ALTER COLUMN SET DEFAULT falha');
SELECT pg_temp.expect_error(
    $q$GRANT INSERT ON audit.audit_events TO ptmarket_migrator$q$, '42501', 'GRANT em audit_events a si próprio falha');
SELECT pg_temp.expect_error(
    $q$ALTER TABLE audit.audit_chain_heads OWNER TO ptmarket_migrator$q$, '42501', 'ALTER TABLE OWNER falha');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit.audit_append(
           p_action text, p_target_type text, p_target_id text, p_outcome text, p_reason text,
           p_changes jsonb, p_store_id uuid, p_tenant_id uuid DEFAULT NULL)
       RETURNS uuid LANGUAGE sql AS 'SELECT NULL::uuid'$q$,
    '42501', 'CREATE OR REPLACE FUNCTION audit.audit_append falha');
SELECT pg_temp.expect_error(
    $q$ALTER FUNCTION audit._chain_insert(audit.audit_events, boolean) OWNER TO ptmarket_migrator$q$,
    '42501', 'ALTER FUNCTION OWNER falha');
SELECT pg_temp.expect_error(
    $q$ALTER FUNCTION audit.audit_append(text, text, text, text, text, jsonb, uuid, uuid) RESET search_path$q$,
    '42501', 'ALTER FUNCTION … RESET search_path falha');
SELECT pg_temp.expect_error(
    $q$CREATE TABLE public.evil_part PARTITION OF audit.audit_events_standard
       FOR VALUES FROM ('2099-01-01') TO ('2099-02-01')$q$,
    '42501', 'CREATE TABLE … PARTITION OF uma tabela de audit falha');
SELECT pg_temp.expect_error($q$DROP SCHEMA audit CASCADE$q$, '42501', 'DROP SCHEMA audit falha');
SELECT pg_temp.expect_error($q$ALTER SCHEMA audit RENAME TO audit_old$q$, '42501', 'ALTER SCHEMA audit RENAME falha');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit_admin.audit_seal() RETURNS void LANGUAGE sql AS ''$q$,
    '42501', 'CREATE OR REPLACE FUNCTION audit_admin.audit_seal falha');

-- ---------------------------------------------------------------------------
-- Catálogo: donos sem LOGIN e a REGRA (nenhuma função DEFINER de audit.* toca em objetos de papéis com LOGIN).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (
           SELECT c.relowner AS owner FROM pg_class c WHERE c.relnamespace = 'audit'::regnamespace
           UNION ALL SELECT p.proowner FROM pg_proc p WHERE p.pronamespace = 'audit'::regnamespace
           UNION ALL SELECT t.typowner FROM pg_type t WHERE t.typnamespace = 'audit'::regnamespace
           UNION ALL SELECT n.nspowner FROM pg_namespace n WHERE n.nspname = 'audit') o
       JOIN pg_roles r ON r.oid = o.owner
       WHERE r.rolcanlogin OR r.rolname NOT IN ('ptmarket_audit_owner', 'ptmarket_audit_writer')$q$,
    0, 'todos os objetos de audit.* (e o schema) têm dono ptmarket_audit_owner/_writer (NOLOGIN)');
-- Lista fixa: o que audit._chain_insert lê/escreve/chama (os corpos plpgsql não ficam em pg_depend).
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (
           SELECT c.relowner AS owner FROM pg_class c
           WHERE c.oid IN (SELECT relid FROM pg_partition_tree('audit.audit_events'))
              OR c.oid IN ('audit.audit_chain_heads'::regclass, 'audit.audit_alerts'::regclass)
           UNION ALL
           SELECT p.proowner FROM pg_proc p
           WHERE p.oid IN ('audit._chain_insert(audit.audit_events, boolean)'::regprocedure,
                           'audit._event_hash(audit.audit_events)'::regprocedure,
                           'audit.audit_retention_class(text, text)'::regprocedure)) o
       JOIN pg_roles r ON r.oid = o.owner
       WHERE r.rolcanlogin$q$,
    0, '_chain_insert: tabelas e funções em que toca sem dono com LOGIN');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM regexp_matches(
           pg_get_functiondef('audit._chain_insert(audit.audit_events, boolean)'::regprocedure),
           '(?:FROM|INTO|UPDATE|JOIN)\s+([a-z_]+\.[a-z_]+)', 'gi') m
       WHERE m[1] NOT IN ('audit.audit_chain_heads', 'audit.audit_events', 'audit.audit_alerts')$q$,
    0, '_chain_insert só refere audit.audit_chain_heads, audit.audit_events e audit.audit_alerts');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.pronamespace = 'audit'::regnamespace
         AND (p.prosrc ~* '\mpublic\s*\.' OR p.prosrc ~* 'outbox')
         -- L2 (0013): as funções de DDL só comparam o nome outbox_events (allowlist da L1 automática).
         AND p.oid NOT IN ('audit.audit_ddl_end()'::regprocedure, 'audit.audit_ddl_drop()'::regprocedure)$q$,
    0, 'nenhuma função de audit.* refere o schema public nem o outbox');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.pronamespace = 'audit'::regnamespace AND p.prosecdef
         AND NOT (p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'])$q$,
    0, 'todas as funções DEFINER de audit.* com search_path = pg_catalog, pg_temp');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
       WHERE a.grantee = 'ptmarket_audit_writer'::regrole AND c.relnamespace <> 'audit'::regnamespace$q$,
    0, 'ptmarket_audit_writer sem privilégios em tabelas fora de audit (nem outbox_events)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_policy p JOIN pg_roles r ON r.oid = ANY (p.polroles)
       WHERE r.rolname = 'ptmarket_audit_writer' AND p.polrelid = 'public.outbox_events'::regclass$q$,
    0, 'sem política do escritor em outbox_events');

-- ---------------------------------------------------------------------------
-- Ataque: o migrator (dono de public.outbox_events) planta um trigger que tenta escrever em audit.* com a
-- identidade de quem dispara. Antes (escritor a inserir no outbox) corria como ptmarket_audit_writer e forjava
-- a cadeia; agora nenhuma escrita da caixa negra passa pelo outbox.
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.ptm_evil_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('ptm.evil_ran_as',
                       COALESCE(current_setting('ptm.evil_ran_as', true), '') || current_user || ';', true);
    BEGIN
        UPDATE audit.audit_chain_heads SET last_seq = 999;
        PERFORM set_config('ptm.evil_wrote', 'heads', true);
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        INSERT INTO audit.audit_events (id, chain_key, actor_type, action, outcome, retention_class, occurred_at,
                                        created_at, chain_seq, prev_hash, hash)
        VALUES (uuidv7(), uuidv7(), 'db', 'forged', 'success', 'standard', now(), now(), 1,
                decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'));
        PERFORM set_config('ptm.evil_wrote', 'events', true);
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        INSERT INTO audit.audit_alerts (id, created_at, event_type, payload) VALUES (uuidv7(), now(), 'forged', '{}');
        PERFORM set_config('ptm.evil_wrote', 'alerts', true);
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    RETURN NEW;
END
$$;
CREATE TRIGGER ptm_evil_outbox BEFORE INSERT OR UPDATE ON public.outbox_events
    FOR EACH ROW EXECUTE FUNCTION public.ptm_evil_outbox();
-- L2 (0013): o DDL acima também é gravado (ddl.*, que o migrator não desliga); a base passa a ser depois da montagem.
SET ROLE ptmarket_worker;
SELECT set_config('ptm.base_seq_sum', (SELECT COALESCE(sum(last_seq), 0) FROM audit.audit_chains())::text, false);
RESET ROLE;

-- App: admin (plataforma) e impersonação (tenant A); depois um evento normal no outbox (o trigger dispara).
SET ROLE ptmarket_app;
SET app.actor_type = 'admin';
SET app.actor_id = '00000000-0000-7000-8000-00000000adad';
SELECT audit.audit_append('tenants.suspend', 'tenant', 't1', 'success', NULL, NULL, NULL);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (SELECT current_setting('ptm.evil_ran_as', true) AS v) s WHERE v IS NOT NULL AND v <> ''$q$,
    0, 'audit_append (admin) não toca no outbox: o trigger plantado não disparou');
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00a';
SET app.actor_type = 'merchant';
SET app.impersonator_id = '00000000-0000-7000-8000-00000000adad';
SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, NULL, NULL);
RESET app.impersonator_id;
INSERT INTO outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
VALUES ('00000000-0000-7000-8000-00000000a00a', 'order', uuidv7(), 'order.created', '{}');
RESET ROLE;

-- Worker: evento de admin pelo stream e marca o outbox como publicado (o trigger dispara no UPDATE).
SET ROLE ptmarket_worker;
SELECT audit.audit_append_event(jsonb_build_object(
    'id', uuidv7(), 'actor_type', 'admin', 'action', 'tenants.reactivate', 'outcome', 'success',
    'request_id', '00000000-0000-7000-8000-00000000b0f9',
    'occurred_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')));
UPDATE outbox_events SET published_at = now() WHERE published_at IS NULL;

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (SELECT current_setting('ptm.evil_ran_as', true) AS v) s
       WHERE v = 'ptmarket_app;ptmarket_worker;'$q$,
    1, 'o trigger plantado só correu como app e worker (nunca como ptmarket_audit_writer)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (SELECT current_setting('ptm.evil_wrote', true) AS v) s WHERE v IS NOT NULL AND v <> ''$q$,
    0, 'o trigger plantado não escreveu em audit_chain_heads, audit_events nem audit_alerts');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chains() WHERE last_seq = 999$q$, 0, 'nenhuma cabeça forjada (999)');
SELECT pg_temp.expect_value(
    $q$SELECT sum(last_seq) - current_setting('ptm.base_seq_sum')::bigint FROM audit.audit_chains()$q$,
    3, 'cabeças: 3 eventos gravados, nenhum a mais');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chains() c,
            audit.audit_verify_chain(c.chain_key, c.retention_class, now() - interval '1 day', now() + interval '1 day')$q$,
    0, 'cadeias íntegras depois do ataque');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts WHERE event_type = 'audit.superadmin_action'$q$,
    3, 'alertas: admin (app), impersonação (app), admin (worker); nenhum forjado');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts$q$, 3, 'audit_alerts só com os 3 alertas legítimos');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM outbox_events WHERE aggregate = 'audit'$q$, 0, 'nenhum evento audit no outbox');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- CREATE no schema audit: o migrator cria objetos novos, mas não ganha nada com eles.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_namespace WHERE nspname = 'audit'
       AND has_schema_privilege('ptmarket_migrator', oid, 'USAGE')
       AND has_schema_privilege('ptmarket_migrator', oid, 'CREATE')$q$,
    1, 'o migrator mantém USAGE + CREATE no schema audit (migrations futuras)');

-- 1. Sobrecarga plantada (varchar, melhor correspondência para colunas varchar): não ganha a resolução,
--    porque _chain_insert passa ::text; e a selagem recusa sobrecargas.
CREATE FUNCTION audit.audit_retention_class(p_action varchar, p_outcome varchar)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('ptm.overload_ran_as', current_user, true);
    RETURN 'security';
END
$$;
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000a00a';
SET app.actor_type = 'merchant';
SELECT audit.audit_append('stores.update', 'store', 's1', 'success', NULL, NULL, NULL);
RESET ROLE;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (SELECT current_setting('ptm.overload_ran_as', true) AS v) s WHERE v IS NOT NULL AND v <> ''$q$,
    0, 'a sobrecarga plantada nunca correu (nem como ptmarket_audit_writer)');
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chains()
       WHERE chain_key = '00000000-0000-7000-8000-00000000a00a' AND retention_class = 'security'$q$,
    0, 'o evento foi para a classe certa (standard), não para a da sobrecarga');
RESET ROLE;
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_seal()$q$, 'P0001', 'audit_seal() recusa sobrecargas em audit');
DROP FUNCTION audit.audit_retention_class(varchar, varchar);

-- 2. Função SECURITY DEFINER fora da allowlist: a selagem falha (a migration seria desfeita).
CREATE FUNCTION audit.ptm_evil_definer() RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS 'SELECT';
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_seal()$q$, 'P0001', 'audit_seal() recusa função DEFINER fora da allowlist');
DROP FUNCTION audit.ptm_evil_definer();

-- 3. Tabela e função inofensivas: antes da selagem são do migrator; depois não lhes mexe.
CREATE TABLE audit.ptm_scratch (id int);
INSERT INTO audit.ptm_scratch VALUES (1);
CREATE FUNCTION audit.ptm_helper() RETURNS int LANGUAGE sql AS 'SELECT 1';
SELECT audit_admin.audit_seal();
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class WHERE oid = 'audit.ptm_scratch'::regclass
       AND relowner = 'ptmarket_audit_owner'::regrole$q$,
    1, 'tabela nova selada: dono ptmarket_audit_owner');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc WHERE oid = 'audit.ptm_helper()'::regprocedure
       AND proowner = 'ptmarket_audit_owner'::regrole$q$,
    1, 'função INVOKER nova selada: dono ptmarket_audit_owner');
SELECT pg_temp.expect_error($q$SELECT * FROM audit.ptm_scratch$q$, '42501', 'tabela selada: SELECT falha');
SELECT pg_temp.expect_error($q$INSERT INTO audit.ptm_scratch VALUES (2)$q$, '42501', 'tabela selada: INSERT falha');
SELECT pg_temp.expect_error($q$DELETE FROM audit.ptm_scratch$q$, '42501', 'tabela selada: DELETE falha');
SELECT pg_temp.expect_error($q$DROP TABLE audit.ptm_scratch$q$, '42501', 'tabela selada: DROP falha');
SELECT pg_temp.expect_error(
    $q$ALTER TABLE audit.ptm_scratch ADD COLUMN x int$q$, '42501', 'tabela selada: ALTER TABLE falha');
SELECT pg_temp.expect_error(
    $q$CREATE POLICY p ON audit.ptm_scratch USING (true)$q$, '42501', 'tabela selada: CREATE POLICY falha');
SELECT pg_temp.expect_error(
    $q$GRANT ALL ON audit.ptm_scratch TO ptmarket_migrator$q$, '42501', 'tabela selada: GRANT a si próprio falha');
SELECT pg_temp.expect_error($q$SELECT audit.ptm_helper()$q$, '42501', 'função selada: EXECUTE falha');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit.ptm_helper() RETURNS int LANGUAGE sql AS 'SELECT 2'$q$,
    '42501', 'função selada: CREATE OR REPLACE falha');

ROLLBACK;
