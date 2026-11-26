-- run.sh: superuser
-- Teste da 0011 + bootstrap (cartão 02/03b): db_user = session_user em cada evento (dentro do hash),
-- audit_verify_actors, audit_append sem 'db', audit_upgrade (alterações seladas aprovadas) e audit_seal com
-- search_path = pg_catalog, pg_temp.
-- Corre como superuser só para mudar o session_user (SET SESSION AUTHORIZATION = "ligado como"; o session_user
-- é o que _chain_insert grava) e para adulterar a cadeia; cada asserção corre com o papel em causa.
-- Tudo numa transação com ROLLBACK.

BEGIN;

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_state text, p_msg_like text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = p_state AND v_msg LIKE p_msg_like THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado % "%", obtido %: %)', p_label, p_state, p_msg_like, v_state, v_msg;
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

-- Tenants do teste (sem FK: a caixa negra não precisa que existam).
\set t_forged   '00000000-0000-7000-8000-00000000d001'
\set t_app      '00000000-0000-7000-8000-00000000d002'
\set t_system   '00000000-0000-7000-8000-00000000d003'
\set zero_chain '00000000-0000-0000-0000-000000000000'

-- ---------------------------------------------------------------------------
-- 1. Bootstrap: audit_upgrade, sealed_changes e audit_seal (donos, search_path, EXECUTE).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid IN ('audit_admin.audit_upgrade(text,text)'::regprocedure, 'audit_admin.audit_seal()'::regprocedure)
         AND p.prosecdef AND p.proowner = 'postgres'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    2, 'audit_upgrade e audit_seal: DEFINER, dono postgres, search_path = pg_catalog, pg_temp');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a
       WHERE p.oid = 'audit_admin.audit_upgrade(text,text)'::regprocedure AND a.grantee <> p.proowner$q$,
    1, 'audit_upgrade: um só GRANT além do dono (sem PUBLIC)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_migrator', 'ptmarket_app', 'ptmarket_worker',
                                         'ptmarket_price_writer', 'ptmarket_audit_writer']) r
       WHERE has_function_privilege(r, 'audit_admin.audit_upgrade(text,text)', 'EXECUTE')$q$,
    1, 'audit_upgrade: EXECUTE só para o migrator (app/worker/price_writer/writer não)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c
       WHERE c.oid IN ('audit_admin.sealed_changes'::regclass, 'audit_admin.sealed_changes_applied'::regclass)
         AND c.relowner = 'postgres'::regrole
         AND NOT EXISTS (SELECT 1 FROM aclexplode(c.relacl) a WHERE a.grantee <> c.relowner)$q$,
    2, 'sealed_changes e sealed_changes_applied: dono postgres, sem GRANT a ninguém');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes
       WHERE name = '0011_db_user'
         AND sha256 = encode(sha256(convert_to(sql, 'UTF8')), 'hex')
         AND sha256 = 'def87fba170d6261f7f44697b915fc0dabc5bf3337e0578fadaf1e4950629e50'$q$,
    1, '0011_db_user aprovada com o sha256 que a 0011 dispara');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied a JOIN pg_roles r ON r.rolname = a.session_user_name
       WHERE a.name = '0011_db_user' AND NOT r.rolsuper$q$,
    1, '0011_db_user aplicada uma vez, por quem migra (não superuser)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied a
       WHERE a.name = '0011_db_user'
         AND audit._db_user_since_us() <= (extract(epoch FROM a.applied_at) * 1000000)::bigint
         AND audit._db_user_since_us() > (extract(epoch FROM a.applied_at - interval '1 minute') * 1000000)::bigint$q$,
    1, '_db_user_since_us() = instante da aplicação (antes do registo em _applied)');

-- ---------------------------------------------------------------------------
-- 2. Como o migrator: audit_upgrade recusa; não lê nem escreve sealed_changes; selagem e catálogos falsos.
-- ---------------------------------------------------------------------------
SET SESSION AUTHORIZATION ptmarket_migrator;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_roles WHERE rolname = session_user AND rolname = 'ptmarket_migrator' AND NOT rolsuper$q$,
    1, 'sessão = ptmarket_migrator (não superuser)');

-- Ataque (achado ALTO): catálogos falsos em pg_temp. Sem pg_temp no search_path, o PostgreSQL pesquisa-o
-- primeiro para relações; a selagem leria um pg_proc vazio e deixava passar a DEFINER plantada.
-- Tem de ser a 1.ª chamada à selagem nesta sessão (o plpgsql guarda os planos da 1.ª chamada; o atacante usa
-- uma sessão nova). Provado contra a audit_seal antiga: este bloco falha com ela.
SAVEPOINT fake_catalogs;
CREATE FUNCTION audit.zz_evil_definer() RETURNS int LANGUAGE sql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp AS 'SELECT 1';
CREATE TEMP TABLE pg_proc AS SELECT * FROM pg_catalog.pg_proc WHERE false;
CREATE TEMP TABLE pg_class AS SELECT * FROM pg_catalog.pg_class WHERE false;
CREATE TEMP TABLE pg_roles AS SELECT * FROM pg_catalog.pg_roles WHERE false;
CREATE TEMP TABLE pg_depend AS SELECT * FROM pg_catalog.pg_depend WHERE false;
SELECT set_config('search_path', 'pg_catalog', true);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc$q$, 0,
    'com search_path = pg_catalog (sem pg_temp) o pg_proc falso ganha (o ataque é real)');
SELECT pg_catalog.set_config('search_path', '"$user", public', true);
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_seal()$q$, 'P0001', '%fora da allowlist%audit.zz_evil_definer()%',
    'audit_seal ignora pg_proc/pg_class/pg_roles/pg_depend falsos e recusa a DEFINER plantada');
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_upgrade('0011_db_user'::text, repeat('0', 64)::text)$q$,
    'P0001', '%difere do aprovado%', 'audit_upgrade com catálogos falsos: continua a ler os verdadeiros');
ROLLBACK TO SAVEPOINT fake_catalogs;
SELECT audit_admin.audit_seal();
SELECT pg_temp.expect_value($q$SELECT 1$q$, 1, 'audit_seal() passa depois da 0011');

SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit_admin.sealed_changes$q$, '42501', '%',
    'migrator não lê sealed_changes');
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit_admin.sealed_changes_applied$q$, '42501', '%',
    'migrator não lê sealed_changes_applied');
SELECT pg_temp.expect_error(
    $q$INSERT INTO audit_admin.sealed_changes VALUES ('x', 'SELECT 1', 'x')$q$, '42501', '%',
    'migrator não escreve sealed_changes');
SELECT pg_temp.expect_error(
    $q$UPDATE audit_admin.sealed_changes SET sql = 'SELECT 1'$q$, '42501', '%',
    'migrator não altera sealed_changes');
SELECT pg_temp.expect_error(
    $q$DELETE FROM audit_admin.sealed_changes_applied$q$, '42501', '%',
    'migrator não apaga sealed_changes_applied (não reaplica)');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit_admin.audit_upgrade(p_name text, p_sha256 text) RETURNS void
       LANGUAGE sql AS ''$q$, '42501', '%', 'migrator não substitui audit_upgrade');

SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_upgrade('nao_existe'::text, repeat('0', 64)::text)$q$,
    'P0001', '%não aprovada%', 'audit_upgrade: nome desconhecido → erro');
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_upgrade('0011_db_user'::text, repeat('0', 64)::text)$q$,
    'P0001', '%difere do aprovado%', 'audit_upgrade: sha256 errado → erro');
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_upgrade('0011_db_user'::text,
           'def87fba170d6261f7f44697b915fc0dabc5bf3337e0578fadaf1e4950629e50'::text)$q$,
    'P0001', '%já foi aplicada%', 'audit_upgrade: segunda aplicação → erro');
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_upgrade(NULL::text, NULL::text)$q$,
    'P0001', '%obrigatórios%', 'audit_upgrade: argumentos NULL → erro');

SET ROLE ptmarket_app;
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_upgrade('0011_db_user'::text, repeat('0', 64)::text)$q$, '42501', '%',
    'ptmarket_app não executa audit_upgrade');
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_upgrade('0011_db_user'::text, repeat('0', 64)::text)$q$, '42501', '%',
    'ptmarket_worker não executa audit_upgrade');
RESET ROLE;


RESET SESSION AUTHORIZATION;

-- DEFINER com search_path = pg_catalog (sem pg_temp) → recusada pela selagem.
SAVEPOINT no_pg_temp;
ALTER FUNCTION audit.audit_chains() SET search_path = pg_catalog;
SET SESSION AUTHORIZATION ptmarket_migrator;
SELECT pg_temp.expect_error(
    $q$SELECT audit_admin.audit_seal()$q$, 'P0001', '%sem search_path fixo a terminar em pg_temp%audit_chains()%',
    'audit_seal recusa DEFINER com search_path = pg_catalog (sem pg_temp)');
RESET SESSION AUTHORIZATION;
ROLLBACK TO SAVEPOINT no_pg_temp;

-- ---------------------------------------------------------------------------
-- 3. Forja: ligado como migrator + SET ROLE ptmarket_app + ator merchant → db_user = migrator, assinalado.
-- ---------------------------------------------------------------------------
SET SESSION AUTHORIZATION ptmarket_migrator;
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', :'t_forged', false);
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-00000000d0a1';
SELECT audit.audit_append('stores.update'::text, 'store'::text, 's1'::text, 'success'::text, NULL::text,
                          NULL::jsonb, NULL::uuid);
RESET ROLE;
-- system como worker, mas ligado como migrator → assinalado.
SET ROLE ptmarket_worker;
SELECT set_config('app.current_tenant_id', :'t_system', false);
SET app.actor_type = 'system';
RESET app.actor_id;
SELECT audit.audit_append('jobs.run'::text, 'job'::text, 'j1'::text, 'success'::text, NULL::text,
                          NULL::jsonb, NULL::uuid);
RESET ROLE;
-- 'db' pelo caminho próprio (audit_append_db): actor_label = db_user = migrator → coerente.
SELECT audit.audit_append_db('manual.fix'::text, 'store'::text, 's9'::text, NULL::jsonb,
                             :'t_system'::uuid, NULL::uuid);
RESET SESSION AUTHORIZATION;

-- Ligado como ptmarket_app (merchant e system) e como ptmarket_worker (system) → coerentes.
SET SESSION AUTHORIZATION ptmarket_app;
SELECT set_config('app.current_tenant_id', :'t_app', false);
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-00000000d0a2';
SELECT audit.audit_append('stores.update'::text, 'store'::text, 's2'::text, 'success'::text, NULL::text,
                          NULL::jsonb, NULL::uuid);
SET app.actor_type = 'system';
RESET app.actor_id;
SELECT audit.audit_append('jobs.run'::text, 'job'::text, 'j2'::text, 'success'::text, NULL::text,
                          NULL::jsonb, NULL::uuid);
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION ptmarket_worker;
SELECT set_config('app.current_tenant_id', :'t_system', false);
SELECT audit.audit_append('jobs.run'::text, 'job'::text, 'j3'::text, 'success'::text, NULL::text,
                          NULL::jsonb, NULL::uuid);
RESET SESSION AUTHORIZATION;
RESET app.current_tenant_id;
RESET app.actor_type;

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE chain_key = %L
              AND actor_type = 'merchant' AND db_user = 'ptmarket_migrator'$q$, :'t_forged'),
    1, 'migrator + SET ROLE ptmarket_app: o evento grava db_user = ptmarket_migrator');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE chain_key = %L AND db_user = 'ptmarket_app'$q$, :'t_app'),
    2, 'ligado como ptmarket_app: db_user = ptmarket_app (2/2)');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE chain_key = %L
              AND ((actor_type = 'system' AND db_user IN ('ptmarket_migrator', 'ptmarket_worker'))
                OR (actor_type = 'db' AND db_user = 'ptmarket_migrator' AND actor_label = 'ptmarket_migrator'))$q$,
           :'t_system'),
    3, 'system (migrator e worker) e db (migrator): db_user = session_user');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_actors(%L::uuid, 'standard'::text,
              now() - interval '1 day', now() + interval '1 day')
              WHERE problem = 'actor_db_user_mismatch' AND db_user = 'ptmarket_migrator'
                AND actor_type = 'merchant'$q$, :'t_forged'),
    1, 'audit_verify_actors assinala o merchant gravado pelo migrator (actor_db_user_mismatch)');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_actors(%L::uuid, 'standard'::text,
              now() - interval '1 day', now() + interval '1 day')$q$, :'t_forged'),
    1, 'só uma linha para o tenant forjado');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_actors(%L::uuid, 'standard'::text,
              now() - interval '1 day', now() + interval '1 day')$q$, :'t_app'),
    0, 'ligado como ptmarket_app: nada assinalado');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_actors(%L::uuid, 'standard'::text,
              now() - interval '1 day', now() + interval '1 day')
              WHERE problem = 'actor_db_user_mismatch' AND actor_type = 'system'
                AND db_user = 'ptmarket_migrator'$q$, :'t_system'),
    1, 'system gravado pelo migrator assinalado; o do worker e o db do migrator não');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_actors(%L::uuid, 'standard'::text,
              now() - interval '1 day', now() + interval '1 day')$q$, :'t_system'),
    1, 'tenant system: uma só linha');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM audit.audit_verify_actors(NULL::uuid, 'standard'::text, now(), now() + interval '1 day')$q$,
    '22023', '%', 'audit_verify_actors: parâmetros obrigatórios');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM audit.audit_verify_actors(uuidv7(), 'x'::text, now(), now() + interval '1 day')$q$,
    '22023', '%', 'audit_verify_actors: classe inválida');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. audit_append recusa app.actor_type = 'db' (e fora da lista) com PTA01; nada gravado.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_writer;
SELECT set_config('ptm.n_before', (SELECT count(*) FROM audit.audit_events)::text, false);
RESET ROLE;
SET SESSION AUTHORIZATION ptmarket_app;
SELECT set_config('app.current_tenant_id', :'t_app', false);
SET app.actor_type = 'db';
SET app.actor_label = 'ptmarket_app';
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update'::text, 'store'::text, 's3'::text, 'success'::text, NULL::text,
                                 NULL::jsonb, NULL::uuid)$q$,
    'PTA01', '%', 'audit_append com app.actor_type = db → PTA01');
SET app.actor_type = 'xpto';
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update'::text, 'store'::text, 's3'::text, 'success'::text, NULL::text,
                                 NULL::jsonb, NULL::uuid)$q$,
    'PTA01', '%', 'audit_append com app.actor_type fora da lista → PTA01');
SET app.actor_type = 'merchant_com_mais_de_16_caracteres';
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('stores.update'::text, 'store'::text, 's3'::text, 'success'::text, NULL::text,
                                 NULL::jsonb, NULL::uuid)$q$,
    'PTA01', '%', 'audit_append com app.actor_type longo → PTA01 (não 22001)');
RESET SESSION AUTHORIZATION;
RESET app.current_tenant_id;
RESET app.actor_type;
RESET app.actor_label;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) - current_setting('ptm.n_before')::bigint FROM audit.audit_events$q$,
    0, 'nada gravado pelas tentativas recusadas');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 5. db_user no hash: cadeia com eventos antigos (NULL) e novos verifica; mudar o db_user parte-a.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM (
              SELECT count(*) FILTER (WHERE db_user IS NULL) AS old_n,
                     count(*) FILTER (WHERE db_user IS NOT NULL) AS new_n
              FROM audit.audit_events WHERE chain_key = %L AND retention_class = 'standard') x
              WHERE x.old_n > 0 AND x.new_n > 0$q$, :'zero_chain'),
    1, 'cadeia da plataforma tem eventos antigos (db_user NULL, até à 0010) e novos (0011+)');
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain(%L::uuid, 'standard'::text,
              '-infinity'::timestamptz, 'infinity'::timestamptz)$q$, :'zero_chain'),
    0, 'audit_verify_chain: antigos (NULL) e novos na mesma cadeia → 0 quebras');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_actors(%L::uuid, 'standard'::text,
              '-infinity'::timestamptz, 'infinity'::timestamptz) WHERE problem = 'db_user_missing'$q$, :'zero_chain'),
    0, 'eventos antigos (NULL, antes da 0011) não são db_user_missing');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain(%L::uuid, 'standard'::text,
              '-infinity'::timestamptz, 'infinity'::timestamptz)$q$, :'t_forged'),
    0, 'cadeia com evento novo: 0 quebras');
RESET ROLE;

-- Adulteração como superuser (trigger de imutabilidade saltado só neste savepoint; BD descartável).
SAVEPOINT tamper;
SET LOCAL session_replication_role = replica;
-- O forjador "limpa" o rasto: db_user passa a ptmarket_app → o hash parte e o verify deixa de o ver como forja.
UPDATE audit.audit_events SET db_user = 'ptmarket_app'
WHERE chain_key = :'t_forged' AND db_user = 'ptmarket_migrator';
-- Linha antiga (NULL) ganha um db_user → hash parte.
UPDATE audit.audit_events SET db_user = 'ptmarket_migrator'
WHERE (retention_class, created_at, id) = (
    SELECT retention_class, created_at, id FROM audit.audit_events
    WHERE chain_key = :'zero_chain' AND retention_class = 'standard' AND db_user IS NULL
    ORDER BY chain_seq LIMIT 1);
-- Linha nova perde o db_user → hash parte e db_user_missing.
UPDATE audit.audit_events SET db_user = NULL
WHERE chain_key = :'t_app' AND actor_type = 'merchant';
-- 'db' com actor_label trocado → db_label_mismatch.
UPDATE audit.audit_events SET actor_label = 'forjado'
WHERE chain_key = :'t_system' AND actor_type = 'db';
RESET session_replication_role;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain(%L::uuid, 'standard'::text,
              '-infinity'::timestamptz, 'infinity'::timestamptz) WHERE problem = 'hash'$q$, :'t_forged'),
    1, 'db_user mudado numa linha nova → audit_verify_chain: hash');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain(%L::uuid, 'standard'::text,
              '-infinity'::timestamptz, 'infinity'::timestamptz) WHERE problem = 'hash'$q$, :'zero_chain'),
    1, 'db_user acrescentado a uma linha antiga → audit_verify_chain: hash');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain(%L::uuid, 'standard'::text,
              '-infinity'::timestamptz, 'infinity'::timestamptz) WHERE problem = 'hash'$q$, :'t_app'),
    1, 'db_user apagado numa linha nova → audit_verify_chain: hash');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_actors(%L::uuid, 'standard'::text,
              '-infinity'::timestamptz, 'infinity'::timestamptz) WHERE problem = 'db_user_missing'$q$, :'t_app'),
    1, 'db_user NULL depois da 0011 → db_user_missing');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_actors(%L::uuid, 'standard'::text,
              '-infinity'::timestamptz, 'infinity'::timestamptz) WHERE problem = 'db_label_mismatch'$q$, :'t_system'),
    1, 'db com actor_label ≠ db_user → db_label_mismatch');
RESET ROLE;
ROLLBACK TO SAVEPOINT tamper;

-- ---------------------------------------------------------------------------
-- 6. Depois da 0011: donos, privilégios e assinatura dos objetos novos.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (
           SELECT c.relowner AS owner FROM pg_class c WHERE c.relnamespace = 'audit'::regnamespace
           UNION ALL SELECT p.proowner FROM pg_proc p WHERE p.pronamespace = 'audit'::regnamespace
           UNION ALL SELECT t.typowner FROM pg_type t WHERE t.typnamespace = 'audit'::regnamespace) o
       WHERE o.owner IN ('postgres'::regrole, 'ptmarket_migrator'::regrole)$q$,
    0, 'nenhum objeto em audit.* com dono postgres ou ptmarket_migrator');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'audit.audit_verify_actors(uuid,text,timestamptz,timestamptz)'::regprocedure
         AND p.prosecdef AND p.provolatile = 's' AND p.proowner = 'ptmarket_audit_writer'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']
         AND pg_get_function_result(p.oid)
             = 'TABLE(event_id uuid, chain_seq bigint, actor_type text, db_user text, problem text)'$q$,
    1, 'audit_verify_actors: DEFINER STABLE, dono writer, search_path fixo, sem changes no resultado');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'audit._db_user_since_us()'::regprocedure
         AND NOT p.prosecdef AND p.provolatile = 'i' AND p.proowner = 'ptmarket_audit_owner'::regrole$q$,
    1, '_db_user_since_us: INVOKER IMMUTABLE, dono ptmarket_audit_owner');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_migrator', 'ptmarket_app', 'ptmarket_worker',
                                         'ptmarket_price_writer']) r
       WHERE has_function_privilege(r, 'audit.audit_verify_actors(uuid,text,timestamptz,timestamptz)', 'EXECUTE')$q$,
    1, 'audit_verify_actors: EXECUTE só para o worker');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_migrator', 'ptmarket_app', 'ptmarket_worker',
                                         'ptmarket_price_writer']) r
       WHERE has_function_privilege(r, 'audit._db_user_since_us()', 'EXECUTE')$q$,
    0, '_db_user_since_us: sem EXECUTE para migrator/app/worker/price_writer');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_migrator', 'ptmarket_app', 'ptmarket_worker']) r
       WHERE has_column_privilege(r, 'audit.audit_events', 'db_user', 'INSERT')
          OR has_column_privilege(r, 'audit.audit_events', 'db_user', 'UPDATE')
          OR has_column_privilege(r, 'audit.audit_events', 'db_user', 'REFERENCES')$q$,
    0, 'db_user: ninguém (migrator/app/worker) insere nem altera');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_attribute a
       WHERE a.attrelid = 'audit.audit_events'::regclass AND a.attname = 'db_user' AND NOT a.attisdropped
         AND NOT a.atthasdef AND a.atttypid = 'text'::regtype$q$,
    1, 'audit_events.db_user: text, sem DEFAULT');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid IN ('audit._chain_insert(audit.audit_events,boolean,boolean)'::regprocedure, -- 03e: assinatura de 3 argumentos
                       'audit.audit_append(text,text,text,text,text,jsonb,uuid,uuid)'::regprocedure)
         AND p.prosecdef AND p.proowner = 'ptmarket_audit_writer'::regrole
         AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']$q$,
    2, '_chain_insert e audit_append mantêm DEFINER, dono writer e search_path');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer']) r
       WHERE has_function_privilege(r, 'audit.audit_append(text,text,text,text,text,jsonb,uuid,uuid)', 'EXECUTE')$q$,
    3, 'audit_append mantém EXECUTE para app/worker/price_writer');

ROLLBACK;
