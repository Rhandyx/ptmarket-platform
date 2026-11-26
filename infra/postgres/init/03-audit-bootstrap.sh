#!/bin/bash
# Bootstrap da caixa negra (spec 13), como superuser. Idempotente.
# Corre: no 1.º arranque (volume novo, depois de 01-roles.sh e 02-pgaudit.sh) e no migrations/tests/run.sh
#   (postgres descartável: `docker exec -i <c> bash -s < este ficheiro`).
# BDs: template1 (as BDs criadas depois, ex.: sqlx::test, herdam o schema audit e audit_admin) e $POSTGRES_DB
#   (já existe quando o init corre). PTM_BOOTSTRAP_DBS substitui a lista.
#
# Papéis (do cluster, criados só aqui; as migrations seguem sempre pelo ramo "já existe" → sem 23505 em paralelo):
#   ptmarket_audit_owner / _writer / _retention: NOLOGIN, sem SUPERUSER/BYPASSRLS/CREATEROLE. Nenhum papel é
#     membro deles (nem o migrator, nem com ADMIN): quem tiver membership é cortado aqui.
#   ptmarket_app / _worker / _price_writer: com os atributos de 0001/0007 se ainda não existirem (no dev o
#     01-roles.sh já criou app/worker com LOGIN); o migrator recebe SET (sem INHERIT, sem ADMIN).
#   ptmarket_bootstrap (cartão 02/20b): NOLOGIN, sem SUPERUSER/BYPASSRLS/CREATEDB/CREATEROLE/REPLICATION; dono da
#     DEFINER public.identity_create_superadmin (0024). Os seus INSERT passam pela L1 (INVOKER) → precisa de USAGE em
#     audit e de EXECUTE em audit.audit_append_db (allowlist de grants da audit_seal; ator 'db' + session_user).
#     O migrator recebe SET (sem INHERIT, sem ADMIN), para o ALTER FUNCTION … OWNER TO da 0024.
# Schemas (por BD):
#   audit: dono ptmarket_audit_owner. USAGE para app, worker, price_writer e writer. O migrator tem USAGE + CREATE
#     (cria objetos novos nas migrations; CREATE não dá poder sobre objetos selados, que não são dele).
#   audit_admin: dono postgres; audit_seal() SECURITY DEFINER, EXECUTE só para o migrator. A ALLOWLIST das funções
#     SECURITY DEFINER de audit.* vive no corpo da audit_seal(): uma função DEFINER nova só entra se o superuser
#     editar este ficheiro e o voltar a aplicar (duas pessoas; ver infra/README.md).
#   audit_admin.audit_upgrade(nome, sha256): único caminho para alterar objetos selados (ALTER TABLE, CREATE OR
#     REPLACE de funções DEFINER). Só executa SQL APROVADO aqui (audit_admin.sealed_changes, texto dollar-quoted
#     neste ficheiro); a migration dispara-o por nome + sha256 (o sqlx fixa o checksum da migration, o superuser
#     fixa o texto aprovado; os dois têm de bater). Uma vez por BD (sealed_changes_applied).
# Reaplicar num cluster existente (idempotente: papéis IF NOT EXISTS, GRANTs repetíveis, CREATE OR REPLACE):
#   PTM_BOOTSTRAP_DBS='template1 ptmarket' bash 03-audit-bootstrap.sh   (como o utilizador do SO com psql -U postgres)
set -euo pipefail

DBS="${PTM_BOOTSTRAP_DBS:-template1 ${POSTGRES_DB:-ptmarket}}"

psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
DO $$
DECLARE
    r text;
    m record;
BEGIN
    IF to_regrole('ptmarket_migrator') IS NULL THEN
        RAISE EXCEPTION '03-audit-bootstrap: ptmarket_migrator não existe (criar primeiro, ver 01-roles.sh)';
    END IF;

    FOREACH r IN ARRAY ARRAY['ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer'] LOOP
        IF to_regrole(r) IS NULL THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION', r);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r AND (rolsuper OR rolbypassrls)) THEN
            RAISE EXCEPTION '03-audit-bootstrap: % tem SUPERUSER ou BYPASSRLS; recusado', r;
        END IF;
        IF NOT pg_has_role('ptmarket_migrator', r, 'SET') THEN
            EXECUTE format('GRANT %I TO ptmarket_migrator WITH INHERIT FALSE, SET TRUE', r);
        END IF;
    END LOOP;

    -- ptmarket_bootstrap (0024): só com os atributos mínimos; outros atributos = recusa (não os corrige em silêncio).
    IF to_regrole('ptmarket_bootstrap') IS NULL THEN
        CREATE ROLE ptmarket_bootstrap NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ptmarket_bootstrap'
               AND (rolsuper OR rolbypassrls OR rolcanlogin OR rolcreatedb OR rolcreaterole OR rolreplication)) THEN
        RAISE EXCEPTION '03-audit-bootstrap: ptmarket_bootstrap tem LOGIN, SUPERUSER, BYPASSRLS, CREATEDB, CREATEROLE ou REPLICATION; recusado';
    END IF;
    IF NOT pg_has_role('ptmarket_migrator', 'ptmarket_bootstrap', 'SET') THEN
        GRANT ptmarket_bootstrap TO ptmarket_migrator WITH INHERIT FALSE, SET TRUE;
    END IF;

    FOREACH r IN ARRAY ARRAY['ptmarket_audit_owner', 'ptmarket_audit_writer', 'ptmarket_audit_retention'] LOOP
        IF to_regrole(r) IS NULL THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION', r);
        ELSE
            EXECUTE format(
                'ALTER ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD NULL', r);
        END IF;
        -- Ninguém é membro (inclui o ADMIN implícito de um CREATEROLE que o tenha criado).
        FOR m IN
            SELECT pg_get_userbyid(a.member) AS member, pg_get_userbyid(a.grantor) AS grantor
            FROM pg_auth_members a
            WHERE a.roleid = to_regrole(r)
        LOOP
            EXECUTE format('REVOKE %I FROM %I GRANTED BY %I CASCADE', r, m.member, m.grantor);
        END LOOP;
    END LOOP;
END
$$;
SQL

for db in $DBS; do
psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$db" <<'SQL'
SET client_min_messages = warning;
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION ptmarket_audit_owner;
ALTER SCHEMA audit OWNER TO ptmarket_audit_owner;
REVOKE ALL ON SCHEMA audit FROM PUBLIC;
GRANT USAGE ON SCHEMA audit
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer, ptmarket_audit_writer, ptmarket_migrator,
       ptmarket_bootstrap;
GRANT CREATE ON SCHEMA audit TO ptmarket_migrator;
-- ptmarket_bootstrap: EXECUTE em audit_append_db (allowlist de grants da audit_seal). Numa BD já migrada (≥ 0010) é
-- dado já aqui; numa BD nova, cada audit_seal() das migrations volta a concedê-lo. A 0024 recusa correr sem ele.
DO $$
BEGIN
    IF to_regprocedure('audit.audit_append_db(text,text,text,jsonb,uuid,uuid)') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION audit.audit_append_db(text, text, text, jsonb, uuid, uuid) TO ptmarket_bootstrap;
    END IF;
    -- ptmarket_identity (0017, NOLOGIN): USAGE em audit só depois da 0025 (dono da DEFINER que chama
    -- audit.admin_read_events). Numa BD nova é a própria alteração 0025_admin_read_events que o concede.
    IF to_regrole('ptmarket_identity') IS NOT NULL
       AND to_regprocedure('audit.admin_read_events(timestamp with time zone,timestamp with time zone,uuid,uuid,uuid,uuid,text,text,timestamp with time zone,uuid,integer)') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA audit TO ptmarket_identity;
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS audit_admin AUTHORIZATION postgres;
ALTER SCHEMA audit_admin OWNER TO postgres;
REVOKE ALL ON SCHEMA audit_admin FROM PUBLIC;
GRANT USAGE ON SCHEMA audit_admin TO ptmarket_migrator;

-- ---------------------------------------------------------------------------
-- audit_seal(): última instrução de cada migration que cria ou altera objetos em audit. Sem argumentos; só itera
-- os catálogos do schema audit. Idempotente. Ordem: allowlist → donos → privilégios → verificação (RAISE = a
-- migration inteira é desfeita).
--   ALLOWLIST: cada função SECURITY DEFINER de audit.* tem de estar na lista fixa abaixo (assinatura → dono);
--     uma fora da lista = RAISE. Acrescentar = editar este ficheiro e reaplicá-lo como superuser.
--   Sem sobrecargas: um nome de função = uma assinatura (uma sobrecarga plantada podia ganhar a resolução).
--   Donos: relações e tipos → ptmarket_audit_owner; DEFINER → o dono da allowlist; INVOKER → ptmarket_audit_owner.
--   Privilégios: REVOKE ALL a quem migra (e a quem chama, se não for superuser) e a PUBLIC em tudo em audit.*
--     (ficam só os GRANTs explícitos das migrations a papéis NOLOGIN).
--   ALLOWLIST DE GRANTS: lista fixa (assinatura, papel) que a selagem volta a conceder e aceita na verificação;
--     qualquer outro privilégio de quem migra em audit.* = RAISE. Hoje: EXECUTE do migrator em
--     audit.audit_append_db (as suas mutações ficam como 'db' com o session_user; app/worker/price_writer sem
--     EXECUTE) e em audit.audit_row_trigger (só para CREATE TRIGGER em tabelas novas; não se chama diretamente); EXECUTE de
--     ptmarket_bootstrap (NOLOGIN) em audit.audit_append_db (L1 dos INSERT da DEFINER da 0024, ator 'db' +
--     session_user); EXECUTE de ptmarket_identity (NOLOGIN) em audit.admin_read_events (0025: só a DEFINER
--     public.identity_admin_read_events, que verifica super_admin + TOTP + sessão com 2FA, chama a timeline).
--     O migrator mantém USAGE + CREATE no schema: pode criar
--     objetos novos, mas depois da selagem não são dele e não lhes mexe.
--   search_path = pg_catalog, pg_temp e catálogos qualificados: com o pg_temp fora da lista, o PostgreSQL
--     pesquisa-o PRIMEIRO para relações e tipos, e quem migra (CREATE TEMP TABLE pg_proc/pg_class/...) faria a
--     selagem ler catálogos falsos. O mesmo vale para todas as DEFINER de audit.*: a verificação exige que o
--     search_path fixo termine em pg_temp.
--   Verifica: donos certos; DEFINER com search_path fixo a terminar em pg_temp; quem chama sem privilégios em
--     audit.*; nenhum papel com LOGIN (não superuser) é membro de owner/writer/retention; nenhum objeto de
--     audit.* (colunas, defaults, constraints, triggers, políticas, índices, regras, funções) depende de um
--     objeto cujo dono tenha LOGIN.
--     (Corpos plpgsql não registam dependências: isso prova-se em migrations/tests/audit_seal.sql.)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_admin.audit_seal()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_ns      oid := to_regnamespace('audit');
    v_owner   oid := to_regrole('ptmarket_audit_owner');
    v_writer  oid := to_regrole('ptmarket_audit_writer');
    v_ret     oid := to_regrole('ptmarket_audit_retention');
    -- ALLOWLIST das funções SECURITY DEFINER de audit.* (assinatura regprocedure com search_path = pg_catalog).
    -- _chain_insert(…, boolean) só até à 0020_mask_v2 (as migrations 0008–0019 criam-na; a 0020 apaga-a e, a
    -- partir daí, esta BD só aceita a de 3 argumentos: ver o início do corpo).
    v_allow_sig   text[] := ARRAY[
        'audit._chain_insert(audit.audit_events,boolean)',
        'audit.audit_append(text,text,text,text,text,jsonb,uuid,uuid)',
        'audit.audit_ensure_partitions(integer)',
        'audit.audit_append_event(jsonb)',
        'audit.audit_verify_chain(uuid,text,timestamp with time zone,timestamp with time zone)',
        'audit.audit_day_root(date)',
        'audit.audit_chains()',
        'audit.audit_default_partition_rows()',
        'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)',
        'audit.audit_verify_actors(uuid,text,timestamp with time zone,timestamp with time zone)',
        'audit.audit_guc_defaults()',
        'audit._chain_insert(audit.audit_events,boolean,boolean)',
        'audit.admin_read_events(timestamp with time zone,timestamp with time zone,uuid,uuid,uuid,uuid,text,text,timestamp with time zone,uuid,integer)'
    ];
    v_allow_owner text[] := ARRAY[
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_owner',  -- cria partições: tem de ser dono das tabelas
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_writer',
        'ptmarket_audit_writer'   -- 0025: timeline do Super-Admin (só lê audit.*)
    ];
    -- ALLOWLIST DE GRANTS: EXECUTE (assinatura regprocedure, papel) mantido pela selagem.
    v_grant_sig   text[] := ARRAY[
        'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)',
        'audit.audit_row_trigger()',
        'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)',  -- 0024: L1 dos INSERT da DEFINER de bootstrap
        -- 0025: só a DEFINER public.identity_admin_read_events (dono ptmarket_identity, NOLOGIN) chama a timeline.
        'audit.admin_read_events(timestamp with time zone,timestamp with time zone,uuid,uuid,uuid,uuid,text,text,timestamp with time zone,uuid,integer)'
    ];
    v_grant_role  text[] := ARRAY[
        'ptmarket_migrator',
        'ptmarket_migrator',
        'ptmarket_bootstrap',
        'ptmarket_identity'
    ];
    v_callers oid[];
    v_c       oid;
    v_target  oid;
    v_bad     text;
    r         record;
BEGIN
    IF v_ns IS NULL OR v_owner IS NULL OR v_writer IS NULL OR v_ret IS NULL
       OR to_regrole('ptmarket_migrator') IS NULL THEN
        RAISE EXCEPTION 'audit_seal: bootstrap em falta (schema audit ou papéis de auditoria)';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ptmarket:audit_seal', 0));

    -- Depois da 0020_mask_v2 nesta BD, a _chain_insert de 2 argumentos deixa de estar na allowlist (sem sobrecargas
    -- nem regresso ao caminho tolerante por pg_trigger_depth()). A posição mantém-se (v_allow_owner).
    IF EXISTS (SELECT 1 FROM audit_admin.sealed_changes_applied a WHERE a.name = '0020_mask_v2') THEN
        v_allow_sig[array_position(v_allow_sig, 'audit._chain_insert(audit.audit_events,boolean)')] :=
            '(retirada pela 0020_mask_v2)';
    END IF;

    SELECT array_agg(oid) INTO v_callers
    FROM pg_catalog.pg_roles
    WHERE (rolname = 'ptmarket_migrator' OR rolname = session_user) AND NOT rolsuper;

    -- 0. Allowlist e sobrecargas (antes de mudar donos).
    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO v_bad
    FROM pg_catalog.pg_proc p
    WHERE p.pronamespace = v_ns AND p.prosecdef AND NOT (p.oid::regprocedure::text = ANY (v_allow_sig));
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: função SECURITY DEFINER fora da allowlist do bootstrap: %', v_bad;
    END IF;
    SELECT string_agg(DISTINCT p.proname, ', ') INTO v_bad
    FROM pg_catalog.pg_proc p
    WHERE p.pronamespace = v_ns
      AND (SELECT count(*) FROM pg_catalog.pg_proc q WHERE q.pronamespace = v_ns AND q.proname = p.proname) > 1;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: sobrecargas em audit (um nome = uma assinatura): %', v_bad;
    END IF;

    -- 1. Donos: relações (as partições e os índices não herdam o ALTER do pai; sequências de identidade
    --    e de serial seguem a tabela).
    FOR r IN
        SELECT c.oid, c.relkind
        FROM pg_catalog.pg_class c
        WHERE c.relnamespace = v_ns
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          AND c.relowner <> v_owner
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                          WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid
                            AND d.deptype IN ('a', 'i') AND c.relkind = 'S')
        ORDER BY c.oid
    LOOP
        EXECUTE format('ALTER %s %s OWNER TO ptmarket_audit_owner',
            CASE r.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW'
                           WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END,
            r.oid::regclass);
    END LOOP;

    -- Tipos próprios (enum, domínio, range, multirange, composto avulso); os de linha/array seguem a relação.
    FOR r IN
        SELECT t.oid
        FROM pg_catalog.pg_type t
        LEFT JOIN pg_catalog.pg_class c ON c.oid = t.typrelid
        WHERE t.typnamespace = v_ns
          AND t.typowner <> v_owner
          AND (t.typtype IN ('e', 'd', 'r', 'm') OR (t.typtype = 'c' AND c.relkind = 'c'))
    LOOP
        EXECUTE format('ALTER TYPE %s OWNER TO ptmarket_audit_owner', r.oid::regtype);
    END LOOP;

    FOR r IN
        SELECT p.oid, p.proname, p.prokind, p.prosecdef, p.proowner
        FROM pg_catalog.pg_proc p
        WHERE p.pronamespace = v_ns
    LOOP
        v_target := CASE WHEN r.prosecdef
                         THEN to_regrole(v_allow_owner[array_position(v_allow_sig, r.oid::regprocedure::text)])
                         ELSE v_owner END;
        IF r.proowner <> v_target THEN
            EXECUTE format('ALTER %s %s OWNER TO %I',
                CASE r.prokind WHEN 'p' THEN 'PROCEDURE' WHEN 'a' THEN 'AGGREGATE' ELSE 'FUNCTION' END,
                r.oid::regprocedure, pg_get_userbyid(v_target));
        END IF;
    END LOOP;

    -- 2. Quem migra e PUBLIC perdem tudo em audit.* (o ACL antigo do dono passou para o novo dono no ALTER OWNER).
    FOR r IN SELECT c.oid, c.relkind FROM pg_catalog.pg_class c
             WHERE c.relnamespace = v_ns AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') LOOP
        EXECUTE format('REVOKE ALL ON %s %s FROM PUBLIC',
            CASE WHEN r.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, r.oid::regclass);
        FOREACH v_c IN ARRAY COALESCE(v_callers, '{}') LOOP
            EXECUTE format('REVOKE ALL ON %s %s FROM %I',
                CASE WHEN r.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, r.oid::regclass, pg_get_userbyid(v_c));
        END LOOP;
    END LOOP;
    FOR r IN SELECT p.oid, p.prokind FROM pg_catalog.pg_proc p WHERE p.pronamespace = v_ns LOOP
        EXECUTE format('REVOKE ALL ON %s %s FROM PUBLIC',
            CASE r.prokind WHEN 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END, r.oid::regprocedure);
        FOREACH v_c IN ARRAY COALESCE(v_callers, '{}') LOOP
            EXECUTE format('REVOKE ALL ON %s %s FROM %I',
                CASE r.prokind WHEN 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
                r.oid::regprocedure, pg_get_userbyid(v_c));
        END LOOP;
    END LOOP;

    -- 2b. Allowlist de grants: volta a conceder só estes pares (se a função existir).
    FOR i IN 1 .. array_length(v_grant_sig, 1) LOOP
        IF to_regprocedure(v_grant_sig[i]) IS NOT NULL THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',
                to_regprocedure(v_grant_sig[i]), v_grant_role[i]);
        END IF;
    END LOOP;

    -- 3. Verificação (qualquer falha desfaz a migration inteira).
    SELECT string_agg(c.oid::regclass::text, ', ') INTO v_bad
    FROM pg_catalog.pg_class c WHERE c.relnamespace = v_ns AND c.relowner <> v_owner;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: relações de audit.* com dono errado: %', v_bad;
    END IF;

    SELECT string_agg(t.oid::regtype::text, ', ') INTO v_bad
    FROM pg_catalog.pg_type t WHERE t.typnamespace = v_ns AND t.typowner <> v_owner;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: tipos de audit.* com dono errado: %', v_bad;
    END IF;

    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO v_bad
    FROM pg_catalog.pg_proc p
    WHERE p.pronamespace = v_ns
      AND p.proowner IS DISTINCT FROM CASE WHEN p.prosecdef
                     THEN to_regrole(v_allow_owner[array_position(v_allow_sig, p.oid::regprocedure::text)])
                     ELSE v_owner END;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: funções de audit.* com dono errado: %', v_bad;
    END IF;

    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO v_bad
    FROM pg_catalog.pg_proc p
    WHERE p.pronamespace = v_ns AND p.prosecdef
      AND NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) s
                      WHERE s ~ '^search_path=(.*,\s*)?"?pg_temp"?$');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: funções SECURITY DEFINER sem search_path fixo a terminar em pg_temp: %', v_bad;
    END IF;

    -- Outros tipos de objeto no schema não são suportados (não há regra de dono para eles).
    SELECT string_agg(x, ', ') INTO v_bad FROM (
        SELECT 'operador ' || oid::regoperator::text AS x FROM pg_catalog.pg_operator WHERE oprnamespace = v_ns
        UNION ALL SELECT 'opclass ' || opcname FROM pg_catalog.pg_opclass WHERE opcnamespace = v_ns
        UNION ALL SELECT 'opfamily ' || opfname FROM pg_catalog.pg_opfamily WHERE opfnamespace = v_ns
        UNION ALL SELECT 'collation ' || collname FROM pg_catalog.pg_collation WHERE collnamespace = v_ns
        UNION ALL SELECT 'conversion ' || conname FROM pg_catalog.pg_conversion WHERE connamespace = v_ns
        UNION ALL SELECT 'statistics ' || stxname FROM pg_catalog.pg_statistic_ext WHERE stxnamespace = v_ns
        UNION ALL SELECT 'ts config ' || cfgname FROM pg_catalog.pg_ts_config WHERE cfgnamespace = v_ns
        UNION ALL SELECT 'ts dict ' || dictname FROM pg_catalog.pg_ts_dict WHERE dictnamespace = v_ns
    ) o;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: objetos não suportados em audit: %', v_bad;
    END IF;

    FOREACH v_c IN ARRAY COALESCE(v_callers, '{}') LOOP
        SELECT string_agg(c.oid::regclass::text, ', ') INTO v_bad
        FROM pg_catalog.pg_class c
        WHERE c.relnamespace = v_ns
          AND CASE WHEN c.relkind IN ('r', 'p', 'v', 'm', 'f')  -- CASE: a função só vê relações deste tipo
                   THEN has_table_privilege(v_c, c.oid,
                            'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
                        OR has_any_column_privilege(v_c, c.oid, 'SELECT, INSERT, UPDATE, REFERENCES')
                   ELSE false END;
        IF v_bad IS NOT NULL THEN
            RAISE EXCEPTION 'audit_seal: % mantém privilégios em: %', pg_get_userbyid(v_c), v_bad;
        END IF;
        SELECT string_agg(c.oid::regclass::text, ', ') INTO v_bad
        FROM pg_catalog.pg_class c
        WHERE c.relnamespace = v_ns
          AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(v_c, c.oid, 'USAGE, SELECT, UPDATE')
                   ELSE false END;
        IF v_bad IS NOT NULL THEN
            RAISE EXCEPTION 'audit_seal: % mantém privilégios nas sequências: %', pg_get_userbyid(v_c), v_bad;
        END IF;
        SELECT string_agg(p.oid::regprocedure::text, ', ') INTO v_bad
        FROM pg_catalog.pg_proc p
        WHERE p.pronamespace = v_ns AND has_function_privilege(v_c, p.oid, 'EXECUTE')
          AND NOT EXISTS (SELECT 1 FROM generate_subscripts(v_grant_sig, 1) g(i)
                          WHERE v_grant_sig[g.i] = p.oid::regprocedure::text
                            AND v_grant_role[g.i] = pg_get_userbyid(v_c));
        IF v_bad IS NOT NULL THEN
            RAISE EXCEPTION 'audit_seal: % mantém EXECUTE (direto ou via PUBLIC) em: %', pg_get_userbyid(v_c), v_bad;
        END IF;
    END LOOP;

    SELECT string_agg(rl.rolname || ' ∈ ' || pg_get_userbyid(a.oid), ', ') INTO v_bad
    FROM pg_catalog.pg_roles rl
    CROSS JOIN unnest(ARRAY[v_owner, v_writer, v_ret]) AS a(oid)
    WHERE rl.oid <> a.oid AND NOT rl.rolsuper AND pg_has_role(rl.oid, a.oid, 'MEMBER');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: membership proibida em papéis de auditoria: %', v_bad;
    END IF;

    SELECT string_agg(rolname, ', ') INTO v_bad
    FROM pg_catalog.pg_roles
    WHERE oid IN (v_owner, v_writer, v_ret)
      AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication);
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: papéis de auditoria com atributos proibidos: %', v_bad;
    END IF;

    WITH objs AS (
        SELECT 'pg_catalog.pg_class'::regclass AS classid, c.oid AS objid FROM pg_catalog.pg_class c WHERE c.relnamespace = v_ns
        UNION ALL SELECT 'pg_catalog.pg_proc'::regclass, p.oid FROM pg_catalog.pg_proc p WHERE p.pronamespace = v_ns
        UNION ALL SELECT 'pg_catalog.pg_type'::regclass, t.oid FROM pg_catalog.pg_type t WHERE t.typnamespace = v_ns
        UNION ALL SELECT 'pg_catalog.pg_constraint'::regclass, k.oid FROM pg_catalog.pg_constraint k WHERE k.connamespace = v_ns
        UNION ALL SELECT 'pg_catalog.pg_trigger'::regclass, g.oid FROM pg_catalog.pg_trigger g
                  JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid WHERE c.relnamespace = v_ns
        UNION ALL SELECT 'pg_catalog.pg_policy'::regclass, p.oid FROM pg_catalog.pg_policy p
                  JOIN pg_catalog.pg_class c ON c.oid = p.polrelid WHERE c.relnamespace = v_ns
        UNION ALL SELECT 'pg_catalog.pg_attrdef'::regclass, a.oid FROM pg_catalog.pg_attrdef a
                  JOIN pg_catalog.pg_class c ON c.oid = a.adrelid WHERE c.relnamespace = v_ns
        UNION ALL SELECT 'pg_catalog.pg_rewrite'::regclass, w.oid FROM pg_catalog.pg_rewrite w
                  JOIN pg_catalog.pg_class c ON c.oid = w.ev_class WHERE c.relnamespace = v_ns
    ), refs AS (
        SELECT DISTINCT d.refclassid, d.refobjid
        FROM pg_catalog.pg_depend d JOIN objs o ON o.classid = d.classid AND o.objid = d.objid
        WHERE d.deptype IN ('n', 'a')
    ), owners AS (
        SELECT f.refclassid, f.refobjid,
               CASE f.refclassid
                   WHEN 'pg_catalog.pg_proc'::regclass      THEN (SELECT proowner FROM pg_catalog.pg_proc WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_class'::regclass     THEN (SELECT relowner FROM pg_catalog.pg_class WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_type'::regclass      THEN (SELECT typowner FROM pg_catalog.pg_type WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_operator'::regclass  THEN (SELECT oprowner FROM pg_catalog.pg_operator WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_opclass'::regclass   THEN (SELECT opcowner FROM pg_catalog.pg_opclass WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_opfamily'::regclass  THEN (SELECT opfowner FROM pg_catalog.pg_opfamily WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_collation'::regclass THEN (SELECT collowner FROM pg_catalog.pg_collation WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_namespace'::regclass THEN (SELECT nspowner FROM pg_catalog.pg_namespace WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_ts_config'::regclass THEN (SELECT cfgowner FROM pg_catalog.pg_ts_config WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_ts_dict'::regclass   THEN (SELECT dictowner FROM pg_catalog.pg_ts_dict WHERE oid = f.refobjid)
                   WHEN 'pg_catalog.pg_language'::regclass  THEN (SELECT lanowner FROM pg_catalog.pg_language WHERE oid = f.refobjid)
               END AS owner,
               f.refclassid IN ('pg_catalog.pg_proc'::regclass, 'pg_catalog.pg_class'::regclass, 'pg_catalog.pg_type'::regclass,
                                'pg_catalog.pg_operator'::regclass, 'pg_catalog.pg_opclass'::regclass, 'pg_catalog.pg_opfamily'::regclass,
                                'pg_catalog.pg_collation'::regclass, 'pg_catalog.pg_namespace'::regclass, 'pg_catalog.pg_ts_config'::regclass,
                                'pg_catalog.pg_ts_dict'::regclass, 'pg_catalog.pg_language'::regclass) AS known
        FROM refs f
    )
    SELECT string_agg(pg_describe_object(o.refclassid, o.refobjid, 0), ', ') INTO v_bad
    FROM owners o
    LEFT JOIN pg_catalog.pg_roles rl ON rl.oid = o.owner
    WHERE (o.known AND rl.rolcanlogin AND NOT rl.rolsuper)
       OR (NOT o.known AND NOT EXISTS (
               SELECT 1 FROM pg_catalog.pg_depend d2
               WHERE d2.classid = o.refclassid AND d2.objid = o.refobjid
                 AND d2.refclassid = 'pg_catalog.pg_class'::regclass
                 AND d2.refobjid IN (SELECT c.oid FROM pg_catalog.pg_class c WHERE c.relnamespace = v_ns)));
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: audit.* depende de objetos de papéis com LOGIN (ou não verificáveis): %', v_bad;
    END IF;
END
$fn$;

REVOKE ALL ON FUNCTION audit_admin.audit_seal() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_admin.audit_seal() TO ptmarket_migrator;

-- ---------------------------------------------------------------------------
-- Alterações seladas aprovadas (duas pessoas: o autor da migration pede, quem revê cola aqui o SQL exato e
-- reaplica este ficheiro como superuser ANTES da migration; ver infra/README.md).
--   sealed_changes(name, sql, sha256): dono postgres, sem GRANT a ninguém. sha256 calculado na BD
--     (encode(sha256(convert_to(sql, 'UTF8')), 'hex')); é o valor que a migration passa a audit_upgrade.
--   requires: nome da alteração anterior (NULL só na primeira). A cadeia é linear: audit_upgrade recusa se a
--     anterior não estiver aplicada nesta BD; o bootstrap recusa requires que não seja uma alteração aprovada.
--   sealed_changes_applied(name, applied_at, session_user_name): uma linha por alteração aplicada nesta BD.
--   Mudar o texto de uma alteração já aplicada nesta BD = RAISE (a migration é imutável; corrigir = nova).
--   O SQL aprovado usa sempre nomes qualificados e tipos exatos; corre como postgres com
--   search_path = pg_catalog, pg_temp (nada do que quem migra cria em audit, public ou pg_temp ganha a resolução).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_admin.sealed_changes (
    name   text PRIMARY KEY,
    sql    text NOT NULL,
    sha256 text NOT NULL
);
ALTER TABLE audit_admin.sealed_changes ADD COLUMN IF NOT EXISTS requires text;
ALTER TABLE audit_admin.sealed_changes OWNER TO postgres;
REVOKE ALL ON audit_admin.sealed_changes FROM PUBLIC;

CREATE TABLE IF NOT EXISTS audit_admin.sealed_changes_applied (
    name              text        PRIMARY KEY,
    applied_at        timestamptz NOT NULL,
    session_user_name text        NOT NULL
);
ALTER TABLE audit_admin.sealed_changes_applied OWNER TO postgres;
REVOKE ALL ON audit_admin.sealed_changes_applied FROM PUBLIC;

DROP TABLE IF EXISTS pg_temp.ptm_sealed_changes_new;
CREATE TEMP TABLE ptm_sealed_changes_new (name text PRIMARY KEY, requires text, sql text NOT NULL);

-- ---------------------------------------------------------------------------
-- APROVADA: 0011_db_user (cartão 02/03b). Disparada por migrations/0011_audit_db_user.sql.
--   audit_events.db_user = session_user (gravado por _chain_insert, dentro do hash): o session_user não muda com
--   SET ROLE nem dentro de DEFINER; só o superuser o muda. Linhas antigas (NULL) mantêm a fórmula do hash.
--   audit_append recusa app.actor_type fora da lista fechada, incluindo 'db' (só nasce em audit_append_db).
--   audit._db_user_since_us(): instante (µs desde a época, UTC) a partir do qual db_user NULL é anomalia.
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0011_db_user', NULL, $chg_0011$
ALTER TABLE audit.audit_events ADD COLUMN db_user text;

CREATE OR REPLACE FUNCTION audit._event_hash(e audit.audit_events)
RETURNS bytea
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $body$
    SELECT sha256(e.prev_hash || convert_to((jsonb_build_array(
        e.id, e.tenant_id, e.store_id, e.actor_type, e.actor_id, e.actor_label, e.impersonator_id,
        e.action, e.target_type, e.target_id, e.outcome, e.reason, e.changes, e.request_id,
        e.ip::text, encode(e.user_agent_hash, 'hex'), e.retention_class,
        (extract(epoch FROM e.occurred_at) * 1000000)::bigint,
        (extract(epoch FROM e.created_at) * 1000000)::bigint,
        e.chain_seq
    ) || CASE WHEN e.db_user IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(e.db_user) END)::text, 'UTF8'))
$body$;

CREATE OR REPLACE FUNCTION audit._chain_insert(p_row audit.audit_events, p_dedupe boolean)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_row audit.audit_events := p_row;
BEGIN
    -- Quem está ligado (LOGIN), não o papel assumido: ignora o que vier em p_row.
    v_row.db_user         := session_user;
    v_row.chain_key       := COALESCE(v_row.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid);
    v_row.retention_class := audit.audit_retention_class(v_row.action::text, v_row.outcome::text);

    INSERT INTO audit.audit_chain_heads (chain_key, retention_class, last_seq, last_hash)
    VALUES (v_row.chain_key, v_row.retention_class, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT DO NOTHING;

    SELECT h.last_seq + 1, h.last_hash INTO STRICT v_row.chain_seq, v_row.prev_hash
    FROM audit.audit_chain_heads h
    WHERE h.chain_key = v_row.chain_key
      AND h.retention_class = v_row.retention_class
    FOR UPDATE;

    IF p_dedupe AND EXISTS (
        SELECT 1 FROM audit.audit_events e
        WHERE e.id = v_row.id
          AND e.created_at >= v_row.occurred_at - interval '1 day'
    ) THEN
        RETURN NULL;
    END IF;

    v_row.created_at  := clock_timestamp();
    v_row.occurred_at := COALESCE(v_row.occurred_at, v_row.created_at);
    v_row.id          := COALESCE(v_row.id, uuidv7());
    v_row.hash        := audit._event_hash(v_row);

    INSERT INTO audit.audit_events (
        id, tenant_id, chain_key, store_id, actor_type, actor_id, actor_label, impersonator_id,
        action, target_type, target_id, outcome, reason, changes, request_id, ip, user_agent_hash,
        retention_class, occurred_at, created_at, chain_seq, prev_hash, hash, db_user
    ) VALUES (
        v_row.id, v_row.tenant_id, v_row.chain_key, v_row.store_id, v_row.actor_type, v_row.actor_id,
        v_row.actor_label, v_row.impersonator_id, v_row.action, v_row.target_type, v_row.target_id,
        v_row.outcome, v_row.reason, v_row.changes, v_row.request_id, v_row.ip, v_row.user_agent_hash,
        v_row.retention_class, v_row.occurred_at, v_row.created_at, v_row.chain_seq, v_row.prev_hash,
        v_row.hash, v_row.db_user
    );

    UPDATE audit.audit_chain_heads
       SET last_seq = v_row.chain_seq, last_hash = v_row.hash
     WHERE chain_key = v_row.chain_key
       AND retention_class = v_row.retention_class;

    IF v_row.actor_type = 'admin' OR v_row.impersonator_id IS NOT NULL THEN
        INSERT INTO audit.audit_alerts (id, created_at, event_type, payload)
        VALUES (
            v_row.id, v_row.created_at, 'audit.superadmin_action',
            to_jsonb(v_row) || jsonb_build_object(
                'prev_hash', encode(v_row.prev_hash, 'hex'),
                'hash', encode(v_row.hash, 'hex'),
                'user_agent_hash', encode(v_row.user_agent_hash, 'hex'))
        );
    END IF;

    RETURN v_row.id;
END
$body$;

CREATE OR REPLACE FUNCTION audit.audit_append(
    p_action      text,
    p_target_type text,
    p_target_id   text,
    p_outcome     text,
    p_reason      text,
    p_changes     jsonb,
    p_store_id    uuid,
    p_tenant_id   uuid DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
AS $body$
DECLARE
    v_row        audit.audit_events;
    v_actor      text;
    v_ctx_tenant uuid;
BEGIN
    v_actor := NULLIF(current_setting('app.actor_type', true), '');
    IF v_actor IS NULL THEN
        RAISE EXCEPTION 'audit_append: app.actor_type em falta (ator obrigatório)'
            USING ERRCODE = 'PTA01';
    END IF;
    -- 'db' só nasce em audit_append_db (trigger L1); a app nunca o escolhe. Lista fechada (CHECK sem 'db').
    IF v_actor NOT IN ('customer', 'merchant', 'municipal', 'admin', 'system', 'api_key', 'anonymous') THEN
        RAISE EXCEPTION 'audit_append: app.actor_type inválido'
            USING ERRCODE = 'PTA01';
    END IF;
    v_row.actor_type      := v_actor;
    v_row.actor_id        := NULLIF(current_setting('app.actor_id', true), '')::uuid;
    v_row.actor_label     := NULLIF(current_setting('app.actor_label', true), '');
    v_row.impersonator_id := NULLIF(current_setting('app.impersonator_id', true), '')::uuid;
    v_row.request_id      := NULLIF(current_setting('app.request_id', true), '')::uuid;
    v_row.ip              := NULLIF(current_setting('app.ip', true), '')::inet;
    v_row.user_agent_hash := decode(NULLIF(current_setting('app.user_agent_hash', true), ''), 'hex');

    v_ctx_tenant := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
    IF p_tenant_id IS NOT NULL THEN
        IF v_row.actor_type <> 'system' THEN
            RAISE EXCEPTION 'audit_append: p_tenant_id só é aceite com app.actor_type = system';
        END IF;
        IF v_ctx_tenant IS NOT NULL AND v_ctx_tenant <> p_tenant_id THEN
            RAISE EXCEPTION 'audit_append: p_tenant_id difere de app.current_tenant_id';
        END IF;
    END IF;
    v_row.tenant_id := COALESCE(v_ctx_tenant, p_tenant_id);

    v_row.store_id    := p_store_id;
    v_row.action      := p_action;
    v_row.target_type := p_target_type;
    v_row.target_id   := p_target_id;
    v_row.outcome     := p_outcome;
    v_row.reason      := p_reason;
    v_row.changes     := p_changes;

    RETURN audit._chain_insert(v_row, false);
END
$body$;

-- Instante da aplicação, fixo no corpo (µs desde a época; sem texto de data: imune a DateStyle/TimeZone).
-- INVOKER, dono ptmarket_audit_owner pela selagem; EXECUTE só para o escritor (audit_verify_actors).
DO $do$
BEGIN
    EXECUTE format(
        'CREATE FUNCTION audit._db_user_since_us() RETURNS bigint LANGUAGE sql IMMUTABLE PARALLEL SAFE '
        'SET search_path = pg_catalog, pg_temp AS %L',
        format('SELECT %s::bigint', (extract(epoch FROM clock_timestamp()) * 1000000)::bigint));
END
$do$;
REVOKE ALL ON FUNCTION audit._db_user_since_us() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._db_user_since_us() TO ptmarket_audit_writer;
$chg_0011$);

-- ---------------------------------------------------------------------------
-- APROVADA: 0012_hardening (cartão 02/03c). Disparada por migrations/0012_audit_hardening.sql.
--   Máscara (audit_redact → audit._redact_walk, recursiva): segredos → "[redacted]", PII → "[pii]" em qualquer
--     tabela, IBAN → 4 últimos; chaves *_id em claro; name/legal_name de tenants/categories/products em claro só
--     ao nível das colunas (raiz de changes ou changes.before/after). _chain_insert aplica-a em todos os caminhos.
--   Dedupe: id repetido com o mesmo conteúdo (audit._event_content_hash) → NULL; conteúdo diferente → PTA03.
--   audit_append_event: erros de conversão só com a chave e o SQLSTATE (nunca SQLERRM); lock_timeout 2s.
--   audit_verify_chain: + bad_genesis, gap_before, head_mismatch (mesma assinatura; fórmula do hash igual).
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0012_hardening', '0011_db_user', $chg_0012$
CREATE FUNCTION audit._redact_walk(p_table text, p_value jsonb, p_level text)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
BEGIN
    -- p_level: 'root' (chaves de changes), 'columns' (chaves de changes.before/after), 'nested' (o resto).
    IF jsonb_typeof(p_value) = 'array' THEN
        RETURN (SELECT COALESCE(jsonb_agg(audit._redact_walk(p_table, a.value, 'nested'::text) ORDER BY a.n),
                                '[]'::jsonb)
                FROM jsonb_array_elements(p_value) WITH ORDINALITY AS a(value, n));
    END IF;
    IF jsonb_typeof(p_value) IS DISTINCT FROM 'object' THEN
        RETURN p_value;
    END IF;
    RETURN (
        SELECT COALESCE(jsonb_object_agg(c.key, CASE
            WHEN c.value = 'null'::jsonb THEN c.value
            WHEN c.key ~* '_id$'
                THEN audit._redact_walk(p_table, c.value, 'nested'::text)
            WHEN c.key ~* '(password|secret|token|credential|passkey|split_key|api_?key|private|otp|totp|cvv|cvc|pan|authorization|_enc$|_hash$)'
                THEN '"[redacted]"'::jsonb
            WHEN c.key ~* 'iban'
                THEN CASE WHEN jsonb_typeof(c.value) = 'string'
                          THEN to_jsonb('****' || right(c.value #>> '{}', 4))
                          ELSE '"[redacted]"'::jsonb END
            WHEN c.key ~* '(email|phone|telefone|nif|nipc|vat_number|name$|full_name|first_name|last_name|address|morada|street|postal|zip|birth|ip$)'
                 AND NOT (p_level IN ('root', 'columns')
                          AND p_table IN ('tenants', 'categories', 'products')
                          AND c.key IN ('name', 'legal_name'))
                THEN '"[pii]"'::jsonb
            ELSE audit._redact_walk(p_table, c.value,
                     CASE WHEN p_level = 'root' AND c.key IN ('before', 'after')
                          THEN 'columns' ELSE 'nested' END::text)
        END), '{}'::jsonb)
        FROM jsonb_each(p_value) AS c);
END
$body$;
REVOKE ALL ON FUNCTION audit._redact_walk(text, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._redact_walk(text, jsonb, text)
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer, ptmarket_audit_writer;

CREATE OR REPLACE FUNCTION audit.audit_redact(p_table text, p_changes jsonb)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
    SELECT audit._redact_walk(p_table, p_changes, 'root'::text)
$body$;

-- Conteúdo do evento para a deduplicação: os campos do produtor, sem chain_seq/prev_hash/hash/created_at
-- (nem os derivados chain_key/retention_class/db_user); changes mascarado (idempotente).
CREATE FUNCTION audit._event_content_hash(e audit.audit_events)
RETURNS bytea
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $body$
    SELECT sha256(convert_to(jsonb_build_array(
        e.id, e.tenant_id, e.store_id, e.actor_type, e.actor_id, e.actor_label, e.impersonator_id,
        e.action, e.target_type, e.target_id, e.outcome, e.reason,
        audit.audit_redact(e.target_type::text, e.changes), e.request_id,
        e.ip::text, encode(e.user_agent_hash, 'hex'),
        (extract(epoch FROM e.occurred_at) * 1000000)::bigint
    )::text, 'UTF8'))
$body$;
REVOKE ALL ON FUNCTION audit._event_content_hash(audit.audit_events) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._event_content_hash(audit.audit_events) TO ptmarket_audit_writer;

CREATE OR REPLACE FUNCTION audit._chain_insert(p_row audit.audit_events, p_dedupe boolean)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_row     audit.audit_events := p_row;
    v_content bytea;
    v_found   bigint;
    v_same    bigint;
BEGIN
    -- Quem está ligado (LOGIN), não o papel assumido: ignora o que vier em p_row.
    v_row.db_user         := session_user;
    -- Máscara em todos os caminhos (app, worker, db); idempotente.
    v_row.changes         := audit.audit_redact(v_row.target_type::text, v_row.changes);
    v_row.chain_key       := COALESCE(v_row.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid);
    v_row.retention_class := audit.audit_retention_class(v_row.action::text, v_row.outcome::text);

    INSERT INTO audit.audit_chain_heads (chain_key, retention_class, last_seq, last_hash)
    VALUES (v_row.chain_key, v_row.retention_class, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT DO NOTHING;

    SELECT h.last_seq + 1, h.last_hash INTO STRICT v_row.chain_seq, v_row.prev_hash
    FROM audit.audit_chain_heads h
    WHERE h.chain_key = v_row.chain_key
      AND h.retention_class = v_row.retention_class
    FOR UPDATE;

    -- Reentrega (mesmo conteúdo) → NULL; id reutilizado com outro conteúdo → PTA03 (nunca em silêncio).
    IF p_dedupe THEN
        v_content := audit._event_content_hash(v_row);
        SELECT count(*), count(*) FILTER (WHERE audit._event_content_hash(e) = v_content)
          INTO v_found, v_same
          FROM audit.audit_events e
         WHERE e.id = v_row.id
           AND e.created_at >= v_row.occurred_at - interval '1 day';
        IF v_same > 0 THEN
            RETURN NULL;
        END IF;
        IF v_found > 0 THEN
            RAISE EXCEPTION '_chain_insert: id já gravado com conteúdo diferente'
                USING ERRCODE = 'PTA03';
        END IF;
    END IF;

    v_row.created_at  := clock_timestamp();
    v_row.occurred_at := COALESCE(v_row.occurred_at, v_row.created_at);
    v_row.id          := COALESCE(v_row.id, uuidv7());
    v_row.hash        := audit._event_hash(v_row);

    INSERT INTO audit.audit_events (
        id, tenant_id, chain_key, store_id, actor_type, actor_id, actor_label, impersonator_id,
        action, target_type, target_id, outcome, reason, changes, request_id, ip, user_agent_hash,
        retention_class, occurred_at, created_at, chain_seq, prev_hash, hash, db_user
    ) VALUES (
        v_row.id, v_row.tenant_id, v_row.chain_key, v_row.store_id, v_row.actor_type, v_row.actor_id,
        v_row.actor_label, v_row.impersonator_id, v_row.action, v_row.target_type, v_row.target_id,
        v_row.outcome, v_row.reason, v_row.changes, v_row.request_id, v_row.ip, v_row.user_agent_hash,
        v_row.retention_class, v_row.occurred_at, v_row.created_at, v_row.chain_seq, v_row.prev_hash,
        v_row.hash, v_row.db_user
    );

    UPDATE audit.audit_chain_heads
       SET last_seq = v_row.chain_seq, last_hash = v_row.hash
     WHERE chain_key = v_row.chain_key
       AND retention_class = v_row.retention_class;

    IF v_row.actor_type = 'admin' OR v_row.impersonator_id IS NOT NULL THEN
        INSERT INTO audit.audit_alerts (id, created_at, event_type, payload)
        VALUES (
            v_row.id, v_row.created_at, 'audit.superadmin_action',
            to_jsonb(v_row) || jsonb_build_object(
                'prev_hash', encode(v_row.prev_hash, 'hex'),
                'hash', encode(v_row.hash, 'hex'),
                'user_agent_hash', encode(v_row.user_agent_hash, 'hex'))
        );
    END IF;

    RETURN v_row.id;
END
$body$;

CREATE OR REPLACE FUNCTION audit.audit_append_event(p_event jsonb)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_row      audit.audit_events;
    v_bad      text;
    v_key      text;
    v_occurred text;
    v_ua       text;
    v_lock     text;
    v_ok       boolean;
BEGIN
    IF p_event IS NULL OR jsonb_typeof(p_event) <> 'object' THEN
        RAISE EXCEPTION 'audit_append_event: o evento tem de ser um objeto JSON'
            USING ERRCODE = 'PTA02';
    END IF;

    SELECT string_agg(k, ', ' ORDER BY k) INTO v_bad
    FROM jsonb_object_keys(p_event) AS k
    WHERE k <> ALL (ARRAY[
        'id', 'tenant_id', 'store_id', 'actor_type', 'actor_id', 'actor_label', 'impersonator_id',
        'action', 'target_type', 'target_id', 'outcome', 'reason', 'changes', 'request_id', 'ip',
        'user_agent_hash', 'occurred_at']);
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_append_event: chave(s) desconhecida(s): %', v_bad
            USING ERRCODE = 'PTA02';
    END IF;

    SELECT string_agg(k, ', ' ORDER BY k) INTO v_bad
    FROM unnest(ARRAY['id', 'actor_type', 'action', 'outcome', 'request_id', 'occurred_at']) AS k
    WHERE jsonb_typeof(p_event -> k) IS DISTINCT FROM 'string';
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_append_event: campo(s) obrigatório(s) em falta ou não texto: %', v_bad
            USING ERRCODE = 'PTA02';
    END IF;

    SELECT string_agg(k, ', ' ORDER BY k) INTO v_bad
    FROM unnest(ARRAY[
        'tenant_id', 'store_id', 'actor_id', 'actor_label', 'impersonator_id', 'target_type',
        'target_id', 'reason', 'ip', 'user_agent_hash']) AS k
    WHERE jsonb_typeof(p_event -> k) NOT IN ('string', 'null');
    IF jsonb_typeof(p_event -> 'changes') NOT IN ('object', 'null') THEN
        v_bad := concat_ws(', ', v_bad, 'changes');
    END IF;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_append_event: campo(s) com tipo errado: %', v_bad
            USING ERRCODE = 'PTA02';
    END IF;

    -- Conversões: qualquer erro de dados (22xxx) passa a PTA02 com a chave e o SQLSTATE, nunca o SQLERRM
    -- (os erros de conversão citam o valor, que pode ser pessoal).
    BEGIN
        v_key := 'id';              v_row.id              := (p_event ->> 'id')::uuid;
        v_key := 'tenant_id';       v_row.tenant_id       := (p_event ->> 'tenant_id')::uuid;
        v_key := 'store_id';        v_row.store_id        := (p_event ->> 'store_id')::uuid;
        v_key := 'actor_type';      v_row.actor_type      := p_event ->> 'actor_type';
        v_key := 'actor_id';        v_row.actor_id        := (p_event ->> 'actor_id')::uuid;
        v_key := 'actor_label';     v_row.actor_label     := p_event ->> 'actor_label';
        v_key := 'impersonator_id'; v_row.impersonator_id := (p_event ->> 'impersonator_id')::uuid;
        v_key := 'action';          v_row.action          := p_event ->> 'action';
        v_key := 'target_type';     v_row.target_type     := p_event ->> 'target_type';
        v_key := 'target_id';       v_row.target_id       := p_event ->> 'target_id';
        v_key := 'outcome';         v_row.outcome         := p_event ->> 'outcome';
        v_key := 'reason';          v_row.reason          := p_event ->> 'reason';
        v_key := 'changes';         v_row.changes         := CASE WHEN jsonb_typeof(p_event -> 'changes') = 'object'
                                                                  THEN p_event -> 'changes' END;
        v_key := 'request_id';      v_row.request_id      := (p_event ->> 'request_id')::uuid;
        v_key := 'ip';              v_row.ip              := (p_event ->> 'ip')::inet;

        v_key := 'user_agent_hash';
        v_ua := p_event ->> 'user_agent_hash';
        IF v_ua IS NOT NULL THEN
            IF v_ua !~ '^([0-9a-fA-F]{2})+$' THEN
                RAISE EXCEPTION 'user_agent_hash não é hexadecimal' USING ERRCODE = 'invalid_parameter_value';
            END IF;
            v_row.user_agent_hash := decode(lower(v_ua), 'hex');
        END IF;

        v_key := 'occurred_at';
        v_occurred := p_event ->> 'occurred_at';
        IF v_occurred !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$' THEN
            RAISE EXCEPTION 'occurred_at não é RFC 3339' USING ERRCODE = 'invalid_datetime_format';
        END IF;
        v_row.occurred_at := v_occurred::timestamptz;
    EXCEPTION WHEN data_exception THEN
        RAISE EXCEPTION 'audit_append_event: valor inválido no contrato (chave %, SQLSTATE %)', v_key, SQLSTATE
            USING ERRCODE = 'PTA02';
    END;

    IF uuid_extract_version(v_row.id) IS DISTINCT FROM 7 THEN
        RAISE EXCEPTION 'audit_append_event: id tem de ser uuidv7' USING ERRCODE = 'PTA02';
    END IF;
    -- 'db' é exclusivo do trigger genérico (mutação na própria BD); nunca vem do stream.
    IF v_row.actor_type NOT IN ('customer', 'merchant', 'municipal', 'admin', 'api_key', 'anonymous', 'system') THEN
        RAISE EXCEPTION 'audit_append_event: actor_type inválido' USING ERRCODE = 'PTA02';
    END IF;
    IF v_row.outcome NOT IN ('success', 'denied', 'error') THEN
        RAISE EXCEPTION 'audit_append_event: outcome inválido' USING ERRCODE = 'PTA02';
    END IF;
    IF char_length(v_row.action) NOT BETWEEN 1 AND 96 THEN
        RAISE EXCEPTION 'audit_append_event: action vazia ou com mais de 96 caracteres' USING ERRCODE = 'PTA02';
    END IF;
    IF char_length(v_row.target_type) > 64 THEN
        RAISE EXCEPTION 'audit_append_event: target_type com mais de 64 caracteres' USING ERRCODE = 'PTA02';
    END IF;
    IF v_row.occurred_at > now() + interval '5 minutes' OR v_row.occurred_at < now() - interval '7 days' THEN
        RAISE EXCEPTION 'audit_append_event: occurred_at fora de [now() - 7 dias, now() + 5 min]'
            USING ERRCODE = 'PTA02';
    END IF;

    -- lock_timeout 2s só durante a escrita (como audit_append). No corpo e não em SET da função: o efeito é o
    -- mesmo (repõe-se no fim; num erro a (sub)transação desfaz o set_config local).
    v_lock := current_setting('lock_timeout');
    PERFORM set_config('lock_timeout', '2s', true);
    -- Cadeia, hash, máscara, idempotência (mesmo conteúdo ⇒ NULL; outro ⇒ PTA03) e alerta: _chain_insert.
    v_ok := audit._chain_insert(v_row, true) IS NOT NULL;
    PERFORM set_config('lock_timeout', v_lock, true);
    RETURN v_ok;
END
$body$;

CREATE OR REPLACE FUNCTION audit.audit_verify_chain(p_chain_key uuid, p_class text, p_from timestamptz, p_to timestamptz)
RETURNS TABLE (broken_id uuid, broken_seq bigint, problem text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
#variable_conflict use_column
DECLARE
    v_zero bytea := decode(repeat('00', 32), 'hex');
BEGIN
    IF p_chain_key IS NULL OR p_from IS NULL OR p_to IS NULL OR p_from >= p_to THEN
        RAISE EXCEPTION 'audit_verify_chain: parâmetros obrigatórios e p_from < p_to'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_class IS NULL OR p_class NOT IN ('fiscal', 'standard', 'security') THEN
        RAISE EXCEPTION 'audit_verify_chain: classe inválida' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Janela [p_from, p_to): hash, bad_genesis (seq 1 sem prev_hash a zeros), gap_before (a 1.ª linha não
    -- continua a última linha anterior à janela, se existir), gap e link.
    RETURN QUERY
    WITH win AS (
        SELECT e.id, e.chain_seq, e.prev_hash, e.hash,
               audit._event_hash(e) AS recomputed,
               lag(e.hash) OVER w      AS prior_hash,
               lag(e.chain_seq) OVER w AS prior_seq,
               row_number() OVER w     AS rn
        FROM audit.audit_events e
        WHERE e.chain_key = p_chain_key
          AND e.retention_class = p_class
          AND e.created_at >= p_from
          AND e.created_at < p_to
        WINDOW w AS (ORDER BY e.chain_seq, e.created_at, e.id)
    ), anchor AS (
        SELECT b.chain_seq AS anchor_seq, b.hash AS anchor_hash
        FROM audit.audit_events b
        WHERE b.chain_key = p_chain_key
          AND b.retention_class = p_class
          AND b.created_at < p_from
        ORDER BY b.chain_seq DESC, b.created_at DESC, b.id DESC
        LIMIT 1
    )
    SELECT x.id, x.chain_seq, q.problem
    FROM win x
    LEFT JOIN anchor a ON x.rn = 1
    CROSS JOIN LATERAL (VALUES
        (1, 'hash'::text,        x.hash IS DISTINCT FROM x.recomputed),
        (2, 'bad_genesis'::text, x.chain_seq = 1 AND x.prev_hash IS DISTINCT FROM v_zero),
        (3, 'gap_before'::text,  x.rn = 1 AND a.anchor_seq IS NOT NULL
                                 AND (x.chain_seq <> a.anchor_seq + 1
                                      OR x.prev_hash IS DISTINCT FROM a.anchor_hash)),
        (4, 'gap'::text,         x.prior_seq IS NOT NULL AND x.chain_seq <> x.prior_seq + 1),
        (5, 'link'::text,        x.prior_seq IS NOT NULL AND x.chain_seq = x.prior_seq + 1
                                 AND x.prev_hash IS DISTINCT FROM x.prior_hash)
    ) AS q(ord, problem, broken)
    WHERE q.broken
    ORDER BY x.chain_seq, q.ord;

    -- Janela até ao presente: a última linha da cadeia tem de ser a cabeça (corte no fim da cadeia).
    -- Cabeça (0, zeros) sem linhas = coerente.
    IF p_to > now() THEN
        RETURN QUERY
        SELECT l.id, COALESCE(l.chain_seq, h.last_seq), 'head_mismatch'::text
        FROM (SELECT 1) AS one(x)
        LEFT JOIN audit.audit_chain_heads h
               ON h.chain_key = p_chain_key AND h.retention_class = p_class
        LEFT JOIN LATERAL (
            SELECT e.id, e.chain_seq, e.hash
            FROM audit.audit_events e
            WHERE e.chain_key = p_chain_key
              AND e.retention_class = p_class
            ORDER BY e.chain_seq DESC, e.created_at DESC, e.id DESC
            LIMIT 1
        ) l ON true
        WHERE (h.chain_key IS NOT NULL OR l.id IS NOT NULL)
          AND (h.chain_key IS NULL
               OR h.last_seq IS DISTINCT FROM COALESCE(l.chain_seq, 0)
               OR h.last_hash IS DISTINCT FROM COALESCE(l.hash, v_zero));
    END IF;
END
$body$;
$chg_0012$);

-- ---------------------------------------------------------------------------
-- APROVADA: 0013_ddl_owner_exec (cartão 02/04). Disparada por migrations/0013_audit_ddl.sql.
--   A L2 (event trigger de DDL, INVOKER) grava por audit_append_db como quem faz o DDL. audit_ensure_partitions
--   (DEFINER, dono ptmarket_audit_owner) cria partições: sem este EXECUTE, a criação falhava (42501). O dono é
--   NOLOGIN e sem membros (só código selado corre como ele).
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0013_ddl_owner_exec', '0012_hardening', $chg_0013$
GRANT EXECUTE ON FUNCTION audit.audit_append_db(text, text, text, jsonb, uuid, uuid) TO ptmarket_audit_owner;
$chg_0013$);

-- ---------------------------------------------------------------------------
-- APROVADA: 0014_mask_limits (cartão 02/03d). Disparada por migrations/0014_audit_mask_limits.sql. Exige 0013.
--   Máscara (audit._redact_walk mantém a assinatura e passa a chamar audit._redact_node, com profundidade):
--     chaves comparadas em minúsculas e sem acentos (audit._redact_key); SEGREDOS antes da exceção *_id
--     (reset_token_id, secret_id, api_key_id → "[redacted]"); a exceção *_id só vale para a PII; pan só como
--     token ((^|[_-])pan($|[_-]): company_id, expand_id em claro). Pares {key|name|field, value}: a etiqueta decide
--     a máscara do value. Por valor (audit._redact_text, todas as strings, também reason e actor_label): e-mail →
--     "[pii]"; JWT e prefixos de chave de API → "[redacted]"; IBAN → ****4 últimos. Contentores abaixo da
--     profundidade 16 → "[depth]".
--   Limites (_chain_insert, antes da máscara): changes ≤ 64 KiB (octet_length do texto), profundidade ≤ 16,
--     reason ≤ 1024, target_id ≤ 256, actor_label ≤ 128 caracteres.
--     Eventos da aplicação (audit_append direto, audit_append_event) → PTA02 com mensagem fixa, nada gravado.
--     L1 (dentro de um trigger) e L2 (event trigger de DDL) e 'db' → nunca falham: target_id → 180 chars +
--     '…sha256:<hex>'; reason/actor_label cortados com '…[truncated]'; folhas string > 4096 → marcador
--     {"truncated","bytes","sha256"} e, se ainda passar de 64 KiB, changes inteiro → esse marcador.
--   _event_content_hash: reason e actor_label pela máscara por valor (idempotente; dedupe estável).
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0014_mask_limits', '0013_ddl_owner_exec', $chg_0014$
CREATE FUNCTION audit._redact_key(p_key text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
    SELECT CASE
        WHEN n.k ~ '(password|passw|pwd|senha|palavra.?passe|segredo|secret|token|credential|passkey|split_key|api.?key|access.?key|chave|private|otp|totp|cvv|cvc|(^|[_-])pan($|[_-])|authorization|bearer|jwt|cookie|session|signature|hmac|pin$|card.?number|cartao|passport|passaporte|_enc$|_hash$)'
            THEN 'secret'
        WHEN n.k ~ 'iban'
            THEN 'iban'
        WHEN n.k ~ '_id$'
            THEN 'id'
        WHEN n.k ~ '(email|phone|telefone|telemovel|nif|nipc|vat_number|contribuinte|name$|full_name|first_name|last_name|nome|apelido|address|morada|street|postal|zip|birth|nascimento|ip$)'
            THEN 'pii'
    END
    FROM (SELECT lower(translate(p_key,
                 'ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇáàâãäéèêëíìîïóòôõöúùûüç',
                 'AAAAAEEEEIIIIOOOOOUUUUCaaaaaeeeeiiiiooooouuuuc')) AS k) AS n
$body$;
REVOKE ALL ON FUNCTION audit._redact_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._redact_key(text)
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer, ptmarket_audit_writer;

CREATE FUNCTION audit._redact_text(p_value text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_out text := p_value;
    v_m   text;
BEGIN
    IF p_value IS NULL OR p_value IN ('[redacted]', '[pii]', '[depth]') THEN
        RETURN p_value;
    END IF;
    -- JWT (três segmentos base64url), prefixos de chaves de API.
    IF p_value ~ '\meyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.'
       OR p_value ~ '[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}'
       OR p_value ~ '\m(sk_|rk_|ghp_|pk_live_|xox[bp]-)[A-Za-z0-9]'
       OR p_value ~ '\mAKIA[0-9A-Z]{16}' THEN
        RETURN '[redacted]';
    END IF;
    IF p_value ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' THEN
        RETURN '[pii]';
    END IF;
    -- IBAN ISO (compacto ou em grupos de 4) e PT50 + 21 dígitos (qualquer caixa, espaços opcionais) → ****4 últimos.
    FOR v_m IN
        SELECT m[1]
        FROM regexp_matches(p_value,
            '\m((?:[A-Z]{2}[0-9]{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)|[Pp][Tt]50(?: ?[0-9]){21}))\M',
            'g') AS m
    LOOP
        v_out := replace(v_out, v_m, '****' || right(replace(v_m, ' ', ''), 4));
    END LOOP;
    RETURN v_out;
END
$body$;
REVOKE ALL ON FUNCTION audit._redact_text(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._redact_text(text)
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer, ptmarket_audit_writer;

-- p_level: 'root' (chaves de changes), 'columns' (chaves de changes.before/after), 'nested' (o resto).
-- p_depth: profundidade deste contentor (raiz = 1); abaixo de 16 → "[depth]".
CREATE FUNCTION audit._redact_node(p_table text, p_value jsonb, p_level text, p_depth integer)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_pair text;
BEGIN
    CASE jsonb_typeof(p_value)
    WHEN 'string' THEN
        RETURN to_jsonb(audit._redact_text(p_value #>> '{}'));
    WHEN 'array' THEN
        IF p_depth > 16 THEN
            RETURN '"[depth]"'::jsonb;
        END IF;
        RETURN (SELECT COALESCE(jsonb_agg(audit._redact_node(p_table, a.value, 'nested'::text, (p_depth + 1)::integer)
                                          ORDER BY a.n), '[]'::jsonb)
                FROM jsonb_array_elements(p_value) WITH ORDINALITY AS a(value, n));
    WHEN 'object' THEN
        IF p_depth > 16 THEN
            RETURN '"[depth]"'::jsonb;
        END IF;
        -- Par genérico {key|name|field, value}: a etiqueta decide a máscara do value.
        IF p_value ? 'value' THEN
            SELECT CASE WHEN bool_or(x.cls = 'secret') THEN 'secret'
                        WHEN bool_or(x.cls = 'iban') THEN 'iban'
                        WHEN bool_or(x.cls = 'pii') THEN 'pii' END
              INTO v_pair
              FROM (SELECT audit._redact_key(p_value ->> l.k) AS cls
                    FROM unnest(ARRAY['key', 'name', 'field']) AS l(k)
                    WHERE jsonb_typeof(p_value -> l.k) = 'string') AS x;
        END IF;
        RETURN (
            SELECT COALESCE(jsonb_object_agg(c.key, CASE
                WHEN c.value = 'null'::jsonb THEN c.value
                WHEN k.cls = 'secret' THEN '"[redacted]"'::jsonb
                WHEN k.cls = 'iban' THEN CASE
                    WHEN jsonb_typeof(c.value) = 'string' AND (c.value #>> '{}') ~ '^\[(redacted|pii|depth)\]$'
                        THEN c.value
                    WHEN jsonb_typeof(c.value) = 'string'
                        THEN to_jsonb('****' || right(c.value #>> '{}', 4))
                    ELSE '"[redacted]"'::jsonb END
                WHEN k.cls = 'pii'
                     AND NOT (p_level IN ('root', 'columns')
                              AND p_table IN ('tenants', 'categories', 'products')
                              AND c.key IN ('name', 'legal_name'))
                    THEN '"[pii]"'::jsonb
                ELSE audit._redact_node(p_table, c.value,
                         CASE WHEN p_level = 'root' AND c.key IN ('before', 'after')
                              THEN 'columns' ELSE 'nested' END::text,
                         (p_depth + 1)::integer)
            END), '{}'::jsonb)
            FROM jsonb_each(p_value) AS c
            CROSS JOIN LATERAL (
                SELECT CASE WHEN c.key = 'value' AND v_pair IS NOT NULL THEN v_pair
                            ELSE audit._redact_key(c.key::text) END AS cls) AS k);
    ELSE
        RETURN p_value;
    END CASE;
END
$body$;
REVOKE ALL ON FUNCTION audit._redact_node(text, jsonb, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._redact_node(text, jsonb, text, integer)
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer, ptmarket_audit_writer;

-- Mesma assinatura (audit_redact e os GRANTs não mudam); a recursão passa para _redact_node.
CREATE OR REPLACE FUNCTION audit._redact_walk(p_table text, p_value jsonb, p_level text)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
BEGIN
    RETURN audit._redact_node(p_table, p_value, p_level, 1::integer);
END
$body$;

-- L1/L2: folhas string com mais de 4096 caracteres → {"truncated": true, "bytes": n, "sha256": hex}.
CREATE FUNCTION audit._truncate_leaves(p_value jsonb)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_s text;
BEGIN
    CASE jsonb_typeof(p_value)
    WHEN 'string' THEN
        v_s := p_value #>> '{}';
        IF char_length(v_s) > 4096 THEN
            RETURN jsonb_build_object('truncated', true, 'bytes', octet_length(v_s),
                                      'sha256', encode(sha256(convert_to(v_s, 'UTF8')), 'hex'));
        END IF;
        RETURN p_value;
    WHEN 'array' THEN
        RETURN (SELECT COALESCE(jsonb_agg(audit._truncate_leaves(a.value) ORDER BY a.n), '[]'::jsonb)
                FROM jsonb_array_elements(p_value) WITH ORDINALITY AS a(value, n));
    WHEN 'object' THEN
        RETURN (SELECT COALESCE(jsonb_object_agg(c.key, audit._truncate_leaves(c.value)), '{}'::jsonb)
                FROM jsonb_each(p_value) AS c);
    ELSE
        RETURN p_value;
    END CASE;
END
$body$;
REVOKE ALL ON FUNCTION audit._truncate_leaves(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._truncate_leaves(jsonb) TO ptmarket_audit_writer;

CREATE OR REPLACE FUNCTION audit._event_content_hash(e audit.audit_events)
RETURNS bytea
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $body$
    SELECT sha256(convert_to(jsonb_build_array(
        e.id, e.tenant_id, e.store_id, e.actor_type, e.actor_id, audit._redact_text(e.actor_label::text),
        e.impersonator_id, e.action, e.target_type, e.target_id, e.outcome, audit._redact_text(e.reason::text),
        audit.audit_redact(e.target_type::text, e.changes), e.request_id,
        e.ip::text, encode(e.user_agent_hash, 'hex'),
        (extract(epoch FROM e.occurred_at) * 1000000)::bigint
    )::text, 'UTF8'))
$body$;

CREATE OR REPLACE FUNCTION audit._chain_insert(p_row audit.audit_events, p_dedupe boolean)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_row     audit.audit_events := p_row;
    v_content bytea;
    v_found   bigint;
    v_same    bigint;
    v_size    bigint;
    v_deep    boolean;
    v_over    boolean;
    v_ctx     text;
    v_text    text;
BEGIN
    -- Quem está ligado (LOGIN), não o papel assumido: ignora o que vier em p_row.
    v_row.db_user := session_user;

    -- Limites, medidos ANTES da máscara. NUL nunca chega aqui: o PostgreSQL recusa chr(0) em text e \u0000 em jsonb.
    v_size := COALESCE(octet_length(v_row.changes::text), 0);
    v_deep := v_row.changes IS NOT NULL AND jsonb_path_exists(v_row.changes,
                  'strict $.**{16} ? (@.type() == "object" || @.type() == "array")'::jsonpath);
    v_over := v_size > 65536 OR v_deep
              OR COALESCE(char_length(v_row.reason), 0) > 1024
              OR COALESCE(char_length(v_row.target_id), 0) > 256
              OR COALESCE(char_length(v_row.actor_label), 0) > 128;
    IF v_over THEN
        -- A auditoria nunca faz falhar uma escrita de negócio nem uma migration: 'db', L1 (dentro de um trigger)
        -- e L2 (event trigger de DDL) seguem e são cortados abaixo. Eventos da aplicação → PTA02, nada gravado.
        GET DIAGNOSTICS v_ctx = PG_CONTEXT;
        IF NOT (v_row.actor_type = 'db' OR pg_trigger_depth() > 0
                OR v_ctx ~ 'PL/pgSQL function audit\.audit_ddl_(end|drop)\(\) line [0-9]+ at PERFORM') THEN
            IF v_size > 65536 THEN
                RAISE EXCEPTION '_chain_insert: changes acima de 64 KiB' USING ERRCODE = 'PTA02';
            END IF;
            IF v_deep THEN
                RAISE EXCEPTION '_chain_insert: changes com profundidade acima de 16' USING ERRCODE = 'PTA02';
            END IF;
            IF char_length(v_row.reason) > 1024 THEN
                RAISE EXCEPTION '_chain_insert: reason acima de 1024 caracteres' USING ERRCODE = 'PTA02';
            END IF;
            IF char_length(v_row.target_id) > 256 THEN
                RAISE EXCEPTION '_chain_insert: target_id acima de 256 caracteres' USING ERRCODE = 'PTA02';
            END IF;
            RAISE EXCEPTION '_chain_insert: actor_label acima de 128 caracteres' USING ERRCODE = 'PTA02';
        END IF;
    END IF;

    -- Máscara em todos os caminhos (app, worker, db); idempotente. reason e actor_label: máscara por valor.
    v_row.changes     := audit.audit_redact(v_row.target_type::text, v_row.changes);
    v_row.reason      := audit._redact_text(v_row.reason::text);
    v_row.actor_label := audit._redact_text(v_row.actor_label::text);

    -- Só no caminho tolerante (L1/L2/db): cortar e marcar, nunca falhar.
    IF v_over THEN
        IF char_length(v_row.target_id) > 256 THEN
            v_row.target_id := left(v_row.target_id, 180) || '…sha256:'
                               || encode(sha256(convert_to(v_row.target_id, 'UTF8')), 'hex');
        END IF;
        IF char_length(v_row.reason) > 1024 THEN
            v_row.reason := left(v_row.reason, 1012) || '…[truncated]';
        END IF;
        IF char_length(v_row.actor_label) > 128 THEN
            v_row.actor_label := left(v_row.actor_label, 116) || '…[truncated]';
        END IF;
        IF octet_length(v_row.changes::text) > 65536 THEN
            v_row.changes := audit._truncate_leaves(v_row.changes);
            v_text := v_row.changes::text;
            IF octet_length(v_text) > 65536 THEN
                v_row.changes := jsonb_build_object('truncated', true, 'bytes', octet_length(v_text),
                                     'sha256', encode(sha256(convert_to(v_text, 'UTF8')), 'hex'));
            END IF;
        END IF;
    END IF;

    v_row.chain_key       := COALESCE(v_row.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid);
    v_row.retention_class := audit.audit_retention_class(v_row.action::text, v_row.outcome::text);

    INSERT INTO audit.audit_chain_heads (chain_key, retention_class, last_seq, last_hash)
    VALUES (v_row.chain_key, v_row.retention_class, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT DO NOTHING;

    SELECT h.last_seq + 1, h.last_hash INTO STRICT v_row.chain_seq, v_row.prev_hash
    FROM audit.audit_chain_heads h
    WHERE h.chain_key = v_row.chain_key
      AND h.retention_class = v_row.retention_class
    FOR UPDATE;

    -- Reentrega (mesmo conteúdo) → NULL; id reutilizado com outro conteúdo → PTA03 (nunca em silêncio).
    IF p_dedupe THEN
        v_content := audit._event_content_hash(v_row);
        SELECT count(*), count(*) FILTER (WHERE audit._event_content_hash(e) = v_content)
          INTO v_found, v_same
          FROM audit.audit_events e
         WHERE e.id = v_row.id
           AND e.created_at >= v_row.occurred_at - interval '1 day';
        IF v_same > 0 THEN
            RETURN NULL;
        END IF;
        IF v_found > 0 THEN
            RAISE EXCEPTION '_chain_insert: id já gravado com conteúdo diferente'
                USING ERRCODE = 'PTA03';
        END IF;
    END IF;

    v_row.created_at  := clock_timestamp();
    v_row.occurred_at := COALESCE(v_row.occurred_at, v_row.created_at);
    v_row.id          := COALESCE(v_row.id, uuidv7());
    v_row.hash        := audit._event_hash(v_row);

    INSERT INTO audit.audit_events (
        id, tenant_id, chain_key, store_id, actor_type, actor_id, actor_label, impersonator_id,
        action, target_type, target_id, outcome, reason, changes, request_id, ip, user_agent_hash,
        retention_class, occurred_at, created_at, chain_seq, prev_hash, hash, db_user
    ) VALUES (
        v_row.id, v_row.tenant_id, v_row.chain_key, v_row.store_id, v_row.actor_type, v_row.actor_id,
        v_row.actor_label, v_row.impersonator_id, v_row.action, v_row.target_type, v_row.target_id,
        v_row.outcome, v_row.reason, v_row.changes, v_row.request_id, v_row.ip, v_row.user_agent_hash,
        v_row.retention_class, v_row.occurred_at, v_row.created_at, v_row.chain_seq, v_row.prev_hash,
        v_row.hash, v_row.db_user
    );

    UPDATE audit.audit_chain_heads
       SET last_seq = v_row.chain_seq, last_hash = v_row.hash
     WHERE chain_key = v_row.chain_key
       AND retention_class = v_row.retention_class;

    IF v_row.actor_type = 'admin' OR v_row.impersonator_id IS NOT NULL THEN
        INSERT INTO audit.audit_alerts (id, created_at, event_type, payload)
        VALUES (
            v_row.id, v_row.created_at, 'audit.superadmin_action',
            to_jsonb(v_row) || jsonb_build_object(
                'prev_hash', encode(v_row.prev_hash, 'hex'),
                'hash', encode(v_row.hash, 'hex'),
                'user_agent_hash', encode(v_row.user_agent_hash, 'hex'))
        );
    END IF;

    RETURN v_row.id;
END
$body$;
$chg_0014$);

-- ---------------------------------------------------------------------------
-- APROVADA: 0015_critical_timeline (cartão 02/09a). Disparada por migrations/0015_audit_critical_timeline.sql.
--   Exige 0014. audit.critical_kind(text, text, text) nasce na migration ANTES do audit_upgrade (INVOKER, selada).
--   audit_alerts.kind (NULL = não crítico; lista fechada = a de critical_kind); o guard passa a proteger kind.
--   _chain_insert (o da 0014, com limites, caminho tolerante e máscara por valor) passa a inserir em
--     audit_alerts quando actor_type = 'admin' OU impersonator_id OU critical_kind(...) não nulo:
--     event_type 'audit.critical' com kind, ou 'audit.superadmin_action' com kind NULL. Payload = linha já
--     mascarada + hashes em hex; kind 'iban_change' sem changes nem reason.
--   Índices da timeline em audit.audit_events: (store_id, created_at), (actor_id, created_at) e
--     ((changes->>'order_id'), created_at) WHERE changes ? 'order_id'.
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0015_critical_timeline', '0014_mask_limits', $chg_0015$
ALTER TABLE audit.audit_alerts ADD COLUMN kind text
    CONSTRAINT audit_alerts_kind_check CHECK (kind IN ('iban_change', 'payment_failure', 'invoice_failure',
                                                       'superadmin_login', 'verify_failure'));

CREATE OR REPLACE FUNCTION audit.audit_alerts_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $body$
BEGIN
    IF OLD.published_at IS NOT NULL
       OR NEW.published_at IS NULL
       OR (NEW.id, NEW.created_at, NEW.event_type, NEW.kind, NEW.payload)
          IS DISTINCT FROM (OLD.id, OLD.created_at, OLD.event_type, OLD.kind, OLD.payload) THEN
        RAISE EXCEPTION 'audit.audit_alerts: só published_at muda, uma vez, de NULL para um valor';
    END IF;
    RETURN NEW;
END
$body$;

CREATE INDEX audit_events_store_created_idx ON audit.audit_events (store_id, created_at);
CREATE INDEX audit_events_actor_created_idx ON audit.audit_events (actor_id, created_at);
CREATE INDEX audit_events_order_created_idx ON audit.audit_events ((changes ->> 'order_id'), created_at)
    WHERE changes ? 'order_id';

CREATE OR REPLACE FUNCTION audit._chain_insert(p_row audit.audit_events, p_dedupe boolean)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_row     audit.audit_events := p_row;
    v_content bytea;
    v_found   bigint;
    v_same    bigint;
    v_size    bigint;
    v_deep    boolean;
    v_over    boolean;
    v_ctx     text;
    v_text    text;
    v_kind    text;
    v_payload jsonb;
BEGIN
    -- Quem está ligado (LOGIN), não o papel assumido: ignora o que vier em p_row.
    v_row.db_user := session_user;

    -- Limites, medidos ANTES da máscara. NUL nunca chega aqui: o PostgreSQL recusa chr(0) em text e \u0000 em jsonb.
    v_size := COALESCE(octet_length(v_row.changes::text), 0);
    v_deep := v_row.changes IS NOT NULL AND jsonb_path_exists(v_row.changes,
                  'strict $.**{16} ? (@.type() == "object" || @.type() == "array")'::jsonpath);
    v_over := v_size > 65536 OR v_deep
              OR COALESCE(char_length(v_row.reason), 0) > 1024
              OR COALESCE(char_length(v_row.target_id), 0) > 256
              OR COALESCE(char_length(v_row.actor_label), 0) > 128;
    IF v_over THEN
        -- A auditoria nunca faz falhar uma escrita de negócio nem uma migration: 'db', L1 (dentro de um trigger)
        -- e L2 (event trigger de DDL) seguem e são cortados abaixo. Eventos da aplicação → PTA02, nada gravado.
        GET DIAGNOSTICS v_ctx = PG_CONTEXT;
        IF NOT (v_row.actor_type = 'db' OR pg_trigger_depth() > 0
                OR v_ctx ~ 'PL/pgSQL function audit\.audit_ddl_(end|drop)\(\) line [0-9]+ at PERFORM') THEN
            IF v_size > 65536 THEN
                RAISE EXCEPTION '_chain_insert: changes acima de 64 KiB' USING ERRCODE = 'PTA02';
            END IF;
            IF v_deep THEN
                RAISE EXCEPTION '_chain_insert: changes com profundidade acima de 16' USING ERRCODE = 'PTA02';
            END IF;
            IF char_length(v_row.reason) > 1024 THEN
                RAISE EXCEPTION '_chain_insert: reason acima de 1024 caracteres' USING ERRCODE = 'PTA02';
            END IF;
            IF char_length(v_row.target_id) > 256 THEN
                RAISE EXCEPTION '_chain_insert: target_id acima de 256 caracteres' USING ERRCODE = 'PTA02';
            END IF;
            RAISE EXCEPTION '_chain_insert: actor_label acima de 128 caracteres' USING ERRCODE = 'PTA02';
        END IF;
    END IF;

    -- Máscara em todos os caminhos (app, worker, db); idempotente. reason e actor_label: máscara por valor.
    v_row.changes     := audit.audit_redact(v_row.target_type::text, v_row.changes);
    v_row.reason      := audit._redact_text(v_row.reason::text);
    v_row.actor_label := audit._redact_text(v_row.actor_label::text);

    -- Só no caminho tolerante (L1/L2/db): cortar e marcar, nunca falhar.
    IF v_over THEN
        IF char_length(v_row.target_id) > 256 THEN
            v_row.target_id := left(v_row.target_id, 180) || '…sha256:'
                               || encode(sha256(convert_to(v_row.target_id, 'UTF8')), 'hex');
        END IF;
        IF char_length(v_row.reason) > 1024 THEN
            v_row.reason := left(v_row.reason, 1012) || '…[truncated]';
        END IF;
        IF char_length(v_row.actor_label) > 128 THEN
            v_row.actor_label := left(v_row.actor_label, 116) || '…[truncated]';
        END IF;
        IF octet_length(v_row.changes::text) > 65536 THEN
            v_row.changes := audit._truncate_leaves(v_row.changes);
            v_text := v_row.changes::text;
            IF octet_length(v_text) > 65536 THEN
                v_row.changes := jsonb_build_object('truncated', true, 'bytes', octet_length(v_text),
                                     'sha256', encode(sha256(convert_to(v_text, 'UTF8')), 'hex'));
            END IF;
        END IF;
    END IF;

    v_row.chain_key       := COALESCE(v_row.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid);
    v_row.retention_class := audit.audit_retention_class(v_row.action::text, v_row.outcome::text);

    INSERT INTO audit.audit_chain_heads (chain_key, retention_class, last_seq, last_hash)
    VALUES (v_row.chain_key, v_row.retention_class, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT DO NOTHING;

    SELECT h.last_seq + 1, h.last_hash INTO STRICT v_row.chain_seq, v_row.prev_hash
    FROM audit.audit_chain_heads h
    WHERE h.chain_key = v_row.chain_key
      AND h.retention_class = v_row.retention_class
    FOR UPDATE;

    -- Reentrega (mesmo conteúdo) → NULL; id reutilizado com outro conteúdo → PTA03 (nunca em silêncio).
    IF p_dedupe THEN
        v_content := audit._event_content_hash(v_row);
        SELECT count(*), count(*) FILTER (WHERE audit._event_content_hash(e) = v_content)
          INTO v_found, v_same
          FROM audit.audit_events e
         WHERE e.id = v_row.id
           AND e.created_at >= v_row.occurred_at - interval '1 day';
        IF v_same > 0 THEN
            RETURN NULL;
        END IF;
        IF v_found > 0 THEN
            RAISE EXCEPTION '_chain_insert: id já gravado com conteúdo diferente'
                USING ERRCODE = 'PTA03';
        END IF;
    END IF;

    v_row.created_at  := clock_timestamp();
    v_row.occurred_at := COALESCE(v_row.occurred_at, v_row.created_at);
    v_row.id          := COALESCE(v_row.id, uuidv7());
    v_row.hash        := audit._event_hash(v_row);

    INSERT INTO audit.audit_events (
        id, tenant_id, chain_key, store_id, actor_type, actor_id, actor_label, impersonator_id,
        action, target_type, target_id, outcome, reason, changes, request_id, ip, user_agent_hash,
        retention_class, occurred_at, created_at, chain_seq, prev_hash, hash, db_user
    ) VALUES (
        v_row.id, v_row.tenant_id, v_row.chain_key, v_row.store_id, v_row.actor_type, v_row.actor_id,
        v_row.actor_label, v_row.impersonator_id, v_row.action, v_row.target_type, v_row.target_id,
        v_row.outcome, v_row.reason, v_row.changes, v_row.request_id, v_row.ip, v_row.user_agent_hash,
        v_row.retention_class, v_row.occurred_at, v_row.created_at, v_row.chain_seq, v_row.prev_hash,
        v_row.hash, v_row.db_user
    );

    UPDATE audit.audit_chain_heads
       SET last_seq = v_row.chain_seq, last_hash = v_row.hash
     WHERE chain_key = v_row.chain_key
       AND retention_class = v_row.retention_class;

    -- Alerta (export WORM + Telegram/Discord no cartão 09): admin, impersonação ou evento crítico.
    -- Payload = linha já mascarada; iban_change sem changes nem reason (o IBAN nunca, nem mascarado).
    v_kind := audit.critical_kind(v_row.action::text, v_row.outcome::text, v_row.actor_type::text);
    IF v_row.actor_type = 'admin' OR v_row.impersonator_id IS NOT NULL OR v_kind IS NOT NULL THEN
        v_payload := to_jsonb(v_row) || jsonb_build_object(
            'prev_hash', encode(v_row.prev_hash, 'hex'),
            'hash', encode(v_row.hash, 'hex'),
            'user_agent_hash', encode(v_row.user_agent_hash, 'hex'));
        IF v_kind = 'iban_change' THEN
            v_payload := v_payload - ARRAY['changes', 'reason']::text[];
        END IF;
        INSERT INTO audit.audit_alerts (id, created_at, event_type, kind, payload)
        VALUES (
            v_row.id, v_row.created_at,
            CASE WHEN v_kind IS NULL THEN 'audit.superadmin_action' ELSE 'audit.critical' END,
            v_kind, v_payload
        );
    END IF;

    RETURN v_row.id;
END
$body$;
$chg_0015$);

-- ---------------------------------------------------------------------------
-- APROVADA: 0020_mask_v2 (cartão 02/03e). Disparada por migrations/0020_audit_mask_v2.sql. Exige 0015.
--   Máscara v2: chaves camelCase → snake_case antes de comparar (taxId → tax_id, cardPan → card_pan); PII de
--     identificação ANTES da exceção *_id (tax_id, vat_id, national_id, niss, dni, nie, cif, …); PII + mobile,
--     cell, whatsapp; classe 'iban' + nib, account_number, bank_account, numero_conta. Pares com etiqueta em
--     key|name|field|path|label|type|k e valor em value|v|val (path: último segmento); tuplos ["nif", "…"].
--     Por valor: IBAN em qualquer caixa com espaços/NBSP/"-"/"." e NIB de 21 dígitos (controlo certo) → ****4
--     últimos; só UUID ou só data/hora ISO → em claro; PAN com Luhn → "[redacted]"; NIF PT (mód. 11), DNI/NIE
--     ES e telefone (E.164 e PT nacional) → "[pii]".
--   _chain_insert(p_row, p_dedupe, p_tolerant): ÚNICO ponto de máscara (audit_append_db e audit_row_trigger
--     entregam changes em cru); iban_change medido antes da máscara (chave de classe 'iban' que muda em
--     before/after, after não nulo), com prioridade sobre critical_kind. A de 2 argumentos é apagada (a selagem
--     deixa de a aceitar nesta BD); sem pg_trigger_depth(): audit_append_db → tolerante; audit_append_event → não;
--     audit_append → só se a linha 2 do PG_CONTEXT for a atribuição da L1/L2 (audit_row_trigger, audit_ddl_end e
--     audit_ddl_drop chamam-na com v_ev := …, nunca PERFORM: sem a linha 'SQL statement' controlável).
--   REVOKE TEMPORARY na BD atual de PUBLIC, app, worker e price_writer (ninguém cria funções em pg_temp).
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0020_mask_v2', '0015_critical_timeline', $chg_0020$
-- _chain_insert com 3 argumentos: o caminho tolerante é decidido por quem chama (audit_append_db → true;
-- audit_append_event → false; audit_append → true só chamado pela L1/L2). Criada ANTES de mudar quem chama e de
-- apagar a de 2 argumentos: cada DDL deste bloco passa pela L2 (audit_append_db) e nunca encontra a cadeia partida.
CREATE FUNCTION audit._chain_insert(p_row audit.audit_events, p_dedupe boolean, p_tolerant boolean)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_row     audit.audit_events := p_row;
    v_content bytea;
    v_found   bigint;
    v_same    bigint;
    v_size    bigint;
    v_deep    boolean;
    v_over    boolean;
    v_text    text;
    v_iban    boolean := false;
    v_kind    text;
    v_payload jsonb;
BEGIN
    -- Quem está ligado (LOGIN), não o papel assumido: ignora o que vier em p_row.
    v_row.db_user := session_user;

    -- Limites, medidos ANTES da máscara. NUL nunca chega aqui: o PostgreSQL recusa chr(0) em text e \u0000 em jsonb.
    v_size := COALESCE(octet_length(v_row.changes::text), 0);
    v_deep := v_row.changes IS NOT NULL AND jsonb_path_exists(v_row.changes,
                  'strict $.**{16} ? (@.type() == "object" || @.type() == "array")'::jsonpath);
    v_over := v_size > 65536 OR v_deep
              OR COALESCE(char_length(v_row.reason), 0) > 1024
              OR COALESCE(char_length(v_row.target_id), 0) > 256
              OR COALESCE(char_length(v_row.actor_label), 0) > 128;
    -- A auditoria nunca faz falhar uma escrita de negócio nem uma migration: o caminho tolerante (db, L1, L2) segue
    -- e é cortado abaixo. Eventos da aplicação → PTA02 com mensagem fixa (nunca o valor), nada gravado.
    IF v_over AND NOT COALESCE(p_tolerant, false) THEN
        IF v_size > 65536 THEN
            RAISE EXCEPTION '_chain_insert: changes acima de 64 KiB' USING ERRCODE = 'PTA02';
        END IF;
        IF v_deep THEN
            RAISE EXCEPTION '_chain_insert: changes com profundidade acima de 16' USING ERRCODE = 'PTA02';
        END IF;
        IF char_length(v_row.reason) > 1024 THEN
            RAISE EXCEPTION '_chain_insert: reason acima de 1024 caracteres' USING ERRCODE = 'PTA02';
        END IF;
        IF char_length(v_row.target_id) > 256 THEN
            RAISE EXCEPTION '_chain_insert: target_id acima de 256 caracteres' USING ERRCODE = 'PTA02';
        END IF;
        RAISE EXCEPTION '_chain_insert: actor_label acima de 128 caracteres' USING ERRCODE = 'PTA02';
    END IF;

    -- iban_change, medido ANTES da máscara (dois IBAN com os mesmos 4 últimos são diferentes): uma chave de classe
    -- 'iban' em before ∪ after com before->k IS DISTINCT FROM after->k e after->k não nulo (INSERT e UPDATE; DELETE não).
    IF jsonb_typeof(v_row.changes) = 'object' THEN
        SELECT EXISTS (
            SELECT 1
            FROM (SELECT b.k FROM jsonb_object_keys(CASE WHEN jsonb_typeof(v_row.changes -> 'before') = 'object'
                                                         THEN v_row.changes -> 'before' ELSE '{}'::jsonb END) AS b(k)
                  UNION
                  SELECT a.k FROM jsonb_object_keys(CASE WHEN jsonb_typeof(v_row.changes -> 'after') = 'object'
                                                         THEN v_row.changes -> 'after' ELSE '{}'::jsonb END) AS a(k)) AS s
            WHERE audit._redact_key(s.k::text) = 'iban'
              AND (v_row.changes -> 'before' -> s.k) IS DISTINCT FROM (v_row.changes -> 'after' -> s.k)
              AND NULLIF(v_row.changes -> 'after' -> s.k, 'null'::jsonb) IS NOT NULL)
          INTO v_iban;
    END IF;

    -- Máscara em todos os caminhos (app, worker, db): ÚNICO ponto de máscara (quem chama entrega em cru);
    -- idempotente. reason e actor_label: máscara por valor.
    v_row.changes     := audit.audit_redact(v_row.target_type::text, v_row.changes);
    v_row.reason      := audit._redact_text(v_row.reason::text);
    v_row.actor_label := audit._redact_text(v_row.actor_label::text);

    -- Só no caminho tolerante (L1/L2/db): cortar e marcar, nunca falhar.
    IF v_over THEN
        IF char_length(v_row.target_id) > 256 THEN
            v_row.target_id := left(v_row.target_id, 180) || '…sha256:'
                               || encode(sha256(convert_to(v_row.target_id, 'UTF8')), 'hex');
        END IF;
        IF char_length(v_row.reason) > 1024 THEN
            v_row.reason := left(v_row.reason, 1012) || '…[truncated]';
        END IF;
        IF char_length(v_row.actor_label) > 128 THEN
            v_row.actor_label := left(v_row.actor_label, 116) || '…[truncated]';
        END IF;
        IF octet_length(v_row.changes::text) > 65536 THEN
            v_row.changes := audit._truncate_leaves(v_row.changes);
            v_text := v_row.changes::text;
            IF octet_length(v_text) > 65536 THEN
                v_row.changes := jsonb_build_object('truncated', true, 'bytes', octet_length(v_text),
                                     'sha256', encode(sha256(convert_to(v_text, 'UTF8')), 'hex'));
            END IF;
        END IF;
    END IF;

    v_row.chain_key       := COALESCE(v_row.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid);
    v_row.retention_class := audit.audit_retention_class(v_row.action::text, v_row.outcome::text);

    INSERT INTO audit.audit_chain_heads (chain_key, retention_class, last_seq, last_hash)
    VALUES (v_row.chain_key, v_row.retention_class, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT DO NOTHING;

    SELECT h.last_seq + 1, h.last_hash INTO STRICT v_row.chain_seq, v_row.prev_hash
    FROM audit.audit_chain_heads h
    WHERE h.chain_key = v_row.chain_key
      AND h.retention_class = v_row.retention_class
    FOR UPDATE;

    -- Reentrega (mesmo conteúdo) → NULL; id reutilizado com outro conteúdo → PTA03 (nunca em silêncio).
    IF p_dedupe THEN
        v_content := audit._event_content_hash(v_row);
        SELECT count(*), count(*) FILTER (WHERE audit._event_content_hash(e) = v_content)
          INTO v_found, v_same
          FROM audit.audit_events e
         WHERE e.id = v_row.id
           AND e.created_at >= v_row.occurred_at - interval '1 day';
        IF v_same > 0 THEN
            RETURN NULL;
        END IF;
        IF v_found > 0 THEN
            RAISE EXCEPTION '_chain_insert: id já gravado com conteúdo diferente'
                USING ERRCODE = 'PTA03';
        END IF;
    END IF;

    v_row.created_at  := clock_timestamp();
    v_row.occurred_at := COALESCE(v_row.occurred_at, v_row.created_at);
    v_row.id          := COALESCE(v_row.id, uuidv7());
    v_row.hash        := audit._event_hash(v_row);

    INSERT INTO audit.audit_events (
        id, tenant_id, chain_key, store_id, actor_type, actor_id, actor_label, impersonator_id,
        action, target_type, target_id, outcome, reason, changes, request_id, ip, user_agent_hash,
        retention_class, occurred_at, created_at, chain_seq, prev_hash, hash, db_user
    ) VALUES (
        v_row.id, v_row.tenant_id, v_row.chain_key, v_row.store_id, v_row.actor_type, v_row.actor_id,
        v_row.actor_label, v_row.impersonator_id, v_row.action, v_row.target_type, v_row.target_id,
        v_row.outcome, v_row.reason, v_row.changes, v_row.request_id, v_row.ip, v_row.user_agent_hash,
        v_row.retention_class, v_row.occurred_at, v_row.created_at, v_row.chain_seq, v_row.prev_hash,
        v_row.hash, v_row.db_user
    );

    UPDATE audit.audit_chain_heads
       SET last_seq = v_row.chain_seq, last_hash = v_row.hash
     WHERE chain_key = v_row.chain_key
       AND retention_class = v_row.retention_class;

    -- Alerta (export WORM + Telegram/Discord no cartão 09): admin, impersonação ou evento crítico.
    -- Payload = linha já mascarada; iban_change sem changes nem reason (o IBAN nunca, nem mascarado).
    -- iban_change pelas chaves (acima) tem prioridade sobre critical_kind; a action não muda (ex.: stores.update).
    v_kind := CASE WHEN v_iban THEN 'iban_change'
                   ELSE audit.critical_kind(v_row.action::text, v_row.outcome::text, v_row.actor_type::text) END;
    IF v_row.actor_type = 'admin' OR v_row.impersonator_id IS NOT NULL OR v_kind IS NOT NULL THEN
        v_payload := to_jsonb(v_row) || jsonb_build_object(
            'prev_hash', encode(v_row.prev_hash, 'hex'),
            'hash', encode(v_row.hash, 'hex'),
            'user_agent_hash', encode(v_row.user_agent_hash, 'hex'));
        IF v_kind = 'iban_change' THEN
            v_payload := v_payload - ARRAY['changes', 'reason']::text[];
        END IF;
        INSERT INTO audit.audit_alerts (id, created_at, event_type, kind, payload)
        VALUES (
            v_row.id, v_row.created_at,
            CASE WHEN v_kind IS NULL THEN 'audit.superadmin_action' ELSE 'audit.critical' END,
            v_kind, v_payload
        );
    END IF;

    RETURN v_row.id;
END
$body$;
REVOKE ALL ON FUNCTION audit._chain_insert(audit.audit_events, boolean, boolean) FROM PUBLIC;
-- Já do writer (a selagem fá-lo-ia no fim): com a L2 ativa, cada DDL seguinte deste bloco grava por audit_append_db
-- (DEFINER do writer), que passa a chamar esta função logo a seguir.
ALTER FUNCTION audit._chain_insert(audit.audit_events, boolean, boolean) OWNER TO ptmarket_audit_writer;

CREATE OR REPLACE FUNCTION audit.audit_append_db(
    p_action      text,
    p_target_type text,
    p_target_id   text,
    p_changes     jsonb,
    p_tenant_id   uuid,
    p_store_id    uuid
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
AS $body$
DECLARE
    v_row audit.audit_events;
BEGIN
    v_row.actor_type  := 'db';
    v_row.actor_label := session_user;
    v_row.tenant_id   := COALESCE(p_tenant_id,
                                  NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
    v_row.store_id    := p_store_id;
    v_row.action      := p_action;
    v_row.target_type := p_target_type;
    v_row.target_id   := p_target_id;
    v_row.outcome     := 'success';
    v_row.changes     := p_changes; -- em cru: _chain_insert mede (limites, iban_change) e mascara

    -- Caminho tolerante: as mutações do migrator/superuser e a L2 nunca falham por causa da auditoria.
    RETURN audit._chain_insert(v_row, false, true);
END
$body$;

CREATE OR REPLACE FUNCTION audit.audit_append(
    p_action      text,
    p_target_type text,
    p_target_id   text,
    p_outcome     text,
    p_reason      text,
    p_changes     jsonb,
    p_store_id    uuid,
    p_tenant_id   uuid DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
AS $body$
DECLARE
    v_row        audit.audit_events;
    v_actor      text;
    v_ctx_tenant uuid;
    v_ctx        text;
    v_tolerant   boolean;
BEGIN
    v_actor := NULLIF(current_setting('app.actor_type', true), '');
    IF v_actor IS NULL THEN
        RAISE EXCEPTION 'audit_append: app.actor_type em falta (ator obrigatório)'
            USING ERRCODE = 'PTA01';
    END IF;
    -- 'db' só nasce em audit_append_db (trigger L1); a app nunca o escolhe. Lista fechada (CHECK sem 'db').
    IF v_actor NOT IN ('customer', 'merchant', 'municipal', 'admin', 'system', 'api_key', 'anonymous') THEN
        RAISE EXCEPTION 'audit_append: app.actor_type inválido'
            USING ERRCODE = 'PTA01';
    END IF;
    v_row.actor_type      := v_actor;
    v_row.actor_id        := NULLIF(current_setting('app.actor_id', true), '')::uuid;
    v_row.actor_label     := NULLIF(current_setting('app.actor_label', true), '');
    v_row.impersonator_id := NULLIF(current_setting('app.impersonator_id', true), '')::uuid;
    v_row.request_id      := NULLIF(current_setting('app.request_id', true), '')::uuid;
    v_row.ip              := NULLIF(current_setting('app.ip', true), '')::inet;
    v_row.user_agent_hash := decode(NULLIF(current_setting('app.user_agent_hash', true), ''), 'hex');

    v_ctx_tenant := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
    IF p_tenant_id IS NOT NULL THEN
        IF v_row.actor_type <> 'system' THEN
            RAISE EXCEPTION 'audit_append: p_tenant_id só é aceite com app.actor_type = system';
        END IF;
        IF v_ctx_tenant IS NOT NULL AND v_ctx_tenant <> p_tenant_id THEN
            RAISE EXCEPTION 'audit_append: p_tenant_id difere de app.current_tenant_id';
        END IF;
    END IF;
    v_row.tenant_id := COALESCE(v_ctx_tenant, p_tenant_id);

    v_row.store_id    := p_store_id;
    v_row.action      := p_action;
    v_row.target_type := p_target_type;
    v_row.target_id   := p_target_id;
    v_row.outcome     := p_outcome;
    v_row.reason      := p_reason;
    v_row.changes     := p_changes;

    -- Caminho tolerante (cortar e marcar acima dos limites) só para a L1/L2: a linha 2 do PG_CONTEXT (o chamador
    -- imediato), inteira, tem de ser a atribuição de audit_row_trigger/audit_ddl_end/audit_ddl_drop. Um chamador por
    -- SPI (EXECUTE, query_to_xml, PERFORM) põe aí 'SQL statement "…"' (texto controlável, nunca aceite); um DO põe
    -- 'inline_code_block'. A app tem EXECUTE aqui, por isso não é um parâmetro; ninguém cria funções em audit.*
    -- (selagem) nem em pg_temp (sem TEMPORARY).
    GET DIAGNOSTICS v_ctx = PG_CONTEXT;
    v_tolerant := COALESCE(split_part(v_ctx, E'\n', 2)
                  ~ '^PL/pgSQL function audit\.audit_(row_trigger|ddl_end|ddl_drop)\(\) line [0-9]+ at assignment$', false);

    RETURN audit._chain_insert(v_row, false, v_tolerant);
END
$body$;

CREATE OR REPLACE FUNCTION audit.audit_append_event(p_event jsonb)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_row      audit.audit_events;
    v_bad      text;
    v_key      text;
    v_occurred text;
    v_ua       text;
    v_lock     text;
    v_ok       boolean;
BEGIN
    IF p_event IS NULL OR jsonb_typeof(p_event) <> 'object' THEN
        RAISE EXCEPTION 'audit_append_event: o evento tem de ser um objeto JSON'
            USING ERRCODE = 'PTA02';
    END IF;

    SELECT string_agg(k, ', ' ORDER BY k) INTO v_bad
    FROM jsonb_object_keys(p_event) AS k
    WHERE k <> ALL (ARRAY[
        'id', 'tenant_id', 'store_id', 'actor_type', 'actor_id', 'actor_label', 'impersonator_id',
        'action', 'target_type', 'target_id', 'outcome', 'reason', 'changes', 'request_id', 'ip',
        'user_agent_hash', 'occurred_at']);
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_append_event: chave(s) desconhecida(s): %', v_bad
            USING ERRCODE = 'PTA02';
    END IF;

    SELECT string_agg(k, ', ' ORDER BY k) INTO v_bad
    FROM unnest(ARRAY['id', 'actor_type', 'action', 'outcome', 'request_id', 'occurred_at']) AS k
    WHERE jsonb_typeof(p_event -> k) IS DISTINCT FROM 'string';
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_append_event: campo(s) obrigatório(s) em falta ou não texto: %', v_bad
            USING ERRCODE = 'PTA02';
    END IF;

    SELECT string_agg(k, ', ' ORDER BY k) INTO v_bad
    FROM unnest(ARRAY[
        'tenant_id', 'store_id', 'actor_id', 'actor_label', 'impersonator_id', 'target_type',
        'target_id', 'reason', 'ip', 'user_agent_hash']) AS k
    WHERE jsonb_typeof(p_event -> k) NOT IN ('string', 'null');
    IF jsonb_typeof(p_event -> 'changes') NOT IN ('object', 'null') THEN
        v_bad := concat_ws(', ', v_bad, 'changes');
    END IF;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_append_event: campo(s) com tipo errado: %', v_bad
            USING ERRCODE = 'PTA02';
    END IF;

    -- Conversões: qualquer erro de dados (22xxx) passa a PTA02 com a chave e o SQLSTATE, nunca o SQLERRM
    -- (os erros de conversão citam o valor, que pode ser pessoal).
    BEGIN
        v_key := 'id';              v_row.id              := (p_event ->> 'id')::uuid;
        v_key := 'tenant_id';       v_row.tenant_id       := (p_event ->> 'tenant_id')::uuid;
        v_key := 'store_id';        v_row.store_id        := (p_event ->> 'store_id')::uuid;
        v_key := 'actor_type';      v_row.actor_type      := p_event ->> 'actor_type';
        v_key := 'actor_id';        v_row.actor_id        := (p_event ->> 'actor_id')::uuid;
        v_key := 'actor_label';     v_row.actor_label     := p_event ->> 'actor_label';
        v_key := 'impersonator_id'; v_row.impersonator_id := (p_event ->> 'impersonator_id')::uuid;
        v_key := 'action';          v_row.action          := p_event ->> 'action';
        v_key := 'target_type';     v_row.target_type     := p_event ->> 'target_type';
        v_key := 'target_id';       v_row.target_id       := p_event ->> 'target_id';
        v_key := 'outcome';         v_row.outcome         := p_event ->> 'outcome';
        v_key := 'reason';          v_row.reason          := p_event ->> 'reason';
        v_key := 'changes';         v_row.changes         := CASE WHEN jsonb_typeof(p_event -> 'changes') = 'object'
                                                                  THEN p_event -> 'changes' END;
        v_key := 'request_id';      v_row.request_id      := (p_event ->> 'request_id')::uuid;
        v_key := 'ip';              v_row.ip              := (p_event ->> 'ip')::inet;

        v_key := 'user_agent_hash';
        v_ua := p_event ->> 'user_agent_hash';
        IF v_ua IS NOT NULL THEN
            IF v_ua !~ '^([0-9a-fA-F]{2})+$' THEN
                RAISE EXCEPTION 'user_agent_hash não é hexadecimal' USING ERRCODE = 'invalid_parameter_value';
            END IF;
            v_row.user_agent_hash := decode(lower(v_ua), 'hex');
        END IF;

        v_key := 'occurred_at';
        v_occurred := p_event ->> 'occurred_at';
        IF v_occurred !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$' THEN
            RAISE EXCEPTION 'occurred_at não é RFC 3339' USING ERRCODE = 'invalid_datetime_format';
        END IF;
        v_row.occurred_at := v_occurred::timestamptz;
    EXCEPTION WHEN data_exception THEN
        RAISE EXCEPTION 'audit_append_event: valor inválido no contrato (chave %, SQLSTATE %)', v_key, SQLSTATE
            USING ERRCODE = 'PTA02';
    END;

    IF uuid_extract_version(v_row.id) IS DISTINCT FROM 7 THEN
        RAISE EXCEPTION 'audit_append_event: id tem de ser uuidv7' USING ERRCODE = 'PTA02';
    END IF;
    -- 'db' é exclusivo do trigger genérico (mutação na própria BD); nunca vem do stream.
    IF v_row.actor_type NOT IN ('customer', 'merchant', 'municipal', 'admin', 'api_key', 'anonymous', 'system') THEN
        RAISE EXCEPTION 'audit_append_event: actor_type inválido' USING ERRCODE = 'PTA02';
    END IF;
    IF v_row.outcome NOT IN ('success', 'denied', 'error') THEN
        RAISE EXCEPTION 'audit_append_event: outcome inválido' USING ERRCODE = 'PTA02';
    END IF;
    IF char_length(v_row.action) NOT BETWEEN 1 AND 96 THEN
        RAISE EXCEPTION 'audit_append_event: action vazia ou com mais de 96 caracteres' USING ERRCODE = 'PTA02';
    END IF;
    IF char_length(v_row.target_type) > 64 THEN
        RAISE EXCEPTION 'audit_append_event: target_type com mais de 64 caracteres' USING ERRCODE = 'PTA02';
    END IF;
    IF v_row.occurred_at > now() + interval '5 minutes' OR v_row.occurred_at < now() - interval '7 days' THEN
        RAISE EXCEPTION 'audit_append_event: occurred_at fora de [now() - 7 dias, now() + 5 min]'
            USING ERRCODE = 'PTA02';
    END IF;

    -- lock_timeout 2s só durante a escrita (como audit_append). No corpo e não em SET da função: o efeito é o
    -- mesmo (repõe-se no fim; num erro a (sub)transação desfaz o set_config local).
    v_lock := current_setting('lock_timeout');
    PERFORM set_config('lock_timeout', '2s', true);
    -- Cadeia, hash, máscara, idempotência (mesmo conteúdo ⇒ NULL; outro ⇒ PTA03) e alerta: _chain_insert.
    v_ok := audit._chain_insert(v_row, true, false) IS NOT NULL;
    PERFORM set_config('lock_timeout', v_lock, true);
    RETURN v_ok;
END
$body$;

CREATE OR REPLACE FUNCTION audit.audit_row_trigger()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_actor   text    := NULLIF(current_setting('app.actor_type', true), '');
    v_is_app  boolean := current_user IN ('ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer');
    v_action  text    := TG_TABLE_NAME || '.' || lower(TG_OP);
    v_key     text    := COALESCE(TG_ARGV[0], 'id');
    v_old     jsonb;
    v_new     jsonb;
    v_row     jsonb;
    v_before  jsonb;
    v_after   jsonb;
    v_changes jsonb;
    v_target  text;
    v_tenant  uuid;
    v_store   uuid;
    v_ev      uuid;
BEGIN
    IF v_is_app AND v_actor IS NULL THEN
        RAISE EXCEPTION 'mutação sem ator: % por %', v_action, current_user
            USING ERRCODE = 'PTA01';
    END IF;

    IF TG_LEVEL = 'ROW' THEN
        IF TG_OP <> 'INSERT' THEN
            v_old := to_jsonb(OLD);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            v_new := to_jsonb(NEW);
        END IF;
        v_row := COALESCE(v_new, v_old);

        IF TG_OP = 'INSERT' THEN
            v_changes := jsonb_build_object('after', v_new);
        ELSIF TG_OP = 'DELETE' THEN
            v_changes := jsonb_build_object('before', v_old);
        ELSE
            SELECT jsonb_object_agg(k.key, v_old -> k.key), jsonb_object_agg(k.key, v_new -> k.key)
              INTO v_before, v_after
              FROM jsonb_object_keys(v_new) AS k(key)
             WHERE (v_old -> k.key) IS DISTINCT FROM (v_new -> k.key);
            IF v_before IS NULL THEN
                RETURN NULL; -- UPDATE sem diferenças: sem evento
            END IF;
            v_changes := jsonb_build_object('before', v_before, 'after', v_after);
        END IF;

        v_target := v_row ->> v_key;
        v_tenant := CASE WHEN TG_TABLE_NAME = 'tenants' THEN (v_row ->> 'id')::uuid
                         ELSE (v_row ->> 'tenant_id')::uuid END;
        v_store  := CASE WHEN TG_TABLE_NAME = 'stores' THEN (v_row ->> 'id')::uuid
                         ELSE (v_row ->> 'store_id')::uuid END;
    END IF;

    IF v_is_app THEN
        -- audit_append só aceita p_tenant_id com ator 'system' (os outros usam o tenant do contexto).
        -- changes em cru: _chain_insert mede (limites, iban_change) e mascara. Atribuição (expressão simples, sem
        -- SPI): a linha 2 do PG_CONTEXT em audit_append é exatamente 'PL/pgSQL function audit.audit_row_trigger()
        -- line N at assignment' (caminho tolerante da L1). Um PERFORM poria antes uma linha 'SQL statement "…"'.
        v_ev := audit.audit_append(
            v_action::text, TG_TABLE_NAME::text, v_target::text, 'success'::text, NULL::text,
            v_changes::jsonb, v_store::uuid,
            CASE WHEN v_actor = 'system' THEN v_tenant END::uuid);
    ELSE
        PERFORM audit.audit_append_db(
            v_action::text, TG_TABLE_NAME::text, v_target::text, v_changes::jsonb, v_tenant::uuid, v_store::uuid);
    END IF;

    RETURN NULL;
END
$body$;

CREATE OR REPLACE FUNCTION audit._redact_key(p_key text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
    SELECT CASE
        WHEN n.k ~ '(password|passw|pwd|senha|palavra.?passe|segredo|secret|token|credential|passkey|split_key|api.?key|access.?key|chave|private|otp|totp|cvv|cvc|(^|[_-])pan($|[_-])|authorization|bearer|jwt|cookie|session|signature|hmac|pin$|card.?number|cartao|passport|passaporte|_enc$|_hash$)'
            THEN 'secret'
        WHEN n.k ~ '(iban|(^|[_-])nib($|[_-])|account.?number|bank.?account|numero.?conta)'
            THEN 'iban'
        WHEN n.k ~ '((tax|vat|fiscal|national|citizen|taxpayer|social.?security)[_-]?(id|number|no|num|code)$|(^|[_-])(niss|dni|nie|cif)($|[_-]))'
            THEN 'pii'
        WHEN n.k ~ '_id$'
            THEN 'id'
        WHEN n.k ~ '(email|phone|telefone|telemovel|mobile|(^|[_-])cell|whatsapp|nif|nipc|vat_number|contribuinte|name$|full_name|first_name|last_name|nome|apelido|address|morada|street|postal|zip|birth|nascimento|ip$)'
            THEN 'pii'
    END
    FROM (SELECT lower(translate(regexp_replace(p_key, '([a-z0-9])([A-Z])', '\1_\2', 'g'),
                 'ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇáàâãäéèêëíìîïóòôõöúùûüç',
                 'AAAAAEEEEIIIIOOOOOUUUUCaaaaaeeeeiiiiooooouuuuc')) AS k) AS n
$body$;

CREATE OR REPLACE FUNCTION audit._redact_text(p_value text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_out  text := p_value;
    v_m    text;
    v_a    text[];
    v_d    text;
    v_g    text[];
    v_acc  text;
    v_i    integer;
    v_j    integer;
    v_k    integer;
    v_x    integer;
    v_sum  integer;
    v_n    bigint;
BEGIN
    -- 1. Marcadores já postos.
    IF p_value IS NULL OR p_value IN ('[redacted]', '[pii]', '[depth]') THEN
        RETURN p_value;
    END IF;
    -- 2. JWT (três segmentos base64url), prefixos de chaves de API.
    IF p_value ~ '\meyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.'
       OR p_value ~ '[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}'
       OR p_value ~ '\m(sk_|rk_|ghp_|pk_live_|xox[bp]-)[A-Za-z0-9]'
       OR p_value ~ '\mAKIA[0-9A-Z]{16}' THEN
        RETURN '[redacted]';
    END IF;
    -- 3. E-mail.
    IF p_value ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' THEN
        RETURN '[pii]';
    END IF;
    -- 4. IBAN no sítio (qualquer caixa; entre grupos: espaço(s), NBSP, "-" ou ".") → ****4 últimos.
    FOR v_m IN
        SELECT m[1]
        FROM regexp_matches(v_out,
            '\m([A-Za-z]{2}[0-9]{2}(?:[A-Za-z0-9]{11,30}|(?:(?: +| |-|\.)[A-Za-z0-9]{4}){2,7}(?:(?: +| |-|\.)[A-Za-z0-9]{1,4})?)|[Pp][Tt]50(?:(?: +| |-|\.)?[0-9]){21})\M',
            'g') AS m
    LOOP
        v_out := replace(v_out, v_m, '****' || right(regexp_replace(v_m, '[^A-Za-z0-9]', '', 'g'), 4));
    END LOOP;
    -- 5. NIB PT: 21 dígitos (mesmos separadores) com os 2 dígitos de controlo certos → ****4 últimos.
    FOR v_m IN
        SELECT m[1]
        FROM regexp_matches(v_out, '\m([0-9](?:(?: +| |-|\.)?[0-9]){20})\M', 'g') AS m
    LOOP
        v_d := regexp_replace(v_m, '[^0-9]', '', 'g');
        IF 98 - ((left(v_d, 19)::numeric * 100) % 97) = right(v_d, 2)::numeric THEN
            v_out := replace(v_out, v_m, '****' || right(v_d, 4));
        END IF;
    END LOOP;
    -- 6. Só um UUID ou só uma data/hora ISO 8601: como está (um UUID só de dígitos passaria no Luhn).
    IF v_out ~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
       OR v_out ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}([Tt ][0-9]{2}:[0-9]{2}(:[0-9]{2}([.,][0-9]+)?)?([Zz]|[+-][0-9]{2}(:?[0-9]{2})?)?)?$' THEN
        RETURN v_out;
    END IF;
    -- 7. PAN: 13–19 dígitos (espaço ou "-" entre eles) com Luhn válido, entre fronteiras de palavra (não dentro de
    --    um hash hexadecimal). Por grupos contíguos da sequência (um PAN seguido de outros números também conta).
    FOR v_m IN SELECT m[1] FROM regexp_matches(v_out, '\m([0-9](?:[ -]?[0-9])*)\M', 'g') AS m LOOP
        CONTINUE WHEN length(v_m) < 13;
        v_g := regexp_split_to_array(v_m, '[ -]');
        FOR v_i IN 1 .. cardinality(v_g) LOOP
            v_acc := '';
            FOR v_j IN v_i .. cardinality(v_g) LOOP
                v_acc := v_acc || v_g[v_j];
                EXIT WHEN length(v_acc) > 19;
                CONTINUE WHEN length(v_acc) < 13;
                v_sum := 0;
                FOR v_k IN 1 .. length(v_acc) LOOP
                    v_x := substr(v_acc, length(v_acc) - v_k + 1, 1)::integer;
                    IF v_k % 2 = 0 THEN
                        v_x := v_x * 2;
                        IF v_x > 9 THEN
                            v_x := v_x - 9;
                        END IF;
                    END IF;
                    v_sum := v_sum + v_x;
                END LOOP;
                IF v_sum % 10 = 0 THEN
                    RETURN '[redacted]';
                END IF;
            END LOOP;
        END LOOP;
    END LOOP;
    -- 8. NIF PT: 9 dígitos entre fronteiras de palavra ("PT" opcional), 1.º ≠ 0, controlo módulo 11.
    FOR v_m IN SELECT m[1] FROM regexp_matches(v_out, '\m(?:[Pp][Tt])?([1-9][0-9]{8})\M', 'g') AS m LOOP
        v_sum := 0;
        FOR v_k IN 1 .. 8 LOOP
            v_sum := v_sum + substr(v_m, v_k, 1)::integer * (10 - v_k);
        END LOOP;
        v_sum := v_sum % 11;
        IF (CASE WHEN v_sum < 2 THEN 0 ELSE 11 - v_sum END) = substr(v_m, 9, 1)::integer THEN
            RETURN '[pii]';
        END IF;
    END LOOP;
    -- 9. DNI (8 dígitos + letra) / NIE (X/Y/Z + 7 dígitos + letra) ES: letra = tabela[n mod 23].
    FOR v_a IN SELECT m FROM regexp_matches(v_out, '\m([XYZxyz]?)([0-9]{7,8})([A-Za-z])\M', 'g') AS m LOOP
        IF (v_a[1] = '' AND length(v_a[2]) = 8) OR (v_a[1] <> '' AND length(v_a[2]) = 7) THEN
            v_n := (translate(upper(v_a[1]), 'XYZ', '012') || v_a[2])::bigint;
            IF substr('TRWAGMYFPDXBNJZSQVHLCKE', (v_n % 23)::integer + 1, 1) = upper(v_a[3]) THEN
                RETURN '[pii]';
            END IF;
        END IF;
    END LOOP;
    -- 10. Telefone: E.164 ("+" ou "00" + 8–15 dígitos; separadores espaço . - ( )) e PT nacional (9 dígitos a
    --     começar por 2 ou 9, com ou sem grupos de 3).
    FOR v_m IN
        SELECT m[1] FROM regexp_matches(v_out, '(?:\+|(?:^|[^0-9A-Za-z_])00)((?:[ .()-]*[0-9])+)', 'g') AS m
    LOOP
        v_acc := '';
        FOREACH v_d IN ARRAY regexp_split_to_array(v_m, '[ .()-]+') LOOP
            v_acc := v_acc || v_d;
            IF length(v_acc) BETWEEN 8 AND 15 THEN
                RETURN '[pii]';
            END IF;
        END LOOP;
    END LOOP;
    IF v_out ~ '\m[29][0-9]{2}(?:[ .-]?[0-9]{3}){2}\M' THEN
        RETURN '[pii]';
    END IF;
    RETURN v_out;
END
$body$;

CREATE OR REPLACE FUNCTION audit._redact_node(p_table text, p_value jsonb, p_level text, p_depth integer)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_pair text;
    v_cls  text;
BEGIN
    CASE jsonb_typeof(p_value)
    WHEN 'string' THEN
        RETURN to_jsonb(audit._redact_text(p_value #>> '{}'));
    WHEN 'array' THEN
        IF p_depth > 16 THEN
            RETURN '"[depth]"'::jsonb;
        END IF;
        -- Tuplo ["etiqueta", escalar]: a etiqueta (segredo/IBAN/PII) decide a máscara do 2.º elemento.
        IF jsonb_array_length(p_value) = 2 AND jsonb_typeof(p_value -> 0) = 'string'
           AND jsonb_typeof(p_value -> 1) IN ('string', 'number', 'boolean') THEN
            v_cls := audit._redact_key(p_value ->> 0);
            IF v_cls IN ('secret', 'iban', 'pii') THEN
                RETURN jsonb_build_array(
                    to_jsonb(audit._redact_text(p_value ->> 0)),
                    CASE
                        WHEN v_cls = 'secret' THEN '"[redacted]"'::jsonb
                        WHEN v_cls = 'pii' THEN '"[pii]"'::jsonb
                        WHEN jsonb_typeof(p_value -> 1) = 'string' AND (p_value ->> 1) ~ '^\[(redacted|pii|depth)\]$'
                            THEN p_value -> 1
                        WHEN jsonb_typeof(p_value -> 1) = 'string'
                            THEN to_jsonb('****' || right(p_value ->> 1, 4))
                        ELSE '"[redacted]"'::jsonb
                    END);
            END IF;
        END IF;
        RETURN (SELECT COALESCE(jsonb_agg(audit._redact_node(p_table, a.value, 'nested'::text, (p_depth + 1)::integer)
                                          ORDER BY a.n), '[]'::jsonb)
                FROM jsonb_array_elements(p_value) WITH ORDINALITY AS a(value, n));
    WHEN 'object' THEN
        IF p_depth > 16 THEN
            RETURN '"[depth]"'::jsonb;
        END IF;
        -- Par genérico {key|name|field|path|label|type|k, value|v|val}: a etiqueta decide a máscara do valor
        -- (em path, o último segmento; separadores . / [ ]).
        IF p_value ?| ARRAY['value', 'v', 'val'] THEN
            SELECT CASE WHEN bool_or(x.cls = 'secret') THEN 'secret'
                        WHEN bool_or(x.cls = 'iban') THEN 'iban'
                        WHEN bool_or(x.cls = 'pii') THEN 'pii' END
              INTO v_pair
              FROM (SELECT audit._redact_key(CASE WHEN l.k = 'path'
                               THEN (SELECT s.seg
                                     FROM regexp_split_to_table(p_value ->> 'path', '[].[/]+') WITH ORDINALITY AS s(seg, n)
                                     WHERE s.seg <> ''
                                     ORDER BY s.n DESC
                                     LIMIT 1)
                               ELSE p_value ->> l.k END) AS cls
                    FROM unnest(ARRAY['key', 'name', 'field', 'path', 'label', 'type', 'k']) AS l(k)
                    WHERE jsonb_typeof(p_value -> l.k) = 'string') AS x;
        END IF;
        RETURN (
            SELECT COALESCE(jsonb_object_agg(c.key, CASE
                WHEN c.value = 'null'::jsonb THEN c.value
                WHEN k.cls = 'secret' THEN '"[redacted]"'::jsonb
                WHEN k.cls = 'iban' THEN CASE
                    WHEN jsonb_typeof(c.value) = 'string' AND (c.value #>> '{}') ~ '^\[(redacted|pii|depth)\]$'
                        THEN c.value
                    WHEN jsonb_typeof(c.value) = 'string'
                        THEN to_jsonb('****' || right(c.value #>> '{}', 4))
                    ELSE '"[redacted]"'::jsonb END
                WHEN k.cls = 'pii'
                     AND NOT (p_level IN ('root', 'columns')
                              AND p_table IN ('tenants', 'categories', 'products')
                              AND c.key IN ('name', 'legal_name'))
                    THEN '"[pii]"'::jsonb
                ELSE audit._redact_node(p_table, c.value,
                         CASE WHEN p_level = 'root' AND c.key IN ('before', 'after')
                              THEN 'columns' ELSE 'nested' END::text,
                         (p_depth + 1)::integer)
            END), '{}'::jsonb)
            FROM jsonb_each(p_value) AS c
            CROSS JOIN LATERAL (
                SELECT CASE WHEN c.key IN ('value', 'v', 'val') AND v_pair IS NOT NULL THEN v_pair
                            ELSE audit._redact_key(c.key::text) END AS cls) AS k);
    ELSE
        RETURN p_value;
    END CASE;
END
$body$;

CREATE OR REPLACE FUNCTION audit.audit_ddl_end()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_fn      oid     := to_regprocedure('audit.audit_row_trigger()');
    v_super   boolean := COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user), false);
    v_is_app  boolean := current_user IN ('ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer');
    v_ctx     text;
    v_auto    boolean;
    v_cmds    record;
    r         record;
    v_rels    oid[]   := '{}';
    v_new     oid[]   := '{}';
    v_rel     oid;
    v_bad     text;
    v_tenant  text;
    v_changes jsonb;
    v_ev      uuid;
    -- máscara
    v_q text; v_out text; v_pos int; v_len int; v_k int; v_i int; v_j int; v_j2 int; v_s int; v_end int;
    v_n int; v_d int; v_r int; v_pre int; v_esc boolean; v_c text; v_tag text; v_tok text; v_rep text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_event_trigger_ddl_commands()) THEN
        RETURN;
    END IF;
    IF v_fn IS NULL THEN
        RAISE EXCEPTION 'audit_ddl_end: audit.audit_row_trigger() em falta' USING ERRCODE = 'PTA04';
    END IF;

    -- Comandos executados por esta função (criação automática): logo abaixo do frame atual, um dos três textos
    -- exatos do passo 2 e o EXECUTE desta função. Forjar a pilha só dá estes três comandos (inofensivos).
    GET DIAGNOSTICS v_ctx = PG_CONTEXT;
    v_auto := v_ctx ~ ('^[^\n]*\nSQL statement "('
        || 'CREATE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE ON [^\n]* FOR EACH ROW EXECUTE FUNCTION audit\.audit_row_trigger\(\)'
        || '|CREATE TRIGGER zz_audit_truncate BEFORE TRUNCATE ON [^\n]* FOR EACH STATEMENT EXECUTE FUNCTION audit\.audit_row_trigger\(\)'
        || '|ALTER TABLE [^\n]* ENABLE ALWAYS TRIGGER zz_audit_(row|truncate)'
        || ')"\nPL/pgSQL function audit\.audit_ddl_end\(\) line [0-9]+ at EXECUTE(\n|$)');

    -- 1. Relações tocadas (e tabelas novas de public a cobrir).
    FOR v_cmds IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
        v_rel := NULL;
        IF v_cmds.classid = 'pg_catalog.pg_class'::regclass THEN
            v_rel := v_cmds.objid;
        ELSIF v_cmds.classid = 'pg_catalog.pg_trigger'::regclass THEN
            SELECT t.tgrelid INTO v_rel FROM pg_catalog.pg_trigger t WHERE t.oid = v_cmds.objid;
        END IF;
        IF v_rel IS NOT NULL THEN
            v_rels := v_rels || v_rel
                || ARRAY(SELECT p.relid::oid FROM pg_catalog.pg_partition_tree(v_rel::regclass) p);
        END IF;
        IF v_cmds.command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
           AND v_cmds.object_type = 'table' AND v_cmds.schema_name = 'public'
           AND v_cmds.classid = 'pg_catalog.pg_class'::regclass
           AND EXISTS (SELECT 1 FROM pg_catalog.pg_class c
                       WHERE c.oid = v_cmds.objid AND c.relkind IN ('r', 'p') AND NOT c.relispartition
                         AND c.relname NOT IN ('audit_events', 'outbox_events')) THEN
            v_new := v_new || v_cmds.objid;
        END IF;
    END LOOP;

    -- 2. L1 automática (os EXECUTE abaixo são os únicos desta função: a exceção v_auto só os reconhece a eles).
    FOREACH v_rel IN ARRAY v_new LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = v_rel AND t.tgname = 'zz_audit_row') THEN
            EXECUTE format('CREATE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE ON %s '
                           'FOR EACH ROW EXECUTE FUNCTION audit.audit_row_trigger()', v_rel::regclass);
        END IF;
        EXECUTE format('ALTER TABLE %s ENABLE ALWAYS TRIGGER zz_audit_row', v_rel::regclass);
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = v_rel AND t.tgname = 'zz_audit_truncate') THEN
            EXECUTE format('CREATE TRIGGER zz_audit_truncate BEFORE TRUNCATE ON %s '
                           'FOR EACH STATEMENT EXECUTE FUNCTION audit.audit_row_trigger()', v_rel::regclass);
        END IF;
        EXECUTE format('ALTER TABLE %s ENABLE ALWAYS TRIGGER zz_audit_truncate', v_rel::regclass);
        IF (SELECT count(*) FROM pg_catalog.pg_trigger t
            WHERE t.tgrelid = v_rel AND t.tgfoid = v_fn AND t.tgenabled = 'A'
              AND ((t.tgname = 'zz_audit_row' AND t.tgtype = 29) OR (t.tgname = 'zz_audit_truncate' AND t.tgtype = 34))) <> 2 THEN
            RAISE EXCEPTION 'audit_ddl_end: L1 automática falhou em %', v_rel::regclass USING ERRCODE = 'PTA04';
        END IF;
    END LOOP;

    -- 3. Guarda dos zz_audit_* (antes de gravar: a recusa não depende do ator).
    IF NOT v_super AND NOT v_auto AND cardinality(v_rels) > 0 THEN
        SELECT string_agg(format('%s em %s (tgenabled %s)', t.tgname, t.tgrelid::regclass, t.tgenabled), ', ')
          INTO v_bad
        FROM pg_catalog.pg_trigger t
        WHERE t.tgrelid = ANY (v_rels)
          AND (t.tgname IN ('zz_audit_row', 'zz_audit_truncate') OR t.tgfoid = v_fn)
          AND NOT (t.tgfoid = v_fn AND t.tgenabled = 'A' AND t.tgqual IS NULL AND t.tgconstraint = 0
                   AND cardinality(t.tgattr::int2[]) = 0
                   AND ((t.tgname = 'zz_audit_row' AND t.tgtype = 29)
                        OR (t.tgname = 'zz_audit_truncate' AND t.tgtype = 34)));
        IF v_bad IS NOT NULL THEN
            RAISE EXCEPTION 'audit_ddl_end: os triggers da caixa negra não se alteram (%)', v_bad
                USING ERRCODE = 'PTA04';
        END IF;
    END IF;

    IF v_is_app AND NULLIF(current_setting('app.actor_type', true), '') IS NULL THEN
        RAISE EXCEPTION 'DDL sem ator por %', current_user USING ERRCODE = 'PTA01';
    END IF;

    -- 4. Query: máscara (PASSWORD/SECRET) + sha256 do mascarado + corte a 4096.
    v_q := current_query();
    IF v_q IS NOT NULL THEN
        v_out := ''; v_pos := 1; v_len := length(v_q);
        LOOP
            v_k := regexp_instr(v_q, '\m(password|secret)\M', v_pos, 1, 1, 'i');
            EXIT WHEN v_k IS NULL OR v_k = 0;
            v_i := v_k;
            IF substr(v_q, v_i, 1) = '"' THEN v_i := v_i + 1; END IF;
            LOOP -- separadores: espaços, '=', ':', comentários
                v_c := substr(v_q, v_i, 2);
                IF v_c ~ '^[[:space:]=:]' THEN
                    v_i := v_i + 1;
                ELSIF v_c = '/*' THEN
                    v_j := strpos(substr(v_q, v_i + 2), '*/');
                    v_i := CASE WHEN v_j = 0 THEN v_len + 1 ELSE v_i + v_j + 3 END;
                ELSIF v_c = '--' THEN
                    v_j := strpos(substr(v_q, v_i), E'\n');
                    v_i := CASE WHEN v_j = 0 THEN v_len + 1 ELSE v_i + v_j END;
                ELSE
                    EXIT;
                END IF;
            END LOOP;
            v_out := v_out || substr(v_q, v_pos, v_i - v_pos);
            v_pre := CASE WHEN substr(v_q, v_i, 3) ~* '^u&''' THEN 2
                          WHEN substr(v_q, v_i, 2) ~* '^[ebxn]''' THEN 1 ELSE 0 END;
            v_esc := substr(v_q, v_i, 2) ~* '^e''';
            v_s := v_i + v_pre;
            v_c := substr(v_q, v_s, 1);
            v_end := NULL;
            IF v_c = '''' THEN
                -- Aspas a nível d (1, 2, 4… por aninhamento): abre com d, conteúdo em múltiplos de 2d, fecha com d.
                v_n := length((regexp_match(substr(v_q, v_s, 1000), '^''+'))[1]);
                v_d := v_n & -v_n;
                v_j := v_s + v_d;
                LOOP
                    v_j2 := regexp_instr(v_q, CASE WHEN v_esc THEN '[''\\]' ELSE '''' END, v_j);
                    EXIT WHEN v_j2 = 0;
                    IF substr(v_q, v_j2, 1) = '\' THEN
                        v_j := v_j2 + 2;
                        CONTINUE;
                    END IF;
                    v_r := length((regexp_match(substr(v_q, v_j2, 1000), '^''+'))[1]);
                    IF v_r >= v_d AND v_r % (2 * v_d) <> 0 THEN
                        v_end := v_j2 + ((v_r - v_d) / (2 * v_d)) * (2 * v_d) + v_d;
                        EXIT;
                    END IF;
                    v_j := v_j2 + v_r;
                END LOOP;
                v_rep := substr(v_q, v_i, v_pre) || repeat('''', v_d) || '[redacted]'
                         || CASE WHEN v_end IS NULL THEN '' ELSE repeat('''', v_d) END;
            ELSIF v_c = '$' AND substr(v_q, v_s, 256) ~ '^\$([A-Za-z_][A-Za-z_0-9]*)?\$' THEN
                v_tag := substring(substr(v_q, v_s, 256) from '^(\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$)');
                v_j := strpos(substr(v_q, v_s + length(v_tag)), v_tag);
                IF v_j > 0 THEN
                    v_end := v_s + length(v_tag) + v_j - 1 + length(v_tag);
                END IF;
                v_rep := v_tag || '[redacted]' || CASE WHEN v_end IS NULL THEN '' ELSE v_tag END;
            ELSIF v_c = '"' THEN
                v_j := v_s + 1;
                LOOP
                    v_j2 := regexp_instr(v_q, '["\\]', v_j);
                    EXIT WHEN v_j2 = 0;
                    IF substr(v_q, v_j2, 1) = '\' THEN
                        v_j := v_j2 + 2;
                        CONTINUE;
                    END IF;
                    v_end := v_j2 + 1;
                    EXIT;
                END LOOP;
                v_rep := '"[redacted]' || CASE WHEN v_end IS NULL THEN '' ELSE '"' END;
            ELSE
                v_tok := substring(substr(v_q, v_s) from '^[^[:space:];,()''"]*');
                v_end := v_s + length(v_tok);
                v_rep := CASE WHEN v_tok = '' THEN '' ELSE '[redacted]' END;
            END IF;
            v_out := v_out || v_rep;
            v_pos := COALESCE(v_end, v_len + 1);
        END LOOP;
        v_out := v_out || substr(v_q, v_pos);
    END IF;
    v_changes := jsonb_build_object(
        'query_sha256', encode(sha256(convert_to(v_out, 'UTF8')), 'hex'),
        'query',        left(v_out, 4096),
        'truncated',    COALESCE(length(v_out) > 4096, false));

    -- 5. Um evento por comando, na cadeia da plataforma (tenant NULL).
    v_tenant := NULLIF(current_setting('app.current_tenant_id', true), '');
    IF v_tenant IS NOT NULL THEN
        PERFORM set_config('app.current_tenant_id', '', true);
    END IF;
    FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
        IF v_is_app THEN
            -- Atribuição (expressão simples, sem SPI): a linha 2 do PG_CONTEXT em audit_append é exatamente
            -- 'PL/pgSQL function audit.audit_ddl_end() line N at assignment' (caminho tolerante da L2).
            v_ev := audit.audit_append(
                ('ddl.' || lower(replace(r.command_tag, ' ', '_')))::text, lower(r.object_type)::text,
                r.object_identity::text, 'success'::text, NULL::text, v_changes::jsonb, NULL::uuid, NULL::uuid);
        ELSE
            PERFORM audit.audit_append_db(
                ('ddl.' || lower(replace(r.command_tag, ' ', '_')))::text, lower(r.object_type)::text,
                r.object_identity::text, v_changes::jsonb, NULL::uuid, NULL::uuid);
        END IF;
    END LOOP;
    IF v_tenant IS NOT NULL THEN
        PERFORM set_config('app.current_tenant_id', v_tenant, true);
    END IF;
END
$body$;

REVOKE ALL ON FUNCTION audit.audit_ddl_end() FROM PUBLIC;

CREATE OR REPLACE FUNCTION audit.audit_ddl_drop()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_super   boolean := COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user), false);
    v_is_app  boolean := current_user IN ('ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer');
    r         record;
    v_bad     text;
    v_tenant  text;
    v_changes jsonb;
    v_ev      uuid;
    -- máscara (igual à de audit_ddl_end)
    v_q text; v_out text; v_pos int; v_len int; v_k int; v_i int; v_j int; v_j2 int; v_s int; v_end int;
    v_n int; v_d int; v_r int; v_pre int; v_esc boolean; v_c text; v_tag text; v_tok text; v_rep text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_event_trigger_dropped_objects()) THEN
        RETURN;
    END IF;

    -- 1. Guarda: um zz_audit_* só cai com a sua tabela (no mesmo comando).
    IF NOT v_super THEN
        SELECT string_agg(o.object_identity, ', ') INTO v_bad
        FROM pg_event_trigger_dropped_objects() o
        WHERE o.object_type = 'trigger'
          AND o.address_names[3] IN ('zz_audit_row', 'zz_audit_truncate')
          AND NOT EXISTS (SELECT 1 FROM pg_event_trigger_dropped_objects() t
                          WHERE t.object_type = 'table' AND t.address_names = o.address_names[1:2]);
        IF v_bad IS NOT NULL THEN
            RAISE EXCEPTION 'audit_ddl_drop: os triggers da caixa negra não se apagam (%)', v_bad
                USING ERRCODE = 'PTA04';
        END IF;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_event_trigger_dropped_objects() WHERE original) THEN
        RETURN;
    END IF;
    IF v_is_app AND NULLIF(current_setting('app.actor_type', true), '') IS NULL THEN
        RAISE EXCEPTION 'DDL sem ator por %', current_user USING ERRCODE = 'PTA01';
    END IF;

    -- 2. Query: máscara (PASSWORD/SECRET) + sha256 do mascarado + corte a 4096.
    v_q := current_query();
    IF v_q IS NOT NULL THEN
        v_out := ''; v_pos := 1; v_len := length(v_q);
        LOOP
            v_k := regexp_instr(v_q, '\m(password|secret)\M', v_pos, 1, 1, 'i');
            EXIT WHEN v_k IS NULL OR v_k = 0;
            v_i := v_k;
            IF substr(v_q, v_i, 1) = '"' THEN v_i := v_i + 1; END IF;
            LOOP
                v_c := substr(v_q, v_i, 2);
                IF v_c ~ '^[[:space:]=:]' THEN
                    v_i := v_i + 1;
                ELSIF v_c = '/*' THEN
                    v_j := strpos(substr(v_q, v_i + 2), '*/');
                    v_i := CASE WHEN v_j = 0 THEN v_len + 1 ELSE v_i + v_j + 3 END;
                ELSIF v_c = '--' THEN
                    v_j := strpos(substr(v_q, v_i), E'\n');
                    v_i := CASE WHEN v_j = 0 THEN v_len + 1 ELSE v_i + v_j END;
                ELSE
                    EXIT;
                END IF;
            END LOOP;
            v_out := v_out || substr(v_q, v_pos, v_i - v_pos);
            v_pre := CASE WHEN substr(v_q, v_i, 3) ~* '^u&''' THEN 2
                          WHEN substr(v_q, v_i, 2) ~* '^[ebxn]''' THEN 1 ELSE 0 END;
            v_esc := substr(v_q, v_i, 2) ~* '^e''';
            v_s := v_i + v_pre;
            v_c := substr(v_q, v_s, 1);
            v_end := NULL;
            IF v_c = '''' THEN
                v_n := length((regexp_match(substr(v_q, v_s, 1000), '^''+'))[1]);
                v_d := v_n & -v_n;
                v_j := v_s + v_d;
                LOOP
                    v_j2 := regexp_instr(v_q, CASE WHEN v_esc THEN '[''\\]' ELSE '''' END, v_j);
                    EXIT WHEN v_j2 = 0;
                    IF substr(v_q, v_j2, 1) = '\' THEN
                        v_j := v_j2 + 2;
                        CONTINUE;
                    END IF;
                    v_r := length((regexp_match(substr(v_q, v_j2, 1000), '^''+'))[1]);
                    IF v_r >= v_d AND v_r % (2 * v_d) <> 0 THEN
                        v_end := v_j2 + ((v_r - v_d) / (2 * v_d)) * (2 * v_d) + v_d;
                        EXIT;
                    END IF;
                    v_j := v_j2 + v_r;
                END LOOP;
                v_rep := substr(v_q, v_i, v_pre) || repeat('''', v_d) || '[redacted]'
                         || CASE WHEN v_end IS NULL THEN '' ELSE repeat('''', v_d) END;
            ELSIF v_c = '$' AND substr(v_q, v_s, 256) ~ '^\$([A-Za-z_][A-Za-z_0-9]*)?\$' THEN
                v_tag := substring(substr(v_q, v_s, 256) from '^(\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$)');
                v_j := strpos(substr(v_q, v_s + length(v_tag)), v_tag);
                IF v_j > 0 THEN
                    v_end := v_s + length(v_tag) + v_j - 1 + length(v_tag);
                END IF;
                v_rep := v_tag || '[redacted]' || CASE WHEN v_end IS NULL THEN '' ELSE v_tag END;
            ELSIF v_c = '"' THEN
                v_j := v_s + 1;
                LOOP
                    v_j2 := regexp_instr(v_q, '["\\]', v_j);
                    EXIT WHEN v_j2 = 0;
                    IF substr(v_q, v_j2, 1) = '\' THEN
                        v_j := v_j2 + 2;
                        CONTINUE;
                    END IF;
                    v_end := v_j2 + 1;
                    EXIT;
                END LOOP;
                v_rep := '"[redacted]' || CASE WHEN v_end IS NULL THEN '' ELSE '"' END;
            ELSE
                v_tok := substring(substr(v_q, v_s) from '^[^[:space:];,()''"]*');
                v_end := v_s + length(v_tok);
                v_rep := CASE WHEN v_tok = '' THEN '' ELSE '[redacted]' END;
            END IF;
            v_out := v_out || v_rep;
            v_pos := COALESCE(v_end, v_len + 1);
        END LOOP;
        v_out := v_out || substr(v_q, v_pos);
    END IF;
    v_changes := jsonb_build_object(
        'query_sha256', encode(sha256(convert_to(v_out, 'UTF8')), 'hex'),
        'query',        left(v_out, 4096),
        'truncated',    COALESCE(length(v_out) > 4096, false));

    -- 3. Um evento por objeto original, na cadeia da plataforma (tenant NULL).
    v_tenant := NULLIF(current_setting('app.current_tenant_id', true), '');
    IF v_tenant IS NOT NULL THEN
        PERFORM set_config('app.current_tenant_id', '', true);
    END IF;
    FOR r IN SELECT * FROM pg_event_trigger_dropped_objects() WHERE original LOOP
        IF v_is_app THEN
            -- Atribuição (expressão simples, sem SPI): a linha 2 do PG_CONTEXT em audit_append é exatamente
            -- 'PL/pgSQL function audit.audit_ddl_drop() line N at assignment' (caminho tolerante da L2).
            v_ev := audit.audit_append(
                ('ddl.drop_' || lower(replace(r.object_type, ' ', '_')))::text, lower(r.object_type)::text,
                r.object_identity::text, 'success'::text, NULL::text, v_changes::jsonb, NULL::uuid, NULL::uuid);
        ELSE
            PERFORM audit.audit_append_db(
                ('ddl.drop_' || lower(replace(r.object_type, ' ', '_')))::text, lower(r.object_type)::text,
                r.object_identity::text, v_changes::jsonb, NULL::uuid, NULL::uuid);
        END IF;
    END LOOP;
    IF v_tenant IS NOT NULL THEN
        PERFORM set_config('app.current_tenant_id', v_tenant, true);
    END IF;
END
$body$;

REVOKE ALL ON FUNCTION audit.audit_ddl_drop() FROM PUBLIC;

-- A de 2 argumentos sai por último (todos os chamadores já usam a de 3; a L2 deste bloco também).
DROP FUNCTION audit._chain_insert(audit.audit_events, boolean);

-- Sem TEMPORARY: os papéis da app deixam de criar funções/tabelas em pg_temp (o migrator, dono da BD, mantém).
DO $do$
BEGIN
    EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC, ptmarket_app, ptmarket_worker, ptmarket_price_writer',
                   current_database());
END
$do$;
$chg_0020$);

-- ---------------------------------------------------------------------------
-- APROVADA: 0023_mask_uuid (cartão 02/03f). Disparada por migrations/0023_audit_mask_uuid.sql. Exige 0020.
--   audit._redact_text deixa de corromper UUIDs dentro de texto (a regra do IBAN apanhava "ac77-73f5-8fa6" no
--   meio de um UUIDv7). Como o Rust (redact_str) e o Go (Redact): JWT/chaves e e-mail sobre o texto inteiro;
--   IBAN e NIB só nos troços FORA dos UUID (8-4-4-4-12 hex, qualquer caixa, entre fronteiras de palavra), que
--   voltam a entrar intactos; PAN, NIF, DNI/NIE e telefone procurados nos troços unidos por uma quebra de linha
--   (só para detetar, nunca devolvida; nenhuma regra a atravessa). Só esta função muda (assinatura, dono, grants,
--   IMMUTABLE PARALLEL SAFE e search_path ficam: CREATE OR REPLACE).
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0023_mask_uuid', '0020_mask_v2', $chg_0023$
CREATE OR REPLACE FUNCTION audit._redact_text(p_value text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    c_uuid constant text :=
        '\m[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\M';
    v_out  text;
    v_scan text;
    v_seg  text[];
    v_uuid text[];
    v_s    text;
    v_m    text;
    v_a    text[];
    v_d    text;
    v_g    text[];
    v_acc  text;
    v_i    integer;
    v_j    integer;
    v_k    integer;
    v_x    integer;
    v_sum  integer;
    v_n    bigint;
BEGIN
    -- 1. Marcadores já postos.
    IF p_value IS NULL OR p_value IN ('[redacted]', '[pii]', '[depth]') THEN
        RETURN p_value;
    END IF;
    -- 2. JWT (três segmentos base64url), prefixos de chaves de API (texto inteiro).
    IF p_value ~ '\meyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.'
       OR p_value ~ '[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}'
       OR p_value ~ '\m(sk_|rk_|ghp_|pk_live_|xox[bp]-)[A-Za-z0-9]'
       OR p_value ~ '\mAKIA[0-9A-Z]{16}' THEN
        RETURN '[redacted]';
    END IF;
    -- 3. E-mail (texto inteiro).
    IF p_value ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' THEN
        RETURN '[pii]';
    END IF;
    -- Troços fora dos UUID (n + 1) e os UUID (n), pela ordem. Um troço só começa com letra/dígito no início do
    -- texto e só acaba com letra/dígito no fim (antes e depois de um UUID há sempre uma não-palavra): as fronteiras
    -- \m \M dentro de um troço são as do texto inteiro. Contagens incoerentes → falha fechada.
    v_seg  := regexp_split_to_array(p_value, c_uuid);
    v_uuid := ARRAY(SELECT m[1] FROM regexp_matches(p_value, '(' || c_uuid || ')', 'g') AS m);
    IF cardinality(v_seg) IS DISTINCT FROM cardinality(v_uuid) + 1 THEN
        RETURN '[redacted]';
    END IF;
    v_out  := '';
    v_scan := '';
    FOR v_i IN 1 .. cardinality(v_seg) LOOP
        v_s := v_seg[v_i];
        -- 4. IBAN no sítio (qualquer caixa; entre grupos: espaço(s), NBSP, "-" ou ".") → ****4 últimos.
        FOR v_m IN
            SELECT m[1]
            FROM regexp_matches(v_s,
                '\m([A-Za-z]{2}[0-9]{2}(?:[A-Za-z0-9]{11,30}|(?:(?: +| |-|\.)[A-Za-z0-9]{4}){2,7}(?:(?: +| |-|\.)[A-Za-z0-9]{1,4})?)|[Pp][Tt]50(?:(?: +| |-|\.)?[0-9]){21})\M',
                'g') AS m
        LOOP
            v_s := replace(v_s, v_m, '****' || right(regexp_replace(v_m, '[^A-Za-z0-9]', '', 'g'), 4));
        END LOOP;
        -- 5. NIB PT: 21 dígitos (mesmos separadores) com os 2 dígitos de controlo certos → ****4 últimos.
        FOR v_m IN
            SELECT m[1]
            FROM regexp_matches(v_s, '\m([0-9](?:(?: +| |-|\.)?[0-9]){20})\M', 'g') AS m
        LOOP
            v_d := regexp_replace(v_m, '[^0-9]', '', 'g');
            IF 98 - ((left(v_d, 19)::numeric * 100) % 97) = right(v_d, 2)::numeric THEN
                v_s := replace(v_s, v_m, '****' || right(v_d, 4));
            END IF;
        END LOOP;
        IF v_i <= cardinality(v_uuid) THEN
            v_out  := v_out || v_s || v_uuid[v_i];
            v_scan := v_scan || v_s || E'\n';
        ELSE
            v_out  := v_out || v_s;
            v_scan := v_scan || v_s;
        END IF;
    END LOOP;
    -- 6. Só um UUID ou só uma data/hora ISO 8601: como está.
    IF v_out ~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
       OR v_out ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}([Tt ][0-9]{2}:[0-9]{2}(:[0-9]{2}([.,][0-9]+)?)?([Zz]|[+-][0-9]{2}(:?[0-9]{2})?)?)?$' THEN
        RETURN v_out;
    END IF;
    -- 7–10 procuram em v_scan (troços fora dos UUID, separados por uma quebra de linha); devolvem v_out.
    -- 7. PAN: 13–19 dígitos (espaço ou "-" entre eles) com Luhn válido, entre fronteiras de palavra (não dentro de
    --    um hash hexadecimal). Por grupos contíguos da sequência (um PAN seguido de outros números também conta).
    FOR v_m IN SELECT m[1] FROM regexp_matches(v_scan, '\m([0-9](?:[ -]?[0-9])*)\M', 'g') AS m LOOP
        CONTINUE WHEN length(v_m) < 13;
        v_g := regexp_split_to_array(v_m, '[ -]');
        FOR v_i IN 1 .. cardinality(v_g) LOOP
            v_acc := '';
            FOR v_j IN v_i .. cardinality(v_g) LOOP
                v_acc := v_acc || v_g[v_j];
                EXIT WHEN length(v_acc) > 19;
                CONTINUE WHEN length(v_acc) < 13;
                v_sum := 0;
                FOR v_k IN 1 .. length(v_acc) LOOP
                    v_x := substr(v_acc, length(v_acc) - v_k + 1, 1)::integer;
                    IF v_k % 2 = 0 THEN
                        v_x := v_x * 2;
                        IF v_x > 9 THEN
                            v_x := v_x - 9;
                        END IF;
                    END IF;
                    v_sum := v_sum + v_x;
                END LOOP;
                IF v_sum % 10 = 0 THEN
                    RETURN '[redacted]';
                END IF;
            END LOOP;
        END LOOP;
    END LOOP;
    -- 8. NIF PT: 9 dígitos entre fronteiras de palavra ("PT" opcional), 1.º ≠ 0, controlo módulo 11.
    FOR v_m IN SELECT m[1] FROM regexp_matches(v_scan, '\m(?:[Pp][Tt])?([1-9][0-9]{8})\M', 'g') AS m LOOP
        v_sum := 0;
        FOR v_k IN 1 .. 8 LOOP
            v_sum := v_sum + substr(v_m, v_k, 1)::integer * (10 - v_k);
        END LOOP;
        v_sum := v_sum % 11;
        IF (CASE WHEN v_sum < 2 THEN 0 ELSE 11 - v_sum END) = substr(v_m, 9, 1)::integer THEN
            RETURN '[pii]';
        END IF;
    END LOOP;
    -- 9. DNI (8 dígitos + letra) / NIE (X/Y/Z + 7 dígitos + letra) ES: letra = tabela[n mod 23].
    FOR v_a IN SELECT m FROM regexp_matches(v_scan, '\m([XYZxyz]?)([0-9]{7,8})([A-Za-z])\M', 'g') AS m LOOP
        IF (v_a[1] = '' AND length(v_a[2]) = 8) OR (v_a[1] <> '' AND length(v_a[2]) = 7) THEN
            v_n := (translate(upper(v_a[1]), 'XYZ', '012') || v_a[2])::bigint;
            IF substr('TRWAGMYFPDXBNJZSQVHLCKE', (v_n % 23)::integer + 1, 1) = upper(v_a[3]) THEN
                RETURN '[pii]';
            END IF;
        END IF;
    END LOOP;
    -- 10. Telefone: E.164 ("+" ou "00" + 8–15 dígitos; separadores espaço . - ( )) e PT nacional (9 dígitos a
    --     começar por 2 ou 9, com ou sem grupos de 3).
    FOR v_m IN
        SELECT m[1] FROM regexp_matches(v_scan, '(?:\+|(?:^|[^0-9A-Za-z_])00)((?:[ .()-]*[0-9])+)', 'g') AS m
    LOOP
        v_acc := '';
        FOREACH v_d IN ARRAY regexp_split_to_array(v_m, '[ .()-]+') LOOP
            v_acc := v_acc || v_d;
            IF length(v_acc) BETWEEN 8 AND 15 THEN
                RETURN '[pii]';
            END IF;
        END LOOP;
    END LOOP;
    IF v_scan ~ '\m[29][0-9]{2}(?:[ .-]?[0-9]{3}){2}\M' THEN
        RETURN '[pii]';
    END IF;
    RETURN v_out;
END
$body$;
$chg_0023$);

-- ---------------------------------------------------------------------------
-- APROVADA: 0025_admin_read_events (cartão 02/23a). Disparada por migrations/0025_audit_admin_read_events.sql.
--   Exige 0023. Timeline global do Super-Admin; só lê audit.* (a REGRA da 0008 fica: nada de public).
--   audit._admin_read_events_sql(7 × boolean): INVOKER, IMMUTABLE; devolve o texto da consulta com $1..$11 e só
--     os filtros pedidos (a DEFINER corre-o com EXECUTE … USING: plano por chamada com os valores, índices da
--     0008/0015; o teste faz EXPLAIN do mesmo texto). EXECUTE só para ptmarket_audit_writer.
--   audit.admin_read_events(…): DEFINER (dono ptmarket_audit_writer), STABLE. Recusa (42501) sem
--     app.actor_type = 'admin'; valida (22023, mensagens fixas) janela [p_from, p_to) ≤ 31 dias, 1 ≤ p_limit ≤ 100,
--     prefixo de ação ^[a-z0-9._]{1,100}$ (LIKE com '!' como escape de % e _), outcome da lista, cursor completo.
--     Ordem (created_at, id) DESC; página seguinte (created_at, id) < cursor; nunca OFFSET.
--     chain_ok: hash da linha = audit._event_hash (a única fórmula) e elo com o anterior da mesma cadeia
--     (chain_key, retention_class): seq 1 → prev_hash a zeros; seq − 1 único → prev_hash = hash dele; sem
--     seq − 1 → só aceite se não houver linhas mais antigas na cadeia (corte da retenção); repetido → false.
--     EXECUTE só para ptmarket_identity (dono NOLOGIN da DEFINER public.identity_admin_read_events, que faz a
--     porta super_admin + TOTP + sessão com 2FA); USAGE em audit para ptmarket_identity.
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0025_admin_read_events', '0023_mask_uuid', $chg_0025$
CREATE FUNCTION audit._admin_read_events_sql(p_tenant boolean, p_store boolean, p_actor boolean, p_order boolean,
    p_action boolean, p_outcome boolean, p_cursor boolean)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
    SELECT 'WITH page AS MATERIALIZED ('
        || ' SELECT e AS r FROM audit.audit_events e'
        || ' WHERE e.created_at >= $1 AND e.created_at < $2'
        || CASE WHEN p_tenant THEN ' AND e.tenant_id = $3' ELSE '' END
        || CASE WHEN p_store THEN ' AND e.store_id = $4' ELSE '' END
        || CASE WHEN p_actor THEN ' AND e.actor_id = $5' ELSE '' END
        || CASE WHEN p_order
                THEN ' AND ((e.target_type = ''order'' AND e.target_id = $6::text)'
                     || ' OR (e.changes ? ''order_id'' AND e.changes ->> ''order_id'' = $6::text))'
                ELSE '' END
        || CASE WHEN p_action THEN ' AND e.action LIKE $7 ESCAPE ''!''' ELSE '' END
        || CASE WHEN p_outcome THEN ' AND e.outcome = $8' ELSE '' END
        || CASE WHEN p_cursor THEN ' AND e.created_at <= $9 AND (e.created_at, e.id) < ($9, $10)' ELSE '' END
        || ' ORDER BY e.created_at DESC, e.id DESC LIMIT $11)'
        || ' SELECT (p.r).id, (p.r).created_at, (p.r).tenant_id, (p.r).store_id, (p.r).actor_type::text,'
        || ' (p.r).actor_id, (p.r).actor_label, (p.r).impersonator_id, (p.r).action::text, (p.r).target_type::text,'
        || ' (p.r).target_id, (p.r).outcome::text, (p.r).reason, (p.r).changes, (p.r).chain_seq,'
        || ' COALESCE((p.r).hash = audit._event_hash(p.r) AND CASE'
        || ' WHEN (p.r).chain_seq = 1 THEN (p.r).prev_hash = decode(repeat(''00'', 32), ''hex'')'
        || ' WHEN k.n = 1 THEN k.ok'
        || ' WHEN k.n = 0 THEN NOT EXISTS (SELECT 1 FROM audit.audit_events o'
        || ' WHERE o.chain_key = (p.r).chain_key AND o.retention_class = (p.r).retention_class'
        || ' AND o.chain_seq < (p.r).chain_seq)'
        || ' ELSE false END, false)'
        || ' FROM page p'
        || ' CROSS JOIN LATERAL (SELECT count(*) AS n, bool_and(q.hash = (p.r).prev_hash) AS ok'
        || ' FROM audit.audit_events q'
        || ' WHERE q.chain_key = (p.r).chain_key AND q.retention_class = (p.r).retention_class'
        || ' AND q.chain_seq = (p.r).chain_seq - 1) k'
        || ' ORDER BY (p.r).created_at DESC, (p.r).id DESC'
$body$;

REVOKE ALL ON FUNCTION audit._admin_read_events_sql(boolean, boolean, boolean, boolean, boolean, boolean, boolean)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._admin_read_events_sql(boolean, boolean, boolean, boolean, boolean, boolean, boolean)
    TO ptmarket_audit_writer;

CREATE FUNCTION audit.admin_read_events(p_from timestamptz, p_to timestamptz, p_tenant_id uuid, p_store_id uuid,
    p_actor_id uuid, p_order_id uuid, p_action_prefix text, p_outcome text, p_cursor_at timestamptz,
    p_cursor_id uuid, p_limit integer)
RETURNS TABLE (id uuid, created_at timestamptz, tenant_id uuid, store_id uuid, actor_type text, actor_id uuid,
    actor_label text, impersonator_id uuid, action text, target_type text, target_id text, outcome text,
    reason text, changes jsonb, chain_seq bigint, chain_ok boolean)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_like text;
BEGIN
    IF current_setting('app.actor_type', true) IS DISTINCT FROM 'admin' THEN
        RAISE EXCEPTION 'admin_read_events: acesso recusado' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_from IS NULL OR p_to IS NULL OR p_from >= p_to OR p_to - p_from > interval '31 days' THEN
        RAISE EXCEPTION 'admin_read_events: janela inválida (p_from < p_to, no máximo 31 dias)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'admin_read_events: p_limit fora de 1..100' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_action_prefix IS NOT NULL AND p_action_prefix !~ '^[a-z0-9._]{1,100}$' THEN
        RAISE EXCEPTION 'admin_read_events: prefixo de ação inválido' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_outcome IS NOT NULL AND p_outcome NOT IN ('success', 'denied', 'error') THEN
        RAISE EXCEPTION 'admin_read_events: outcome inválido' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF (p_cursor_at IS NULL) <> (p_cursor_id IS NULL) THEN
        RAISE EXCEPTION 'admin_read_events: cursor incompleto' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- LIKE de prefixo: '!' (fora do alfabeto aceite) escapa % e _.
    v_like := replace(replace(p_action_prefix, '%', '!%'), '_', '!_') || '%';

    RETURN QUERY EXECUTE audit._admin_read_events_sql(
            (p_tenant_id IS NOT NULL)::boolean, (p_store_id IS NOT NULL)::boolean, (p_actor_id IS NOT NULL)::boolean,
            (p_order_id IS NOT NULL)::boolean, (p_action_prefix IS NOT NULL)::boolean,
            (p_outcome IS NOT NULL)::boolean, (p_cursor_at IS NOT NULL)::boolean)
        USING p_from, p_to, p_tenant_id, p_store_id, p_actor_id, p_order_id, v_like, p_outcome, p_cursor_at,
              p_cursor_id, p_limit;
END
$body$;

REVOKE ALL ON FUNCTION audit.admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text,
    timestamptz, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text,
    timestamptz, uuid, integer) TO ptmarket_identity;
GRANT USAGE ON SCHEMA audit TO ptmarket_identity;
$chg_0025$);

-- ---------------------------------------------------------------------------
-- APROVADA: 0026_admin_read_events_v2 (achados da auditoria do cartão 02/23a). Disparada por
--   migrations/0026_audit_admin_read_events_v2.sql. Exige 0025. Assinaturas, donos e grants iguais (CREATE OR REPLACE).
--   audit.admin_read_events passa a VOLATILE e:
--     * recusa (42501) se session_user não for ptmarket_app (o SET ROLE não muda o session_user: o migrator e
--       outros logins não leem pela porta);
--     * janela máxima de 24 h sem filtro seletivo (tenant, loja, ator ou encomenda); 31 dias com um deles (22023);
--     * grava ela própria, por audit._chain_insert e na transação de quem chama, o evento
--       'admin.audit_timeline.read' (ator do contexto, como audit_append; outcome success; changes = os filtros, o
--       cursor só como booleano, e o número de linhas devolvidas): nenhuma leitura global fica fora da cadeia.
--   audit._admin_read_events_sql: chain_ok também verifica a cauda (uma linha sem seq + 1 só é true se
--     seq = audit_chain_heads.last_seq da cadeia) e as sondagens de seq − 1, seq + 1 e de linhas mais antigas
--     limitam created_at (poda de partições; created_at cresce com o seq, sob o lock da cabeça).
--     Sondagens como subconsultas escalares (nunca "hashed SubPlan": sempre pelo índice da cadeia ou pela PK das
--     cabeças, no máximo 100 linhas por página).
--     O prefixo da cadeia (linhas mais antigas apagadas, indistinguíveis do corte da retenção numa linha) não é
--     verificado aqui: é responsabilidade de audit.audit_verify_chain e da raiz diária em WORM.
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, requires, sql) VALUES ('0026_admin_read_events_v2', '0025_admin_read_events', $chg_0026$
CREATE OR REPLACE FUNCTION audit._admin_read_events_sql(p_tenant boolean, p_store boolean, p_actor boolean,
    p_order boolean, p_action boolean, p_outcome boolean, p_cursor boolean)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $body$
    SELECT 'WITH page AS MATERIALIZED ('
        || ' SELECT e AS r FROM audit.audit_events e'
        || ' WHERE e.created_at >= $1 AND e.created_at < $2'
        || CASE WHEN p_tenant THEN ' AND e.tenant_id = $3' ELSE '' END
        || CASE WHEN p_store THEN ' AND e.store_id = $4' ELSE '' END
        || CASE WHEN p_actor THEN ' AND e.actor_id = $5' ELSE '' END
        || CASE WHEN p_order
                THEN ' AND ((e.target_type = ''order'' AND e.target_id = $6::text)'
                     || ' OR (e.changes ? ''order_id'' AND e.changes ->> ''order_id'' = $6::text))'
                ELSE '' END
        || CASE WHEN p_action THEN ' AND e.action LIKE $7 ESCAPE ''!''' ELSE '' END
        || CASE WHEN p_outcome THEN ' AND e.outcome = $8' ELSE '' END
        || CASE WHEN p_cursor THEN ' AND e.created_at <= $9 AND (e.created_at, e.id) < ($9, $10)' ELSE '' END
        || ' ORDER BY e.created_at DESC, e.id DESC LIMIT $11)'
        || ' SELECT (p.r).id, (p.r).created_at, (p.r).tenant_id, (p.r).store_id, (p.r).actor_type::text,'
        || ' (p.r).actor_id, (p.r).actor_label, (p.r).impersonator_id, (p.r).action::text, (p.r).target_type::text,'
        || ' (p.r).target_id, (p.r).outcome::text, (p.r).reason, (p.r).changes, (p.r).chain_seq,'
        || ' COALESCE((p.r).hash = audit._event_hash(p.r)'
        || ' AND CASE'
        || ' WHEN (p.r).chain_seq = 1 THEN (p.r).prev_hash = decode(repeat(''00'', 32), ''hex'')'
        || ' WHEN k.n = 1 THEN k.ok'
        || ' WHEN k.n = 0 THEN (SELECT 1 FROM audit.audit_events o'
        || ' WHERE o.chain_key = (p.r).chain_key AND o.retention_class = (p.r).retention_class'
        || ' AND o.chain_seq < (p.r).chain_seq AND o.created_at <= (p.r).created_at LIMIT 1) IS NULL'
        || ' ELSE false END'
        || ' AND ((SELECT 1 FROM audit.audit_events s'
        || ' WHERE s.chain_key = (p.r).chain_key AND s.retention_class = (p.r).retention_class'
        || ' AND s.chain_seq = (p.r).chain_seq + 1 AND s.created_at >= (p.r).created_at LIMIT 1) IS NOT NULL'
        || ' OR (SELECT h.last_seq FROM audit.audit_chain_heads h'
        || ' WHERE h.chain_key = (p.r).chain_key AND h.retention_class = (p.r).retention_class)'
        || ' = (p.r).chain_seq), false)'
        || ' FROM page p'
        || ' CROSS JOIN LATERAL (SELECT count(*) AS n, bool_and(q.hash = (p.r).prev_hash) AS ok'
        || ' FROM audit.audit_events q'
        || ' WHERE q.chain_key = (p.r).chain_key AND q.retention_class = (p.r).retention_class'
        || ' AND q.chain_seq = (p.r).chain_seq - 1 AND q.created_at <= (p.r).created_at) k'
        || ' ORDER BY (p.r).created_at DESC, (p.r).id DESC'
$body$;

CREATE OR REPLACE FUNCTION audit.admin_read_events(p_from timestamptz, p_to timestamptz, p_tenant_id uuid,
    p_store_id uuid, p_actor_id uuid, p_order_id uuid, p_action_prefix text, p_outcome text, p_cursor_at timestamptz,
    p_cursor_id uuid, p_limit integer)
RETURNS TABLE (id uuid, created_at timestamptz, tenant_id uuid, store_id uuid, actor_type text, actor_id uuid,
    actor_label text, impersonator_id uuid, action text, target_type text, target_id text, outcome text,
    reason text, changes jsonb, chain_seq bigint, chain_ok boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
DECLARE
    v_selective boolean := p_tenant_id IS NOT NULL OR p_store_id IS NOT NULL OR p_actor_id IS NOT NULL
                           OR p_order_id IS NOT NULL;
    v_like      text;
    v_rows      bigint;
    v_row       audit.audit_events;
BEGIN
    IF session_user::text IS DISTINCT FROM 'ptmarket_app'
       OR current_setting('app.actor_type', true) IS DISTINCT FROM 'admin' THEN
        RAISE EXCEPTION 'admin_read_events: acesso recusado' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_from IS NULL OR p_to IS NULL OR p_from >= p_to OR p_to - p_from > interval '31 days' THEN
        RAISE EXCEPTION 'admin_read_events: janela inválida (p_from < p_to, no máximo 31 dias)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT v_selective AND p_to - p_from > interval '24 hours' THEN
        RAISE EXCEPTION 'admin_read_events: sem filtro de tenant, loja, ator ou encomenda a janela máxima é 24 h'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'admin_read_events: p_limit fora de 1..100' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_action_prefix IS NOT NULL AND p_action_prefix !~ '^[a-z0-9._]{1,100}$' THEN
        RAISE EXCEPTION 'admin_read_events: prefixo de ação inválido' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_outcome IS NOT NULL AND p_outcome NOT IN ('success', 'denied', 'error') THEN
        RAISE EXCEPTION 'admin_read_events: outcome inválido' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF (p_cursor_at IS NULL) <> (p_cursor_id IS NULL) THEN
        RAISE EXCEPTION 'admin_read_events: cursor incompleto' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- LIKE de prefixo: '!' (fora do alfabeto aceite) escapa % e _.
    v_like := replace(replace(p_action_prefix, '%', '!%'), '_', '!_') || '%';

    RETURN QUERY EXECUTE audit._admin_read_events_sql(
            (p_tenant_id IS NOT NULL)::boolean, (p_store_id IS NOT NULL)::boolean, (p_actor_id IS NOT NULL)::boolean,
            (p_order_id IS NOT NULL)::boolean, (p_action_prefix IS NOT NULL)::boolean,
            (p_outcome IS NOT NULL)::boolean, (p_cursor_at IS NOT NULL)::boolean)
        USING p_from, p_to, p_tenant_id, p_store_id, p_actor_id, p_order_id, v_like, p_outcome, p_cursor_at,
              p_cursor_id, p_limit;
    GET DIAGNOSTICS v_rows = ROW_COUNT;

    -- A própria leitura entra na cadeia (mesma transação; falhar aqui desfaz a leitura). Ator do contexto, como
    -- audit_append; changes = os filtros (ids e datas, sem dados pessoais), o cursor só como booleano.
    v_row.actor_type      := 'admin';
    v_row.actor_id        := NULLIF(current_setting('app.actor_id', true), '')::uuid;
    v_row.actor_label     := NULLIF(current_setting('app.actor_label', true), '');
    v_row.impersonator_id := NULLIF(current_setting('app.impersonator_id', true), '')::uuid;
    v_row.request_id      := NULLIF(current_setting('app.request_id', true), '')::uuid;
    v_row.ip              := NULLIF(current_setting('app.ip', true), '')::inet;
    v_row.user_agent_hash := decode(NULLIF(current_setting('app.user_agent_hash', true), ''), 'hex');
    v_row.tenant_id       := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
    v_row.action          := 'admin.audit_timeline.read';
    v_row.target_type     := 'audit_events';
    v_row.outcome         := 'success';
    v_row.changes         := jsonb_strip_nulls(jsonb_build_object(
        'from', p_from, 'to', p_to, 'tenant_id', p_tenant_id, 'store_id', p_store_id, 'actor_id', p_actor_id,
        'order_id', p_order_id, 'action_prefix', p_action_prefix, 'outcome', p_outcome,
        'cursor', p_cursor_at IS NOT NULL, 'limit', p_limit, 'rows', v_rows));
    PERFORM audit._chain_insert(v_row, false::boolean, false::boolean);
END
$body$;
$chg_0026$);

-- Upsert das aprovadas; recusa mudar o texto de uma já aplicada nesta BD.
DO $$
DECLARE
    v_bad text;
BEGIN
    SELECT string_agg(n.name, ', ') INTO v_bad
    FROM pg_temp.ptm_sealed_changes_new n
    JOIN audit_admin.sealed_changes c ON c.name = n.name
    JOIN audit_admin.sealed_changes_applied a ON a.name = n.name
    WHERE c.sha256 <> encode(sha256(convert_to(n.sql, 'UTF8')), 'hex');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '03-audit-bootstrap: texto de alteração selada já aplicada nesta BD mudou: % (corrigir = nova alteração)', v_bad;
    END IF;
    -- Cadeia linear: requires aponta para uma alteração aprovada (NULL só numa) e nenhuma tem duas sucessoras.
    SELECT string_agg(n.name, ', ') INTO v_bad
    FROM pg_temp.ptm_sealed_changes_new n
    WHERE n.requires IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM pg_temp.ptm_sealed_changes_new p WHERE p.name = n.requires);
    IF v_bad IS NOT NULL
       OR (SELECT count(*) FROM pg_temp.ptm_sealed_changes_new WHERE requires IS NULL) <> 1
       OR EXISTS (SELECT 1 FROM pg_temp.ptm_sealed_changes_new GROUP BY requires HAVING count(*) > 1) THEN
        RAISE EXCEPTION '03-audit-bootstrap: requires das alterações seladas não forma uma cadeia linear (%)', v_bad;
    END IF;
    INSERT INTO audit_admin.sealed_changes (name, requires, sql, sha256)
    SELECT n.name, n.requires, n.sql, encode(sha256(convert_to(n.sql, 'UTF8')), 'hex')
    FROM pg_temp.ptm_sealed_changes_new n
    ON CONFLICT (name) DO UPDATE SET requires = EXCLUDED.requires, sql = EXCLUDED.sql, sha256 = EXCLUDED.sha256;
END
$$;
DROP TABLE pg_temp.ptm_sealed_changes_new;

-- ---------------------------------------------------------------------------
-- audit_upgrade(nome, sha256): aplica UMA alteração aprovada, na transação da migration (falha = tudo desfeito).
--   Nome inexistente, sha256 diferente do aprovado, ou já aplicada nesta BD → RAISE. Nunca aceita SQL do chamador.
--   Sela antes (o que a migration criou até aqui deixa de ser de quem migra: nada dele toca no EXECUTE) e depois
--   (os objetos criados pelo EXECUTE nascem com dono postgres; a selagem passa-os para owner/writer).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_admin.audit_upgrade(p_name text, p_sha256 text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
    v_sql text;
    v_sha text;
    v_req text;
BEGIN
    IF p_name IS NULL OR p_sha256 IS NULL THEN
        RAISE EXCEPTION 'audit_upgrade: nome e sha256 obrigatórios';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ptmarket:audit_seal', 0));

    SELECT c.sql, c.sha256, c.requires INTO v_sql, v_sha, v_req
    FROM audit_admin.sealed_changes c
    WHERE c.name = p_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit_upgrade: alteração % não aprovada no bootstrap', p_name;
    END IF;
    IF v_req IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM audit_admin.sealed_changes_applied a WHERE a.name = v_req) THEN
        RAISE EXCEPTION 'audit_upgrade: % exige % aplicada antes nesta BD', p_name, v_req;
    END IF;
    IF v_sha IS DISTINCT FROM pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_sql, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION 'audit_upgrade: sealed_changes incoerente para % (reaplicar o bootstrap)', p_name;
    END IF;
    IF p_sha256 IS DISTINCT FROM v_sha THEN
        RAISE EXCEPTION 'audit_upgrade: sha256 de % difere do aprovado no bootstrap', p_name;
    END IF;
    IF EXISTS (SELECT 1 FROM audit_admin.sealed_changes_applied a WHERE a.name = p_name) THEN
        RAISE EXCEPTION 'audit_upgrade: % já foi aplicada nesta BD', p_name;
    END IF;

    PERFORM audit_admin.audit_seal();
    EXECUTE v_sql;
    INSERT INTO audit_admin.sealed_changes_applied (name, applied_at, session_user_name)
    VALUES (p_name, pg_catalog.clock_timestamp(), session_user);
    PERFORM audit_admin.audit_seal();
END
$fn$;

REVOKE ALL ON FUNCTION audit_admin.audit_upgrade(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_admin.audit_upgrade(text, text) TO ptmarket_migrator;
SQL
done
