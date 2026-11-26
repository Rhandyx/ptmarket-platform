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
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer, ptmarket_audit_writer, ptmarket_migrator;
GRANT CREATE ON SCHEMA audit TO ptmarket_migrator;

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
--     EXECUTE) e em audit.audit_row_trigger (só para CREATE TRIGGER em tabelas novas; não se chama diretamente). O migrator mantém USAGE + CREATE no schema: pode criar
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
        'audit.audit_guc_defaults()'
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
        'ptmarket_audit_writer'
    ];
    -- ALLOWLIST DE GRANTS: EXECUTE (assinatura regprocedure, papel) mantido pela selagem.
    v_grant_sig   text[] := ARRAY[
        'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)',
        'audit.audit_row_trigger()'
    ];
    v_grant_role  text[] := ARRAY[
        'ptmarket_migrator',
        'ptmarket_migrator'
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
CREATE TEMP TABLE ptm_sealed_changes_new (name text PRIMARY KEY, sql text NOT NULL);

-- ---------------------------------------------------------------------------
-- APROVADA: 0011_db_user (cartão 02/03b). Disparada por migrations/0011_audit_db_user.sql.
--   audit_events.db_user = session_user (gravado por _chain_insert, dentro do hash): o session_user não muda com
--   SET ROLE nem dentro de DEFINER; só o superuser o muda. Linhas antigas (NULL) mantêm a fórmula do hash.
--   audit_append recusa app.actor_type fora da lista fechada, incluindo 'db' (só nasce em audit_append_db).
--   audit._db_user_since_us(): instante (µs desde a época, UTC) a partir do qual db_user NULL é anomalia.
-- ---------------------------------------------------------------------------
INSERT INTO pg_temp.ptm_sealed_changes_new (name, sql) VALUES ('0011_db_user', $chg_0011$
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
INSERT INTO pg_temp.ptm_sealed_changes_new (name, sql) VALUES ('0012_hardening', $chg_0012$
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
    INSERT INTO audit_admin.sealed_changes (name, sql, sha256)
    SELECT n.name, n.sql, encode(sha256(convert_to(n.sql, 'UTF8')), 'hex')
    FROM pg_temp.ptm_sealed_changes_new n
    ON CONFLICT (name) DO UPDATE SET sql = EXCLUDED.sql, sha256 = EXCLUDED.sha256;
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
BEGIN
    IF p_name IS NULL OR p_sha256 IS NULL THEN
        RAISE EXCEPTION 'audit_upgrade: nome e sha256 obrigatórios';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ptmarket:audit_seal', 0));

    SELECT c.sql, c.sha256 INTO v_sql, v_sha
    FROM audit_admin.sealed_changes c
    WHERE c.name = p_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit_upgrade: alteração % não aprovada no bootstrap', p_name;
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
