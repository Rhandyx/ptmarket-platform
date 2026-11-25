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
        'audit.audit_verify_actors(uuid,text,timestamp with time zone,timestamp with time zone)'
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
