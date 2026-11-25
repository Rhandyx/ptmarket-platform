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
--   Verifica: donos certos; DEFINER com search_path fixo; quem chama sem privilégios em audit.*; nenhum papel
--     com LOGIN (não superuser) é membro de owner/writer/retention; nenhum objeto de audit.* (colunas, defaults,
--     constraints, triggers, políticas, índices, regras, funções) depende de um objeto cujo dono tenha LOGIN.
--     (Corpos plpgsql não registam dependências: isso prova-se em migrations/tests/audit_seal.sql.)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_admin.audit_seal()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
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
        'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)'
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
    FROM pg_roles
    WHERE (rolname = 'ptmarket_migrator' OR rolname = session_user) AND NOT rolsuper;

    -- 0. Allowlist e sobrecargas (antes de mudar donos).
    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO v_bad
    FROM pg_proc p
    WHERE p.pronamespace = v_ns AND p.prosecdef AND NOT (p.oid::regprocedure::text = ANY (v_allow_sig));
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: função SECURITY DEFINER fora da allowlist do bootstrap: %', v_bad;
    END IF;
    SELECT string_agg(DISTINCT p.proname, ', ') INTO v_bad
    FROM pg_proc p
    WHERE p.pronamespace = v_ns
      AND (SELECT count(*) FROM pg_proc q WHERE q.pronamespace = v_ns AND q.proname = p.proname) > 1;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: sobrecargas em audit (um nome = uma assinatura): %', v_bad;
    END IF;

    -- 1. Donos: relações (as partições e os índices não herdam o ALTER do pai; sequências de identidade
    --    e de serial seguem a tabela).
    FOR r IN
        SELECT c.oid, c.relkind
        FROM pg_class c
        WHERE c.relnamespace = v_ns
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          AND c.relowner <> v_owner
          AND NOT EXISTS (SELECT 1 FROM pg_depend d
                          WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
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
        FROM pg_type t
        LEFT JOIN pg_class c ON c.oid = t.typrelid
        WHERE t.typnamespace = v_ns
          AND t.typowner <> v_owner
          AND (t.typtype IN ('e', 'd', 'r', 'm') OR (t.typtype = 'c' AND c.relkind = 'c'))
    LOOP
        EXECUTE format('ALTER TYPE %s OWNER TO ptmarket_audit_owner', r.oid::regtype);
    END LOOP;

    FOR r IN
        SELECT p.oid, p.proname, p.prokind, p.prosecdef, p.proowner
        FROM pg_proc p
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
    FOR r IN SELECT c.oid, c.relkind FROM pg_class c
             WHERE c.relnamespace = v_ns AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') LOOP
        EXECUTE format('REVOKE ALL ON %s %s FROM PUBLIC',
            CASE WHEN r.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, r.oid::regclass);
        FOREACH v_c IN ARRAY COALESCE(v_callers, '{}') LOOP
            EXECUTE format('REVOKE ALL ON %s %s FROM %I',
                CASE WHEN r.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, r.oid::regclass, pg_get_userbyid(v_c));
        END LOOP;
    END LOOP;
    FOR r IN SELECT p.oid, p.prokind FROM pg_proc p WHERE p.pronamespace = v_ns LOOP
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
    FROM pg_class c WHERE c.relnamespace = v_ns AND c.relowner <> v_owner;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: relações de audit.* com dono errado: %', v_bad;
    END IF;

    SELECT string_agg(t.oid::regtype::text, ', ') INTO v_bad
    FROM pg_type t WHERE t.typnamespace = v_ns AND t.typowner <> v_owner;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: tipos de audit.* com dono errado: %', v_bad;
    END IF;

    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO v_bad
    FROM pg_proc p
    WHERE p.pronamespace = v_ns
      AND p.proowner IS DISTINCT FROM CASE WHEN p.prosecdef
                     THEN to_regrole(v_allow_owner[array_position(v_allow_sig, p.oid::regprocedure::text)])
                     ELSE v_owner END;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: funções de audit.* com dono errado: %', v_bad;
    END IF;

    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO v_bad
    FROM pg_proc p
    WHERE p.pronamespace = v_ns AND p.prosecdef
      AND NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) s WHERE s LIKE 'search\_path=%');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: funções SECURITY DEFINER sem search_path fixo: %', v_bad;
    END IF;

    -- Outros tipos de objeto no schema não são suportados (não há regra de dono para eles).
    SELECT string_agg(x, ', ') INTO v_bad FROM (
        SELECT 'operador ' || oid::regoperator::text AS x FROM pg_operator WHERE oprnamespace = v_ns
        UNION ALL SELECT 'opclass ' || opcname FROM pg_opclass WHERE opcnamespace = v_ns
        UNION ALL SELECT 'opfamily ' || opfname FROM pg_opfamily WHERE opfnamespace = v_ns
        UNION ALL SELECT 'collation ' || collname FROM pg_collation WHERE collnamespace = v_ns
        UNION ALL SELECT 'conversion ' || conname FROM pg_conversion WHERE connamespace = v_ns
        UNION ALL SELECT 'statistics ' || stxname FROM pg_statistic_ext WHERE stxnamespace = v_ns
        UNION ALL SELECT 'ts config ' || cfgname FROM pg_ts_config WHERE cfgnamespace = v_ns
        UNION ALL SELECT 'ts dict ' || dictname FROM pg_ts_dict WHERE dictnamespace = v_ns
    ) o;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: objetos não suportados em audit: %', v_bad;
    END IF;

    FOREACH v_c IN ARRAY COALESCE(v_callers, '{}') LOOP
        SELECT string_agg(c.oid::regclass::text, ', ') INTO v_bad
        FROM pg_class c
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
        FROM pg_class c
        WHERE c.relnamespace = v_ns
          AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(v_c, c.oid, 'USAGE, SELECT, UPDATE')
                   ELSE false END;
        IF v_bad IS NOT NULL THEN
            RAISE EXCEPTION 'audit_seal: % mantém privilégios nas sequências: %', pg_get_userbyid(v_c), v_bad;
        END IF;
        SELECT string_agg(p.oid::regprocedure::text, ', ') INTO v_bad
        FROM pg_proc p
        WHERE p.pronamespace = v_ns AND has_function_privilege(v_c, p.oid, 'EXECUTE')
          AND NOT EXISTS (SELECT 1 FROM generate_subscripts(v_grant_sig, 1) g(i)
                          WHERE v_grant_sig[g.i] = p.oid::regprocedure::text
                            AND v_grant_role[g.i] = pg_get_userbyid(v_c));
        IF v_bad IS NOT NULL THEN
            RAISE EXCEPTION 'audit_seal: % mantém EXECUTE (direto ou via PUBLIC) em: %', pg_get_userbyid(v_c), v_bad;
        END IF;
    END LOOP;

    SELECT string_agg(rl.rolname || ' ∈ ' || pg_get_userbyid(a.oid), ', ') INTO v_bad
    FROM pg_roles rl
    CROSS JOIN unnest(ARRAY[v_owner, v_writer, v_ret]) AS a(oid)
    WHERE rl.oid <> a.oid AND NOT rl.rolsuper AND pg_has_role(rl.oid, a.oid, 'MEMBER');
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: membership proibida em papéis de auditoria: %', v_bad;
    END IF;

    SELECT string_agg(rolname, ', ') INTO v_bad
    FROM pg_roles
    WHERE oid IN (v_owner, v_writer, v_ret)
      AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication);
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: papéis de auditoria com atributos proibidos: %', v_bad;
    END IF;

    WITH objs AS (
        SELECT 'pg_class'::regclass AS classid, c.oid AS objid FROM pg_class c WHERE c.relnamespace = v_ns
        UNION ALL SELECT 'pg_proc'::regclass, p.oid FROM pg_proc p WHERE p.pronamespace = v_ns
        UNION ALL SELECT 'pg_type'::regclass, t.oid FROM pg_type t WHERE t.typnamespace = v_ns
        UNION ALL SELECT 'pg_constraint'::regclass, k.oid FROM pg_constraint k WHERE k.connamespace = v_ns
        UNION ALL SELECT 'pg_trigger'::regclass, g.oid FROM pg_trigger g
                  JOIN pg_class c ON c.oid = g.tgrelid WHERE c.relnamespace = v_ns
        UNION ALL SELECT 'pg_policy'::regclass, p.oid FROM pg_policy p
                  JOIN pg_class c ON c.oid = p.polrelid WHERE c.relnamespace = v_ns
        UNION ALL SELECT 'pg_attrdef'::regclass, a.oid FROM pg_attrdef a
                  JOIN pg_class c ON c.oid = a.adrelid WHERE c.relnamespace = v_ns
        UNION ALL SELECT 'pg_rewrite'::regclass, w.oid FROM pg_rewrite w
                  JOIN pg_class c ON c.oid = w.ev_class WHERE c.relnamespace = v_ns
    ), refs AS (
        SELECT DISTINCT d.refclassid, d.refobjid
        FROM pg_depend d JOIN objs o ON o.classid = d.classid AND o.objid = d.objid
        WHERE d.deptype IN ('n', 'a')
    ), owners AS (
        SELECT f.refclassid, f.refobjid,
               CASE f.refclassid
                   WHEN 'pg_proc'::regclass      THEN (SELECT proowner FROM pg_proc WHERE oid = f.refobjid)
                   WHEN 'pg_class'::regclass     THEN (SELECT relowner FROM pg_class WHERE oid = f.refobjid)
                   WHEN 'pg_type'::regclass      THEN (SELECT typowner FROM pg_type WHERE oid = f.refobjid)
                   WHEN 'pg_operator'::regclass  THEN (SELECT oprowner FROM pg_operator WHERE oid = f.refobjid)
                   WHEN 'pg_opclass'::regclass   THEN (SELECT opcowner FROM pg_opclass WHERE oid = f.refobjid)
                   WHEN 'pg_opfamily'::regclass  THEN (SELECT opfowner FROM pg_opfamily WHERE oid = f.refobjid)
                   WHEN 'pg_collation'::regclass THEN (SELECT collowner FROM pg_collation WHERE oid = f.refobjid)
                   WHEN 'pg_namespace'::regclass THEN (SELECT nspowner FROM pg_namespace WHERE oid = f.refobjid)
                   WHEN 'pg_ts_config'::regclass THEN (SELECT cfgowner FROM pg_ts_config WHERE oid = f.refobjid)
                   WHEN 'pg_ts_dict'::regclass   THEN (SELECT dictowner FROM pg_ts_dict WHERE oid = f.refobjid)
                   WHEN 'pg_language'::regclass  THEN (SELECT lanowner FROM pg_language WHERE oid = f.refobjid)
               END AS owner,
               f.refclassid IN ('pg_proc'::regclass, 'pg_class'::regclass, 'pg_type'::regclass,
                                'pg_operator'::regclass, 'pg_opclass'::regclass, 'pg_opfamily'::regclass,
                                'pg_collation'::regclass, 'pg_namespace'::regclass, 'pg_ts_config'::regclass,
                                'pg_ts_dict'::regclass, 'pg_language'::regclass) AS known
        FROM refs f
    )
    SELECT string_agg(pg_describe_object(o.refclassid, o.refobjid, 0), ', ') INTO v_bad
    FROM owners o
    LEFT JOIN pg_roles rl ON rl.oid = o.owner
    WHERE (o.known AND rl.rolcanlogin AND NOT rl.rolsuper)
       OR (NOT o.known AND NOT EXISTS (
               SELECT 1 FROM pg_depend d2
               WHERE d2.classid = o.refclassid AND d2.objid = o.refobjid
                 AND d2.refclassid = 'pg_class'::regclass
                 AND d2.refobjid IN (SELECT c.oid FROM pg_class c WHERE c.relnamespace = v_ns)));
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'audit_seal: audit.* depende de objetos de papéis com LOGIN (ou não verificáveis): %', v_bad;
    END IF;
END
$fn$;

REVOKE ALL ON FUNCTION audit_admin.audit_seal() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_admin.audit_seal() TO ptmarket_migrator;
SQL
done
