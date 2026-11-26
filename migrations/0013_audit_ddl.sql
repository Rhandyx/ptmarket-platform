-- 0013 — Caixa negra L2 (spec 13 §0; cartão 02/04): event triggers de DDL → audit_events ('ddl.*') e L1 automática
-- em tabelas novas de public.
--
-- LIMITE DO POSTGRESQL: event triggers NÃO disparam para objetos globais (CREATE/ALTER/DROP ROLE, GRANT de pertença
-- a papel, ALTER SYSTEM, CREATE/DROP DATABASE/TABLESPACE). Esses ficam cobertos só pela L3 (pgaudit, classe
-- `role`, cartão 05). Não há alternativa inventada. Não existe função nem GUC de bypass.
-- Outros limites (provados no PG 18): num GRANT/REVOKE, pg_event_trigger_ddl_commands() dá object_identity NULL
-- (o evento fica sem target_id; o alvo está em changes.query). DROP não aparece em ddl_command_end, só em sql_drop.
--
-- PASSO 0 (provado em postgres:18.7, 26/11/2026): CREATE EVENT TRIGGER exige superuser ("Must be superuser to
-- create an event trigger"), mesmo para o dono da BD. Caminho "Não": esta migration cria só as funções; os
-- CREATE EVENT TRIGGER vivem em infra/postgres/bootstrap/event-triggers.sql (idempotente, superuser, DEPOIS das
-- migrations: migrations/tests/run.sh, infra/scripts/dev-check.sh; em produção, passo de deploy). Sem esse passo a
-- L2 não existe (o teste migrations/tests/audit_ddl.sql chumba). As BDs do sqlx::test (de template1) não têm L2.
--
-- Rollback mental (só em dev, como superuser — objetos selados):
--   DROP EVENT TRIGGER audit_ddl_end; DROP EVENT TRIGGER audit_ddl_drop;
--   DROP FUNCTION audit.audit_ddl_end(); DROP FUNCTION audit.audit_ddl_drop();
--   REVOKE EXECUTE ON FUNCTION audit.audit_append_db(text,text,text,jsonb,uuid,uuid) FROM ptmarket_audit_owner;
--   DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0013_ddl_owner_exec';
--   (os eventos ddl.* gravados ficam; os zz_audit_* criados nas tabelas novas ficam.)
--
-- Modelo:
--   audit.audit_ddl_end()  — ddl_command_end. audit.audit_ddl_drop() — sql_drop. Ambas SECURITY INVOKER (dono
--     ptmarket_audit_owner pela selagem): correm como quem faz o DDL. O disparo não verifica EXECUTE na função do
--     event trigger; quem dispara precisa de EXECUTE em audit_append_db (o migrator tem; o superuser tem; o
--     ptmarket_audit_owner recebe-o pela alteração aprovada '0013_ddl_owner_exec', porque audit_ensure_partitions
--     corre como ele e cria partições). Outro papel sem EXECUTE falha fechado (42501). app/worker/price_writer
--     gravam por audit_append com ator obrigatório (sem app.actor_type → PTA01), como em 0010.
--     Toda a lógica vive dentro das duas funções: um auxiliar em audit.* ficava sem EXECUTE para quem migra
--     (a selagem tira-o; a allowlist de grants é fixa), por isso a máscara está repetida nas duas.
--   Evento: action = 'ddl.' || command_tag (minúsculas, espaços → '_') ou 'ddl.drop_' || object_type;
--     target_type = object_type (minúsculas); target_id = object_identity; tenant NULL (cadeia da plataforma:
--     app.current_tenant_id é limpo só durante a escrita e reposto); changes = {"query_sha256": hex do texto
--     JÁ MASCARADO inteiro (nunca do original: não depende da password), "query": texto mascarado cortado a 4096
--     caracteres, "truncated": bool}.
--   Máscara: a seguir às palavras PASSWORD/SECRET (palavra inteira, qualquer caixa) o literal seguinte é
--     substituído por '[redacted]': '…' (com aspas duplicadas a qualquer nível de aninhamento), E'…', U&'…',
--     $tag$…$tag$, "…" e palavra solta (ex.: password=… numa conninfo). Literal sem fim → '[redacted]' até ao fim.
--     Na dúvida, mascara a mais (nunca a menos).
--   L1 automática: CREATE TABLE / CREATE TABLE AS / SELECT INTO em public, tabela (não partição), fora de
--     {audit_events, outbox_events} → zz_audit_row (AFTER ROW I/U/D) + zz_audit_truncate (BEFORE TRUNCATE),
--     ambos ENABLE ALWAYS, como em 0010. As partições herdam o zz_audit_row do pai (PostgreSQL).
--   Guarda dos zz_audit_* (SQLSTATE PTA04, qualquer papel não superuser, o migrator incluído): depois de
--     qualquer comando sobre uma relação ou um trigger, os triggers zz_audit_* (por nome ou por função) dessa
--     relação e das suas partições têm de ser exatamente: função audit.audit_row_trigger, tgtype 29/34, sem WHEN,
--     sem colunas, sem constraint trigger, tgenabled 'A'. Recusa DISABLE, ENABLE (sem ALWAYS), ENABLE REPLICA,
--     CREATE OR REPLACE TRIGGER, RENAME. DROP de zz_audit_* (sql_drop) sem a tabela cair no mesmo comando →
--     PTA04. Única exceção: os comandos que o próprio audit_ddl_end executa na criação automática, reconhecidos
--     pela pilha de chamadas (PG_CONTEXT: o texto exato do comando seguido de "PL/pgSQL function
--     audit.audit_ddl_end() line N at EXECUTE"). Não é um bypass: quem forjasse a pilha só conseguia correr esses
--     mesmos comandos (criar o trigger certo, pô-lo em ALWAYS). A 0010 é anterior aos event triggers.
--     A guarda corre antes da escrita do evento: a recusa não depende do ator.

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0013: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
END
$$;

-- Alteração aprovada: EXECUTE em audit.audit_append_db para ptmarket_audit_owner (partições criadas por
-- audit_ensure_partitions ficam em ddl.create_table).
SELECT audit_admin.audit_upgrade(
    '0013_ddl_owner_exec'::text,
    'c3891813b63c51e6b2fef2378b8f6aa9577af49c62ae8cf89b8a6a2558bdd9e8'::text);

-- ---------------------------------------------------------------------------
-- audit_ddl_end (ddl_command_end): guarda dos zz_audit_*, L1 automática e um evento por comando.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_ddl_end()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
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
            PERFORM audit.audit_append(
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
$$;

REVOKE ALL ON FUNCTION audit.audit_ddl_end() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- audit_ddl_drop (sql_drop): guarda do DROP dos zz_audit_* e um evento por objeto original.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_ddl_drop()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_super   boolean := COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user), false);
    v_is_app  boolean := current_user IN ('ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer');
    r         record;
    v_bad     text;
    v_tenant  text;
    v_changes jsonb;
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
            PERFORM audit.audit_append(
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
$$;

REVOKE ALL ON FUNCTION audit.audit_ddl_drop() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Selagem (última instrução): as duas funções são INVOKER (dono ptmarket_audit_owner, sem allowlist).
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_seal();
