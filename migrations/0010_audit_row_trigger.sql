-- 0010 — Caixa negra L1 (spec 13 §0, §3.2, §3.5): trigger genérico de auditoria em TODAS as tabelas.
-- Rollback mental (só em dev; depois da selagem quem migra não é dono de nada em audit.*: rollback do superuser):
--   para cada tabela do retrofit (tenants, categories, stores, products, product_variants, customers,
--   product_price_history, _sqlx_migrations): DROP TRIGGER zz_audit_row ON t; DROP TRIGGER zz_audit_truncate ON t;
--   DROP FUNCTION audit.audit_row_trigger(); DROP FUNCTION audit.audit_append_db(text,text,text,jsonb,uuid,uuid);
--   DROP FUNCTION audit.audit_redact(text, jsonb);
--   (os eventos já gravados ficam: a caixa negra é só de acréscimo.)
--
-- Modelo:
--   audit.audit_row_trigger() — SECURITY INVOKER (precisa do current_user real), dono ptmarket_audit_owner (selada).
--     app/worker/price_writer: ator obrigatório (sem app.actor_type → PTA01, a transação aborta) → audit_append.
--     Qualquer outro papel → audit_append_db ('db' + session_user), mesmo com app.* no contexto (quem não é a app
--     não escolhe o ator). Só o migrator (allowlist de grants da audit_seal) e o superuser têm EXECUTE nela:
--     outro papel qualquer falha fechado (42501). As ações referenciais (CASCADE/SET NULL) correm como dono da
--     tabela e ficam como 'db' com o session_user da sessão que as causou.
--     Dados como dono que passem por price_writer (ex.: INSERT/UPDATE de preço em product_variants, cujo trigger
--     DEFINER de 0007 escreve o histórico como ptmarket_price_writer) exigem ator explícito (app.actor_type);
--     sem ele, PTA01. Seeds de preços fazem-se com SET ROLE ptmarket_app + ator + contexto do tenant.
--   audit.audit_append_db(...) — SECURITY DEFINER (dono ptmarket_audit_writer, na allowlist do bootstrap):
--     actor_type = 'db' e actor_label = session_user calculados lá dentro; nenhum parâmetro os muda.
--   audit.audit_redact(tabela, changes) — máscara aplicada antes de gravar (§3.5), nos dois caminhos.
--   Triggers: zz_audit_row AFTER INSERT/UPDATE/DELETE FOR EACH ROW (último por ordem alfabética: vê a linha final)
--     e zz_audit_truncate BEFORE TRUNCATE FOR EACH STATEMENT; ambos ENABLE ALWAYS (session_replication_role não
--     os salta). Argumento opcional = coluna do target_id (por omissão 'id'; _sqlx_migrations usa 'version').
--   Exceções (allowlist fixa em migrations/tests/audit_l1.sql): audit_events, audit_chain_heads, outbox_events.
--   Tabela nova: CREATE TRIGGER zz_audit_row ... EXECUTE FUNCTION audit.audit_row_trigger() + zz_audit_truncate,
--     ambos ENABLE ALWAYS; sem isso o teste chumba.

-- ---------------------------------------------------------------------------
-- Máscara: segredos → "[redacted]"; IBAN → só os 4 últimos; PII → "[pii]". Opera em changes->'before'/'after'.
-- O evento diz QUE mudou, não o valor. Idempotente (o caminho 'db' volta a aplicá-la dentro da DEFINER).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_redact(p_table text, p_changes jsonb)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT CASE
        WHEN p_changes IS NULL OR jsonb_typeof(p_changes) <> 'object' THEN p_changes
        ELSE COALESCE((
            SELECT jsonb_object_agg(e.key, CASE
                WHEN e.key IN ('before', 'after') AND jsonb_typeof(e.value) = 'object' THEN COALESCE((
                    SELECT jsonb_object_agg(c.key, CASE
                        WHEN c.value = 'null'::jsonb THEN c.value
                        WHEN c.key ~* '(password|secret|token|credential|passkey|split_key|_enc$|_hash$)'
                            THEN '"[redacted]"'::jsonb
                        WHEN c.key ~* 'iban' THEN to_jsonb('****' || right(c.value #>> '{}', 4))
                        WHEN c.key ~* '(^|_)ip(_|$)'
                          OR (p_table = 'customers' AND c.key IN ('email', 'name', 'phone', 'nif'))
                          OR (p_table = 'users' AND c.key IN ('email', 'full_name'))
                            THEN '"[pii]"'::jsonb
                        ELSE c.value
                    END)
                    FROM jsonb_each(e.value) c), '{}'::jsonb)
                ELSE e.value
            END)
            FROM jsonb_each(p_changes) e), '{}'::jsonb)
    END
$$;

REVOKE ALL ON FUNCTION audit.audit_redact(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.audit_redact(text, jsonb)
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer, ptmarket_audit_writer;

-- ---------------------------------------------------------------------------
-- audit_append_db: mutações fora da app (migrator, superuser). Ator fixo: 'db' + session_user.
-- EXECUTE só para o migrator (dado pela audit_seal, allowlist de grants); app/worker/price_writer → 42501.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_append_db(
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
AS $$
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
    v_row.changes     := audit.audit_redact(p_target_type::text, p_changes);

    RETURN audit._chain_insert(v_row, false);
END
$$;

REVOKE ALL ON FUNCTION audit.audit_append_db(text, text, text, jsonb, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.audit_append_db(text, text, text, jsonb, uuid, uuid) TO ptmarket_migrator;

-- ---------------------------------------------------------------------------
-- audit_row_trigger: um evento por linha alterada (e um por TRUNCATE). Falha fechado.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_row_trigger()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
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
        PERFORM audit.audit_append(
            v_action::text, TG_TABLE_NAME::text, v_target::text, 'success'::text, NULL::text,
            audit.audit_redact(TG_TABLE_NAME::text, v_changes), v_store::uuid,
            CASE WHEN v_actor = 'system' THEN v_tenant END::uuid);
    ELSE
        PERFORM audit.audit_append_db(
            v_action::text, TG_TABLE_NAME::text, v_target::text, v_changes::jsonb, v_tenant::uuid, v_store::uuid);
    END IF;

    RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION audit.audit_row_trigger() FROM PUBLIC;
-- O disparo não verifica EXECUTE na função do trigger; o migrator recebe-o da audit_seal (CREATE TRIGGER).

-- ---------------------------------------------------------------------------
-- Retrofit: todas as tabelas de 0002–0007 e _sqlx_migrations (NÃO audit_events, audit_chain_heads, outbox_events).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT t.name, t.key
        FROM (VALUES
            ('tenants', NULL), ('categories', NULL), ('stores', NULL), ('products', NULL),
            ('product_variants', NULL), ('customers', NULL), ('product_price_history', NULL),
            ('_sqlx_migrations', 'version')
        ) AS t(name, key)
    LOOP
        EXECUTE format(
            'CREATE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE ON %I '
            'FOR EACH ROW EXECUTE FUNCTION audit.audit_row_trigger(%s)',
            r.name, COALESCE(quote_literal(r.key), ''));
        EXECUTE format(
            'CREATE TRIGGER zz_audit_truncate BEFORE TRUNCATE ON %I '
            'FOR EACH STATEMENT EXECUTE FUNCTION audit.audit_row_trigger(%s)',
            r.name, COALESCE(quote_literal(r.key), ''));
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER zz_audit_row', r.name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER zz_audit_truncate', r.name);
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- Selagem (última instrução): donos, privilégios, allowlists (DEFINER e grants) e verificação.
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_seal();
