-- 0009 — Caixa negra: funções do worker (gravação assíncrona do Redis Stream, verificação e raiz diária).
-- Rollback mental (só em dev, como superuser — depois da selagem quem migra não é dono de nada em audit.*;
-- em produção exportar e verificar a cadeia antes):
--   DROP FUNCTION audit.audit_append_event(jsonb);
--   DROP FUNCTION audit.audit_verify_chain(uuid, text, timestamptz, timestamptz);
--   DROP FUNCTION audit.audit_day_root(date); DROP FUNCTION audit.audit_chains();
--   DROP FUNCTION audit.audit_default_partition_rows();
--   (as linhas gravadas por audit_append_event ficam: são caixa negra, nunca se apagam.)
-- Todas: SECURITY DEFINER, dono ptmarket_audit_writer (pela selagem), EXECUTE só para ptmarket_worker.
-- Nenhuma apaga, altera ou filtra eventos; nenhuma tem parâmetro para saltar a cadeia.
-- audit_append_event grava por audit._chain_insert (0008): a mesma cabeça, o mesmo hash e o mesmo alerta de
-- audit_append; nunca procura a última linha nas partições. A verificação usa o mesmo audit._event_hash.
-- REGRA da 0008: nenhuma destas funções toca em objetos cujo dono tenha LOGIN (só audit.*).
-- Última instrução: SELECT audit_admin.audit_seal() (as funções novas estão na allowlist do bootstrap).

-- ---------------------------------------------------------------------------
-- audit_append_event: grava um evento do Redis Stream dentro da cadeia. true = gravou; false = já existia.
-- O ator vem do JSON (o pedido HTTP já acabou), nunca do contexto app.*.
-- Contrato inválido → SQLSTATE PTA02 (o worker manda para a fila morta). As mensagens só citam chaves,
-- nunca valores (podem conter dados pessoais).
-- Chaves com "|null" no contrato podem vir a null ou ausentes; as restantes são obrigatórias e não nulas.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_append_event(p_event jsonb)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_row      audit.audit_events;
    v_bad      text;
    v_occurred text;
    v_ua       text;
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

    -- Conversões: qualquer erro de dados (22xxx) passa a PTA02.
    BEGIN
        v_row.id              := (p_event ->> 'id')::uuid;
        v_row.tenant_id       := (p_event ->> 'tenant_id')::uuid;
        v_row.store_id        := (p_event ->> 'store_id')::uuid;
        v_row.actor_type      := p_event ->> 'actor_type';
        v_row.actor_id        := (p_event ->> 'actor_id')::uuid;
        v_row.actor_label     := p_event ->> 'actor_label';
        v_row.impersonator_id := (p_event ->> 'impersonator_id')::uuid;
        v_row.action          := p_event ->> 'action';
        v_row.target_type     := p_event ->> 'target_type';
        v_row.target_id       := p_event ->> 'target_id';
        v_row.outcome         := p_event ->> 'outcome';
        v_row.reason          := p_event ->> 'reason';
        v_row.changes         := CASE WHEN jsonb_typeof(p_event -> 'changes') = 'object'
                                      THEN p_event -> 'changes' END;
        v_row.request_id      := (p_event ->> 'request_id')::uuid;
        v_row.ip              := (p_event ->> 'ip')::inet;

        v_ua := p_event ->> 'user_agent_hash';
        IF v_ua IS NOT NULL THEN
            IF v_ua !~ '^([0-9a-fA-F]{2})+$' THEN
                RAISE EXCEPTION 'user_agent_hash não é hexadecimal' USING ERRCODE = 'invalid_parameter_value';
            END IF;
            v_row.user_agent_hash := decode(lower(v_ua), 'hex');
        END IF;

        v_occurred := p_event ->> 'occurred_at';
        IF v_occurred !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$' THEN
            RAISE EXCEPTION 'occurred_at não é RFC 3339' USING ERRCODE = 'invalid_datetime_format';
        END IF;
        v_row.occurred_at := v_occurred::timestamptz;
    EXCEPTION WHEN data_exception THEN
        RAISE EXCEPTION 'audit_append_event: valor inválido no contrato (%)', SQLERRM
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

    -- Cadeia, hash, idempotência (id já gravado ⇒ NULL) e alerta: a mesma implementação de audit_append.
    RETURN audit._chain_insert(v_row, true) IS NOT NULL;
END
$$;

-- ---------------------------------------------------------------------------
-- audit_verify_chain: recalcula a cadeia (chain_key, classe) nas linhas com created_at em [p_from, p_to),
-- por ordem de chain_seq. Uma linha por quebra; zero linhas = íntegra.
--   'hash' — hash gravado ≠ sha256(prev_hash || linha canónica)
--   'gap'  — chain_seq ≠ anterior + 1 (o elo dessa linha aponta para uma linha em falta: não se avalia 'link')
--   'link' — prev_hash ≠ hash da linha anterior
-- A 1.ª linha do intervalo aceita o prev_hash gravado (âncora = raiz diária publicada em WORM).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_verify_chain(p_chain_key uuid, p_class text, p_from timestamptz, p_to timestamptz)
RETURNS TABLE (broken_id uuid, broken_seq bigint, problem text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
#variable_conflict use_column
BEGIN
    IF p_chain_key IS NULL OR p_from IS NULL OR p_to IS NULL OR p_from >= p_to THEN
        RAISE EXCEPTION 'audit_verify_chain: parâmetros obrigatórios e p_from < p_to'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_class IS NULL OR p_class NOT IN ('fiscal', 'standard', 'security') THEN
        RAISE EXCEPTION 'audit_verify_chain: classe inválida' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    SELECT x.id, x.chain_seq, q.problem
    FROM (
        SELECT e.id, e.chain_seq, e.prev_hash, e.hash,
               audit._event_hash(e) AS recomputed,
               lag(e.hash) OVER w      AS prior_hash,
               lag(e.chain_seq) OVER w AS prior_seq
        FROM audit.audit_events e
        WHERE e.chain_key = p_chain_key
          AND e.retention_class = p_class
          AND e.created_at >= p_from
          AND e.created_at < p_to
        WINDOW w AS (ORDER BY e.chain_seq, e.created_at, e.id)
    ) x
    CROSS JOIN LATERAL (VALUES
        (1, 'hash'::text, x.hash IS DISTINCT FROM x.recomputed),
        (2, 'gap'::text,  x.prior_seq IS NOT NULL AND x.chain_seq <> x.prior_seq + 1),
        (3, 'link'::text, x.prior_seq IS NOT NULL AND x.chain_seq = x.prior_seq + 1
                          AND x.prev_hash IS DISTINCT FROM x.prior_hash)
    ) AS q(ord, problem, broken)
    WHERE q.broken
    ORDER BY x.chain_seq, q.ord;
END
$$;

-- ---------------------------------------------------------------------------
-- audit_day_root: por cadeia, os eventos com created_at no dia UTC p_day; last_hash = hash da última linha.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_day_root(p_day date)
RETURNS TABLE (chain_key uuid, retention_class text, first_seq bigint, last_seq bigint, last_hash bytea, events bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    v_from timestamptz;
    v_to   timestamptz;
BEGIN
    IF p_day IS NULL THEN
        RAISE EXCEPTION 'audit_day_root: p_day obrigatório' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_from := p_day::timestamp AT TIME ZONE 'UTC';
    v_to   := (p_day + 1)::timestamp AT TIME ZONE 'UTC';

    RETURN QUERY
    SELECT a.chain_key, a.retention_class::text, a.first_seq, a.last_seq, l.hash, a.events
    FROM (
        SELECT e.chain_key, e.retention_class, min(e.chain_seq) AS first_seq, max(e.chain_seq) AS last_seq,
               count(*) AS events
        FROM audit.audit_events e
        WHERE e.created_at >= v_from AND e.created_at < v_to
        GROUP BY e.chain_key, e.retention_class
    ) a
    JOIN LATERAL (
        SELECT e.hash
        FROM audit.audit_events e
        WHERE e.chain_key = a.chain_key
          AND e.retention_class = a.retention_class
          AND e.chain_seq = a.last_seq
          AND e.created_at >= v_from AND e.created_at < v_to
        ORDER BY e.created_at DESC, e.id DESC
        LIMIT 1
    ) l ON true
    ORDER BY a.chain_key, a.retention_class;
END
$$;

-- ---------------------------------------------------------------------------
-- audit_chains: as cadeias existentes, lidas das cabeças (não das partições).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_chains()
RETURNS TABLE (chain_key uuid, retention_class text, last_seq bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT h.chain_key, h.retention_class::text, h.last_seq
    FROM audit.audit_chain_heads h
    ORDER BY h.chain_key, h.retention_class;
$$;

-- ---------------------------------------------------------------------------
-- audit_default_partition_rows: linhas nas partições DEFAULT (> 0 = faltam partições mensais).
-- O escritor não tem privilégios nas partições: conta pelo pai, filtrando por tableoid (exato) e com o
-- complemento dos intervalos mensais da classe (poda as partições mensais; só a DEFAULT é lida).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_default_partition_rows()
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_class   text;
    v_parent  regclass;
    v_default oid;
    v_ranges  text;
    v_unknown bigint;
    v_n       bigint;
    v_total   bigint := 0;
BEGIN
    FOREACH v_class IN ARRAY ARRAY['fiscal', 'standard', 'security'] LOOP
        v_parent := to_regclass(format('audit.%I', 'audit_events_' || v_class));
        CONTINUE WHEN v_parent IS NULL;

        SELECT c.oid INTO v_default
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = v_parent
          AND pg_catalog.pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT';
        CONTINUE WHEN v_default IS NULL;

        SELECT string_agg(format('(e.created_at >= %L::timestamptz AND e.created_at < %L::timestamptz)',
                                 m[1], m[2]), ' OR '),
               count(*) FILTER (WHERE m IS NULL)
          INTO v_ranges, v_unknown
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
        CROSS JOIN LATERAL regexp_match(pg_catalog.pg_get_expr(c.relpartbound, c.oid),
                                        '^FOR VALUES FROM \(''([^'']+)''\) TO \(''([^'']+)''\)$') AS m
        WHERE i.inhparent = v_parent
          AND c.oid <> v_default;

        IF v_ranges IS NULL OR v_unknown > 0 THEN
            v_ranges := 'false'; -- limite não reconhecido: sem poda, conta só por tableoid (continua exato)
        END IF;

        EXECUTE format(
            'SELECT count(*) FROM audit.audit_events e '
            'WHERE e.retention_class = %L AND e.tableoid = %s::oid AND NOT (%s)',
            v_class, v_default, v_ranges)
        INTO v_n;
        v_total := v_total + v_n;
    END LOOP;

    RETURN v_total;
END
$$;

-- ---------------------------------------------------------------------------
-- Privilégios: só ptmarket_worker executa. O dono passa a ptmarket_audit_writer na selagem (o ACL de quem
-- migra transfere-se para o novo dono e a selagem retira-lhe o resto).
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION audit.audit_append_event(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.audit_verify_chain(uuid, text, timestamptz, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.audit_day_root(date) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.audit_chains() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.audit_default_partition_rows() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit.audit_append_event(jsonb) TO ptmarket_worker;
GRANT EXECUTE ON FUNCTION audit.audit_verify_chain(uuid, text, timestamptz, timestamptz) TO ptmarket_worker;
GRANT EXECUTE ON FUNCTION audit.audit_day_root(date) TO ptmarket_worker;
GRANT EXECUTE ON FUNCTION audit.audit_chains() TO ptmarket_worker;
GRANT EXECUTE ON FUNCTION audit.audit_default_partition_rows() TO ptmarket_worker;

-- ---------------------------------------------------------------------------
-- Selagem de audit.*: donos NOLOGIN, migrator e PUBLIC sem privilégios, allowlist, verificação.
-- Tem de ser a última instrução.
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_seal();
