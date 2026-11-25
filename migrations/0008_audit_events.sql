-- 0008 — Caixa negra: audit_events (tabela única, particionada, só de acréscimo, encadeada por hash).
-- Rollback mental (só em dev; em produção a caixa negra é prova — exportar e verificar a cadeia antes):
--   DROP POLICY audit_writer_insert ON outbox_events; REVOKE INSERT ON outbox_events FROM ptmarket_audit_writer;
--   ALTER POLICY app_insert ON outbox_events WITH CHECK (<expressão de 0006>);
--   SET ROLE ptmarket_audit_writer; DROP FUNCTION audit_append(text, text, text, text, text, jsonb, uuid, uuid);
--   DROP TABLE audit_chain_heads; RESET ROLE;
--   DROP FUNCTION audit_ensure_partitions(int);
--   DROP TABLE audit_events;  (partições, políticas, grants, índices e triggers caem com a tabela;
--     o trigger BEFORE TRUNCATE não impede o DROP — a retenção faz-se por DROP de partição.)
--   DROP FUNCTION audit_events_immutable(); DROP FUNCTION audit_retention_class(text, text);
--   REVOKE USAGE ON SCHEMA public FROM ptmarket_audit_writer;
--   DROP ROLE ptmarket_audit_writer; DROP ROLE ptmarket_audit_retention;
--   (os papéis podem ser partilhados por outras BDs do cluster.)
-- Quem escreve é só audit_append (SECURITY DEFINER, dono ptmarket_audit_writer); o ator vem só do
-- contexto da transação (app.*), nunca por parâmetro. Ninguém (dono incluído) altera, apaga ou trunca:
-- REVOKE + triggers que fazem sempre RAISE; não existe GUC, coluna nem função para os desligar.
-- Uma cadeia por (chain_key, retention_class): o DROP de partições de uma classe não parte as outras.

-- ---------------------------------------------------------------------------
-- Papéis (padrão de 0007). ptmarket_audit_retention fica SEM privilégios (retenção = decisão do owner).
-- ---------------------------------------------------------------------------
-- Papéis são do cluster e o advisory lock é por BD: várias BDs a migrar em paralelo (sqlx::test) correm
-- na mesma; por isso "já existe" (duplicate_object/unique_violation) conta como sucesso.
DO $$
DECLARE
    r text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('ptmarket:migration:roles', 0));

    FOREACH r IN ARRAY ARRAY['ptmarket_audit_writer', 'ptmarket_audit_retention'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            BEGIN
                EXECUTE format(
                    'CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                    r
                );
            EXCEPTION WHEN duplicate_object OR unique_violation THEN
                NULL; -- criado por outra sessão em paralelo; as verificações abaixo aplicam-se na mesma
            END;
        END IF;

        IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE rolname = r AND (rolsuper OR rolbypassrls)
        ) THEN
            RAISE EXCEPTION 'O papel % já existe com SUPERUSER ou BYPASSRLS; recusado.', r;
        END IF;

        IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
           AND NOT pg_has_role(current_user, r, 'SET') THEN
            BEGIN
                EXECUTE format('GRANT %I TO %I WITH INHERIT FALSE, SET TRUE', r, current_user);
            EXCEPTION WHEN duplicate_object OR unique_violation THEN
                NULL; -- concedido por outra sessão em paralelo
            END;
        END IF;
    END LOOP;
END
$$;

GRANT USAGE ON SCHEMA public TO ptmarket_audit_writer;

-- ---------------------------------------------------------------------------
-- Tabela: LIST (retention_class) → RANGE (created_at) mensal + DEFAULT por classe.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_events (
    id               UUID         NOT NULL,
    tenant_id        UUID, -- NULL = plataforma; sem FK (a caixa negra sobrevive ao tenant)
    chain_key        UUID         NOT NULL, -- COALESCE(tenant_id, uuid zero)
    store_id         UUID,
    actor_type       VARCHAR(16)  NOT NULL CHECK (actor_type IN (
                         'customer', 'merchant', 'municipal', 'admin', 'system', 'api_key', 'db', 'anonymous')),
    actor_id         UUID,
    actor_label      TEXT, -- 'db': papel/session_user; 'system': job
    impersonator_id  UUID,
    action           VARCHAR(96)  NOT NULL,
    target_type      VARCHAR(64),
    target_id        TEXT,
    outcome          VARCHAR(8)   NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    reason           TEXT,
    changes          JSONB, -- já mascarado por quem chama
    request_id       UUID,
    ip               INET,
    user_agent_hash  BYTEA,
    retention_class  VARCHAR(8)   NOT NULL CHECK (retention_class IN ('fiscal', 'standard', 'security')),
    occurred_at      TIMESTAMPTZ  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL,
    chain_seq        BIGINT       NOT NULL CHECK (chain_seq >= 1),
    prev_hash        BYTEA        NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash             BYTEA        NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (retention_class, created_at, id)
) PARTITION BY LIST (retention_class);

CREATE TABLE audit_events_fiscal PARTITION OF audit_events
    FOR VALUES IN ('fiscal') PARTITION BY RANGE (created_at);
CREATE TABLE audit_events_standard PARTITION OF audit_events
    FOR VALUES IN ('standard') PARTITION BY RANGE (created_at);
CREATE TABLE audit_events_security PARTITION OF audit_events
    FOR VALUES IN ('security') PARTITION BY RANGE (created_at);

-- Um INSERT nunca falha por falta de partição mensal.
CREATE TABLE audit_events_fiscal_default PARTITION OF audit_events_fiscal DEFAULT;
CREATE TABLE audit_events_standard_default PARTITION OF audit_events_standard DEFAULT;
CREATE TABLE audit_events_security_default PARTITION OF audit_events_security DEFAULT;

-- Índices no pai: propagam-se a todas as partições, incluindo as futuras.
CREATE INDEX audit_events_tenant_created_idx ON audit_events (tenant_id, created_at);
CREATE INDEX audit_events_target_created_idx ON audit_events (target_type, target_id, created_at);
CREATE INDEX audit_events_chain_idx ON audit_events (chain_key, chain_seq DESC);
CREATE INDEX audit_events_id_idx ON audit_events (id);

-- ---------------------------------------------------------------------------
-- Imutabilidade: trigger que faz sempre RAISE (linha: UPDATE/DELETE; instrução: TRUNCATE).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit_events_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events é só de acréscimo: % recusado em %', TG_OP, TG_TABLE_NAME;
END
$$;

REVOKE ALL ON FUNCTION audit_events_immutable() FROM PUBLIC;

-- Trigger de linha no pai: clonado para todas as partições (atuais e futuras).
CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

-- TRUNCATE é de instrução (não é clonado): no pai e em cada partição; as mensais em audit_ensure_partitions.
-- Nas partições ninguém escreve diretamente (o encaminhamento via pai não verifica privilégios da partição):
-- o dono fica só com SELECT (backup/inspeção), sem INSERT/UPDATE/DELETE/TRUNCATE.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'audit_events',
        'audit_events_fiscal', 'audit_events_standard', 'audit_events_security',
        'audit_events_fiscal_default', 'audit_events_standard_default', 'audit_events_security_default'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON public.%I '
            'FOR EACH STATEMENT EXECUTE FUNCTION public.audit_events_immutable()', t);
        EXECUTE format(
            'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I FROM PUBLIC, %I', t, current_user);
    END LOOP;
END
$$;

REVOKE UPDATE, DELETE, TRUNCATE ON audit_events
    FROM ptmarket_app, ptmarket_worker, ptmarket_price_writer,
         ptmarket_audit_writer, ptmarket_audit_retention;

-- ---------------------------------------------------------------------------
-- RLS: só o escritor insere/lê tudo; a app lê só o seu tenant. Leitura global do admin = épico admin.
-- ---------------------------------------------------------------------------
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY writer_insert ON audit_events
    FOR INSERT TO ptmarket_audit_writer
    WITH CHECK (true);

CREATE POLICY writer_select ON audit_events
    FOR SELECT TO ptmarket_audit_writer
    USING (true);

CREATE POLICY tenant_read ON audit_events
    FOR SELECT TO ptmarket_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

GRANT INSERT, SELECT ON audit_events TO ptmarket_audit_writer;
GRANT SELECT ON audit_events TO ptmarket_app;

-- O escritor só publica no outbox eventos da própria caixa negra.
CREATE POLICY audit_writer_insert ON outbox_events
    FOR INSERT TO ptmarket_audit_writer
    WITH CHECK (aggregate = 'audit');

GRANT INSERT ON outbox_events TO ptmarket_audit_writer; -- sem SELECT/UPDATE

-- A app deixa de poder criar eventos 'audit' (nem globais nem de tenant): só o escritor os forja.
-- (0006 é imutável; a política app_insert é redefinida aqui com a mesma regra de tenant.)
ALTER POLICY app_insert ON outbox_events
    WITH CHECK (
        aggregate <> 'audit'
        AND (
            tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            OR (
                tenant_id IS NULL
                AND NULLIF(current_setting('app.current_tenant_id', true), '')::uuid IS NULL
            )
        )
    );

-- ---------------------------------------------------------------------------
-- Cabeça de cada cadeia (chain_key, retention_class): serializa audit_append por bloqueio de linha.
-- Em READ COMMITTED a 2.ª transação espera e lê a cabeça nova; em REPEATABLE READ/SERIALIZABLE recebe
-- 40001 (o chamador repete) — nunca há bifurcação. Não particionada: sobrevive ao DROP de partições.
-- Dono = ptmarket_audit_writer, só SELECT/INSERT/UPDATE; app/worker sem qualquer acesso.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_chain_heads (
    chain_key       UUID        NOT NULL,
    retention_class VARCHAR(8)  NOT NULL CHECK (retention_class IN ('fiscal', 'standard', 'security')),
    last_seq        BIGINT      NOT NULL CHECK (last_seq >= 0),
    last_hash       BYTEA       NOT NULL CHECK (octet_length(last_hash) = 32),
    PRIMARY KEY (chain_key, retention_class)
);

ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads FORCE ROW LEVEL SECURITY;

CREATE POLICY writer_all ON audit_chain_heads
    FOR ALL TO ptmarket_audit_writer
    USING (true)
    WITH CHECK (true);

REVOKE ALL ON audit_chain_heads FROM PUBLIC;
GRANT CREATE ON SCHEMA public TO ptmarket_audit_writer;
ALTER TABLE audit_chain_heads OWNER TO ptmarket_audit_writer;
REVOKE CREATE ON SCHEMA public FROM ptmarket_audit_writer;
SET ROLE ptmarket_audit_writer;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON audit_chain_heads FROM ptmarket_audit_writer;
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Classe de retenção (define a partição e a cadeia).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit_retention_class(p_action text, p_outcome text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
    SELECT CASE
        WHEN p_outcome = 'denied' THEN 'security'
        WHEN EXISTS (
            SELECT 1
            FROM unnest(ARRAY[
                'orders.', 'sub_orders.', 'sub_order_items.', 'payments.', 'refunds.', 'payouts.',
                'invoices.', 'loyalty_ledger.', 'product_price_history.', 'product_variants.',
                'order.', 'payment.', 'refund.', 'payout.', 'invoice.', 'price.'
            ]) AS p(prefix)
            WHERE starts_with(p_action, p.prefix)
        ) THEN 'fiscal'
        ELSE 'standard'
    END
$$;

-- ---------------------------------------------------------------------------
-- Partições mensais (UTC): mês corrente + N, nas 3 classes. Idempotente; devolve quantas criou.
-- Se a DEFAULT já tiver linhas desse mês, a partição não é criada (WARNING) e as outras seguem.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit_ensure_partitions(p_months_ahead int)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_class   text;
    v_month   timestamp;
    v_from    timestamptz;
    v_to      timestamptz;
    v_name    text;
    v_created int := 0;
BEGIN
    IF p_months_ahead IS NULL OR p_months_ahead < 0 OR p_months_ahead > 36 THEN
        RAISE EXCEPTION 'audit_ensure_partitions: p_months_ahead fora de [0, 36]: %', p_months_ahead
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Dois workers em simultâneo não competem pela mesma partição.
    PERFORM pg_advisory_xact_lock(hashtextextended('audit:partitions', 0));

    FOREACH v_class IN ARRAY ARRAY['fiscal', 'standard', 'security'] LOOP
        FOR i IN 0..p_months_ahead LOOP
            v_month := date_trunc('month', now() AT TIME ZONE 'UTC') + make_interval(months => i);
            v_from  := v_month AT TIME ZONE 'UTC';
            v_to    := (v_month + interval '1 month') AT TIME ZONE 'UTC';
            v_name  := format('audit_events_%s_y%sm%s', v_class, to_char(v_month, 'YYYY'), to_char(v_month, 'MM'));

            CONTINUE WHEN to_regclass(format('public.%I', v_name)) IS NOT NULL;

            BEGIN
                EXECUTE format(
                    'CREATE TABLE public.%I PARTITION OF public.%I FOR VALUES FROM (%L) TO (%L)',
                    v_name, 'audit_events_' || v_class, v_from, v_to);
                EXECUTE format(
                    'CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON public.%I '
                    'FOR EACH STATEMENT EXECUTE FUNCTION public.audit_events_immutable()', v_name);
                EXECUTE format(
                    'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I FROM PUBLIC, %I',
                    v_name, current_user);
                v_created := v_created + 1;
            EXCEPTION WHEN check_violation THEN
                RAISE WARNING 'audit_ensure_partitions: % não criada (a DEFAULT já tem linhas desse mês)',
                    v_name;
            END;
        END LOOP;
    END LOOP;

    RETURN v_created;
END
$$;

REVOKE ALL ON FUNCTION audit_ensure_partitions(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_ensure_partitions(int) TO ptmarket_worker;

SELECT audit_ensure_partitions(3);

-- ---------------------------------------------------------------------------
-- audit_append: única porta de escrita. Ator só do contexto; cadeia serializada pela linha de audit_chain_heads.
-- Relações sempre qualificadas com public. (o search_path imposto não lista pg_temp).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit_append(
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
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_row        public.audit_events%ROWTYPE;
    v_ctx_tenant uuid;
BEGIN
    v_row.actor_type := NULLIF(current_setting('app.actor_type', true), '');
    IF v_row.actor_type IS NULL THEN
        RAISE EXCEPTION 'audit_append: app.actor_type em falta (ator obrigatório)'
            USING ERRCODE = 'PTA01';
    END IF;
    v_row.actor_id        := NULLIF(current_setting('app.actor_id', true), '')::uuid;
    v_row.actor_label     := NULLIF(current_setting('app.actor_label', true), '');
    v_row.impersonator_id := NULLIF(current_setting('app.impersonator_id', true), '')::uuid;
    v_row.request_id      := NULLIF(current_setting('app.request_id', true), '')::uuid;
    v_row.ip              := NULLIF(current_setting('app.ip', true), '')::inet;
    v_row.user_agent_hash := decode(NULLIF(current_setting('app.user_agent_hash', true), ''), 'hex');

    v_ctx_tenant := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid;
    IF v_ctx_tenant IS NOT NULL AND p_tenant_id IS NOT NULL AND v_ctx_tenant <> p_tenant_id THEN
        RAISE EXCEPTION 'audit_append: p_tenant_id difere de app.current_tenant_id';
    END IF;
    v_row.tenant_id := COALESCE(v_ctx_tenant, p_tenant_id);
    v_row.chain_key := COALESCE(v_row.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid);

    v_row.store_id        := p_store_id;
    v_row.action          := p_action;
    v_row.target_type     := p_target_type;
    v_row.target_id       := p_target_id;
    v_row.outcome         := p_outcome;
    v_row.reason          := p_reason;
    v_row.changes         := p_changes;
    v_row.retention_class := public.audit_retention_class(p_action, p_outcome);

    -- Cabeça da cadeia (génese: seq 0 + 32 bytes a zero) e bloqueio da linha até ao fim da transação.
    INSERT INTO public.audit_chain_heads (chain_key, retention_class, last_seq, last_hash)
    VALUES (v_row.chain_key, v_row.retention_class, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT DO NOTHING;

    SELECT h.last_seq + 1, h.last_hash INTO STRICT v_row.chain_seq, v_row.prev_hash
    FROM public.audit_chain_heads h
    WHERE h.chain_key = v_row.chain_key
      AND h.retention_class = v_row.retention_class
    FOR UPDATE;

    -- Depois do lock: created_at cresce com chain_seq dentro de cada cadeia.
    v_row.created_at  := clock_timestamp();
    v_row.occurred_at := v_row.created_at;
    v_row.id          := uuidv7();

    v_row.hash := sha256(v_row.prev_hash || convert_to(jsonb_build_array(
        v_row.id, v_row.tenant_id, v_row.store_id, v_row.actor_type, v_row.actor_id, v_row.actor_label,
        v_row.impersonator_id, v_row.action, v_row.target_type, v_row.target_id, v_row.outcome,
        v_row.reason, v_row.changes, v_row.request_id, host(v_row.ip), encode(v_row.user_agent_hash, 'hex'),
        v_row.retention_class,
        (extract(epoch FROM v_row.occurred_at) * 1000000)::bigint,
        (extract(epoch FROM v_row.created_at) * 1000000)::bigint,
        v_row.chain_seq
    )::text, 'UTF8'));

    INSERT INTO public.audit_events (
        id, tenant_id, chain_key, store_id, actor_type, actor_id, actor_label, impersonator_id,
        action, target_type, target_id, outcome, reason, changes, request_id, ip, user_agent_hash,
        retention_class, occurred_at, created_at, chain_seq, prev_hash, hash
    ) VALUES (
        v_row.id, v_row.tenant_id, v_row.chain_key, v_row.store_id, v_row.actor_type, v_row.actor_id,
        v_row.actor_label, v_row.impersonator_id, v_row.action, v_row.target_type, v_row.target_id,
        v_row.outcome, v_row.reason, v_row.changes, v_row.request_id, v_row.ip, v_row.user_agent_hash,
        v_row.retention_class, v_row.occurred_at, v_row.created_at, v_row.chain_seq, v_row.prev_hash,
        v_row.hash
    );

    UPDATE public.audit_chain_heads
       SET last_seq = v_row.chain_seq, last_hash = v_row.hash
     WHERE chain_key = v_row.chain_key
       AND retention_class = v_row.retention_class;

    -- Ação de admin ou com impersonação: sinal imediato fora da BD (mesma transação).
    IF v_row.actor_type = 'admin' OR v_row.impersonator_id IS NOT NULL THEN
        INSERT INTO public.outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
        VALUES (
            NULL, 'audit', v_row.id, 'audit.superadmin_action',
            to_jsonb(v_row) || jsonb_build_object(
                'prev_hash', encode(v_row.prev_hash, 'hex'),
                'hash', encode(v_row.hash, 'hex'),
                'user_agent_hash', encode(v_row.user_agent_hash, 'hex'))
        );
    END IF;

    RETURN v_row.id;
END
$$;

REVOKE ALL ON FUNCTION audit_append(text, text, text, text, text, jsonb, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_append(text, text, text, text, text, jsonb, uuid, uuid)
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer;

-- Dono da função DEFINER = ptmarket_audit_writer (quem migra deixa de ter EXECUTE).
-- O novo dono precisa de CREATE no schema só durante o ALTER; retira-se logo a seguir.
GRANT CREATE ON SCHEMA public TO ptmarket_audit_writer;
ALTER FUNCTION audit_append(text, text, text, text, text, jsonb, uuid, uuid) OWNER TO ptmarket_audit_writer;
REVOKE CREATE ON SCHEMA public FROM ptmarket_audit_writer;
