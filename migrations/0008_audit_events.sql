-- 0008 — Caixa negra: audit.audit_events (tabela única, particionada, só de acréscimo, encadeada por hash).
-- Rollback mental (só em dev; em produção a caixa negra é prova — exportar e verificar a cadeia antes).
--   Depois da selagem quem migra já não é dono de nada em audit.*: o rollback é do superuser.
--   DROP SCHEMA audit CASCADE;  (tabelas, partições, funções, políticas, triggers e grants)
--   ALTER POLICY app_insert ON outbox_events WITH CHECK (<expressão de 0006>);
--   (papéis, schema audit vazio e audit_admin são do bootstrap: infra/postgres/init/03-audit-bootstrap.sh.)
--
-- Quem escreve é só audit.audit_append (app) e audit.audit_append_event (0009, worker), SECURITY DEFINER com dono
-- ptmarket_audit_writer, e ambas passam por audit._chain_insert (uma só implementação da cadeia e do hash).
-- O ator vem só do contexto da transação (app.*), nunca por parâmetro.
-- Dono das tabelas: ptmarket_audit_owner (NOLOGIN); nem esse tem UPDATE/DELETE/TRUNCATE. REVOKE + triggers que
-- fazem sempre RAISE; não existe GUC, coluna nem função para os desligar.
-- Uma cadeia por (chain_key, retention_class): o DROP de partições de uma classe não parte as outras.
--
-- Selagem: os objetos nascem com dono = quem migra (o bootstrap dá-lhe USAGE + CREATE no schema audit) e a
-- audit_admin.audit_seal() (dono postgres), última instrução desta e de qualquer migration que crie ou altere
-- objetos em audit, passa-os para ptmarket_audit_owner / ptmarket_audit_writer, tira ao migrator e a PUBLIC
-- todos os privilégios em audit.* e verifica (allowlist fixa das funções DEFINER, sem sobrecargas, donos,
-- membros, dependências). O CREATE que fica não dá poder sobre objetos selados (não são do migrator).
-- Chamadas entre funções de audit.* passam argumentos com o tipo exato da assinatura (::text, linha
-- audit.audit_events, boolean): uma sobrecarga plantada com outros tipos nunca ganha a resolução.
--
-- REGRA: nenhuma função SECURITY DEFINER de audit.* lê ou escreve objetos cujo dono seja um papel com LOGIN.
-- Um dono com LOGIN (ex.: o migrator, dono de public.outbox_events) pode pôr lá triggers, DEFAULTs ou políticas
-- que correm com a identidade de quem escreve (ptmarket_audit_writer) e forjar a cadeia. Por isso o alerta de
-- admin/impersonação vai para audit.audit_alerts e não para o outbox. Provado em migrations/tests/audit_seal.sql.
--
-- Risco residual: o superuser pode tudo (mitigação: pgaudit.log='all' no postgres e a raiz diária em WORM,
-- cartão 09). O dono da BD pode fazer DROP DATABASE: em produção a BD tem dono postgres e o migrator não tem
-- CREATEDB (o CREATEDB só existe em dev/CI para o sqlx::test). Com o CREATE no schema audit, o migrator pode
-- plantar uma sobrecarga com argumentos DEFAULT que torna ambígua uma chamada interna (as escritas falham,
-- fechado; nada é forjado); fica no pgaudit e a audit_seal() seguinte recusa-a. O resto fica no pgaudit e na
-- raiz em WORM.

-- ---------------------------------------------------------------------------
-- Pré-condição: bootstrap aplicado (papéis, schema audit vazio com CREATE para quem migra, audit_seal).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regnamespace('audit') IS NULL
       OR to_regrole('ptmarket_audit_owner') IS NULL
       OR to_regrole('ptmarket_audit_writer') IS NULL
       OR to_regrole('ptmarket_audit_retention') IS NULL
       OR to_regnamespace('audit_admin') IS NULL THEN
        RAISE EXCEPTION '0008: falta o bootstrap da caixa negra (infra/postgres/init/03-audit-bootstrap.sh, como superuser)';
    END IF;
    IF NOT has_schema_privilege('audit', 'CREATE') THEN
        RAISE EXCEPTION '0008: sem CREATE no schema audit (o superuser concede-o só para a migration)';
    END IF;
    IF pg_has_role(current_user, 'ptmarket_audit_writer', 'MEMBER')
       OR pg_has_role(current_user, 'ptmarket_audit_owner', 'MEMBER') THEN
        IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
            RAISE EXCEPTION '0008: quem migra não pode ser membro dos papéis de auditoria';
        END IF;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Tabela: LIST (retention_class) → RANGE (created_at) mensal + DEFAULT por classe.
-- ---------------------------------------------------------------------------
CREATE TABLE audit.audit_events (
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

CREATE TABLE audit.audit_events_fiscal PARTITION OF audit.audit_events
    FOR VALUES IN ('fiscal') PARTITION BY RANGE (created_at);
CREATE TABLE audit.audit_events_standard PARTITION OF audit.audit_events
    FOR VALUES IN ('standard') PARTITION BY RANGE (created_at);
CREATE TABLE audit.audit_events_security PARTITION OF audit.audit_events
    FOR VALUES IN ('security') PARTITION BY RANGE (created_at);

-- Um INSERT nunca falha por falta de partição mensal.
CREATE TABLE audit.audit_events_fiscal_default PARTITION OF audit.audit_events_fiscal DEFAULT;
CREATE TABLE audit.audit_events_standard_default PARTITION OF audit.audit_events_standard DEFAULT;
CREATE TABLE audit.audit_events_security_default PARTITION OF audit.audit_events_security DEFAULT;

-- Índices no pai: propagam-se a todas as partições, incluindo as futuras.
CREATE INDEX audit_events_tenant_created_idx ON audit.audit_events (tenant_id, created_at);
CREATE INDEX audit_events_target_created_idx ON audit.audit_events (target_type, target_id, created_at);
CREATE INDEX audit_events_chain_idx ON audit.audit_events (chain_key, chain_seq DESC);
CREATE INDEX audit_events_id_idx ON audit.audit_events (id);

-- ---------------------------------------------------------------------------
-- Imutabilidade: trigger que faz sempre RAISE (linha: UPDATE/DELETE; instrução: TRUNCATE).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_events_immutable()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'audit.% é só de acréscimo: % recusado', TG_TABLE_NAME, TG_OP;
END
$$;

REVOKE ALL ON FUNCTION audit.audit_events_immutable() FROM PUBLIC;

-- Trigger de linha no pai: clonado para todas as partições (atuais e futuras).
CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit.audit_events
    FOR EACH ROW EXECUTE FUNCTION audit.audit_events_immutable();

-- TRUNCATE é de instrução (não é clonado): no pai e em cada partição; as mensais em audit_ensure_partitions.
-- Nas partições ninguém escreve diretamente (o encaminhamento via pai não verifica privilégios da partição):
-- o dono fica só com SELECT (backup/inspeção), sem INSERT/UPDATE/DELETE/TRUNCATE (o ACL passa ao novo dono).
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
            'CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit.%I '
            'FOR EACH STATEMENT EXECUTE FUNCTION audit.audit_events_immutable()', t);
        EXECUTE format(
            'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit.%I FROM PUBLIC, %I', t, current_user);
    END LOOP;
END
$$;

REVOKE UPDATE, DELETE, TRUNCATE ON audit.audit_events
    FROM ptmarket_app, ptmarket_worker, ptmarket_price_writer,
         ptmarket_audit_writer, ptmarket_audit_retention;

-- ---------------------------------------------------------------------------
-- RLS: só o escritor insere/lê tudo; a app lê só o seu tenant. Leitura global do admin = épico admin.
-- ---------------------------------------------------------------------------
ALTER TABLE audit.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY writer_insert ON audit.audit_events
    FOR INSERT TO ptmarket_audit_writer
    WITH CHECK (true);

CREATE POLICY writer_select ON audit.audit_events
    FOR SELECT TO ptmarket_audit_writer
    USING (true);

CREATE POLICY tenant_read ON audit.audit_events
    FOR SELECT TO ptmarket_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

GRANT INSERT, SELECT ON audit.audit_events TO ptmarket_audit_writer;
GRANT SELECT ON audit.audit_events TO ptmarket_app;

-- A app não cria eventos 'audit' no outbox (nem globais nem de tenant); ninguém os cria: o alerta de
-- admin/impersonação vive em audit.audit_alerts (ver REGRA no topo).
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
-- Cabeça de cada cadeia (chain_key, retention_class): serializa a escrita por bloqueio de linha.
-- Em READ COMMITTED a 2.ª transação espera e lê a cabeça nova; em REPEATABLE READ/SERIALIZABLE recebe
-- 40001 (o chamador repete) — nunca há bifurcação. Não particionada: sobrevive ao DROP de partições.
-- O escritor só tem SELECT/INSERT/UPDATE; o dono (NOLOGIN) só SELECT; app/worker sem qualquer acesso.
-- ---------------------------------------------------------------------------
CREATE TABLE audit.audit_chain_heads (
    chain_key       UUID        NOT NULL,
    retention_class VARCHAR(8)  NOT NULL CHECK (retention_class IN ('fiscal', 'standard', 'security')),
    last_seq        BIGINT      NOT NULL CHECK (last_seq >= 0),
    last_hash       BYTEA       NOT NULL CHECK (octet_length(last_hash) = 32),
    PRIMARY KEY (chain_key, retention_class)
);

ALTER TABLE audit.audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_chain_heads FORCE ROW LEVEL SECURITY;

CREATE POLICY writer_all ON audit.audit_chain_heads
    FOR ALL TO ptmarket_audit_writer
    USING (true)
    WITH CHECK (true);

REVOKE ALL ON audit.audit_chain_heads FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit.audit_chain_heads FROM CURRENT_USER;
GRANT SELECT, INSERT, UPDATE ON audit.audit_chain_heads TO ptmarket_audit_writer;

-- ---------------------------------------------------------------------------
-- Alertas de admin/impersonação (sinal imediato fora da BD; relay para o WORM e alertas no cartão 09).
-- id = id do evento. Só o escritor insere (dentro de _chain_insert); o worker lê e marca published_at
-- (NULL → valor, uma vez). Ninguém apaga nem trunca; o trigger recusa qualquer outra alteração.
-- ---------------------------------------------------------------------------
CREATE TABLE audit.audit_alerts (
    id           UUID        PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL,
    event_type   VARCHAR(96) NOT NULL,
    payload      JSONB       NOT NULL,
    published_at TIMESTAMPTZ
);

CREATE INDEX audit_alerts_unpublished_idx ON audit.audit_alerts (created_at, id)
    WHERE published_at IS NULL;

CREATE FUNCTION audit.audit_alerts_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF OLD.published_at IS NOT NULL
       OR NEW.published_at IS NULL
       OR (NEW.id, NEW.created_at, NEW.event_type, NEW.payload)
          IS DISTINCT FROM (OLD.id, OLD.created_at, OLD.event_type, OLD.payload) THEN
        RAISE EXCEPTION 'audit.audit_alerts: só published_at muda, uma vez, de NULL para um valor';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION audit.audit_alerts_guard() FROM PUBLIC;

CREATE TRIGGER audit_alerts_publish_only
    BEFORE UPDATE ON audit.audit_alerts
    FOR EACH ROW EXECUTE FUNCTION audit.audit_alerts_guard();
CREATE TRIGGER audit_alerts_no_delete
    BEFORE DELETE ON audit.audit_alerts
    FOR EACH ROW EXECUTE FUNCTION audit.audit_events_immutable();
CREATE TRIGGER audit_alerts_no_truncate
    BEFORE TRUNCATE ON audit.audit_alerts
    FOR EACH STATEMENT EXECUTE FUNCTION audit.audit_events_immutable();

ALTER TABLE audit.audit_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_alerts FORCE ROW LEVEL SECURITY;

CREATE POLICY writer_insert ON audit.audit_alerts
    FOR INSERT TO ptmarket_audit_writer
    WITH CHECK (true);

CREATE POLICY worker_select ON audit.audit_alerts
    FOR SELECT TO ptmarket_worker
    USING (true);

CREATE POLICY worker_publish ON audit.audit_alerts
    FOR UPDATE TO ptmarket_worker
    USING (published_at IS NULL)
    WITH CHECK (published_at IS NOT NULL);

REVOKE ALL ON audit.audit_alerts FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit.audit_alerts FROM CURRENT_USER;
GRANT INSERT ON audit.audit_alerts TO ptmarket_audit_writer; -- sem SELECT/UPDATE
GRANT SELECT, UPDATE (published_at) ON audit.audit_alerts TO ptmarket_worker;

-- ---------------------------------------------------------------------------
-- Classe de retenção (define a partição e a cadeia).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_retention_class(p_action text, p_outcome text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
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

REVOKE ALL ON FUNCTION audit.audit_retention_class(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.audit_retention_class(text, text) TO ptmarket_audit_writer;

-- ---------------------------------------------------------------------------
-- Hash canónico de uma linha (a única fórmula; a verificação da 0009 usa a mesma função).
-- ip::text inclui a máscara (/32, /8, …): mudar a máscara muda o hash.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit._event_hash(e audit.audit_events)
RETURNS bytea
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT sha256(e.prev_hash || convert_to(jsonb_build_array(
        e.id, e.tenant_id, e.store_id, e.actor_type, e.actor_id, e.actor_label, e.impersonator_id,
        e.action, e.target_type, e.target_id, e.outcome, e.reason, e.changes, e.request_id,
        e.ip::text, encode(e.user_agent_hash, 'hex'), e.retention_class,
        (extract(epoch FROM e.occurred_at) * 1000000)::bigint,
        (extract(epoch FROM e.created_at) * 1000000)::bigint,
        e.chain_seq
    )::text, 'UTF8'))
$$;

REVOKE ALL ON FUNCTION audit._event_hash(audit.audit_events) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit._event_hash(audit.audit_events) TO ptmarket_audit_writer;

-- ---------------------------------------------------------------------------
-- Partições mensais (UTC): mês corrente + N, nas 3 classes. Idempotente; devolve quantas criou.
-- Se a DEFAULT já tiver linhas desse mês, a partição não é criada (WARNING) e as outras seguem.
-- Dono (depois da selagem) = ptmarket_audit_owner: tem de ser dono do pai para criar partições.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_ensure_partitions(p_months_ahead int)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
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

            -- Já existe como partição deste pai? (um nome ocupado por outra relação não conta: WARNING abaixo.)
            CONTINUE WHEN EXISTS (
                SELECT 1 FROM pg_catalog.pg_inherits i
                WHERE i.inhrelid = to_regclass(format('audit.%I', v_name))
                  AND i.inhparent = to_regclass(format('audit.%I', 'audit_events_' || v_class)));

            BEGIN
                EXECUTE format(
                    'CREATE TABLE audit.%I PARTITION OF audit.%I FOR VALUES FROM (%L) TO (%L)',
                    v_name, 'audit_events_' || v_class, v_from, v_to);
                EXECUTE format(
                    'CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit.%I '
                    'FOR EACH STATEMENT EXECUTE FUNCTION audit.audit_events_immutable()', v_name);
                EXECUTE format(
                    'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit.%I FROM PUBLIC, %I',
                    v_name, current_user);
                v_created := v_created + 1;
            EXCEPTION
                WHEN check_violation THEN
                    RAISE WARNING 'audit_ensure_partitions: % não criada (a DEFAULT já tem linhas desse mês)',
                        v_name;
                WHEN duplicate_table THEN
                    RAISE WARNING 'audit_ensure_partitions: % não criada (nome ocupado por outra relação)', v_name;
            END;
        END LOOP;
    END LOOP;

    RETURN v_created;
END
$$;

REVOKE ALL ON FUNCTION audit.audit_ensure_partitions(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.audit_ensure_partitions(int) TO ptmarket_worker;

SELECT audit.audit_ensure_partitions(3);

-- ---------------------------------------------------------------------------
-- audit._chain_insert: a única implementação da cadeia. Recebe a linha com os campos do evento (sem
-- chain_key/retention_class/chain_seq/prev_hash/hash/created_at); id e occurred_at a NULL = gerados aqui.
-- p_dedupe: se já existir um evento com este id (janela de 1 dia), devolve NULL sem gravar.
-- Toca só em audit.audit_chain_heads, audit.audit_events e audit.audit_alerts (dono NOLOGIN; ver REGRA).
-- Dono ptmarket_audit_writer, sem EXECUTE para mais ninguém (só as funções DEFINER do escritor a chamam).
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit._chain_insert(p_row audit.audit_events, p_dedupe boolean)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_row audit.audit_events := p_row;
BEGIN
    v_row.chain_key       := COALESCE(v_row.tenant_id, '00000000-0000-0000-0000-000000000000'::uuid);
    v_row.retention_class := audit.audit_retention_class(v_row.action::text, v_row.outcome::text);

    -- Cabeça da cadeia (génese: seq 0 + 32 bytes a zero) e bloqueio da linha até ao fim da transação.
    INSERT INTO audit.audit_chain_heads (chain_key, retention_class, last_seq, last_hash)
    VALUES (v_row.chain_key, v_row.retention_class, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT DO NOTHING;

    SELECT h.last_seq + 1, h.last_hash INTO STRICT v_row.chain_seq, v_row.prev_hash
    FROM audit.audit_chain_heads h
    WHERE h.chain_key = v_row.chain_key
      AND h.retention_class = v_row.retention_class
    FOR UPDATE;

    -- Idempotência (depois do bloqueio: uma reentrega concorrente vê a linha já confirmada).
    -- A PK inclui created_at: a janela de 1 dia permite a poda de partições no índice por id.
    IF p_dedupe AND EXISTS (
        SELECT 1 FROM audit.audit_events e
        WHERE e.id = v_row.id
          AND e.created_at >= v_row.occurred_at - interval '1 day'
    ) THEN
        RETURN NULL;
    END IF;

    -- Depois do lock: created_at cresce com chain_seq dentro de cada cadeia.
    v_row.created_at  := clock_timestamp();
    v_row.occurred_at := COALESCE(v_row.occurred_at, v_row.created_at);
    v_row.id          := COALESCE(v_row.id, uuidv7());
    v_row.hash        := audit._event_hash(v_row);

    INSERT INTO audit.audit_events (
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

    UPDATE audit.audit_chain_heads
       SET last_seq = v_row.chain_seq, last_hash = v_row.hash
     WHERE chain_key = v_row.chain_key
       AND retention_class = v_row.retention_class;

    -- Ação de admin ou com impersonação: alerta na mesma transação.
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
$$;

REVOKE ALL ON FUNCTION audit._chain_insert(audit.audit_events, boolean) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- audit_append: porta de escrita da app. Ator só do contexto (app.*).
-- Chamar NO FIM da transação: o FOR UPDATE da cabeça da cadeia fica até ao COMMIT; lock_timeout = 2 s
-- impede que uma transação lenta bloqueie a cadeia do tenant para sempre (55P03 → o chamador repete).
-- p_tenant_id só com app.actor_type = 'system' (jobs sem contexto); a app nunca injeta eventos noutro tenant.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_append(
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
AS $$
DECLARE
    v_row        audit.audit_events;
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
$$;

REVOKE ALL ON FUNCTION audit.audit_append(text, text, text, text, text, jsonb, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.audit_append(text, text, text, text, text, jsonb, uuid, uuid)
    TO ptmarket_app, ptmarket_worker, ptmarket_price_writer;

-- ---------------------------------------------------------------------------
-- Selagem (última instrução).
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_seal();
