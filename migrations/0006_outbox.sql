-- 0006 — outbox_events (API só insere; worker lê e marca published_at).
-- Rollback mental: DROP TABLE outbox_events;  (políticas, grants e índices caem com a tabela.)

CREATE TABLE outbox_events (
    id           UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id    UUID, -- NULL = evento global; sem FK
    aggregate    VARCHAR(64) NOT NULL,
    aggregate_id UUID        NOT NULL,
    event_type   VARCHAR(96) NOT NULL,
    payload      JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);

CREATE INDEX outbox_events_created_at_idx ON outbox_events (created_at);
CREATE INDEX outbox_events_unpublished_idx ON outbox_events (created_at, id)
    WHERE published_at IS NULL;

ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY;

-- Evento de tenant só no contexto desse tenant; evento global (NULL) só SEM contexto de tenant
-- (uma transação do tenant A nunca grava eventos globais).
CREATE POLICY app_insert ON outbox_events
    FOR INSERT TO ptmarket_app
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        OR (
            tenant_id IS NULL
            AND NULLIF(current_setting('app.current_tenant_id', true), '')::uuid IS NULL
        )
    );

CREATE POLICY worker_select ON outbox_events
    FOR SELECT TO ptmarket_worker
    USING (true);

-- O worker só marca como publicado; repor published_at = NULL (replay) é recusado.
CREATE POLICY worker_update ON outbox_events
    FOR UPDATE TO ptmarket_worker
    USING (true)
    WITH CHECK (published_at IS NOT NULL);

GRANT INSERT ON outbox_events TO ptmarket_app;
GRANT SELECT ON outbox_events TO ptmarket_worker;
GRANT UPDATE (published_at) ON outbox_events TO ptmarket_worker;
