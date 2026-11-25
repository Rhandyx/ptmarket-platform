-- 0003 — stores (por tenant, RLS forçado).
-- Rollback mental: DROP TABLE stores;  (políticas, grants e índices caem com a tabela;
--   só depois de 0004 revertida — products referencia stores(tenant_id, id).)

CREATE TABLE stores (
    id                         UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id                  UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name                       VARCHAR(255) NOT NULL,
    slug                       VARCHAR(120) NOT NULL,
    legal_name                 VARCHAR(255) NOT NULL, -- DSA
    nif                        VARCHAR(20)  NOT NULL,
    iban                       VARCHAR(34)  NOT NULL,
    email                      VARCHAR(255) NOT NULL,
    phone                      VARCHAR(50),
    address_json               JSONB        NOT NULL DEFAULT '{}',
    geo_lat                    DOUBLE PRECISION,
    geo_lng                    DOUBLE PRECISION,
    business_hours             JSONB        NOT NULL DEFAULT '{}',
    is_vacation_mode           BOOLEAN      NOT NULL DEFAULT false,
    vacation_message           TEXT,
    supports_click_collect     BOOLEAN      NOT NULL DEFAULT true,
    supports_local_courier     BOOLEAN      NOT NULL DEFAULT false,
    supports_national_shipping BOOLEAN      NOT NULL DEFAULT true,
    shipping_config            JSONB        NOT NULL DEFAULT '{}',
    vat_exempt_art53           BOOLEAN      NOT NULL DEFAULT false, -- true = IVA 0%
    invoicing_provider         VARCHAR(30)  NOT NULL DEFAULT 'none'
        CHECK (invoicing_provider IN ('moloni', 'invoicexpress', 'vendus', 'none')),
    invoicing_credentials_enc  TEXT, -- AES-256-GCM, chave fora da BD
    eupago_split_key           VARCHAR(255),
    stripe_account_id          VARCHAR(255),
    custom_commission_bps      INT -- NULL = herda do tenant
        CHECK (custom_commission_bps BETWEEN 0 AND 10000),
    kyc_verified               BOOLEAN      NOT NULL DEFAULT false,
    publish_to_national_portal BOOLEAN      NOT NULL DEFAULT false,
    is_active                  BOOLEAN      NOT NULL DEFAULT true,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug), -- também serve de índice da FK tenant_id
    UNIQUE (tenant_id, id)
);

CREATE INDEX stores_national_portal_idx ON stores (publish_to_national_portal)
    WHERE publish_to_national_portal;

ALTER TABLE stores ENABLE ROW LEVEL SECURITY;
ALTER TABLE stores FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON stores
    FOR ALL TO ptmarket_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON stores TO ptmarket_app;
