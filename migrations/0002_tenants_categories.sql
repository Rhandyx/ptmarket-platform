-- 0002 — tenants e categories (tabelas globais, sem RLS; só leitura para a API).
-- Rollback mental: DROP TABLE categories; DROP TABLE tenants;
--   (só depois de 0003+ revertidas — stores e products referenciam estas tabelas.)

CREATE TABLE tenants (
    id                     UUID PRIMARY KEY DEFAULT uuidv7(),
    slug                   VARCHAR(64)  NOT NULL UNIQUE,
    custom_domain          VARCHAR(255) NOT NULL UNIQUE,
    name                   VARCHAR(255) NOT NULL,
    tenant_type            VARCHAR(24)  NOT NULL DEFAULT 'municipal'
        CHECK (tenant_type IN ('municipal', 'national_portal', 'niche')),
    country_code           CHAR(2)      NOT NULL DEFAULT 'PT'
        CHECK (country_code IN ('PT', 'ES')),
    currency               CHAR(3)      NOT NULL DEFAULT 'EUR',
    default_commission_bps INT          NOT NULL DEFAULT 0
        CHECK (default_commission_bps BETWEEN 0 AND 10000),
    template_layout        VARCHAR(32)  NOT NULL DEFAULT 'bairro'
        CHECK (template_layout IN ('bairro', 'editorial', 'catalogo')),
    theme_config           JSONB        NOT NULL DEFAULT '{"primary_color":"#0F4C81","secondary_color":"#111827","logo_url":"","favicon_url":"","institutional_footer":"","accessibility_statement_url":""}',
    legal_config           JSONB        NOT NULL DEFAULT '{"entity_name":"","nif":"","ral_entity":"CNIACC","livro_reclamacoes_url":"https://www.livroreclamacoes.pt"}',
    loyalty_enabled        BOOLEAN      NOT NULL DEFAULT true,
    loyalty_cashback_bps   INT          NOT NULL DEFAULT 500
        CHECK (loyalty_cashback_bps BETWEEN 0 AND 10000),
    is_active              BOOLEAN      NOT NULL DEFAULT true,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE categories (
    id                   UUID PRIMARY KEY DEFAULT uuidv7(),
    parent_id            UUID REFERENCES categories (id) ON DELETE SET NULL,
    taxonomy_code        VARCHAR(64) UNIQUE,
    slug                 VARCHAR(140) NOT NULL,
    name                 JSONB        NOT NULL, -- {"pt":"Padaria","es":"Panadería"}
    default_vat_rate_bps INT          NOT NULL DEFAULT 2300 -- taxa normal PT continente; ES/ilhas resolvem-se na app
        CHECK (default_vat_rate_bps BETWEEN 0 AND 10000),
    is_featured          BOOLEAN      NOT NULL DEFAULT false,
    sort_order           INT          NOT NULL DEFAULT 0
);

CREATE INDEX categories_parent_id_idx ON categories (parent_id);

GRANT SELECT ON tenants, categories TO ptmarket_app;
