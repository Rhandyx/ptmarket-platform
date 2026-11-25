-- 0004 — products e product_variants (por tenant, RLS forçado).
-- Rollback mental: DROP TABLE product_variants; DROP TABLE products;
--   (políticas, grants e índices caem com as tabelas; cartão 03 (preços/Omnibus) tem de ser revertido antes.)
-- products não tem preço/stock/sku/ean: vivem em product_variants (produto simples = 1 variante).

CREATE TABLE products (
    id              UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id       UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    store_id        UUID        NOT NULL,
    category_id     UUID        REFERENCES categories (id) ON DELETE SET NULL,
    catalog_item_id UUID, -- sem FK: catalog_items vem depois
    title           JSONB       NOT NULL,
    description     JSONB       NOT NULL DEFAULT '{}',
    vat_rate_bps    INT         NOT NULL -- SEM default: a app decide por categoria+país
        CHECK (vat_rate_bps BETWEEN 0 AND 10000),
    is_perishable   BOOLEAN     NOT NULL DEFAULT false,
    attributes      JSONB       NOT NULL DEFAULT '{}',
    images          JSONB       NOT NULL DEFAULT '[]',
    ai_enriched     BOOLEAN     NOT NULL DEFAULT false,
    is_published    BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, store_id) REFERENCES stores (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, id)
);

CREATE INDEX products_tenant_store_idx    ON products (tenant_id, store_id);
CREATE INDEX products_tenant_category_idx ON products (tenant_id, category_id);
CREATE INDEX products_category_idx        ON products (category_id);

CREATE TABLE product_variants (
    id                     UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id              UUID         NOT NULL,
    product_id             UUID         NOT NULL,
    sku                    VARCHAR(100),
    ean                    VARCHAR(64),
    attributes             JSONB        NOT NULL DEFAULT '{}',
    price_cents            BIGINT       NOT NULL CHECK (price_cents >= 0), -- PVP com IVA incluído
    compare_at_price_cents BIGINT       CHECK (compare_at_price_cents >= 0),
    lowest_price_30d_cents BIGINT       CHECK (lowest_price_30d_cents >= 0),
    stock_qty              INT          NOT NULL DEFAULT 0 CHECK (stock_qty >= 0),
    is_active              BOOLEAN      NOT NULL DEFAULT true,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, product_id) REFERENCES products (tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, id)
);

CREATE INDEX product_variants_tenant_product_idx ON product_variants (tenant_id, product_id);
CREATE INDEX product_variants_tenant_ean_idx     ON product_variants (tenant_id, ean)
    WHERE ean IS NOT NULL;

ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE products FORCE ROW LEVEL SECURITY;
ALTER TABLE product_variants ENABLE ROW LEVEL SECURITY;
ALTER TABLE product_variants FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON products
    FOR ALL TO ptmarket_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation ON product_variants
    FOR ALL TO ptmarket_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON products, product_variants TO ptmarket_app;
