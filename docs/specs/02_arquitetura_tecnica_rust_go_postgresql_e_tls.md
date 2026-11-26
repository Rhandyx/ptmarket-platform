# 02. Especificação da Arquitetura Técnica (Rust + Go + PostgreSQL 17 + Next.js)

> Atualizada a 26/11/2026: canais, patrocínio, comissões e planos seguem a spec 14 (prevalece).

> **Revisto em 25/11/2026:** o modelo de dados (§4) muda segundo a **spec 11 §2**: `product_variants`, stock atómico com reservas, `outbox_events`, `customers`, UUIDv7, **PostgreSQL 18 em vez de 17**, IVA em bps e preços com IVA. A edge/TLS (§1) muda segundo a **spec 12 §1**: Cloudflare for SaaS, com o Caddy On-Demand TLS só como fallback. Em caso de conflito, prevalecem as specs 11 e 12.

**Princípio Orientador:** Máxima segurança financeira e isolamento multi-tenant no núcleo (**Rust + PostgreSQL**), velocidade de adaptação em integrações externas (**Go**) e zero dessincronização entre backend e frontend (**OpenAPI tipado**).

---

## 1. Diagrama Geral da Arquitetura

```text
+-----------------------------------------------------------------------------+
|                EDGE / REVERSE PROXY & ON-DEMAND TLS (Caddy)                 |
|  - Emite/renova SSL automático para qualquer domínio municipal (CNAME)      |
|  - Valida domínio permitido via endpoint interno Rust (/internal/tls-check) |
|  - Serve media local (/media/*) na Fase 1 ou redireciona para R2 na Fase 2  |
+-----------------------------------------------------------------------------+
                                       │
                                       ▼
+-----------------------------------------------------------------------------+
|                    FRONTEND UNIFICADO & PWA (Next.js)                       |
|  - App Router + TypeScript Estrito + Tailwind CSS + shadcn/ui (WCAG 2.1 AA) |
|  - Resolve Tenant pelo HTTP Header 'Host' (compreemX.pt vs lojaportugal.pt) |
|  - Consome exclusivamente SDK gerado do openapi.json (utoipa)               |
+-----------------------------------------------------------------------------+
                       │                                       │
                       ▼                                       ▼
+---------------------------------------------+ +-----------------------------+
|         CORE API & LEDGER (RUST)            | |   WORKERS ASSÍNCRONOS (GO)  |
|  - Axum 0.8 + Tokio + SQLx + rust_decimal   | |  - pgx + Asynq + Redis      |
|  - Pools duplas: Primary (W) + Replica (R)  | |  - Pagamentos Eupago/Stripe |
|  - Autenticação JWT + 2FA TOTP + RBAC       | |  - Faturação AT (Moloni/IX) |
|  - Catálogo, Stock Atómico, Histórico Preço | |  - Envios (CTT/DPD/Sendcld) |
|  - Motor Split, IVA PT/ES, Devoluções       | |  - Enriquecimento IA + Sync |
|  - Cartão da Cidade + Data Studio Admin     | |  - Migração Woo/Moloni/CSV  |
+---------------------------------------------+ +-----------------------------+
                       \                                       /
                        ▼                                     ▼
+-----------------------------------------------------------------------------+
|                  PERSISTÊNCIA & FILAS (PostgreSQL 17 + Redis)               |
|  - PostgreSQL 17: Row-Level Security (RLS) + JSONB + UUIDv7/v4 + pg_trgm    |
|  - Redis 7: Filas Asynq (Rust -> Go), Carrinhos, Cache Tenant, Rate Limit   |
+-----------------------------------------------------------------------------+
```

---

## 2. Porquê Rust + Go + PostgreSQL (e Como Evita Bugs e Manutenção Pesada)

| Camada | Stack Escolhida | Justificação Técnica e Impacto na Manutenção |
| :--- | :--- | :--- |
| **Core API & Financeiro** | **Rust** (`Axum 0.8`, `SQLx`, `rust_decimal`, `utoipa`, `thiserror`) | O compilador impede erros de tipos, `null` pointers e condições de corrida antes do código ir para produção. `rust_decimal` elimina erros de vírgula flutuante em euros. Binário estático único, memória constante e manutenção previsível. |
| **Workers & Conectores** | **Go** (`Asynq`, `pgx`, `net/http`) | APIs externas (Eupago, Moloni, CTT, WooCommerce) mudam frequentemente. Em Go, cada conector fica isolado com *retries* exponenciais e *timeouts*, sem nunca bloquear o checkout principal nem exigir recompilar o núcleo Rust. |
| **Base de Dados** | **PostgreSQL 17** | Isolamento físico por **Row-Level Security (RLS)**, `JSONB` indexado para atributos/traduções PT-ES, pesquisa tolerante a erros (`pg_trgm`) e suporte nativo a replicação *Streaming* quando escalar para 2 VPS. |
| **Reverse Proxy & SSL** | **Caddy Server** | Substitui configurações manuais de Nginx + Certbot. Suporta **On-Demand TLS**: quando uma nova Câmara aponta o domínio `compreem[concelho].pt` para o servidor, o Caddy consulta o Rust e emite o certificado SSL automaticamente em segundos. |
| **Armazenamento Media** | Abstração `StorageBackend` | Na Demo e Fase 1 usa **Disco Local do VPS** (`LocalDiskStorage`, custo 0€). Na Fase 2 muda via variável `.env` para **Cloudflare R2 / S3** sem alterar código de negócio. |

---

## 3. Preparação Nativa para Escala (Dual Pool Primary / Replica)

Para permitir migrar de 1 VPS para 2 VPS com réplica de leitura sem reescrever uma linha de código, o estado da aplicação em Rust (`AppState`) mantém sempre duas pools `PgPool`:

```rust
// backend-rust/src/state.rs
pub struct AppState {
    pub db_primary: sqlx::PgPool, // Escritas, checkouts, stock, payouts, admin
    pub db_replica: sqlx::PgPool, // Leituras públicas, catálogo, pesquisas, relatórios Câmara
    pub redis: deadpool_redis::Pool,
    pub storage: std::sync::Arc<dyn crate::storage::StorageBackend>,
}
```
- **Na Demo e Fase 1 (1 VPS):** `DATABASE_PRIMARY_URL` e `DATABASE_REPLICA_URL` no `.env` apontam para o mesmo PostgreSQL local.
- **Na Fase 2 (2 VPS):** `DATABASE_REPLICA_URL` aponta para a réplica de leitura.

---

## 4. Esquema Completo da Base de Dados (PostgreSQL 17)

Inclui suporte a multi-tenancy RLS, PT/ES, comissões dinâmicas, IVA por categoria/produto/Art. 53.º, **histórico de preços 30 dias (Diretiva Omnibus)**, **horários/modo férias das lojas**, **reembolsos parciais** e **Cartão da Cidade**:

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- 1. TENANTS (Municípios, Associações, Portal Nacional lojaportugal.pt, Nichos)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug VARCHAR(64) UNIQUE NOT NULL,
    custom_domain VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    tenant_type VARCHAR(24) NOT NULL DEFAULT 'municipal', -- canal (spec 14 §1): 'national_portal' (um por país), 'municipal' (domínio white-label de entidade; também Juntas/Associações com domínio), 'niche'
    country_code VARCHAR(2) NOT NULL DEFAULT 'PT',        -- 'PT' ou 'ES'
    currency VARCHAR(3) NOT NULL DEFAULT 'EUR',
    default_commission_bps INT NOT NULL DEFAULT 0,        -- LEGADO: sem efeito na comissão (ver spec 14 §3)
    template_layout VARCHAR(32) NOT NULL DEFAULT 'bairro', -- 'bairro', 'editorial', 'catalogo'
    theme_config JSONB NOT NULL DEFAULT '{
        "primary_color": "#0F4C81",
        "secondary_color": "#111827",
        "logo_url": "",
        "favicon_url": "",
        "institutional_footer": "",
        "accessibility_statement_url": ""
    }'::jsonb,
    legal_config JSONB NOT NULL DEFAULT '{
        "entity_name": "",
        "nif": "",
        "ral_entity": "CNIACC",
        "livro_reclamacoes_url": "https://www.livroreclamacoes.pt"
    }'::jsonb,
    loyalty_enabled BOOLEAN NOT NULL DEFAULT true,
    loyalty_cashback_bps INT NOT NULL DEFAULT 500,        -- 5.00% cashback local
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. TAXONOMIA GLOBAL DE CATEGORIAS (Seed Google/Shopify Taxonomy PT/ES)
CREATE TABLE categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    parent_id UUID REFERENCES categories(id) ON DELETE SET NULL,
    taxonomy_code VARCHAR(64) UNIQUE,
    slug VARCHAR(140) NOT NULL,
    name JSONB NOT NULL,                                  -- {"pt": "Padaria", "es": "Panadería"}
    default_vat_rate NUMERIC(5,2) NOT NULL DEFAULT 23.00,
    is_featured BOOLEAN NOT NULL DEFAULT false,
    sort_order INT NOT NULL DEFAULT 0
);
CREATE INDEX idx_categories_parent ON categories(parent_id);

-- 3. LOJAS / COMERCIANTES (Inclui KYC DSA, Fiscalidade AT, Horários e Modo Férias)
CREATE TABLE stores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, -- canal nacional do país da loja (catálogo universal, spec 14 §1)
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(120) NOT NULL,
    legal_name VARCHAR(255) NOT NULL,                     -- Obrigatório DSA (Digital Services Act)
    nif VARCHAR(20) NOT NULL,
    iban VARCHAR(34) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    address_json JSONB NOT NULL DEFAULT '{}'::jsonb,      -- DEPRECADO (spec 14 §5)
    fiscal_address JSONB,                                 -- morada de faturação (spec 14 §5)
    storefront_address JSONB,                             -- morada física; dá elegibilidade ao patrocínio
    storefront_dicofre VARCHAR(6) REFERENCES geo_dicofre(code), -- freguesia DICOFRE confirmada
    shipping_scope VARCHAR(16) NOT NULL DEFAULT 'national', -- 'national', 'local_only', 'pickup_only' (spec 14 §1.1)
    billing_plan_code VARCHAR(32) NOT NULL DEFAULT 'commission_payg', -- spec 14 §4
    accepted_base_commission_bps INT,                     -- aceite no registo (spec 14 §6)
    terms_version VARCHAR(32),
    terms_accepted_at TIMESTAMPTZ,
    geo_lat DOUBLE PRECISION,
    geo_lng DOUBLE PRECISION,
    -- Operação Local (Horários, Férias, Click & Collect)
    business_hours JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_vacation_mode BOOLEAN NOT NULL DEFAULT false,
    vacation_message TEXT,
    supports_click_collect BOOLEAN NOT NULL DEFAULT true,
    supports_local_courier BOOLEAN NOT NULL DEFAULT false,
    supports_national_shipping BOOLEAN NOT NULL DEFAULT true,
    shipping_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Fiscalidade e Faturação AT (BYOK)
    vat_exempt_art53 BOOLEAN NOT NULL DEFAULT false,      -- Se true, 0% IVA automático
    invoicing_provider VARCHAR(30) NOT NULL DEFAULT 'none', -- 'moloni', 'invoicexpress', 'vendus', 'none'
    invoicing_credentials_enc TEXT,                       -- Encriptado AES-256-GCM
    -- Pagamentos Split
    eupago_split_key VARCHAR(255),
    stripe_account_id VARCHAR(255),
    custom_commission_bps INT,                            -- NULL por defeito; exceção negociada, só o super_admin a define, auditada (spec 14 §3)
    -- Aprovação e Canal Nacional
    kyc_verified BOOLEAN NOT NULL DEFAULT false,          -- Validação Câmara/DSA
    publish_to_national_portal BOOLEAN NOT NULL DEFAULT false, -- DEPRECADO: deixa de ser lido; todas as lojas ativas aparecem no canal nacional (spec 14 §1.1)
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, slug)
);
CREATE INDEX idx_stores_tenant ON stores(tenant_id);
CREATE INDEX idx_stores_national ON stores(publish_to_national_portal) WHERE publish_to_national_portal = true; -- legado, sai com a coluna

-- 3b. CANAIS, PATROCÍNIO, GEOGRAFIA E PLANOS (resumo; definição completa na spec 14)
-- sponsor_entities     : Câmara/Junta/Associação (type, área DICOFRE, logótipo, channel_tenant_id NULL = sem domínio) (§1)
-- store_sponsorships   : N:N loja <-> entidade; status, valid_from/valid_to, commission_override_bps; EXCLUDE gist anti-sobreposição (§2)
-- geo_dicofre          : referência CAOP/DGT (distrito DD, concelho DDCC, freguesia DDCCFF, caop_version), carga por seed (§5)
-- platform_settings    : base_commission_bps (800), configurável, auditada (§3)
-- billing_plan_tiers   : escalões dos planos (plan_code, gmv_from/to_cents, monthly_fee_cents, marginal_commission_bps); só super_admin (§4)
-- store_verifications  : NIF/documentos (kind, sha256, storage_key privado, status, delete_after) (§6)

-- 4. PRODUTOS (Multi-idioma, Variantes JSONB, Perecíveis e Diretiva Omnibus)
CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    store_id UUID NOT NULL REFERENCES stores(id) ON DELETE CASCADE,
    category_id UUID REFERENCES categories(id) ON DELETE SET NULL,
    sku VARCHAR(100),
    ean VARCHAR(64),
    title JSONB NOT NULL,                                 -- {"pt": "...", "es": "..."}
    description JSONB NOT NULL DEFAULT '{}'::jsonb,
    price_cents BIGINT NOT NULL CHECK (price_cents >= 0),
    compare_at_price_cents BIGINT,                        -- Preço anterior se em promoção
    lowest_price_30d_cents BIGINT,                        -- Obrigatório Diretiva Omnibus (DL 70/2007)
    vat_rate NUMERIC(5,2) NOT NULL DEFAULT 23.00,
    is_perishable BOOLEAN NOT NULL DEFAULT false,         -- Exclui devolução 14 dias se perecível
    stock_qty INT NOT NULL DEFAULT 0,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,        -- {"cor": "Azul", "tamanho": "42"}
    variants JSONB NOT NULL DEFAULT '[]'::jsonb,
    images JSONB NOT NULL DEFAULT '[]'::jsonb,            -- [{thumb, card, full}]
    ai_enriched BOOLEAN NOT NULL DEFAULT false,
    is_published BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_products_tenant_store ON products(tenant_id, store_id);
CREATE INDEX idx_products_title_trgm ON products USING gin ((title->>'pt') gin_trgm_ops);

-- 4.1 HISTÓRICO DE PREÇOS (Auditoria ASAE / Diretiva Omnibus 30 dias)
CREATE TABLE product_price_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    price_cents BIGINT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_price_history_product_date ON product_price_history(product_id, recorded_at DESC);

-- 5. ENCOMENDAS (CARRINHO UNIFICADO DO COMPRADOR)
CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),       -- Canal onde a venda ocorreu (Câmara ou lojaportugal.pt)
    order_number VARCHAR(50) UNIQUE NOT NULL,
    customer_name VARCHAR(255) NOT NULL,
    customer_email VARCHAR(255) NOT NULL,
    customer_phone VARCHAR(50),
    customer_nif VARCHAR(20),
    customer_anonymized BOOLEAN NOT NULL DEFAULT false,   -- Suporte a direito ao esquecimento RGPD mantendo dados fiscais
    shipping_address JSONB NOT NULL,
    total_cents BIGINT NOT NULL,
    loyalty_discount_cents BIGINT NOT NULL DEFAULT 0,
    payment_status VARCHAR(30) NOT NULL DEFAULT 'pending', -- 'pending', 'paid', 'partially_refunded', 'refunded', 'failed'
    payment_gateway VARCHAR(30) NOT NULL,                 -- 'eupago_mbway', 'eupago_mb', 'stripe'
    gateway_reference VARCHAR(255),
    idempotency_key VARCHAR(128) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. SUB-ENCOMENDAS (UMA POR LOJA NO CARRINHO)
CREATE TABLE sub_orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    store_id UUID NOT NULL REFERENCES stores(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    subtotal_cents BIGINT NOT NULL,
    shipping_cents BIGINT NOT NULL DEFAULT 0,
    applied_commission_bps INT NOT NULL DEFAULT 0,        -- snapshot (spec 14 §7)
    platform_fee_cents BIGINT NOT NULL DEFAULT 0,
    -- Snapshot congelado no checkout, nunca recalculado (spec 14 §7)
    base_commission_bps INT NOT NULL DEFAULT 0,           -- referência (âncora)
    sponsored_discount_cents BIGINT NOT NULL DEFAULT 0,
    billing_plan_code VARCHAR(32),
    store_monthly_gmv_before_cents BIGINT NOT NULL DEFAULT 0,
    active_sponsor_ids UUID[] NOT NULL DEFAULT '{}',
    store_dicofre VARCHAR(6),
    origin_channel_id UUID REFERENCES tenants(id),        -- canal onde foi feita a compra
    store_payout_cents BIGINT NOT NULL,
    delivery_method VARCHAR(30) NOT NULL,                 -- 'click_collect', 'local_courier', 'ctt', 'dpd'
    pickup_slot JSONB,                                    -- Janela horária de levantamento
    fulfillment_status VARCHAR(30) NOT NULL DEFAULT 'unfulfilled',
    tracking_code VARCHAR(100),
    shipping_label_url TEXT,
    invoice_status VARCHAR(30) NOT NULL DEFAULT 'pending',
    invoice_number VARCHAR(64),
    invoice_pdf_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sub_orders_store ON sub_orders(store_id);
CREATE INDEX idx_sub_orders_sponsors ON sub_orders USING GIN (active_sponsor_ids);

-- Relatórios deduplicados (spec 14 §7): entidade = `active_sponsor_ids @> ARRAY[:entity]`; união de vários = `&&`;
-- interseção (co-patrocinado por todos) = `@> ARRAY[...]`. Totais calculam-se sobre `sub_orders` únicas, nunca somando
-- linhas desagregadas por entidade; relatórios das entidades não expõem dados de compradores.

-- 7. LINHAS DA SUB-ENCOMENDA (SNAPSHOT IMUTÁVEL)
CREATE TABLE sub_order_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sub_order_id UUID NOT NULL REFERENCES sub_orders(id) ON DELETE CASCADE,
    product_id UUID NOT NULL REFERENCES products(id),
    product_title_snapshot VARCHAR(255) NOT NULL,
    quantity INT NOT NULL CHECK (quantity > 0),
    unit_price_cents BIGINT NOT NULL,
    vat_rate_applied NUMERIC(5,2) NOT NULL
);

-- 8. DEVOLUÇÕES, REEMBOLSOS PARCIAIS E NOTAS DE CRÉDITO AT
CREATE TABLE refunds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sub_order_id UUID NOT NULL REFERENCES sub_orders(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
    reason VARCHAR(64) NOT NULL,                          -- 'withdrawal_14d', 'damaged', 'out_of_stock'
    gateway_refund_id VARCHAR(255),
    credit_note_number VARCHAR(64),                       -- Nota de Crédito emitida no Moloni/InvoiceXpress
    credit_note_pdf_url TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'requested',      -- 'requested', 'approved', 'processed', 'rejected'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 9. CARTÃO DA CIDADE (FIDELIZAÇÃO E CASHBACK LOCAL VIA QR CODE)
CREATE TABLE loyalty_ledger (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    customer_email VARCHAR(255) NOT NULL,
    store_id UUID NOT NULL REFERENCES stores(id),
    sub_order_id UUID REFERENCES sub_orders(id),
    points_cents_delta BIGINT NOT NULL,
    transaction_type VARCHAR(30) NOT NULL,                -- 'online_purchase', 'pos_qr_scan', 'redeem', 'refund_reversal'
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_loyalty_customer ON loyalty_ledger(tenant_id, customer_email);

-- ATIVAÇÃO DE ROW-LEVEL SECURITY (RLS)
ALTER TABLE stores ENABLE ROW LEVEL SECURITY;
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE sub_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE refunds ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_stores ON stores
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation_products ON products
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
```

---

## 5. Blindagem Contra Bugs, Manutenção e Atualizações

1. **Contrato Único OpenAPI (`utoipa`):** Toda a alteração num endpoint em Rust atualiza o `openapi.json`, regenerando automaticamente os tipos TypeScript em `/frontend-web`. Inconsistências falham na compilação local, nunca em produção.
2. **Testes Automatizados Focados (Alto Retorno, Zero Perda de Tempo):**
   - `#[sqlx::test]` para cálculo de *split* financeiro e IVA (PT 6%/13%/23%, ES 4%/10%/21%, Art. 53.º).
   - `#[sqlx::test]` para desconto atómico de stock sob concorrência (`UPDATE products SET stock_qty = stock_qty - $1 WHERE id = $2 AND stock_qty >= $1`).
   - `#[sqlx::test]` para garantir que uma sessão RLS do Município A devolve zero registos do Município B.
   - `#[sqlx::test]` para estorno parcial + nota de crédito + reversão de pontos de fidelização.
3. **Dependências Congeladas (`Cargo.lock` / `go.sum`):** Ao contrário de sites WordPress que exigem atualizações semanais de plugins sob risco de invasão, binários compilados em Rust e Go correm estáveis durante meses. Atualizações de segurança fazem-se trimestralmente em branch de teste.
4. **Rollback em 1 Segundo:** O deploy guarda sempre a versão anterior do binário (`ptmarket-api.prev`). Em caso de falha pós-deploy, o script repõe o binário anterior instantaneamente.