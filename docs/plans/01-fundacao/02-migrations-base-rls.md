# 02 — Migrations base com RLS forçado (épico: 01-fundacao)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** — · **Paralelo com:** 01, 04, 07, 08

## Objetivo
BD limpa PG18 recebe tenants, categories, stores, products, product_variants, customers e outbox_events, isolados por tenant e fechados por omissão.

## Pode alterar
- `migrations/0001_roles.sql` … `0006_outbox.sql`, `migrations/tests/run.sh`, `migrations/tests/rls.sql` (criar)

## Não tocar
- `infra/`, `backend-rust/`, `workers-go/`, `frontend-web/` — outros cartões; `product_price_history` e triggers de preço — cartão 03; orders/stock_reservations/índices de pesquisa — épicos seguintes

## Contexto exato (colado da spec; não ler a spec)
```
Papéis: ptmarket_app (API) e ptmarket_worker (outbox). 0001 cria-os NOLOGIN só se não existirem (DO + pg_roles), sem password, nunca SUPERUSER/BYPASSRLS; quem corre a migration tem de conseguir SET ROLE para ambos.
Convenções: id UUID PRIMARY KEY DEFAULT uuidv7() (sem uuid-ossp) · created_at TIMESTAMPTZ NOT NULL DEFAULT now() · dinheiro BIGINT cêntimos CHECK (>= 0) · todo o *_bps INT CHECK (BETWEEN 0 AND 10000) · nunca REAL/FLOAT/NUMERIC em dinheiro (só geo_lat/geo_lng são DOUBLE PRECISION) · ON DELETE explícito · índice em toda a FK · compostos começam por tenant_id · rollback mental no topo de cada ficheiro.
tenants(id, slug VARCHAR(64) UNIQUE NOT NULL, custom_domain VARCHAR(255) UNIQUE NOT NULL, name VARCHAR(255) NOT NULL, tenant_type VARCHAR(24) NOT NULL DEFAULT 'municipal' CHECK IN ('municipal','national_portal','niche'), country_code CHAR(2) NOT NULL DEFAULT 'PT' CHECK IN ('PT','ES'), currency CHAR(3) NOT NULL DEFAULT 'EUR', default_commission_bps INT NOT NULL DEFAULT 0, template_layout VARCHAR(32) NOT NULL DEFAULT 'bairro' CHECK IN ('bairro','editorial','catalogo'), theme_config JSONB NOT NULL DEFAULT '{"primary_color":"#0F4C81","secondary_color":"#111827","logo_url":"","favicon_url":"","institutional_footer":"","accessibility_statement_url":""}', legal_config JSONB NOT NULL DEFAULT '{"entity_name":"","nif":"","ral_entity":"CNIACC","livro_reclamacoes_url":"https://www.livroreclamacoes.pt"}', loyalty_enabled BOOLEAN NOT NULL DEFAULT true, loyalty_cashback_bps INT NOT NULL DEFAULT 500, is_active BOOLEAN NOT NULL DEFAULT true, created_at)  -- global, sem RLS
categories(id, parent_id UUID REFERENCES categories ON DELETE SET NULL, taxonomy_code VARCHAR(64) UNIQUE, slug VARCHAR(140) NOT NULL, name JSONB NOT NULL /* {"pt":"Padaria","es":"Panadería"} */, default_vat_rate_bps INT NOT NULL DEFAULT 2300 /* taxa normal PT continente; ES/ilhas resolvem-se na app */, is_featured BOOLEAN NOT NULL DEFAULT false, sort_order INT NOT NULL DEFAULT 0)  -- global, sem RLS
stores(id, tenant_id UUID NOT NULL REFERENCES tenants ON DELETE CASCADE, name VARCHAR(255) NOT NULL, slug VARCHAR(120) NOT NULL, legal_name VARCHAR(255) NOT NULL /* DSA */, nif VARCHAR(20) NOT NULL, iban VARCHAR(34) NOT NULL, email VARCHAR(255) NOT NULL, phone VARCHAR(50), address_json JSONB NOT NULL DEFAULT '{}', geo_lat DOUBLE PRECISION, geo_lng DOUBLE PRECISION, business_hours JSONB NOT NULL DEFAULT '{}', is_vacation_mode BOOLEAN NOT NULL DEFAULT false, vacation_message TEXT, supports_click_collect BOOLEAN NOT NULL DEFAULT true, supports_local_courier BOOLEAN NOT NULL DEFAULT false, supports_national_shipping BOOLEAN NOT NULL DEFAULT true, shipping_config JSONB NOT NULL DEFAULT '{}', vat_exempt_art53 BOOLEAN NOT NULL DEFAULT false /* true = IVA 0% */, invoicing_provider VARCHAR(30) NOT NULL DEFAULT 'none' CHECK IN ('moloni','invoicexpress','vendus','none'), invoicing_credentials_enc TEXT /* AES-256-GCM, chave fora da BD */, eupago_split_key VARCHAR(255), stripe_account_id VARCHAR(255), custom_commission_bps INT /* NULL = herda do tenant */, kyc_verified BOOLEAN NOT NULL DEFAULT false, publish_to_national_portal BOOLEAN NOT NULL DEFAULT false, is_active BOOLEAN NOT NULL DEFAULT true, created_at, UNIQUE(tenant_id, slug), UNIQUE(tenant_id, id)); índice parcial (publish_to_national_portal) WHERE publish_to_national_portal
products(id, tenant_id UUID NOT NULL REFERENCES tenants ON DELETE CASCADE, store_id UUID NOT NULL, FOREIGN KEY (tenant_id, store_id) REFERENCES stores(tenant_id, id) ON DELETE CASCADE, category_id UUID REFERENCES categories ON DELETE SET NULL, catalog_item_id UUID /* sem FK: catalog_items vem depois */, title JSONB NOT NULL, description JSONB NOT NULL DEFAULT '{}', vat_rate_bps INT NOT NULL /* SEM default: a app decide por categoria+país */, is_perishable BOOLEAN NOT NULL DEFAULT false, attributes JSONB NOT NULL DEFAULT '{}', images JSONB NOT NULL DEFAULT '[]', ai_enriched BOOLEAN NOT NULL DEFAULT false, is_published BOOLEAN NOT NULL DEFAULT true, created_at, updated_at, UNIQUE(tenant_id, id)); índices (tenant_id, store_id), (tenant_id, category_id), (category_id)  -- sem preço, stock, sku, ean nem `variants` JSONB
product_variants(id, tenant_id UUID NOT NULL, product_id UUID NOT NULL, FOREIGN KEY (tenant_id, product_id) REFERENCES products(tenant_id, id) ON DELETE CASCADE, sku VARCHAR(100), ean VARCHAR(64), attributes JSONB NOT NULL DEFAULT '{}', price_cents BIGINT NOT NULL /* PVP com IVA incluído */, compare_at_price_cents BIGINT, lowest_price_30d_cents BIGINT, stock_qty INT NOT NULL DEFAULT 0 CHECK (stock_qty >= 0), is_active BOOLEAN NOT NULL DEFAULT true, created_at, updated_at, UNIQUE(tenant_id, id)); índices (tenant_id, product_id), (tenant_id, ean) WHERE ean IS NOT NULL  -- produto simples = 1 variante
customers(id, email VARCHAR(255), name VARCHAR(255), phone VARCHAR(50), nif VARCHAR(20), password_hash TEXT /* Argon2id PHC; NULL = só passkey */, passkeys JSONB NOT NULL DEFAULT '[]', consents JSONB NOT NULL DEFAULT '{}', anonymized_at TIMESTAMPTZ, created_at, updated_at, CHECK (email IS NOT NULL OR anonymized_at IS NOT NULL)); UNIQUE INDEX (lower(email))  -- global
outbox_events(id, tenant_id UUID /* NULL = evento global; sem FK */, aggregate VARCHAR(64) NOT NULL, aggregate_id UUID NOT NULL, event_type VARCHAR(96) NOT NULL, payload JSONB NOT NULL, created_at, published_at TIMESTAMPTZ); índices (created_at) e (created_at, id) WHERE published_at IS NULL
RLS: ENABLE + FORCE ROW LEVEL SECURITY em stores, products, product_variants, customers, outbox_events. T := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid (sem contexto = NULL = zero linhas).
  stores, products, product_variants: CREATE POLICY tenant_isolation ON <t> FOR ALL TO ptmarket_app USING (tenant_id = T) WITH CHECK (tenant_id = T); GRANT SELECT, INSERT, UPDATE, DELETE TO ptmarket_app
  outbox_events: policy INSERT TO ptmarket_app WITH CHECK (tenant_id IS NULL OR tenant_id = T) + GRANT INSERT (sem SELECT); policies SELECT e UPDATE TO ptmarket_worker USING (true) + GRANT SELECT, UPDATE (published_at)
  customers: ZERO policies e ZERO grants (fechada até ao épico identity). tenants, categories: GRANT SELECT TO ptmarket_app. USAGE no schema public para ambos os papéis.
```

## Feito quando
- [ ] `run.sh` cria um `postgres:18` descartável (ou usa `MIGRATIONS_TEST_URL`), corre `sqlx migrate run --source migrations` e todos os `tests/*.sql` com `ON_ERROR_STOP`
- [ ] Teste novo `tests/rls.sql` (sempre com `SET ROLE`, nunca como superuser): app sem contexto vê 0 lojas; tenant A só vê as suas; INSERT/UPDATE para o tenant B falha (42501); produto com loja de outro tenant falha (23503); `stock_qty = -1` falha (23514); app não lê `customers` nem `outbox_events`; worker lê o outbox mas não altera `payload`; nenhum dos papéis tem `rolsuper`/`rolbypassrls`

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- —
