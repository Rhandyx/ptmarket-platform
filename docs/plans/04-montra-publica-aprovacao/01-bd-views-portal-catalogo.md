# 01 — BD 0039: views de portal para produtos, variantes e categorias; leitura pública só pelo portal (épico: 04-montra-publica-aprovacao)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** épico 03 até à 0038 · **Par atómico com:** 02 (o 02 corre logo a seguir; um só commit, com tudo verde, no fim do par) · **Auditoria:** security-auditor obrigatório

## Objetivo
O catálogo público lê-se só por três views de `ptmarket_portal` (sem colunas privadas, já filtradas pelo canal); a app deixa de ler diretamente produtos de outras lojas.

## Pode alterar
- `migrations/0039_portal_catalog_views.sql` (criar); `migrations/tests/portal_catalog.sql` (criar) + registo em `migrations/tests/run.sh`; adaptar `migrations/tests/{portal,channel_visibility,store_scope_rls,stores_national_channel,identity_portal_hardening,rls}.sql` só onde provam leitura pública direta de `products`/`product_variants`

## Não tocar
- Migrations 0001–0038 (imutáveis); `audit.*` (selado); a view `portal_stores`, `portal_store_badges` e a policy `portal_view` de `stores`; `backend-rust/`, `workers-go/`, `frontend-web/`. Nunca ler `.env`.

## Contexto exato (spec 14 §1.1; padrão das 0021/0033/0035)
```
Padrão (copiar da 0033): views WITH (security_barrier = true), dona ptmarket_portal (NOLOGIN, sem BYPASSRLS); REVOKE ALL FROM PUBLIC; GRANT SELECT só a ptmarket_app. Sem SET ROLE: o migrator ganha INHERIT em ptmarket_portal só durante o bloco e volta a INHERIT FALSE, SET TRUE (verificar no fim, com os RAISE da 0033 alargados às views novas). GRANT CREATE ON SCHEMA só durante o ALTER … OWNER. Views não levam bloco L1.
ptmarket_portal: GRANT SELECT só das colunas que as views leem em products, product_variants e categories. products e product_variants têm FORCE RLS: criar policy portal_view FOR SELECT TO ptmarket_portal em cada uma, com a mesma condição da view.
"Loja visível" = EXISTS em portal_stores (s.tenant_id = p.tenant_id AND s.id = p.store_id): o canal (nacional vs. white-label) já vem resolvido aí. Não repetir a condição do canal.
portal_products: id, tenant_id, store_id, category_id, title, description, vat_rate_bps, is_perishable, attributes, images, created_at, updated_at. WHERE is_published AND loja visível AND EXISTS variante is_active.
portal_product_variants: id, tenant_id, product_id, ean, attributes, price_cents, lowest_price_30d_cents, (stock_qty > 0) AS in_stock. WHERE is_active AND produto em portal_products.
portal_categories: id, parent_id, slug, name, is_featured, sort_order, has_direct_products = EXISTS produto em portal_products com esta categoria (os ascendentes resolvem-se no Rust).
NUNCA nas views nem nos grants do portal: stock_qty, sku, compare_at_price_cents, catalog_item_id, ai_enriched, taxonomy_code, default_vat_rate_bps. Dinheiro continua BIGINT em cêntimos (PVP com IVA incluído).
Fecho da leitura direta (como a 0021 fez a stores): DROP POLICY portal_read ON products e ON product_variants; ALTER POLICY store_scope_select ON products, product_variants e product_price_history para ficar só com "loja do contexto OR app_is_platform_admin()" (sai o ramo público). O lojista e o admin continuam a ler os seus; anónimo/cliente lê 0 linhas nas tabelas e lê pelas views. O trigger Omnibus (ptmarket_price_writer) não muda.
Índices (parciais, começam por tenant_id): products (tenant_id, id DESC) WHERE is_published; products (tenant_id, category_id, id DESC) WHERE is_published; products (tenant_id, store_id, id DESC) WHERE is_published; product_variants (tenant_id, product_id, price_cents) WHERE is_active.
categories.slug passa a UNIQUE (índice categories_slug_key); duplicados existentes abortam a migration com a lista (padrão da 0035).
Topo da migration: rollback mental completo, como nas anteriores.
```

## Feito quando
- [ ] `portal_catalog.sql`: no nacional saem os produtos publicados de todas as lojas ativas; no white-label A só os de lojas patrocinadas por entidades do canal A (patrocínio expirado/revogado sai sem job); sem contexto → 0 linhas; produto não publicado, variante inativa e loja inativa nunca saem
- [ ] Como `ptmarket_app` sem `app.store_id`: `SELECT` direto em `products`/`product_variants` de loja alheia → 0 linhas; `SELECT stock_qty FROM portal_product_variants` → erro de coluna; a loja A não lê produtos não publicados de B por nenhuma via
- [ ] `EXPLAIN` no teste: listagem por `id DESC` com `id < $cursor`, por categoria e por loja usam os índices novos (sem Seq Scan em `products`)
- [ ] Donos e memberships verificados; lista das falhas Rust esperadas (testes que liam `products` em modo público) entregue ao cartão 02

## Prova (um comando)
`migrations/tests/run.sh` → esperado: tudo verde, incluindo `portal_catalog`, `audit_l1` e `store_scope_rls`

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Omnibus — `migrations/tests/omnibus.sql` (incluído no `run.sh`); isolamento por loja — `store_scope_rls.sql`; a suite Rust só fica verde no fim do par (cartão 02)
