# 02 — Rust `tenancy::portal`: produtos, variantes e categorias por canal (épico: 04-montra-publica-aprovacao)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 01 · **Par atómico com:** 01 (corre logo a seguir; um só commit no fim do par) · **Auditoria:** security-auditor obrigatório

## Objetivo
O `PortalReadTx` passa a ler produtos, variantes e categorias pelas views da 0039, com paginação por cursor, Omnibus correto e sem colunas privadas. Sem rotas HTTP (cartão 05).

## Pode alterar
- `backend-rust/src/tenancy/portal/catalog.rs` (criar; submódulo de `portal.rs`, para aceder ao `tx` privado); `src/tenancy/portal.rs` (só `mod catalog`, reexports, `PORTAL_FORBIDDEN_COLUMNS`, campo novo em `PortalStore`); `src/tenancy/mod.rs` (reexports); `backend-rust/tests/portal_catalog.rs` (criar); `tests/{store_scope,channels,rls_isolation}.rs` (só o que a 0039 partiu)

## Não tocar
- `src/tenancy/{resolver,host,db,http}.rs`; `src/identity/`, `src/audit/`, `src/money/`, `src/catalog/`, `src/http/`; `migrations/` (só leitura). Não dar acesso à ligação do `PortalReadTx`.

## Contexto exato (cartão 01 + regras do módulo)
```
Views (0039), já filtradas pelo canal do contexto: portal_products(id, tenant_id, store_id, category_id, title jsonb, description jsonb, vat_rate_bps int4, is_perishable, attributes jsonb, images jsonb, created_at, updated_at) · portal_product_variants(id, tenant_id, product_id, ean, attributes jsonb, price_cents int8, lowest_price_30d_cents int8 NULL, in_stock bool) · portal_categories(id, parent_id, slug, name jsonb, is_featured, sort_order, has_direct_products bool)
Regra Rust (exceção já aprovada para portal_stores, alargada a estas views): query_as com SQL estático + cast de tipo exato em cada coluna e argumento; nunca query! nem SQL montado. Leituras em state.db_replica. A app já NÃO lê products/product_variants diretamente em modo público.
API (em impl PortalReadTx):
  categories() → Vec<PortalCategory { id, parent_id, slug, name, is_featured, sort_order, has_products }>: has_products = direto OU de qualquer descendente (propagar em memória); por sort_order, slug.
  products_page(filter, after: Option<Uuid>, limit) → ProductPage { items: Vec<PortalProductCard>, next: Option<Uuid> }. filter = { category_ids: Option<Vec<Uuid>> (máx. 200), store_id: Option<Uuid>, entity_slug: Option<String> } (entidade = EXISTS em portal_store_badges com esse slug). Ordem: id DESC (UUIDv7 = mais recentes primeiro); cursor = id do último; lê limit + 1 para saber se há mais; 1 ≤ limit ≤ 48.
  product_by_id(id) → Option<PortalProduct> com todas as variantes (por price_cents, id); None se não for visível NESTE canal (nunca revelar que existe noutro).
  products_by_ids(ids, máx. 100) → Vec<PortalProductCard>, pela ordem de `ids`; os invisíveis ficam de fora sem erro.
Sem N+1: por chamada, 1 query de produtos + 1 de variantes (product_id = ANY($1)) + stores_by_ids (lojas + selos). N.º de queries escrito no doc de cada função.
PortalProductCard: id, title, images, category_id, store: PortalStore (com selos), price_from_cents: i64 (mínimo das variantes), variants_count, in_stock (alguma variante), previous_lowest_cents: Option<i64>. PortalProduct junta description, attributes, is_perishable e variants: Vec<PortalVariant { id, ean, attributes, price_cents: i64, in_stock, previous_lowest_cents: Option<i64> }>.
OMNIBUS (DL 70/2007 art. 5.º, red. DL 109-G/2021; ES art. 20 Ley 7/1996): previous_lowest_cents = Some(lowest_price_30d_cents) SÓ se não for NULL e price_cents < lowest_price_30d_cents; senão None. No cartão de lista só se preenche com exatamente 1 variante ativa. Só comparação: nenhuma conta nem percentagem (aritmética de dinheiro é do módulo money). Dinheiro sempre i64.
ART. 53.º: PortalStore ganha vat_exempt_art53: bool (já está na view portal_stores). Em PortalProduct/Card, vat_rate_bps: i32 efetivo = 0 se a loja for vat_exempt_art53, senão o do produto.
PORTAL_FORBIDDEN_COLUMNS ganha: stock_qty, sku, compare_at_price_cents, catalog_item_id, ai_enriched.
```

## Feito quando
- [ ] `portal_catalog`, **isolamento entre canais**: canal A só vê produtos de lojas patrocinadas por A; `product_by_id`/`products_by_ids` de um produto só do canal B → vazio; nacional vê todos os publicados; loja co-patrocinada: produto sai uma vez, com 2 selos
- [ ] Paginação: 60 produtos em páginas de 24 → sem repetidos nem saltos, `next` None no fim; `limit` 0 e 49 são limitados; mais de 200 categorias ou 100 ids → `Validation`
- [ ] Omnibus: descida de preço → `previous_lowest_cents` = mínimo dos 30 dias; subida ou preço nunca alterado → None; 2 variantes → None no cartão de lista. Art. 53.º → `vat_rate_bps` 0
- [ ] Teste de serialização: nenhuma chave `stock_qty`, `sku`, `compare_at*`, `iban`, `*commission*`; o SQL do módulo não nomeia colunas proibidas; `store_scope`/`channels`/`rls_isolation` adaptados continuam a provar o isolamento

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api` → esperado: 0 falhas na suite completa, incluindo doctests (fecha o par 01 + 02)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `migrations/tests/run.sh` e `cd workers-go && go test -race ./...` verdes antes do commit do par; `sponsorships_admin` (usa `stores_by_ids`) incluído na suite
