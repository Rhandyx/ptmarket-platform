# 05 — Rust: rotas públicas read-only do catálogo + OpenAPI (épico: 04-montra-publica-aprovacao)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** par 01 + 02, par 03 + 04 · **Paralelo com:** — (Rust em série) · **Auditoria:** security-auditor obrigatório

## Objetivo
A montra tem a sua API: cinco rotas GET anónimas, por canal (`Host`), documentadas no `openapi.json`, que só leem pelo `tenancy::portal`.

## Pode alterar
- `backend-rust/src/catalog/{mod,http,dto,cursor}.rs` (criar os três últimos); `src/http/{mod,openapi}.rs`; `openapi.json`; `backend-rust/tests/catalog_http.rs` (criar)

## Não tocar
- `src/tenancy/` (só se usam `ResolvedTenant`, `begin_portal_read_tx` e os métodos do `PortalReadTx`); `src/identity/`, `src/audit/`, `src/money/`, `src/sponsors/`; `migrations/`; `.sqlx/` (não há `query!` novo: o `catalog` não escreve SQL neste cartão).

## Contexto exato (cartões 02 e 04; spec 11 §3; spec 12 §3)
```
Todas GET, anónimas, extractor ResolvedTenant (Host desconhecido → 404), classe AuditClass::ReadAsync, state.db_replica, begin_portal_read_tx + finish(). Query DTOs com deny_unknown_fields. limit: 1..=48, por defeito 24. cursor opaco (base64url; inválido → 422). Nunca 500 por input.
GET /api/v1/catalog/categories → [{"id","parent_id","slug","name","has_products"}] (árvore plana, por sort_order).
GET /api/v1/catalog/products?category=<slug>&store=<slug>&entity=<slug>&q=<1..200>&cursor=&limit= → {"items":[ProductCard],"next_cursor": string|null}
  category inclui os descendentes (ids resolvidos em memória a partir de categories(); máx. 200). category/store desconhecidos NESTE canal → 404. Com q: search_products e os outros filtros são recusados com 422 (v1).
GET /api/v1/catalog/products/{id} → Product | 404 (id inexistente, não publicado ou de loja invisível neste canal: resposta igual, sem distinguir).
GET /api/v1/catalog/stores?entity=<slug>&cursor=&limit= → {"items":[StoreCard],"next_cursor"} · GET /api/v1/catalog/stores/{slug} → StoreProfile | 404
ProductCard: {"id","title","image":{"thumb","card"}|null,"store":{"slug","name","badges":[{"kind","name","slug","logo_key"}]},"price_from_cents","variants_count","in_stock","previous_lowest_cents": int|null,"vat_rate_bps","vat_exempt_art53"}
Product = ProductCard + {"description","attributes","is_perishable","images":[{"thumb","card","full"}],"category":{"slug","name"}|null,"breadcrumb":[{"slug","name"}],"variants":[{"id","ean","attributes","price_cents","in_stock","previous_lowest_cents"}],"store": StoreCard}
StoreCard: {"slug","name","shipping_scope","is_vacation_mode","badges":[…]} · StoreProfile = StoreCard + {"legal_name","nif","email","phone","address","business_hours","vacation_message","supports_click_collect","supports_local_courier","supports_national_shipping","vat_exempt_art53"}
DINHEIRO: só inteiros (cêntimos i64, bps i32); nenhum float no JSON; nenhuma conta aqui; previous_lowest_cents vem do portal (Omnibus): não recalcular. NUNCA sair no JSON: ids de tenant, stock_qty, sku, compare_at*, catalog_item_id, storefront_dicofre, iban, comissões, KYC.
title/name/description: string já resolvida pela língua do canal (country_code PT → "pt", ES → "es"; se faltar, a outra; se faltarem as duas, ""). Limites: description ≤ 20 000 caracteres (truncar).
images: aceitar só entradas cujo thumb/card/full são strings que começam por "/media/"; o resto é ignorado (sem URLs externos: CSP img-src 'self').
Sem Set-Cookie e sem cabeçalhos de cache novos (a cache fica para um cartão de desempenho). utoipa em todas as rotas e schemas; atualizar openapi.json com o binário `openapi` (o frontend gera o cliente daí).
```

## Feito quando
- [ ] `catalog_http`, **isolamento entre canais**: em `Host` do canal A, produto/loja/categoria só do canal B → 404 e não aparece em listas nem na pesquisa; no nacional aparece tudo; Host desconhecido → 404
- [ ] Teste sobre o JSON de todas as rotas: sem `stock_qty`, `sku`, `compare_at`, `iban`, `commission`, `kyc`, `tenant_id`; todos os valores monetários são inteiros; Omnibus e Art. 53.º (`vat_rate_bps` 0 + `vat_exempt_art53` true) corretos
- [ ] Paginação por cursor sem repetidos; `limit=1000`, `cursor=lixo`, campo desconhecido, `q` de 201 caracteres → 422; `q` com `'`, `"` e `%` → 200; imagem com `https://…` ou `javascript:` é ignorada
- [ ] Pedido anónimo não grava evento na caixa negra nem abre sessão; n.º de queries por rota documentado (≤ 5); `openapi.json` regenerado e `cargo test` do contrato verde

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test catalog_http` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suite completa `cargo test -p ptmarket-api` (mesmas variáveis): `/api/v1/tenant`, travão de Hosts, caixa negra e CSRF partilham `http/mod.rs`; `cd frontend-web && npm run check:api`
