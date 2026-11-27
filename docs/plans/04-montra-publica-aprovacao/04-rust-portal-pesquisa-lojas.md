# 04 — Rust `tenancy::portal`: pesquisa, lojas por cursor e perfil público da loja (épico: 04-montra-publica-aprovacao)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 03 · **Par atómico com:** 03 (corre logo a seguir; um só commit no fim do par) · **Auditoria:** security-auditor obrigatório

## Objetivo
O módulo do portal ganha as três leituras que faltam à montra: pesquisa de produtos, lista de lojas paginada e a ficha pública da loja (dados de exibição obrigatória).

## Pode alterar
- `backend-rust/src/tenancy/portal.rs` e `src/tenancy/portal/catalog.rs`; `src/tenancy/mod.rs` (reexports); `backend-rust/tests/portal_catalog.rs` (acrescentar)

## Não tocar
- `src/tenancy/{resolver,host,db,http}.rs`; `src/identity/`, `src/audit/`, `src/money/`, `src/catalog/`, `src/http/`, `src/search.rs` (o trait `SearchBackend` fica como está, para o motor externo); `migrations/` (só leitura). As assinaturas já existentes (`published_stores`, `stores_by_entity`, `store_by_slug`, `stores_by_ids`) não mudam: o cartão 20 do épico 03 usa-as.

## Contexto exato (cartão 03 + view `portal_stores` da 0033)
```
Função da 0040: portal_search_product_ids(p_query text, p_after uuid, p_limit int) RETURNS SETOF uuid — só ids de produtos visíveis no canal do contexto, id DESC. Chamar com query_scalar estático e casts ($1::text, $2::uuid, $3::int4): mesma exceção das views.
search_products(q, after: Option<Uuid>, limit) → ProductPage { items, next }:
  q: trim; 1..=200 caracteres (fora disso → Validation); 1 ≤ limit ≤ 48; pede limit + 1 ids; depois products_by_ids (cartão 02), que volta a filtrar pela view (dupla verificação) e mantém a ordem.
stores_page(entity_slug: Option<&str>, after: Option<(String, Uuid)>, limit) → StorePage { items: Vec<PortalStore>, next: Option<(String, Uuid)> }: ordem (name, id); cursor = (name, id) do último, comparação por tuplo; 1 ≤ limit ≤ 48; selos numa 2.ª query (with_badges).
store_profile_by_slug(slug) → Option<PortalStoreProfile>; None se não for visível NESTE canal.
PortalStoreProfile = PortalStore + só estas colunas de portal_stores: legal_name, email, phone, address_json, storefront_address, geo_lat, geo_lng, business_hours, is_vacation_mode, vacation_message, supports_click_collect, supports_local_courier, supports_national_shipping.
  Porquê estas: identificação do comerciante é de exibição obrigatória (DSA art. 30.º; DL 7/2004 art. 10.º; ES Ley 34/2002 art. 10): nome/firma, NIF, morada, contacto. Nada além da view: NUNCA iban, chaves, comissões, KYC, verificações, plano, termos.
  geo_lat/geo_lng: ler com cast para text (ou o tipo exato da coluna); nunca f32/f64 em contas.
Aproveitar: trocar o O(n·m) de with_badges por HashMap<Uuid, Vec<StoreBadge>> (dívida registada no ESTADO), sem mudar a ordem dos selos (municipality → parish → association; depois nome).
Leituras em state.db_replica; n.º de queries no doc de cada função (search: 1 + as do products_by_ids; stores_page: 2; perfil: 2).
```

## Feito quando
- [ ] `portal_catalog`: `search_products("pao")` encontra "Pão"; no canal A não devolve produtos só do canal B; paginação sem repetidos; `q` vazio ou com 201 caracteres → `Validation`; `q` com aspas/operadores não dá 500
- [ ] `stores_page`: 60 lojas em páginas de 24, duas lojas com o mesmo nome não se perdem nem repetem; com `entity_slug` só as que têm selo dessa entidade; loja co-patrocinada sai uma vez
- [ ] `store_profile_by_slug` de loja só visível noutro canal → None; teste de serialização: chaves exatamente as listadas (sem `iban`, `*_enc`, `*commission*`, `kyc*`, `billing*`, `terms*`)
- [ ] Ordem dos selos igual à anterior (teste `channels` verde sem alterações)

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api` → esperado: 0 falhas na suite completa, incluindo doctests (fecha o par 03 + 04)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `channels`, `store_scope`, `rls_isolation` e `sponsorships_admin` (incluídos na suite); `migrations/tests/run.sh` verde antes do commit do par
