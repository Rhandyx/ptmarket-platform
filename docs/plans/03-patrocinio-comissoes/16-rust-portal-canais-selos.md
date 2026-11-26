# 16 — Rust `tenancy::portal`: leitura por canal (nacional e white-label) e selos (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 13, 08 · **Par atómico com:** 08 (corre logo a seguir ao 08; um só commit, com tudo verde, no fim do par) · **Auditoria:** security-auditor obrigatório

## Objetivo
O `PortalReadTx` serve os dois tipos de canal a partir da mesma view, devolve os selos pela ordem fixa e nada no Rust volta a ler `publish_to_national_portal`.

## Pode alterar
- `backend-rust/src/tenancy/portal.rs`; `src/tenancy/mod.rs` (reexports); `backend-rust/tests/rls_isolation.rs` (adaptar: lojas no canal nacional, sem opt-in), `backend-rust/tests/channels.rs` (criar)

## Não tocar
- `src/tenancy/{resolver,host,db,http}.rs`; `src/identity/`; `src/audit/`; `migrations/` (só leitura). Não criar endpoints de catálogo (épico de catálogo): aqui só a API do módulo e os testes.

## Contexto exato (spec 14 §1.1 + cartão 08)
```
Canal nacional: todas as lojas ativas do mesmo país; sem opt-out; shipping_scope (national / local_only / pickup_only) não esconde a loja.
Canal white-label: vista filtrada do mesmo catálogo: só lojas com ≥ 1 patrocínio active e vigente de uma entidade cujo channel_tenant_id é esse canal.
Entidade sem domínio: as suas lojas aparecem no nacional com os selos e numa página/filtro dedicado /entidade/<slug>. Selos: ordem fixa municipality → parish → association; no mesmo tipo, por nome. portal_stores é a forma ÚNICA de ler lojas fora do backoffice.
BD (cartão 08): view portal_stores (colunas da 0021 + shipping_scope, storefront_address, storefront_dicofre), já filtrada pelo canal do contexto (app.current_tenant_id); no nacional exige também o GUC app.portal_national = 'on', no white-label não. View portal_store_badges (store_id, sponsor_entity_id, kind, name, slug, logo_key), só para lojas visíveis. Uma loja só pode existir num tenant national_portal (trinco do 08).
Regra Rust: as duas views leem-se com query_as estático + cast de tipo exato em cada coluna (a macro não tem SELECT nas views; exceção aprovada). Leituras públicas em state.db_replica.
API do módulo (manter PortalReadTx e begin_portal_read_tx; o doctest compile_fail do `SELECT iban FROM stores` fica):
  begin_portal_read_tx funciona nos dois tipos de canal e só liga app.portal_national quando o tenant resolvido é national_portal (usar o que o resolver já expõe; se não expuser o tipo, PARAR e reportar em vez de mexer no resolver).
  published_stores(limit) → Vec<PortalStore>, por nome. PortalStore ganha shipping_scope (enum), storefront_dicofre e badges: Vec<StoreBadge { sponsor_entity_id, kind, name, slug, logo_key }> já ordenados; sem N+1 (uma 2.ª query com store_id = ANY($1)).
  stores_by_entity(slug, limit) → lojas visíveis no canal que têm selo dessa entidade (para /entidade/<slug>) · store_by_slug(slug) → Option<PortalStore>; None se não for visível NESTE canal (nunca revelar que existe noutro).
  stores_by_ids(ids: &[Uuid]) → Vec<PortalStore> (máx. 100 ids): é por aqui que outros módulos (ex.: o painel do sponsor_admin, cartão 20) obtêm nome, NIF e DICOFRE de lojas sem ler `stores`.
  Limites: 1 ≤ limit ≤ 100. Remover do código e dos comentários qualquer leitura de publish_to_national_portal.
```

## Feito quando
- [ ] `channels`, **isolamento entre canais**: no canal da Câmara A só saem as lojas patrocinadas por entidades do canal A; `store_by_slug` e `stores_by_ids` de uma loja só do canal B devolvem vazio; no nacional saem todas as ativas do país
- [ ] **Co-patrocínio:** loja com Câmara + Junta sai uma só vez, com 2 selos pela ordem fixa; `stores_by_entity` da Câmara e da Junta devolvem ambas a loja; a contagem de lojas do canal não a conta duas vezes
- [ ] Patrocínio `active` com `valid_to` no passado, ou revogado: a loja sai do white-label e fica no nacional sem esse selo (sem correr job nenhum)
- [ ] `PortalStore` não tem `iban`, chaves nem comissões (teste de serialização); `rg publish_to_national_portal backend-rust/src` → 0 resultados; `rls_isolation` adaptado continua a provar que o tenant A não lê nem escreve dados de B e que sem contexto saem 0 linhas

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api` → esperado: 0 falhas na suite completa, incluindo doctests (fecha o par 08 + 16)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `migrations/tests/run.sh` e `cd workers-go && go test -race ./...` verdes antes do commit do par
