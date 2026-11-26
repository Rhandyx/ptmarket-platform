# 08b — BD: isolamento entre lojas do mesmo país na RLS (`app.store_id`, policies RESTRICTIVE) (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 08 + 16 (par fechado) · **Par atómico com:** 14 (o 14 corre logo a seguir; um só commit, com tudo verde, no fim do par) · **Auditoria:** security-auditor obrigatório

## Objetivo
Mesmo com todas as lojas de um país no mesmo `tenant_id`, a `ptmarket_app` só escreve e só lê em backoffice as linhas da loja (ou da entidade) que o extractor pôs no contexto; a leitura pública continua a passar pelo portal.

## Pode alterar
- `migrations/0034_store_scope_rls.sql`, `migrations/tests/store_scope_rls.sql` (criar); testes existentes em `migrations/tests/` que escrevem em tabelas de loja como `ptmarket_app` (só acrescentar o GUC ao contexto; não mudar o que provam)

## Não tocar
- `migrations/0001–0033`; as policies `tenant_isolation`, `portal_read`, `portal_view` e as views do portal (ficam como o 08 as deixou); `audit.*`; `backend-rust/` (cartão 14). Nunca ler `.env`.

## Contexto exato (decisão do supervisor; padrão do GUC `app.session_id` da 0026)
```
GUCs novos, postos pelo TenantTx com set_config(…, true) (locais à transação, como app.session_id): app.store_id (extractor de loja) e app.sponsor_entity_id (extractor de entidade). Vazio ou ausente = sem âmbito.
Funções SQL INVOKER STABLE, SET search_path = pg_catalog, pg_temp, EXECUTE só para ptmarket_app: app_store_id() = NULLIF(current_setting('app.store_id', true), '')::uuid; app_sponsor_entity_id() idem; app_is_platform_admin() = (current_setting('app.actor_type', true) = 'admin') — confirmar na 0010 o nome exato do GUC do tipo de ator.
Policies AS RESTRICTIVE … TO ptmarket_app (somam-se por AND às permissivas; não tocam em ptmarket_portal, ptmarket_identity, ptmarket_worker). Uma policy por comando (SELECT, INSERT, UPDATE, DELETE); S = "store_id = (SELECT app_store_id())", ADM = "(SELECT app_is_platform_admin())":
  stores           escrita: id = app_store_id() OR ADM · SELECT: id = app_store_id() OR ADM   (a leitura pública é só pela view portal_stores, cuja dona não é a app)
  products         escrita: S OR ADM · SELECT: S OR ADM OR (is_published AND EXISTS em portal_stores com o mesmo tenant_id e store_id)
  product_variants escrita e SELECT pelo produto (EXISTS products p com o mesmo tenant_id/product_id e p.store_id = app_store_id()) OR ADM; no SELECT também OR (is_active AND produto publicado de loja presente em portal_stores)
  product_price_history: o mesmo critério pela variante → produto. Confirmar que o trigger Omnibus da 0007 (INSERT no histórico ao mudar o preço) continua a gravar quando o lojista da loja muda o preço.
  store_sponsorships INSERT: S · UPDATE: sponsor_entity_id = app_sponsor_entity_id() OR ADM · SELECT: S OR sponsor_entity_id = app_sponsor_entity_id() OR ADM
  Outras tabelas de loja: listar em information_schema todas as tabelas de public com coluna store_id (ou FK para stores/products) e aplicar o mesmo critério; user_roles fica de fora (já só tem own_select). store_verifications nasce no cartão 09 já com a sua policy.
Exceções explícitas e únicas: super_admin (ator 'admin') e a leitura pública pelas policies/views do portal. Sem app.store_id, um ator merchant, municipal, customer ou system não escreve em nenhuma loja.
O GUC é posto pela app (o mesmo nível de confiança de app.current_tenant_id): é defesa em profundidade contra um handler que se esqueça do filtro, não contra uma app comprometida. Dizê-lo no COMMENT.
Sem tabelas novas (sem bloco L1). Nunca SET ROLE para papéis sem acesso a audit. Índices: confirmar que products (tenant_id, store_id) serve as policies (EXPLAIN no teste, sem Seq Scan).
```

## Feito quando
- [ ] Teste `store_scope_rls`, lojas L1 e L2 no canal nacional PT, como `ptmarket_app` com ator merchant e `app.store_id = L1`: lê e escreve L1 (loja, produto, variante, preço com histórico Omnibus); em L2, UPDATE/DELETE afetam 0 linhas, INSERT → 42501, SELECT direto de `stores`/produto não publicado → 0 linhas
- [ ] Sem `app.store_id`: nenhuma escrita passa; a leitura pública (canal nacional e white-label) de lojas e produtos publicados dá o mesmo que no cartão 08; ator `admin` lê e escreve as duas lojas
- [ ] **Co-patrocínio:** `app.sponsor_entity_id` = Câmara vê e altera só o seu patrocínio da loja co-patrocinada, não o da Junta; o lojista vê os dois e não consegue UPDATE em nenhum
- [ ] `rls`, `portal`, `channel_visibility`, `omnibus` e `store_sponsorships` continuam verdes

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `store_scope_rls` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Dentro do par, `cargo test -p ptmarket-api` pode falhar onde o Rust ainda não põe o GUC: listar as falhas para o 14, que as fecha. O par só é entregue com `run.sh`, `cargo test -p ptmarket-api` e `go test -race ./...` verdes.
