# 05 — BD: `stores.tenant_id` passa para o canal nacional do país (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 04, 13 (o Rust já decide pelo papel e os testes já semeiam lojas no canal nacional) · **Paralelo com:** —

## Objetivo
Todas as lojas existentes (e tudo o que depende delas) ficam com `tenant_id` = canal nacional (`tenant_type = 'national_portal'`) do país do tenant onde estavam; os tenants municipais continuam a existir como canais. Tudo continua verde.

## Pode alterar
- `migrations/0030_stores_to_national_channel.sql`, `migrations/tests/stores_national_channel.sql` (criar)

## Não tocar
- `migrations/0001–0029`; `tenants` (nenhuma linha muda); policies e views (cartões 08 e 08b); `backend-rust/`. Nunca ler `.env`.

## Contexto exato (spec 14 §1)
```
Loja: vive no catálogo universal: stores.tenant_id aponta SEMPRE para o canal nacional do país da loja. UNIQUE (tenant_id, slug) garante URLs sem colisão no portal. Um national_portal por país.
Migração de dados: não há produção (pré-lançamento); numa BD vazia é um no-op; em dev move as lojas. O trinco "loja só em canal nacional" NÃO entra aqui (fica no cartão 08), por isso os testes que ainda semeiam lojas em tenants municipais (`portal`, `rls`, `rls_isolation`) continuam verdes.
Estado atual: stores UNIQUE (tenant_id, slug) e UNIQUE (tenant_id, id); FKs compostas SEM ON UPDATE CASCADE: products (tenant_id, store_id) → stores; product_variants (tenant_id, product_id) → products; product_price_history (tenant_id, variant_id) → product_variants (ON DELETE RESTRICT; append-only, Omnibus); user_roles (tenant_id, store_id) → stores.
Passos, numa só transação:
  1. Pré-condições (RAISE EXCEPTION claro, sem mexer em nada): cada país com lojas tem exatamente um national_portal ativo; não há dois slugs iguais entre lojas que vão para o mesmo canal (listar os pares; NÃO renomear slugs automaticamente).
  2. Descobrir em pg_constraint TODAS as tabelas com tenant_id que dependem de stores, direta ou indiretamente (não confiar só na lista acima).
  3. Trocar essas FKs compostas por versões com ON UPDATE CASCADE (DROP + ADD, mesmo nome e mesmo ON DELETE) e depois UPDATE stores SET tenant_id = <nacional do país> WHERE tenant_id <> esse; as filhas seguem pela cascata. As FKs ficam com ON UPDATE CASCADE (a app já não tem UPDATE em stores.tenant_id: cartão 04).
  4. user_roles: os merchant_* seguem a loja pela cascata; os tenant_admin NÃO mudam.
  5. Verificação final dentro da migration: zero lojas fora de um national_portal; contagens por tabela iguais às de antes.
Se uma guarda append-only (ex.: product_price_history) ou a caixa negra recusar o UPDATE em cascata: PARAR e reportar ao supervisor com o erro exato. Não desligar triggers, não usar session_replication_role, não fazer SET ROLE. A L1 grava cada linha mexida com ator 'db': é o esperado.
O corpo que move os dados tem de poder ser exercitado pelo teste (ex.: o mesmo bloco DO copiado no teste, com dados semeados antes).
REGRA: o cartão só fecha com tudo verde. Se um teste Rust falhar por causa desta migration, PARAR e reportar (não corrigir Rust aqui; não fechar vermelho).
```

## Feito quando
- [ ] BD limpa e BD com L2: a 0030 aplica sem dados e só muda as FKs
- [ ] Teste `stores_national_channel` com dados (lojas, produtos, variantes, histórico de preços e papéis em 2 tenants municipais PT): tudo fica no nacional PT, contagens iguais, histórico Omnibus intacto, `merchant_owner` ligado à sua loja e `tenant_admin` ao seu tenant
- [ ] Dois slugs iguais no mesmo país, ou país sem `national_portal` → aborta com mensagem clara e nada muda
- [ ] BD de dev migrada; o relatório traz as contagens antes/depois por tabela

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `stores_national_channel`, `omnibus`, `rls`, `portal`, `users_rbac` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suites completas, verdes: `cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api` e `cd workers-go && go test -race ./...`
