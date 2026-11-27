# 06 — Rust: `GET /api/v1/sponsors/mine`, as entidades do `sponsor_admin` em sessão (épico: 04-montra-publica-aprovacao)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 05; cartão 20 do épico 03 (módulo `sponsors` com `admin.rs`) · **Paralelo com:** — (Rust em série) · **Auditoria:** security-auditor obrigatório

## Objetivo
O painel sabe o nome, o tipo e o logótipo das entidades que o utilizador gere, sem receber nenhum id do pedido. É a única peça de backend que falta ao ecrã de aprovação.

## Pode alterar
- `backend-rust/src/sponsors/{admin,http,mod}.rs`; `src/http/{mod,openapi}.rs`; `openapi.json`; `.sqlx/**`; `backend-rust/tests/sponsorships_admin.rs` (acrescentar)

## Não tocar
- `src/identity/` e `src/tenancy/` (só se usam os extractores e as transações que já existem); `src/money/`, `src/audit/`, `src/catalog/`; `migrations/`. As rotas e os DTOs do cartão 20 não mudam.

## Contexto exato (spec 14 §8; cartões 14 e 20 do épico 03)
```
Painel único: staff autentica-se só em PLATFORM_ADMIN_HOST; o âmbito vem do papel, nunca do Host nem do pedido. sponsor_admin tem 2FA obrigatório.
GET /api/v1/sponsors/mine → 200 [{"id","kind","name","slug","logo_key","has_channel": bool}] por (kind na ordem municipality → parish → association, name).
  Sem parâmetros (Query DTO vazio com deny_unknown_fields). Os ids vêm SÓ dos grants `sponsor_admin` da sessão (StaffRoles): anti-IDOR por construção.
  Extractor: o de staff com 2FA feito (o mesmo nível do RequireSponsorAdmin; sem 2FA → 403). Sem sessão ou num Host de canal → 401. Staff sem nenhum grant sponsor_admin (lojista, tenant_admin, super_admin) → 200 [].
  Só entidades com is_active = true (a desativada não aparece: coerente com a adenda do cartão 20, que lhe dá 404 em tudo).
  has_channel = channel_tenant_id IS NOT NULL. NUNCA devolver channel_tenant_id, áreas DICOFRE, contactos, preços do contrato nem comissões.
  Leitura: pela função do módulo `sponsors` que o cartão 20 já usa para ler a entidade (mesma transação/âmbito; se essa função só ler uma entidade de cada vez, acrescentar a variante por lista de ids, máx. 50, com `id = ANY($1)`). Não ler `sponsor_entities` a partir de outro módulo.
  Classe da caixa negra: leitura de admin = síncrona (AuditClass::ReadSync), como a listagem do cartão 20. Resposta com Cache-Control: no-store.
  utoipa + openapi.json atualizado.
```

## Feito quando
- [ ] `sponsorships_admin`: utilizador com grants na Câmara e na Junta recebe as duas, pela ordem fixa; com um só grant, uma; a entidade de outro utilizador nunca aparece
- [ ] Entidade desativada não aparece; lojista e super_admin → `[]`; sem 2FA → 403; sem sessão → 401; em Host de canal → 401; query string com campo desconhecido → 422
- [ ] Teste sobre o JSON: só as 6 chaves; sem `channel_tenant_id`, `commission`, `email`, `phone`
- [ ] A leitura fica na caixa negra como leitura síncrona do ator `Municipal` (teste confirma o evento)

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test sponsorships_admin` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suite completa `cargo test -p ptmarket-api` (inclui `rbac`, `store_scope`, `catalog_http`); `cd frontend-web && npm run check:api`
