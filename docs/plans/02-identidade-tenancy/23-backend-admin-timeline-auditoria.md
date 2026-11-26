# 23 — API da timeline de auditoria no Super-Admin (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 09a, 20, 23a (função `audit.admin_read_events`) · **Paralelo com:** 21

## Objetivo
O super_admin consulta a caixa negra numa timeline filtrável por tenant, loja, utilizador e encomenda, com antes/depois e o estado da cadeia (decisão do owner, 26/11/2026). A UI fica no 1.º cartão do épico de backoffice; este cartão entrega a API e o contrato OpenAPI.

## Pode alterar
- `backend-rust/src/admin/audit_timeline.rs` + testes (criar), `src/admin/mod.rs`, `src/http/router.rs` (só registar a rota), `.sqlx/`, `openapi.json` (regenerado)

## Não tocar
- `src/audit/`, `src/identity/`, `src/tenancy/` (usar só as APIs públicas), `migrations/`, `workers-go/`, `frontend-web/`

## Ajustes do supervisor (prevalecem sobre o contexto abaixo)
- Rota: `GET /api/v1/superadmin/audit/events`, dentro do grupo `superadmin` já fechado pelo `superadmin_gate` (cartão 20). Quem não for super_admin com 2FA recebe o 404 uniforme + `denied`/`superadmin_gate` (não 403).
- A leitura global faz-se só por `audit.admin_read_events(...)` (cartão 23a), com `query_as` estático + casts (exceção `audit.*`). Um 42501 da função dá 404 + denied; um 22023 dá 400.
- `src/http/mod.rs` (registar a rota no grupo superadmin) substitui `src/http/router.rs` em "Pode alterar". Teste de integração em `tests/admin_timeline.rs`; a Prova passa a `--test admin_timeline`.

## Contexto exato
```
GET /admin/audit/events?tenant_id&store_id&actor_id&order_id&action_prefix&outcome&from&to&cursor&limit (limit ≤ 100, default 50; from/to obrigatórios, janela máx. 31 dias)
  Só super_admin com 2FA verificado na sessão (cartão 20); qualquer outro → 403 auditado (denied).
  Leitura global: papel/ligação de leitura admin definidos no cartão 20 ou numa função audit.admin_read_events(...) SECURITY DEFINER na allowlist (pedir ao supervisor se faltar; não dar SELECT global à ptmarket_app).
  order_id: target_type='order' AND target_id = $id, OU changes->>'order_id' = $id.
  Paginação por cursor (created_at, id), nunca OFFSET. Resposta: id, created_at, tenant_id, store_id, actor_type, actor_id, actor_label, impersonator_id, action, target_type, target_id, outcome, reason, changes (já mascarado), chain_seq, chain_ok (bool: o verify da janela devolvida não encontrou quebra).
  A própria consulta gera um audit_event síncrono (leitura de admin; 503 se a gravação falhar) com os filtros usados em changes.
```

## Feito quando
- [ ] Filtros por tenant, loja, utilizador e encomenda devolvem só os eventos certos (dados de teste com 2 tenants, 2 lojas, 2 utilizadores, 1 encomenda com eventos de pagamento e fatura)
- [ ] Não super_admin, ou super_admin sem 2FA → 403 + evento denied; janela > 31 dias ou limit > 100 → 400
- [ ] Cada consulta deixa 1 audit_event com os filtros; se a gravação falhar → 503 e nenhum dado devolvido
- [ ] Cursor estável: 3 páginas seguidas sem repetidos nem buracos; `openapi.json` atualizado

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket cargo test -p ptmarket-api admin::audit_timeline` → 0 falhas
