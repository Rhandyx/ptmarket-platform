# 14 — Rust: âmbito de loja e de entidade no contexto da BD (`app.store_id`) + `RequireSponsorAdmin` (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 13, 08b · **Par atómico com:** 08b (corre logo a seguir ao 08b; um só commit, com tudo verde, no fim do par) · **Auditoria:** security-auditor obrigatório

## Objetivo
O extractor de loja e o de entidade põem o seu âmbito na transação (GUCs lidos pelas policies RESTRICTIVE do 08b); o isolamento entre lojas do mesmo país fica provado dos dois lados: extractor e RLS.

## Pode alterar
- `backend-rust/src/identity/rbac.rs`; `src/tenancy/db.rs` e `src/audit/ctx.rs` (só o necessário para os dois GUCs, como foi feito para `app.session_id`); `backend-rust/tests/rbac.rs` e helpers de teste; `backend-rust/tests/store_scope.rs` (criar); `src/http/mod.rs` (rotas `_test`), `.sqlx/**`

## Não tocar
- `src/identity/{staff,login,session}.rs` (fechados no 13); `src/tenancy/{resolver,host,portal}.rs`; o resto de `src/audit/`; `migrations/`.

## Contexto exato (spec 14 §1.1, §8 + cartão 08b)
```
Todas as lojas de um país partilham o mesmo tenant_id. O isolamento entre lojas tem duas camadas: o extractor (papel na loja) e a RLS (policies RESTRICTIVE do 08b, que comparam store_id com o GUC app.store_id e sponsor_entity_id com app.sponsor_entity_id; exceções: ator 'admin' e a leitura pública pelo portal).
Padrão a seguir: o GUC app.session_id que o TenantTx/PlatformTx já põe (cartões 23/23a da Fase 2): set_config(nome, valor, true), local à transação, posto no início do tx junto com os outros GUCs do AuditCtx.
TenantTx: nova forma de abrir com âmbito, p. ex. begin_store_tx(pool, ctx, tenant, store_id) e begin_sponsor_tx(pool, ctx, tenant, entity_id) (ou um enum Scope { None, Store(Uuid), Sponsor(Uuid) } em begin_tenant_tx). O âmbito só pode vir de um tipo que prova a autorização:
  StoreScope { tenant: TenantId, store_id: Uuid } — só construível por RequireStoreRole/RequireStoreOwner (campos privados; sem construtor público fora de test-support).
  SponsorScope { entity_id: Uuid } — só construível por RequireSponsorAdmin.
  Sem âmbito, begin_tenant_tx continua a funcionar para leitura pública e para o que não é de loja; qualquer escrita em tabelas de loja falha na BD (é o esperado).
RequireStoreRole { store_id: Path } / RequireStoreOwner (regras do cartão 13) passam a expor scope(): StoreScope.
RequireSponsorAdmin { entity_id: Path } (novo): sponsor_admin com RoleGrant.sponsor_entity_id = {entity_id} E sessão com mfa_verified_at. Outra entidade ou inexistente → NotFound + Denied("idor"); sem 2FA → 403 'mfa_required'. Expõe scope(): SponsorScope e user_id; o tenant de contexto (canal nacional do país da entidade) é resolvido pelo módulo que o usa.
REGRA mantida (spec 07 §1), também para sponsor_admin: NUNCA recebem iban, invoicing_credentials_enc, eupago_split_key, stripe_account_id nem custom_commission_bps: comentário de módulo + nenhum tipo de resposta com esses campos.
Rotas de prova só com a feature test-support: GET /api/v1/_test/stores/{store_id} (lê a loja dentro de um begin_store_tx), PUT /api/v1/_test/stores/{store_id}/name (escreve), GET /api/v1/_test/sponsors/{entity_id}.
```

## Feito quando
- [ ] `rbac` (lado do extractor): merchant de L1 → 200 em L1; 404 + `denied`/`idor` em L2 do mesmo país, em loja ES e em UUID inexistente; sponsor_admin da Câmara A → 200 em A e 404 + `idor` na Junta B; sem 2FA → 403
- [ ] `store_scope` (lado da RLS, sem passar pelo extractor): um tx com `StoreScope` de L1 (test-support) que tenta UPDATE/DELETE em L2 afeta 0 linhas, INSERT de produto em L2 → erro de RLS, SELECT direto de L2 → 0 linhas; um tx sem âmbito não escreve em nenhuma loja; com âmbito de L1 a escrita em L1 passa e o histórico Omnibus é gravado
- [ ] **Co-patrocínio:** tx com `SponsorScope` da Câmara vê só o seu patrocínio da loja co-patrocinada e não altera o da Junta
- [ ] Os GUCs não vazam entre pedidos na mesma ligação da pool (teste com 2 transações seguidas na mesma ligação); `StoreScope` não se constrói fora do extractor (doctest `compile_fail`)

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api` → esperado: 0 falhas na suite completa (fecha o par 08b + 14)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `migrations/tests/run.sh` e `cd workers-go && go test -race ./...` verdes antes do commit do par; a suite Rust completa acima cobre login, 2FA, sessões, timeline e portal
