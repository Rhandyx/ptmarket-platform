# 06 — `AuditCtx` obrigatório em todas as transações + `audit::record` (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 03 · **Paralelo com:** 04, 09

> **Mudou no 01b:** as funções da caixa negra estão no schema `audit` (ex.: `audit.audit_append`, `audit.audit_append_event`); chamar sempre com o schema e com tipos exatos (`::text`, `::uuid`), para nunca resolver para uma sobrecarga plantada. A app e o worker só têm EXECUTE nas funções previstas e USAGE no schema.

## Objetivo
Nenhuma transação da API abre sem ator: `begin_tenant_tx` e a nova `begin_platform_tx` exigem `AuditCtx` (sem ele não compila) e fixam o contexto de ator na BD; existe a única função para eventos semânticos.

## Pode alterar
- `backend-rust/src/audit/{mod,ctx,record}.rs`, `backend-rust/tests/audit_ctx.rs` (criar); `src/tenancy/db.rs`, `src/outbox.rs`, `src/lib.rs`, `tests/rls_isolation.rs`, `.sqlx/**` (editar)

## Não tocar
- `migrations/` — só leitura (falta algo na BD → parar e reportar); `src/money/`, `src/http/` (middleware = cartão 07), `src/error.rs`; `workers-go/`, `frontend-web/`, `infra/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §3.1: as mutações recebem um AuditCtx obrigatório (ator, ip, request_id) vindo do extractor; sem AuditCtx não compila. §3.2: na mesma transação a app faz set_config('app.actor_type'|'app.actor_id'|'app.impersonator_id'|'app.request_id'|'app.ip', …, true), tal como o tenant; TenantTx passa a exigir o AuditCtx.
BD (cartões 01–03, feitos): trigger L1 em todas as tabelas; mutação de ptmarket_app sem app.actor_type → SQLSTATE 'PTA01'. Função (ator lido do contexto, nunca por parâmetro):
  audit_append(p_action text, p_target_type text, p_target_id text, p_outcome text, p_reason text, p_changes jsonb, p_store_id uuid, p_tenant_id uuid DEFAULT NULL) RETURNS uuid
  outcome ∈ success|denied|error. Admin/impersonation gera sozinha o evento de outbox 'audit.superadmin_action'.
API a criar:
  pub enum ActorType { Customer, Merchant, Municipal, Admin, System, ApiKey, Anonymous }   // 'db' nunca nasce na app
  pub struct AuditCtx { actor_type, actor_id: Option<Uuid>, actor_label: Option<String>, impersonator_id: Option<Uuid>, request_id: Uuid, ip: Option<IpAddr>, user_agent_hash: Option<[u8; 32]>, recorded: Arc<AtomicBool> }
    campos privados; construtores pub(crate) (o extractor HTTP do cartão 07), AuditCtx::system(job: &'static str) e for_tests só com a feature test-support. Sem Default.
  begin_tenant_tx(pool, tenant: TenantId, ctx: &AuditCtx) -> TenantTx ; begin_platform_tx(pool, ctx: &AuditCtx) -> PlatformTx (sem tenant; tabelas globais). Uma só query! com set_config(…, true) para app.current_tenant_id, app.actor_type, app.actor_id, app.actor_label, app.impersonator_id, app.request_id, app.ip, app.user_agent_hash (hex). Proibido SET sem LOCAL, format!/concatenação.
  outbox::append_global passa a receber &mut PlatformTx (deixa de aceitar Transaction crua). Nenhuma Transaction<Postgres> crua sai do crate.
  audit::record(tx, AuditEvent { action, target_type, target_id, outcome, reason, changes: Option<serde_json::Value>, store_id }) -> Result<Uuid, AppError>: passa `changes` por http::telemetry::redact, chama audit_append e marca ctx.recorded = true (o middleware do cartão 07 lê a marca).
Proibido: flag, feature, variável de ambiente ou construtor que desligue ou salte a auditoria.
```

## Feito quando
- [ ] `audit_ctx`: mutação numa `TenantTx` grava o evento L1 com `actor_type`, `actor_id`, `request_id` e `ip` do `AuditCtx`; depois do commit/rollback, a query seguinte na mesma ligação (pool de 1) já não tem ator (INSERT como app → `Err`)
- [ ] `audit::record` grava evento semântico na mesma transação; rollback não deixa evento; `changes` com `password`/IBAN sai mascarado; tenant A não lê o evento de B (anti-IDOR)
- [ ] Doctest `compile_fail`: `begin_tenant_tx(&pool, tenant)` sem `AuditCtx` não compila; `append_global` com `TenantTx` não compila
- [ ] `rls_isolation` volta a verde com `AuditCtx` (mesmas asserções); `.sqlx/` atualizado e `SQLX_OFFLINE=true cargo check` passa
- [ ] Corrida da cadeia em REPEATABLE READ (2 ligações, mesmo tenant, `audit_append` em paralelo): uma recebe 40001 e o `audit_ctx` repete a transação; no fim `chain_seq` é contíguo e sem repetidos (no 0008 a cabeça `audit_chain_heads` é bloqueada com `FOR UPDATE`)

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket cargo test -p ptmarket-api --test audit_ctx --test rls_isolation --doc` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Health, AppError, money, redação de logs — `cd backend-rust && SQLX_OFFLINE=true cargo test -p ptmarket-api --lib`
