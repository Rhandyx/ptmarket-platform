# 06 — Transação com contexto de tenant + outbox, provados contra RLS real (épico: 01-fundacao)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 01, 02, 04, 05 · **Paralelo com:** —

## Objetivo
O backend tem a única forma permitida de abrir uma transação de tenant e de gravar um evento no outbox, com teste de isolamento contra o Postgres 18 real.

## Pode alterar
- `backend-rust/src/tenancy/{mod,db}.rs`, `backend-rust/src/outbox.rs`, `backend-rust/tests/rls_isolation.rs`, `backend-rust/.sqlx/**` (criar); `src/lib.rs` (só `pub mod outbox;`); `Cargo.toml` (só features do sqlx)

## Não tocar
- `migrations/` — só leitura (o teste aplica-as); se faltar algo na BD, parar e reportar, não contornar no Rust
- `src/money/`, `src/http/`, `src/error.rs` — cartões 04/05; `infra/`, `workers-go/`, `frontend-web/`

## Contexto exato (colado da spec; não ler a spec)
```
BD (cartões 01/02, já feitos): dev em 127.0.0.1:5432/ptmarket; ptmarket_migrator (dono, CREATEDB, consegue SET ROLE) · ptmarket_app (API, sem BYPASSRLS).
RLS FORCE em stores, products, product_variants: USING/WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) TO ptmarket_app. Sem contexto = zero linhas.
outbox_events(id, tenant_id NULL, aggregate, aggregate_id, event_type, payload JSONB, created_at, published_at): a app só tem INSERT (WITH CHECK tenant_id IS NULL OR = contexto) — logo NÃO usar RETURNING.
ASVS: "RLS no PostgreSQL E verificação de dono/tenant em cada handler"; só queries verificadas em compilação; JSONB como serde_json::Value, nunca string + ::jsonb. D3: o evento é escrito NA MESMA transação que a alteração de negócio; nunca publicar no Redis a partir de um handler.
API a criar: pub struct TenantId(Uuid);
  pub async fn begin_tenant_tx(pool: &PgPool, tenant: TenantId) -> Result<Transaction<'static, Postgres>, AppError>
    → pool.begin() + sqlx::query!("SELECT set_config('app.current_tenant_id', $1, true)", …)   // is_local = true: morre no COMMIT/ROLLBACK
    Proibido: SET sem LOCAL, format!/concatenação, set_config fora de transação (fuga de contexto entre pedidos na pool).
  pub async fn append(tx: &mut Transaction<'_, Postgres>, ev: NewEvent { tenant_id: Option<TenantId>, aggregate, aggregate_id, event_type, payload: serde_json::Value }) -> Result<Uuid, AppError>   // id = Uuid::now_v7()
Teste: #[sqlx::test(migrations = "../migrations")] recebe (PgPoolOptions, PgConnectOptions); semear tenants como dono; criar a pool do teste com after_connect "SET ROLE ptmarket_app" (o dono/superuser não prova nada).
.sqlx/: com a BD de dev migrada, `cargo sqlx prepare -- --all-targets` e commit da pasta (o hook passa a usar SQLX_OFFLINE=true; query! nova sem prepare = cargo check falha).
```

## Feito quando
- [ ] Teste `rls_isolation`: tenant A só vê as lojas de A; pool sem contexto vê 0 linhas; INSERT de loja com `tenant_id` de B dentro da transação de A → `Err` (anti-IDOR, sem panic)
- [ ] Teste de fuga: pool com 1 ligação, transação de A termina (commit e rollback) → a query seguinte na mesma ligação vê 0 linhas
- [ ] Teste outbox: `append` no tenant A grava; com `tenant_id` de B → `Err`; rollback da transação não deixa evento
- [ ] `.sqlx/` no git; `SQLX_OFFLINE=true cargo check` passa sem BD

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket cargo test -p ptmarket-api --test rls_isolation` → esperado: todos passam, 0 falhas (com `infra/scripts/dev-check.sh` verde)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Health, AppError e money (04, 05) — `cd backend-rust && SQLX_OFFLINE=true cargo test -p ptmarket-api --lib`
