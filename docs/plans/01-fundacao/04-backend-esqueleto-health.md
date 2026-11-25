# 04 — Esqueleto Rust: módulos, AppError, config, dual pool, health (épico: 01-fundacao)

**Agente:** rust-core · **Modelo:** sonnet · **Depende de:** — · **Paralelo com:** 01, 02, 07, 08

## Objetivo
`backend-rust/` compila, arranca sem BD e responde a `/healthz` e `/readyz`, com as fronteiras de módulo e o tratamento de erros que todos os cartões seguintes usam.

## Pode alterar
- `backend-rust/**` (criar): `Cargo.toml`, `Cargo.lock`, `.env.example`, `src/{main,lib,error,config,state,storage,search}.rs`, `src/http/`, `src/{identity,catalog,orders,payments,fulfillment,tenancy,admin}/mod.rs`, `openapi.json`

## Não tocar
- `src/money/` — cartão 05 (opus); `src/tenancy/db.rs` e qualquer SQL — cartão 06 (opus)
- `migrations/`, `infra/`, `workers-go/`, `frontend-web/` — outros cartões; qualquer `.env` real

## Contexto exato (colado da spec; não ler a spec)
```
Crate única `ptmarket-api` (lib + bin). Monólito modular: identity (contas, sessões, RBAC) · catalog · orders · payments · fulfillment · tenancy (Câmaras, lojas, domínios) · admin. Módulos vazios, só com `//!` a descrever a fronteira. Um módulo nunca lê tabelas de outro: chama as funções públicas dele.
pub struct AppState { pub db_primary: sqlx::PgPool /* escritas, checkout, stock, admin */, pub db_replica: sqlx::PgPool /* leituras públicas, catálogo, pesquisa */, pub redis: deadpool_redis::Pool, pub storage: Arc<dyn StorageBackend> }
StorageBackend e SearchBackend: só os traits (+ implementação nula que devolve erro); nada preso a um fornecedor.
Config (env): DATABASE_PRIMARY_URL, DATABASE_REPLICA_URL (Fase 1: o mesmo Postgres), REDIS_URL, BIND_ADDR (omissão 127.0.0.1:8080). URLs em secrecy::SecretString; Debug/logs nunca mostram valores. Pools com connect_lazy. A API liga como `ptmarket_app` (sem SUPERUSER/BYPASSRLS).
AppError { NotFound, Unauthorized, Forbidden, Validation(Vec<FieldError>), Conflict, Internal(anyhow::Error) } → 404/401/403/422/409/500, corpo {"error":{"code":"not_found","message":"…"}}. Internal: regista com tracing e responde genérico, sem detalhe interno. Recurso de outro tenant = NotFound (não revela que existe).
GET /healthz → 200 {"status":"ok"} (não toca na BD). GET /readyz → 200 {"status":"ready"} se primary E replica derem `acquire()` em ≤ 1 s; senão 503 {"status":"unavailable"}. Sem SQL neste cartão (ainda não há `.sqlx/`).
Camadas: limite de corpo 1 MiB · timeout 10 s · request-id · TraceLayer sem corpos nem cabeçalhos de autenticação. Logs JSON com redação de password, token, NIF, IBAN.
utoipa nos dois endpoints; `cargo run --bin openapi` escreve `backend-rust/openapi.json` (contrato com o frontend).
Lints no Cargo.toml: clippy unwrap_used, expect_used, panic = "deny"; unsafe_code = "forbid". Zero unwrap/expect/panic fora de testes. PK futuras: Uuid::now_v7(). Versões fixadas; dependência nova só com justificação.
```

## Feito quando
- [ ] `cargo clippy -p ptmarket-api --all-targets -- -D warnings` limpo; `openapi.json` gerado e no git
- [ ] Teste novo `http::health`: `/healthz` 200 sem BD; `/readyz` 503 com pools para porta fechada (caso de erro), sem fuga de URL/erro no corpo
- [ ] Teste novo `error`: cada variante dá o status e o `code` certos; `Internal` não expõe a mensagem original
- [ ] `Config` em falta/inválida → erro legível à partida (sem panic) e sem imprimir segredos

## Prova (um comando)
`cd backend-rust && cargo test -p ptmarket-api` → esperado: todos os testes passam (health, error, config), 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- —
