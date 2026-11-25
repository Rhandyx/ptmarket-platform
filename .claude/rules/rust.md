---
paths:
  - "backend-rust/**"
---
# Rust (backend-rust) — specs: 02, 11, 12

- Monólito modular: `identity`, `catalog`, `orders`, `payments`, `fulfillment`, `tenancy`, `admin`. Um módulo nunca lê tabelas de outro; chama a API pública dele.
- Zero `.unwrap()`/`.expect()`/`panic!` fora de testes; devolver `Result<T, AppError>`.
- Dinheiro: `i64` cêntimos ou `rust_decimal::Decimal`; IVA e comissões em bps (`i32`). Arredondamento só no módulo `money`.
- PK = UUIDv7 gerado em Rust (`Uuid::now_v7()`).
- `state.db_replica` para leituras públicas; `state.db_primary` para escritas, checkout, stock, admin.
- SQL só com `sqlx::query!`/`query_as!`. JSONB: passar `serde_json::Value`, nunca string + `::jsonb`.
- Stock: `UPDATE ... WHERE stock_qty >= $n` + `stock_reservations`. Eventos: escrever em `outbox_events` na mesma transação; nunca publicar no Redis a partir de um handler.
- Todo o handler com ID verifica dono/tenant (além de RLS) e tem teste anti-IDOR.
- DTOs: `#[serde(deny_unknown_fields)]` + validação; limites de tamanho.
- `StorageBackend` e `SearchBackend` são traits; nada de código preso a um fornecedor.
- Endpoints documentados com `utoipa`; o `openapi.json` é o contrato com o frontend.
- Antes de terminar: só os testes do módulo tocado (`cargo test -p <crate> <módulo>`); o hook já corre `cargo fmt` + `cargo check`.
