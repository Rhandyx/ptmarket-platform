---
trigger: always_on
---
# Regras Globais de Engenharia — PT Market (AGY Workspace)

Antes de propor alterações ou escrever código, consulta `docs/specs/02_arquitetura_tecnica_rust_go_postgresql_e_tls.md` e `docs/specs/03_pagamentos_split_faturacao_at_e_logistica.md`.

## Restrições Absolutas
1. **Valores Monetários:** Proibido usar `f32`/`f64`/`float` para dinheiro ou taxas. Usa `BIGINT` (cêntimos) no PostgreSQL e `rust_decimal::Decimal` em Rust.
2. **Isolamento Multi-Tenant:** Todas as queries devem respeitar `tenant_id` e Row-Level Security (RLS). O canal nacional `lojaportugal.pt` só expõe lojas com `publish_to_national_portal = true`.
3. **Robustez Rust:** Zero `.unwrap()` ou `.expect()` em `/backend-rust`. Propaga sempre erros tipados (`AppError`).
4. **Dual Pool DB:** Usa `db_primary` para escritas/transações e `db_replica` para leituras públicas e relatórios.
5. **Storage:** Usa `StorageBackend` com `LocalDiskStorage` ativo por defeito (sem exigir Cloudflare R2 na demo).
6. **Validação:** Sempre que alterares código, valida no terminal:
   - Rust: `cargo check && cargo test`
   - Go: `go vet ./... && go test ./...`
   - Frontend: `npm run typecheck && npm run lint`
