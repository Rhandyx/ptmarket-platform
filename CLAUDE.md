# PT Market & Loja Portugal (Segjar Soluções)

## Stack
- `backend-rust/` Axum 0.8, SQLx, rust_decimal, utoipa
- `workers-go/` pgx, Asynq, Redis
- `migrations/` PostgreSQL 17 (RLS, JSONB, UUID)
- `frontend-web/` Next.js App Router, TS estrito, Tailwind, shadcn/ui
- `infra/` Caddy, Compose

## Regras inegociáveis
1. Dinheiro: nunca float. SQL `BIGINT` cêntimos / `INT` bps; Rust `rust_decimal::Decimal`.
2. Multi-tenant: toda a query filtra `tenant_id` ou define `app.current_tenant_id` (RLS). Portal nacional só lê lojas com `publish_to_national_portal = true`.
3. Rust: zero `.unwrap()`/`.expect()`; devolver `Result<T, AppError>`.
4. Leituras públicas → `db_replica`; escritas/checkout/stock/admin → `db_primary`.
5. `/api/v1/superadmin/*`: `super_admin` + 2FA TOTP. Escritas no Data Studio: dry-run `BEGIN…ROLLBACK` + `admin_audit_logs`.
6. Mudar `price_cents` → `product_price_history`. `vat_exempt_art53` → IVA 0%.
7. Verificar: `cargo check && cargo test` · `go vet ./... && go test ./...` · `npm run typecheck && npm run lint`.

## Subagentes
- Planear: `architect-master`
- Código: `db-architect`, `rust-core`, `go-integrations`, `frontend-ui`
- Ler/auditar: `codebase-reader`, `security-auditor`
- Trivial: `quick-helper`

## Specs (`docs/specs/`, ler só o necessário)
- `02_*` arquitetura, esquema BD, dual pool
- `03_*` pagamentos split, IVA, faturação AT, logística
- `04_*` catálogo IA, templates, WCAG, mobile
- `05_*` migração, onboarding, portabilidade
- `07_*` backoffices, RBAC, Data Studio
- `08_*` imagens, seed demo, 2 VPS
- `10_*` pontos cegos, checklist
