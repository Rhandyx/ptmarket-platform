# 11 — Extractor de tenant pelo `Host` + transação de leitura do portal nacional (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 07, 10 · **Paralelo com:** 12

## Objetivo
Cada pedido resolve o tenant só a partir do `Host`; é o único sítio que cria `TenantId`. O portal nacional tem uma transação só de leitura. Fica o primeiro endpoint real: `GET /api/v1/tenant`.

## Pode alterar
- `backend-rust/src/tenancy/{host,resolver,portal,http}.rs`, `backend-rust/tests/tenant_host.rs` (criar); `src/tenancy/{mod,db}.rs`, `src/http/mod.rs`, `src/http/health.rs` → mover `ApiDoc` para `src/http/openapi.rs`, `src/bin/openapi.rs`, `src/config.rs`, `src/state.rs`, `Cargo.toml` (`subtle`), `openapi.json`, `.sqlx/**` (editar)

## Não tocar
- `src/audit/`, `src/http/audit_layer.rs` — aprovados (usar, não alterar); `src/identity/` — cartões 15+; `migrations/` (só leitura); `frontend-web/`

## Contexto exato (colado da spec; não ler a spec)
```
tenants(id, slug, custom_domain VARCHAR(255) UNIQUE NOT NULL, name, tenant_type 'municipal'|'national_portal'|'niche', country_code 'PT'|'ES', currency, template_layout 'bairro'|'editorial'|'catalogo', theme_config JSONB, legal_config JSONB, is_active) — global; a app só tem SELECT.
Spec 12 §1: domínios das Câmaras são SUBDOMÍNIOS com CNAME para nós (Cloudflare for SaaS); a edge preserva o Host.
Normalização do Host (função pura, com testes de propriedades): minúsculas; tirar :porta e ponto final; só [a-z0-9.-], ≤ 253, cada etiqueta 1–63; recusar vazio, IP literal e múltiplos cabeçalhos Host. IDN chega em punycode e fica como está.
Resolução: SELECT id, tenant_type, country_code FROM tenants WHERE custom_domain = $1 AND is_active (db_replica, query!). Cache em memória: 60 s positivo, 10 s negativo, máx. 10 000 entradas (sem dependência nova, ou justificar).
  Host desconhecido ou tenant inativo → 404 com o corpo genérico de AppError::NotFound (não revela se o domínio existe).
  PLATFORM_ADMIN_HOST (config, ex. admin.ptmarket.pt) → ResolvedHost::Platform (sem tenant). Rotas de tenant recusam Platform e rotas de plataforma recusam Tenant (404).
  SSR do Next chama a API por rede interna: X-Forwarded-Host só é aceite se X-Internal-Token == INTERNAL_PROXY_TOKEN (SecretString, comparação em tempo constante, mínimo 32 bytes). Sem token válido o cabeçalho é IGNORADO (usa-se o Host). O tenant nunca vem de query, corpo, cookie ou outro cabeçalho.
Tipos: ResolvedTenant { id: TenantId, tenant_type, country_code } como extractor Axum; TenantId::new continua pub(crate) e passa a ser chamado SÓ no resolver (tirar o allow(dead_code)). O middleware de auditoria passa a receber o tenant resolvido (extensão do pedido).
Portal: begin_portal_read_tx(replica, &ResolvedTenant, &AuditCtx) -> Result<PortalReadTx, AppError>: tenant_type ≠ national_portal → AppError::Forbidden (com marca Denied). Faz SET TRANSACTION READ ONLY + set_config('app.portal_national','on',true) + contexto de tenant/ator. PortalReadTx não é aceite por outbox::append nem por audit::record de mutação (por tipo).
  BD (cartão 10): em modo portal vê stores/products/product_variants publicados de todos os tenants do mesmo país. Em modo portal nunca selecionar iban, invoicing_credentials_enc, eupago_split_key, stripe_account_id.
GET /api/v1/tenant (anónimo, AuditClass::ReadAsync, utoipa): 200 {"slug","name","tenant_type","country_code","currency","template_layout","theme_config","legal_config"}; nunca default_commission_bps nem ids internos.
```

## Feito quando
- [ ] `tenant_host`: Host de A devolve o tenant A; maiúsculas, porta e ponto final normalizam; Host desconhecido, inativo, IP literal e Host duplicado → 404 igual
- [ ] Anti-IDOR: `X-Forwarded-Host` de B sem token (ou com token errado) num pedido com Host A → responde A; cabeçalho/param `tenant_id` forjado não tem efeito
- [ ] `PortalReadTx` no tenant portal lê lojas publicadas de A e B; num tenant municipal → `Forbidden` + evento `denied`; um UPDATE dentro dela falha (read only)
- [ ] `openapi.json` regenerado com `/api/v1/tenant`; `cargo run --bin openapi && git diff --exit-code backend-rust/openapi.json` limpo

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test tenant_host` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `rls_isolation`, `audit_ctx`, `audit_layer` — `cargo test -p ptmarket-api --test rls_isolation --test audit_ctx --test audit_layer` · health — `cargo test -p ptmarket-api --lib http`
