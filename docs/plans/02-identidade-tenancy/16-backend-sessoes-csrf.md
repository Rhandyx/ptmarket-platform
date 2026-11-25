# 16 — Sessões: cookie `__Host-`, layer de autenticação, CSRF e logout (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 11, 14 · **Paralelo com:** —

## Objetivo
Um pedido com cookie de sessão válido passa a ter `Actor` (e por isso ator na caixa negra); existem criar/revogar sessão, proteção CSRF e `POST /api/v1/auth/logout`.

## Pode alterar
- `backend-rust/src/identity/{session,csrf,http}.rs`, `backend-rust/tests/session.rs` (criar); `src/identity/mod.rs`, `src/http/{mod,openapi}.rs`, `src/config.rs`, `Cargo.toml` (`hmac`, `rand`, `base64`), `openapi.json`, `.sqlx/**` (editar)

## Não tocar
- `src/audit/`, `src/http/audit_layer.rs`, `src/tenancy/` — aprovados; `src/identity/password.rs` — cartão 15; `migrations/` (só leitura)

## Contexto exato (colado da spec; não ler a spec)
```
Spec 12 §3: cookies de sessão __Host-, HttpOnly, Secure, SameSite=Lax (Strict no admin); rotação do ID de sessão no login; expiração por inatividade. CSRF: token em todos os formulários que alteram estado (além de SameSite).
BD (cartão 14): sessions(id, subject_type 'customer'|'user', subject_id, token_hash BYTEA(32) UNIQUE, tenant_id NULL=plataforma, mfa_verified_at, impersonator_user_id, ip, user_agent_hash, created_at, expires_at, revoked_at). A app: INSERT só para o próprio sujeito (ator já fixado no AuditCtx), UPDATE (revoked_at, mfa_verified_at), sem DELETE.
  identity_session_lookup(p_token_hash bytea) → (id, subject_type, subject_id, tenant_id, mfa_verified_at, impersonator_user_id, created_at, expires_at); só válidas.
Token: 32 bytes de CSPRNG, base64url sem padding; grava-se só sha256(token). Nunca em logs nem em eventos.
Cookies (Path=/, sem Domain, HttpOnly, Secure): tenant → `__Host-ptm_session`, SameSite=Lax · PLATFORM_ADMIN_HOST → `__Host-ptm_admin`, SameSite=Strict.
Prazos (constantes, default até decisão do owner): cliente 30 dias absoluto / 7 dias inativo · staff 12 h / 30 min · plataforma 8 h / 15 min. Inatividade no Redis: chave sess:idle:<id> com TTL renovado a cada pedido; chave ausente = sessão inativa → tratada como anónima. Redis indisponível → 503 (falha fechado).
Layer de autenticação (corre ANTES do middleware de auditoria): cookie → sha256 → lookup → a sessão só vale se session.tenant_id = tenant resolvido pelo Host (ou NULL no host de plataforma) → põe Actor { actor_type, actor_id, impersonator_id } + SessionInfo { id, mfa_verified_at } nas extensões. Cookie inválido/expirado = anónimo (não é erro) e o cookie é limpo.
  actor_type: sujeito 'customer' → Customer; 'user' → fica Merchant/Municipal/Admin conforme os papéis (função a expor para o cartão 19; até lá sessões 'user' não são criadas). Extractor RequireCustomer → 401 (AppError::Unauthorized) se não houver cliente autenticado.
API interna: session::create(tx, subject, tenant, &AuditCtx) -> (SessionId, CookieValue) · session::revoke(tx, id) · session::revoke_all(tx, subject) · session::rotate (cria nova + revoga a antiga na mesma transação; usar em login e ao elevar para 2FA).
CSRF: token = base64url(HMAC-SHA256(CSRF_KEY, session_id)); CSRF_KEY em SecretString (≥ 32 bytes, config obrigatória). Todo o pedido não GET/HEAD/OPTIONS com cookie de sessão exige cabeçalho X-CSRF-Token (ou campo `_csrf` em formulários) válido, comparado em tempo constante, E cabeçalho Origin igual ao Host. Falha → 403 + marca Denied("csrf").
Endpoints (utoipa): GET /api/v1/auth/session → 200 {"authenticated": bool, "actor_type": string|null, "csrf_token": string|null} (ReadSync) · POST /api/v1/auth/logout → 204, revoga a sessão, limpa o cookie, audit::record 'auth.logout'.
```

## Feito quando
- [ ] `session`: sessão criada no Host A é anónima no Host B (anti-IDOR entre tenants); expirada, revogada e inativa (TTL esgotado) → anónimo; `rotate` invalida o token antigo
- [ ] Cabeçalho `Set-Cookie` com `__Host-`, `HttpOnly`, `Secure`, `SameSite` certo por host, sem `Domain`; a BD só tem o hash
- [ ] POST com sessão e sem `X-CSRF-Token`, com token de outra sessão, ou com `Origin` diferente → 403 e 1 evento `denied` (reason `csrf`) com o ator
- [ ] Logout: 204, sessão com `revoked_at`, eventos `auth.logout` e `sessions.update` com o ator; 2.º pedido com o mesmo cookie é anónimo
- [ ] `openapi.json` regenerado e sem diff

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test session` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `tenant_host`, `audit_layer`, `audit_ctx`, `rls_isolation` — `cargo test -p ptmarket-api --test tenant_host --test audit_layer --test audit_ctx --test rls_isolation`
