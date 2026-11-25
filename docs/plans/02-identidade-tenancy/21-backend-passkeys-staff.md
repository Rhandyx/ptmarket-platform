# 21 — Passkeys (WebAuthn) para lojistas e admin (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 20 · **Paralelo com:** —

## Objetivo
Um utilizador de backoffice regista passkeys e entra com elas (sem password); a passkey com verificação do utilizador conta como segundo fator.

## Pode alterar
- `backend-rust/src/identity/passkey.rs`, `backend-rust/tests/passkey.rs` (criar); `src/identity/{mod,http}.rs`, `src/http/{mod,openapi}.rs`, `src/state.rs`, `Cargo.toml` (`webauthn-rs`, e em dev o autenticador de software da mesma família), `openapi.json`, `.sqlx/**` (editar)

## Não tocar
- `src/identity/{password,session,csrf,login,staff,rbac,totp,crypto}.rs`, `src/audit/`, `src/tenancy/` — aprovados; `migrations/` (só leitura)

## Contexto exato (colado da spec; não ler a spec)
```
Spec 12 §3: Passkeys (WebAuthn) para lojistas e admin. ASVS nível 3 em identity.
BD (cartão 14): user_passkeys(id, user_id, credential_id BYTEA UNIQUE, credential JSONB /*credencial pública serializada pela biblioteca*/, sign_count BIGINT, label VARCHAR(64), created_at, last_used_at) — o próprio lê/insere/apaga e atualiza (sign_count, last_used_at, label). identity_passkey_lookup(p_credential_id bytea) → (id, user_id, credential jsonb, sign_count); só utilizadores ativos (única leitura antes de haver sessão).
Relying Party: rp_id = o Host do pedido (o domínio da Câmara ou PLATFORM_ADMIN_HOST), origin = https://<Host>. Uma passkey registada num domínio NÃO serve noutro (é o comportamento do WebAuthn; não contornar com rp_id partilhado). Um Webauthn por Host, em cache.
Estado da cerimónia (challenge): no Redis, chave webauthn:<reg|auth>:<id aleatório>, TTL 5 min, uso único (apagar ao ler). Nunca em cookie nem no cliente.
Endpoints (utoipa):
  POST /api/v1/staff/passkeys/register/start (RequireStaff + CSRF + sessão com mfa_verified_at se o papel exigir 2FA) → 200 opções de criação (user verification = required; resident key = preferred; excluir credenciais já registadas)
  POST /api/v1/staff/passkeys/register/finish {"ceremony_id","label" 1–64,"credential": …} → 201 {"id","label"}; evento 'passkey.registered'
  GET /api/v1/staff/passkeys (ReadSync) → [{"id","label","created_at","last_used_at"}] — só as do próprio
  DELETE /api/v1/staff/passkeys/{id} (CSRF) → 204; id de outro utilizador → 404 + Denied("idor"). Não deixa apagar a última credencial se a conta não tiver password. Evento 'passkey.removed'.
  POST /api/v1/staff/auth/passkey/start (anónimo) → 200 opções de autenticação (discoverable; sem lista de credenciais, para não enumerar contas)
  POST /api/v1/staff/auth/passkey/finish {"ceremony_id","credential": …} → 204 + cookie. Mesmas regras de host/papel do login de staff (cartão 19). Sessão nasce com mfa_verified_at = now() porque houve user verification. Falha → 401 genérico + 'auth.passkey_login' denied.
  sign_count: se o contador recebido não for maior que o guardado (e ambos > 0) → recusar, evento denied reason 'cloned_authenticator' e NÃO autenticar. Sucesso → atualizar sign_count e last_used_at.
Clientes: customers.passkeys JSONB existe mas as passkeys de cliente ficam para o épico de checkout/conta (não implementar aqui). Eventos nunca contêm a credencial, o challenge nem a assinatura; só ids.
```

## Feito quando
- [ ] `passkey` (autenticador de software): registar → listar → entrar com a passkey → sessão com `mfa_verified_at` e evento `auth.passkey_login` success com o ator; registo sem sessão → 401
- [ ] Challenge reutilizado, expirado, de outra cerimónia, ou `origin`/rp_id de outro Host → 401 e evento `denied`; passkey registada no Host A não entra no Host B; contador regressivo → recusa com `cloned_authenticator`
- [ ] Utilizador X não lista nem apaga a passkey de Y (404 + `denied`, anti-IDOR); `super_admin` que entra por passkey passa em `RequireSuperAdmin` só se também tiver TOTP ativo (regra do cartão 20); `openapi.json` sem diff; `cargo audit` + `cargo deny check` limpos

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test passkey` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `totp`, `rbac`, `login`, `session` — `cargo test -p ptmarket-api --test totp --test rbac --test login --test session` · suite completa: `cargo test -p ptmarket-api`
