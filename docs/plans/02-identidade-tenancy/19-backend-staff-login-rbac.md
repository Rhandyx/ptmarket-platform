# 19 — Staff: login de utilizadores de backoffice + extractors de RBAC (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 13, 18 · **Paralelo com:** —

## Objetivo
Lojistas, staff da Câmara e admins autenticam-se; qualquer handler pode exigir um papel com âmbito (loja, tenant, global) por tipo, e uma recusa de papel fica na caixa negra.

## Pode alterar
- `backend-rust/src/identity/{staff,rbac}.rs`, `backend-rust/tests/rbac.rs` (criar); `src/identity/{mod,http,session,login}.rs` (só o necessário para sessões `user` e para reutilizar o throttle), `src/http/{mod,openapi}.rs`, `openapi.json`, `.sqlx/**` (editar)

## Não tocar
- `src/identity/{password,csrf,captcha,customers}.rs`, `src/audit/`, `src/tenancy/` — aprovados; `migrations/` (só leitura)

## Contexto exato (colado da spec; não ler a spec)
```
Spec 07 §1: Lojista (merchant_owner / merchant_staff) — scope store_id · Câmara/Associação (tenant_admin) — scope tenant_id, ZERO acesso a IBANs/chaves · Super-Admin (super_admin) — global, 2FA obrigatório, só em admin.ptmarket.pt. Spec 12 §3: RLS E verificação de dono/tenant em CADA handler; cada endpoint que recebe um ID tem um teste que tenta aceder ao recurso de outro tenant e tem de falhar. 2FA TOTP obrigatório para super_admin e tenant_admin (cartão 20).
BD (cartão 13): users(id, email, password_hash NULL=só passkey, full_name, totp_enabled, is_active, last_login_at); user_roles(user_id, role, tenant_id, store_id) com CHECK de âmbito. A app só LÊ os papéis do próprio (ator fixado); não os consegue escrever. identity_user_credentials(p_email text) → (id uuid, password_hash text, totp_enabled boolean); só ativos.
POST /api/v1/staff/auth/login {"email","password","turnstile_token"?} — mesmas regras do cartão 18 (resposta uniforme, throttle com prefixo próprio `staff:`, eventos 'auth.staff_login' success/denied).
  Sucesso → sessão subject_type 'user' com mfa_verified_at = NULL. 200 {"mfa_required": bool}: true se o utilizador tiver super_admin ou tenant_admin, ou totp_enabled.
  Host de tenant: só entra quem tem papel nesse tenant (tenant_admin do tenant, ou merchant_* de loja do tenant); senão 401 genérico + denied (reason 'no_role_here'). PLATFORM_ADMIN_HOST: só super_admin; cookie `__Host-ptm_admin` SameSite=Strict.
Tipo de ator (para Actor/AuditCtx): tem super_admin e está no host de plataforma → Admin · tem tenant_admin do tenant do Host → Municipal · senão merchant_* → Merchant.
Extractors (FromRequestParts; recusa → AppError::Forbidden + Denied("rbac")), todos leem os papéis de user_roles do próprio (cache por pedido):
  RequireStaff → qualquer papel no tenant do Host (401 se não houver sessão 'user') · RequireTenantAdmin → tenant_admin do tenant do Host E sessão com mfa_verified_at (sem 2FA → 403 reason 'mfa_required')
  RequireStoreRole { store_id: Path } → merchant_owner/merchant_staff dessa loja, ou tenant_admin do tenant; loja de outro tenant/sem papel → AppError::NotFound + Denied("idor") (não revela que existe)
  RequireStoreOwner → só merchant_owner da loja (ações de dinheiro/IBAN nos próximos épicos). RequireSuperAdmin → definido no cartão 20 (não criar aqui um atalho sem 2FA).
  tenant_admin NUNCA recebe iban, invoicing_credentials_enc, eupago_split_key, stripe_account_id: deixar a regra num comentário de módulo + tipo StoreViewForTenantAdmin sem esses campos.
GET /api/v1/staff/me (RequireStaff; ReadSync) → {"id","full_name","roles":[{"role","tenant_id","store_id"}],"mfa_verified": bool}. Rota de prova só em testes (feature test-support): GET /api/v1/_test/stores/{store_id} com RequireStoreRole.
```

## Feito quando
- [ ] `rbac`: merchant da loja L1 acede a L1; a L2 do mesmo tenant → 404; a loja de outro tenant → 404; cada recusa deixa `denied` com reason `idor` e o ator (anti-IDOR)
- [ ] `tenant_admin` sem 2FA verificado → 403 `mfa_required`; `merchant_staff` em `RequireStoreOwner` → 403; cliente (sessão `customer`) em rota de staff → 401
- [ ] Login de staff num Host onde não tem papel → 401 igual ao de password errada; `super_admin` num host de tenant não recebe ator Admin; utilizador inativo não entra
- [ ] `last_login_at` atualizado gera `users.update`; `/staff/me` é síncrono e não devolve hashes nem segredos; `openapi.json` sem diff

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test rbac` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `login`, `customers`, `session` — `cargo test -p ptmarket-api --test login --test customers --test session`
