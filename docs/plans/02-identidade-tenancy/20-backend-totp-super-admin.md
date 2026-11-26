# 20 — 2FA TOTP obrigatório, `RequireSuperAdmin` e criação do 1.º super_admin (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 19, 10b (códigos de recuperação de uso único na BD) · **Paralelo com:** —

## Objetivo
`super_admin` e `tenant_admin` só operam com TOTP verificado na sessão; o grupo `/api/v1/superadmin/*` fica fechado por tipo; o primeiro super_admin cria-se por CLI, nunca pela API.

## Pode alterar
- `backend-rust/src/identity/{totp,crypto,recovery}.rs`, `backend-rust/src/bin/ptmarket-admin.rs`, `backend-rust/tests/totp.rs` (criar); `src/identity/{mod,http,rbac}.rs`, `src/http/{mod,openapi}.rs`, `src/config.rs`, `Cargo.toml` (`totp-rs` ou equivalente, `aes-gcm`), `openapi.json`, `.sqlx/**` (editar)

## Não tocar
- `src/identity/{password,session,csrf,login,staff}.rs`, `src/audit/`, `src/tenancy/` — aprovados; `migrations/` (só leitura)

## Contexto exato (colado da spec; não ler a spec)
```
Spec 12 §3: 2FA TOTP obrigatório para super_admin e tenant_admin. ASVS nível 3 em admin e identity. Credenciais encriptadas em repouso (AES-256-GCM, chave fora da BD).
Spec 07 §3.2: o grupo /api/v1/superadmin/* bloqueia qualquer pedido sem sessão 2FA válida. Spec 13 §1: ninguém está acima da auditoria; leituras de superadmin são síncronas; cada ação gera alerta (a BD já emite 'audit.superadmin_action' quando actor_type = 'admin').
BD: users.totp_secret_enc TEXT, users.totp_enabled (a app atualiza só a própria linha); sessions.mfa_verified_at (UPDATE próprio); user_recovery_codes(user_id, code_hash BYTEA, used_at). Cartão 10b (0021): um trigger recusa qualquer UPDATE a um código já usado (23514) e fixa used_at = now().
TOTP: RFC 6238, SHA-1, 6 dígitos, passo 30 s, tolerância ±1 passo; segredo de 20 bytes aleatórios. Anti-repetição: guardar no Redis o último passo aceite por utilizador (TTL 90 s); o mesmo código não entra duas vezes.
crypto: AES-256-GCM, nonce aleatório de 12 bytes por valor, formato "v1:" + base64(nonce || ciphertext || tag), AAD = id do utilizador. Chave TOTP_ENC_KEY (32 bytes em base64, SecretString, obrigatória; a API não arranca sem ela).
Endpoints (RequireStaff + CSRF; todos audit::record, nunca com o código ou o segredo):
  POST /api/v1/staff/mfa/totp/enroll → 200 {"otpauth_uri","secret_base32"} (segredo gravado encriptado, totp_enabled = false). Só se ainda não estiver ativo. Evento 'mfa.totp_enroll_started'.
  POST /api/v1/staff/mfa/totp/confirm {"code"} → 200 {"recovery_codes": [10 códigos de 10 caracteres]} — mostrados UMA vez; guardados como sha256; totp_enabled = true; session::rotate com mfa_verified_at = now(). Evento 'mfa.totp_enabled'.
  POST /api/v1/staff/mfa/verify {"code"} (TOTP ou código de recuperação) → 204; session::rotate com mfa_verified_at. Código de recuperação: consumo atómico UPDATE … SET used_at = now() WHERE id = $1 AND used_at IS NULL — só vale se afetar 1 linha (0 linhas ou 23514 = recusado). Falha → 401 + 'mfa.verify' denied; throttle como o login (5 falhas → backoff, nunca permanente).
  Desativar TOTP: NÃO existe endpoint para super_admin/tenant_admin (obrigatório); para os outros papéis fica para o épico backoffice. O 2FA vale durante a sessão (plataforma: 8 h absoluto / 15 min inativo, do cartão 16).
RequireSuperAdmin (em rbac.rs): host = PLATFORM_ADMIN_HOST E papel super_admin E totp_enabled E sessão com mfa_verified_at. Qualquer falha → 404 (a consola não se anuncia) + Denied("superadmin_gate"). Router /api/v1/superadmin/* com AuditClass::ReadSync e este extractor aplicado ao grupo inteiro (route_layer), não handler a handler. GET /api/v1/superadmin/whoami → {"id","full_name"} (prova do gate).
CLI `ptmarket-admin create-superadmin --email … --name …`: liga com ADMIN_DATABASE_URL (papel dono; nunca o da API), pede a password pelo terminal (sem eco, nunca por argumento), aplica Password::parse + hash, cria users + user_roles('super_admin') numa transação. TOTP fica por ativar: o 1.º login obriga ao enroll antes de qualquer rota superadmin. Fica auditado como ator 'db' (L1) + pgaudit. Recusa se o email já existir.
```

## Feito quando
- [ ] `totp`: enroll → confirm com código certo ativa e devolve 10 códigos; código errado → 401 + denied; o mesmo código duas vezes → recusado; código de recuperação serve uma só vez (também com dois pedidos em paralelo: só um entra)
- [ ] `super_admin` sem TOTP ativo, com TOTP mas sessão sem `mfa_verified_at`, noutro host, ou `tenant_admin` com 2FA → `/superadmin/whoami` devolve 404 + evento `denied`; com tudo certo → 200 e 1 evento síncrono `actor_type = 'admin'` + 1 linha `audit.superadmin_action` no outbox
- [ ] `totp_secret_enc` na BD não é o segredo em claro; decifrar com AAD de outro utilizador falha; eventos e logs sem segredo, código ou códigos de recuperação
- [ ] CLI cria o super_admin; 2.ª execução com o mesmo email falha; a API (ptmarket_app) continua sem conseguir inserir em `user_roles`; `openapi.json` sem diff

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test totp` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `rbac`, `login`, `session` — `cargo test -p ptmarket-api --test rbac --test login --test session` · `cargo audit` + `cargo deny check`
