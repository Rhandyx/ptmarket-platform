# 14 — `sessions`, `user_passkeys` e `user_recovery_codes` (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 13 · **Paralelo com:** —

## Objetivo
Ficam as tabelas de sessão (token nunca guardado em claro), passkeys de staff e códigos de recuperação do 2FA, cada uma legível só pelo próprio titular.

## Pode alterar
- `migrations/0015_sessions_passkeys.sql`, `migrations/tests/sessions.sql` (criar)

## Não tocar
- `migrations/0001–0014` — imutáveis; `backend-rust/`, `workers-go/`, `infra/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 12 §3: cookies de sessão __Host-, HttpOnly, Secure, SameSite=Lax (Strict no admin); rotação do ID de sessão no login; expiração por inatividade. Passkeys (WebAuthn) para lojistas e admin; 2FA TOTP obrigatório para super_admin e tenant_admin.
sessions(id UUID PK DEFAULT uuidv7(), subject_type VARCHAR(8) NOT NULL CHECK IN ('customer','user'), subject_id UUID NOT NULL /*sem FK: dois alvos*/, token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32) /*sha256 do token; o token NUNCA é gravado*/, tenant_id UUID REFERENCES tenants ON DELETE CASCADE /*Host onde nasceu; NULL = consola de plataforma*/, mfa_verified_at TIMESTAMPTZ, impersonator_user_id UUID REFERENCES users ON DELETE RESTRICT, ip INET, user_agent_hash BYTEA, created_at, expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ); índices (subject_type, subject_id), (tenant_id), (impersonator_user_id), (expires_at)
  Sem coluna last_seen: a inatividade vive no Redis (cartão 16), para não haver uma mutação — e um evento L1 — por pedido.
user_passkeys(id, user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE, credential_id BYTEA NOT NULL UNIQUE, credential JSONB NOT NULL /*credencial pública serializada pela biblioteca WebAuthn; sem segredos*/, sign_count BIGINT NOT NULL DEFAULT 0 CHECK (>= 0), label VARCHAR(64) NOT NULL, created_at, last_used_at); índice (user_id)
user_recovery_codes(id, user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE, code_hash BYTEA NOT NULL, used_at TIMESTAMPTZ, created_at); índice (user_id)
S := (current_setting('app.actor_type', true), actor_id) → subject: 'customer' ↔ subject_type 'customer'; 'merchant'|'municipal'|'admin' ↔ 'user'. U como no cartão 13: actor_id quando actor_type IN ('merchant','municipal','admin').
RLS ENABLE + FORCE nas três. Policies TO ptmarket_app:
  sessions: own_insert FOR INSERT WITH CHECK (subject = S AND revoked_at IS NULL AND impersonator_user_id IS NULL) · own_select FOR SELECT USING (subject = S) · own_update FOR UPDATE USING (subject = S) WITH CHECK (subject = S). GRANT SELECT, INSERT; UPDATE (revoked_at, mfa_verified_at). SEM DELETE (revogar = revoked_at; fica o rasto). Impersonation = épico admin.
  user_passkeys: own (user_id = U) para SELECT/INSERT/DELETE e UPDATE (sign_count, last_used_at, label) · user_recovery_codes: own (user_id = U) para SELECT/INSERT/DELETE e UPDATE (used_at).
Funções DEFINER (dono ptmarket_identity, STABLE, search_path fixo, EXECUTE só ptmarket_app; grants por coluna + policy SELECT USING (true) para ptmarket_identity):
  identity_session_lookup(p_token_hash bytea) RETURNS TABLE (id, subject_type, subject_id, tenant_id, mfa_verified_at, impersonator_user_id, created_at, expires_at) — só revoked_at IS NULL AND expires_at > now() · identity_passkey_lookup(p_credential_id bytea) RETURNS TABLE (id, user_id, credential jsonb, sign_count) — só de utilizadores ativos
Auditoria: zz_audit_row vem sozinho (L2); token_hash/code_hash saem "[redacted]" e ip "[pii]" (máscara do cartão 03). Se `credential` não ficar mascarada pela regex, parar e reportar (não editar 0010).
```

## Feito quando
- [ ] `sessions.sql` (`SET ROLE ptmarket_app`): titular cria, lê e revoga a sua sessão; não lê nem revoga a de outro titular; cliente e utilizador com o MESMO uuid não se veem (anti-IDOR por tipo); DELETE falha
- [ ] INSERT de sessão para outro `subject_id`, com `impersonator_user_id` ou já revogada → 42501; `token_hash` com tamanho ≠ 32 → 23514
- [ ] `identity_session_lookup` devolve a sessão válida e 0 linhas para expirada, revogada ou hash desconhecido; `ptmarket_worker` não a executa
- [ ] Passkeys e códigos: X não vê nem apaga os de Y; `credential_id` repetido → 23505; os eventos L1 não contêm `token_hash`, `code_hash` nem IP em claro

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `users_rbac.sql`, `customers.sql`, `rls.sql`, `audit_*.sql` — todos no `run.sh`
