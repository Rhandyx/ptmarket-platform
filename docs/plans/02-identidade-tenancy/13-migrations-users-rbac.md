# 13 — `users` e `user_roles` (RBAC de lojistas, Câmaras e super_admin) (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 12 · **Paralelo com:** 22

## Objetivo
Existem as contas de backoffice e os seus papéis com âmbito (loja, tenant, global), fechados por RLS; a API não consegue conceder papéis — muito menos `super_admin`.

## Pode alterar
- `migrations/0017_users_roles.sql`, `migrations/tests/users_rbac.sql` (criar)

## Não tocar
- `migrations/0001–0016` — imutáveis; `backend-rust/`, `workers-go/`, `infra/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 07 §1: 3 níveis — Lojista (scope store_id), Câmara/Associação (scope tenant_id; ZERO acesso a IBANs/chaves), Super-Admin Segjar (global, 2FA obrigatório). Papéis: 'super_admin','tenant_admin','merchant_owner','merchant_staff'.
Spec 12 §3: 2FA TOTP obrigatório para super_admin e tenant_admin; passkeys para lojistas e admin. A spec 07 §4 é adaptada: uuidv7() (sem uuid-ossp), sem admin_audit_logs (é a categoria 'admin' de audit_events).
users(id UUID PK DEFAULT uuidv7(), email VARCHAR(255) NOT NULL, password_hash TEXT /*Argon2id PHC; NULL = só passkey*/, full_name VARCHAR(255) NOT NULL, totp_secret_enc TEXT /*AES-256-GCM, chave fora da BD*/, totp_enabled BOOLEAN NOT NULL DEFAULT false, is_active BOOLEAN NOT NULL DEFAULT true, last_login_at TIMESTAMPTZ, created_at, updated_at; CHECK (NOT totp_enabled OR totp_secret_enc IS NOT NULL)); UNIQUE INDEX (lower(email))  -- global
user_roles(id, user_id UUID NOT NULL REFERENCES users ON DELETE CASCADE, role VARCHAR(32) NOT NULL CHECK IN (os 4), tenant_id UUID REFERENCES tenants ON DELETE CASCADE, store_id UUID, FOREIGN KEY (tenant_id, store_id) REFERENCES stores (tenant_id, id) ON DELETE CASCADE, created_at,
  CHECK de âmbito: super_admin → tenant_id e store_id NULL · tenant_admin → tenant_id NOT NULL, store_id NULL · merchant_owner/merchant_staff → ambos NOT NULL; UNIQUE NULLS NOT DISTINCT (user_id, role, tenant_id, store_id)); índices (user_id), (tenant_id, store_id)
Tipo de ator na caixa negra: super_admin → 'admin' · tenant_admin → 'municipal' · merchant_* → 'merchant'. U := CASE WHEN current_setting('app.actor_type', true) IN ('merchant','municipal','admin') THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
RLS ENABLE + FORCE nas duas. Policies TO ptmarket_app:
  users: self_select FOR SELECT USING (id = U AND is_active); self_update FOR UPDATE USING (id = U) WITH CHECK (id = U). GRANT SELECT; UPDATE (full_name, password_hash, totp_secret_enc, totp_enabled, last_login_at, updated_at). SEM INSERT, SEM DELETE, sem UPDATE de email/is_active.
  user_roles: own_select FOR SELECT USING (user_id = U). GRANT só SELECT. ZERO INSERT/UPDATE/DELETE para a app neste épico: criar utilizadores, convites e atribuição de papéis são do épico backoffice; o 1.º super_admin nasce pelo CLI do cartão 20 (ligação do migrator, ator 'db', fica na L1 + pgaudit).
  ptmarket_identity: GRANT SELECT (id, email, password_hash, totp_enabled, is_active) ON users + policy FOR SELECT USING (true).
identity_user_credentials(p_email text) RETURNS TABLE (id uuid, password_hash text, totp_enabled boolean) — SECURITY DEFINER, STABLE, search_path fixo, dono ptmarket_identity; só is_active; EXECUTE só ptmarket_app. Proibida função que liste utilizadores.
Auditoria: as tabelas novas recebem zz_audit_row sozinhas (L2). Máscara do cartão 03 já cobre users(email, full_name), *_enc e *_hash.
```

## Feito quando
- [ ] `users_rbac.sql` (seed como dono; asserções com `SET ROLE ptmarket_app`): utilizador X lê a sua linha e os seus papéis; não lê os de Y (anti-IDOR); ator `customer` com o mesmo id não lê nada
- [ ] A app não consegue INSERT em `users` nem INSERT/UPDATE/DELETE em `user_roles` (42501) — não há escalada para `super_admin`; UPDATE de `is_active`/`email` falha
- [ ] CHECK de âmbito: `super_admin` com `tenant_id`, `tenant_admin` sem `tenant_id`, `merchant_owner` sem `store_id` e loja de outro tenant → falham (23514/23503); par duplicado com NULLs → 23505
- [ ] `identity_user_credentials` não devolve inativos; o teste de cobertura L1 passa sem trigger manual; o evento de UPDATE de `totp_secret_enc`/`password_hash` não contém os valores

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `customers.sql`, `rls.sql`, `portal.sql`, `audit_*.sql` — todos no `run.sh`
