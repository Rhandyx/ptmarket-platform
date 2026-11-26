# 13 — Rust: painel único, login de staff só em `admin.ptmarket.pt` e âmbito pelo papel (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 03, 04 · **Antes de:** 05 (a BD só continua depois deste cartão fechar verde) · **Paralelo com:** — · **Auditoria:** security-auditor obrigatório (ASVS L3)

## Objetivo
Lojistas, `sponsor_admin`, `tenant_admin` e `super_admin` autenticam-se todos em `PLATFORM_ADMIN_HOST`; num Host de canal não há login nem sessão de staff; o tenant de uma loja vem do papel e não do Host; os testes Rust deixam de depender de lojas em tenants municipais.

## Pode alterar
- `backend-rust/src/identity/{rbac,staff}.rs`; `src/identity/{login,session,http,mod}.rs` (só o necessário); `backend-rust/tests/**` (adaptar ao host único e aos helpers novos); `src/http/openapi.rs`, `openapi.json`, `.sqlx/**`

## Não tocar
- `src/tenancy/` (o `resolver.rs` não muda: decisão do owner); `src/identity/{password,csrf,captcha,customers,passkey}.rs` (passkeys: cartão 15); `src/audit/`; `migrations/`. `tests/rls_isolation.rs` (portal antigo: cartão 16).

## Contexto exato (spec 14 §8 + estado atual de `rbac.rs`; decisões aprovadas pelo supervisor)
```
Substitui o que o cartão 19 do épico 02 assumiu ("Host de tenant: só entra quem tem papel nesse tenant; PLATFORM_ADMIN_HOST: só super_admin"): agora o âmbito vem do papel (loja, entidade ou plataforma), NUNCA do Host. Clientes continuam a autenticar-se em qualquer canal (não mexer no login de clientes).
BD (cartão 03): user_roles(user_id, role, tenant_id, store_id, sponsor_entity_id); 'sponsor_admin' tem tenant_id e store_id NULL e sponsor_entity_id NOT NULL. As lojas ainda podem estar em tenants municipais (o cartão 05 move-as depois): o código não pode depender do tipo de tenant da loja.
Estado atual: enum Role {SuperAdmin, TenantAdmin, MerchantOwner, MerchantStaff}; RoleGrant; StaffRoles::here() = "no tenant, os desse tenant; na plataforma, só super_admin"; may_log_in_here(); needs_mfa(); ator: None + super_admin → Admin, Some(tenant) + tenant_admin → Municipal, senão Merchant; staff.rs:125 recusa com 'no_role_here'; RequireStoreRole lê `stores` e compara com o tenant do Host.
Passa a:
  Role::SponsorAdmin; RoleGrant ganha sponsor_entity_id: Option<Uuid>. here(): em plataforma, todos os papéis do utilizador; num canal, nenhum.
  POST /api/v1/staff/auth/login: só em PLATFORM_ADMIN_HOST, onde entra quem tiver PELO MENOS um papel. Num Host de canal → 401 genérico igual ao de password errada + denied (reason 'no_role_here'), sem revelar se a conta existe. Cookie de staff sempre `__Host-ptm_admin`, SameSite=Strict; uma sessão 'user' num Host de canal → 401.
  needs_mfa(): TOTP ligado OU super_admin OU tenant_admin OU sponsor_admin. RequireStoreOwner continua a exigir 2FA sempre.
  Ator (AuditCtx): tem super_admin → Admin; senão tem sponsor_admin ou tenant_admin → Municipal; senão → Merchant. Não criar ActorType novo (o CHECK da caixa negra é selado).
  Duração da sessão (decisão 4 do owner) pelo papel, não pelo Host: quem tem super_admin → plataforma 8 h/15 min; os outros → staff 12 h/30 min.
  RequireStoreRole/RequireStoreOwner: o papel é o RoleGrant com store_id = {store_id}; o tenant do pedido é grant.tenant_id (deixa de vir do Host e de ler `stores`); sem papel ou loja inexistente → NotFound + Denied("idor"). tenant_admin deixa de dar acesso a lojas (remover StoreAccess::TenantAdmin e StoreViewForTenantAdmin se ficarem sem uso). RequireTenantAdmin: tenant pelo parâmetro de rota {tenant_id}. O resto dos extractors (GUC por loja, RequireSponsorAdmin) é o cartão 14.
  GET /api/v1/staff/me → roles: [{"role","tenant_id","store_id","sponsor_entity_id"}]. /api/v1/superadmin/* continua 404 uniforme para quem não é super_admin com 2FA.
  Helpers de teste: TODAS as lojas semeadas pelos testes Rust (exceto em rls_isolation.rs) passam a nascer num tenant national_portal do país; nenhum teste de staff usa Host de canal para entrar.
```

## Feito quando
- [ ] merchant_owner, sponsor_admin e super_admin entram no host de plataforma; os três são recusados num Host de canal com a resposta da password errada; utilizador sem papéis não entra; cookie de staff num Host de canal → 401
- [ ] **Anti-IDOR no mesmo tenant:** merchant de L1 acede a L1 e recebe 404 + `idor` em L2 (as duas no canal nacional) e num UUID inexistente; `tenant_admin` em rota de loja → 404
- [ ] sponsor_admin sem 2FA: `mfa_required: true` e rotas pós-MFA → 403; merchant em `/api/v1/superadmin/whoami` → 404 + `denied`; sessão de merchant dura como staff e a de super_admin como plataforma
- [ ] `rg -n "municipal" backend-rust/tests --glob '!rls_isolation.rs'` não mostra lojas semeadas em tenants municipais; `openapi.json` regenerado sem diff

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api` → esperado: 0 falhas na suite completa

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Tudo o que usa sessões de staff (login, 2FA, passkeys, timeline, RBAC) está na suite completa acima; `cd frontend-web && npm run gen:api && npm run verify`
