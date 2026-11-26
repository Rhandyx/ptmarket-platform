# 17 — Clientes: registo (Turnstile + consentimentos) e perfil `/me` (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 12, 15, 16 · **Paralelo com:** —

## Objetivo
Um visitante regista-se em qualquer Câmara com a mesma conta global; autenticado, lê e altera só os seus dados. Sem enumeração de emails.

## Pode alterar
- `backend-rust/src/identity/{customers,captcha,nif,email}.rs`, `backend-rust/tests/customers.rs` (criar); `src/identity/{mod,http}.rs`, `src/http/{mod,openapi}.rs`, `src/config.rs`, `src/state.rs`, `Cargo.toml` (`unicode-normalization`), `openapi.json`, `.sqlx/**` (editar)

## Não tocar
- `src/identity/{password,session,csrf}.rs`, `src/audit/`, `src/tenancy/` — aprovados (usar pela API pública); `migrations/` (só leitura)

## Contexto exato (colado da spec; não ler a spec)
```
Spec 11 D4: uma conta de cliente para todas as lojas e Câmaras (customers é global). Spec 12 §2: Turnstile SEMPRE no registo; token verificado no servidor (siteverify), uso único, nunca só no browser; honeypot (campo invisível) + tempo mínimo de preenchimento em todos os formulários públicos. §3: DTOs com #[serde(deny_unknown_fields)] + validação e limites de tamanho.
BD (cartão 12): a app faz INSERT em customers só com ator 'anonymous', SEM RETURNING e SEM ON CONFLICT (email repetido = 23505); com ator 'customer' lê/atualiza só a sua linha: UPDATE (email, name, phone, nif, password_hash, passkeys, consents, updated_at). Sem DELETE.
identity::email::normalize (email.rs, função pura pública, usada aqui e no login do cartão 18; auditoria onda 4, achado 7): trim → NFC → minúsculas; vazio, > 255 ou sem "@" → erro de validação. O email gravado e procurado é SEMPRE o normalizado.
POST /api/v1/auth/register (anónimo; é mutação) {"email" ≤ 255, "password", "name" 1–255, "consents": {"terms_version": string, "privacy_version": string, "marketing": bool}, "turnstile_token", "website" (honeypot: tem de vir vazio), "form_started_at" (ms; < 2 s atrás = bot)}
  Ordem: validar DTO → email::normalize → honeypot/tempo → CaptchaVerifier → Password::parse → BreachChecker (vazada → 422 no campo password) → hash → INSERT (id = Uuid::now_v7()).
  Resposta SEMPRE 202 {"status":"ok"}, exista ou não o email: o 23505 NUNCA chega ao utilizador (nem estado, nem código, nem corpo, nem cabeçalho diferentes; o hash é calculado nos dois casos para o tempo ser igual). Não inicia sessão. No 23505: numa transação nova, identity_customer_credentials(email) dá o id e grava-se o evento de outbox 'customer.duplicate_registration' {customer_id} (sem email no payload); o email "já tem conta" ao titular é enviado pelo épico notificações a partir desse evento.
  consents gravado: {"terms": {"version", "at"}, "privacy": {"version", "at"}, "marketing": {"granted": bool, "at"}}. terms/privacy obrigatórios; marketing ausente = false (RGPD: consentimento nunca pré-assinalado; a prova do consentimento é a linha + o evento de auditoria).
  Eventos: customers.insert (L1) + audit::record 'customer.registered' (target_id = id; nunca o email); duplicado: 'customer.register_duplicate' (target_type 'account_hash', target_id = sha256 do email normalizado). Honeypot/captcha falhado → 422 genérico + Denied("bot").
trait CaptchaVerifier { async fn verify(&self, token: &str, ip: Option<IpAddr>) -> bool }; TurnstileVerifier: POST https://challenges.cloudflare.com/turnstile/v0/siteverify (secret = TURNSTILE_SECRET em SecretString, response, remoteip), timeout 3 s, erro → false (falha fechado). Fake nos testes; sem chamadas de rede em testes.
GET /api/v1/me (RequireCustomer; AuditClass::ReadSync — dados pessoais) → 200 {"id","email","name","phone","nif","consents","created_at"}
PATCH /api/v1/me (RequireCustomer + CSRF) {"name"?, "phone"? ≤ 50, "nif"? , "marketing"?: bool} → 200 com o perfil. A linha vem SEMPRE de WHERE id = ator (nunca de um id do pedido).
  NIF: nif::validate_pt (9 dígitos + dígito de controlo módulo 11) quando o tenant é PT. Tenant ES: aceitar 9 caracteres alfanuméricos SEM validar dígito de controlo — validação NIF/NIE/CIF fica para a decisão do owner sobre ES (não inventar). Mudar email e password ficam fora deste cartão (exigem reautenticação e email de confirmação).
```

## Feito quando
- [ ] `customers`: registo válido → 202 e linha criada com hash Argon2id e consentimentos datados; mesmo email outra vez (também com espaços, maiúsculas ou em NFD) → 202 byte a byte idêntico, 1 só linha e 1 evento de outbox `customer.duplicate_registration`; a mesma conta autentica-se em dois tenants (global)
- [ ] Sem `terms_version`, honeypot preenchido, captcha falso, password vazada, campo desconhecido no JSON → 422 e nenhuma linha; `marketing` ausente fica `false`
- [ ] Anti-IDOR: cliente X em `/me` nunca recebe dados de Y (não há id no pedido; testar com dois clientes e trocar cookies); sem sessão → 401 + evento `denied`; `GET /me` é síncrono (BD de auditoria em baixo → 503)
- [ ] PATCH sem CSRF → 403; NIF PT com dígito de controlo errado → 422; PATCH válido gera `customers.update` com ator `customer` e sem valores pessoais em claro; `openapi.json` sem diff

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test customers` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `session`, `tenant_host`, `audit_layer` — `cargo test -p ptmarket-api --test session --test tenant_host --test audit_layer` · `--lib identity::`
