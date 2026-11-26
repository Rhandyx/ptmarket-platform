# 18 — Clientes: login com bloqueio progressivo e Turnstile após 3 falhas (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 17, 11b (variante 429 de `AppError` e IP por /64) · **Paralelo com:** —

## Objetivo
`POST /api/v1/auth/login` autentica clientes com resposta uniforme, atraso crescente por conta e por IP, captcha depois de 3 falhas, e cada tentativa (boa ou má) na caixa negra.

## Pode alterar
- `backend-rust/src/identity/{login,throttle}.rs`, `backend-rust/tests/login.rs` (criar); `src/identity/{mod,http}.rs`, `src/http/{mod,openapi}.rs`, `openapi.json`, `.sqlx/**` (editar)

## Não tocar
- `src/identity/{password,session,csrf,captcha,customers,email}.rs`, `src/audit/`, `src/tenancy/` — aprovados; `migrations/` (só leitura)

## Contexto exato (colado da spec; não ler a spec)
```
Spec 12 §2: Turnstile condicional — login após 3 falhas. Rate limiting por IP, por conta e por endpoint; bloqueio progressivo no login (backoff exponencial, NUNCA bloqueio permanente que permita DoS a contas alheias). §3: rotação do ID de sessão no login. Spec 13 §1: login e login falhado ficam na caixa negra (falhado = outcome 'denied').
BD: identity_customer_credentials(p_email text) → (id uuid, password_hash text), 0 ou 1 linha (única leitura por email). session::rotate/create e password::verify já existem.
POST /api/v1/auth/login (anónimo; mutação) {"email" ≤ 255, "password" ≤ 128, "turnstile_token"?: string} com deny_unknown_fields. O email passa SEMPRE por identity::email::normalize (cartão 17: trim + NFC + minúsculas) antes do lookup, do hash das chaves Redis e do target_id; a password NÃO é normalizada nem aparada.
  204 + Set-Cookie em caso de sucesso. Qualquer falha de credenciais → 401 com o corpo genérico de AppError::Unauthorized — mesmo estado, mesmo código de erro e mesmo corpo para email inexistente, password errada e conta só com passkey; tempo igual: sem conta (ou sem password_hash) corre-se SEMPRE o Argon2 falso (password::verify(…, None)), nunca um retorno antecipado (auditoria onda 4, achado 7).
  Captcha exigido e em falta/errado → 401 genérico com o campo extra "captcha_required": true (único sinal permitido; depende só do contador, não de a conta existir). Atraso em curso → 429 com Retry-After (segundos), sem tocar na BD.
throttle (Redis; chaves com sha256 do email normalizado e do IP — IPv4 inteiro, IPv6 pelo /64; nunca o email em claro): contadores login:fail:acct:<hash> e login:fail:ip:<ip>, TTL 15 min, INCR em cada falha; o da conta é apagado no sucesso. Rate limit de volume (TODAS as tentativas, boas ou más; onda 4): por IP > 20/min → 429 + Retry-After; por email > 10 em 15 min → captcha obrigatório (nunca 429 seco só pelo email: seria DoS à conta alheia).
  ≥ 3 falhas (conta OU IP) → captcha obrigatório. A partir da 5.ª: espera 2^(n-5) s, teto 900 s. Nunca bloqueio definitivo; nunca alterar a conta na BD. Redis indisponível → exigir captcha em todos os logins (degrada para o lado seguro, não abre nem tranca).
Sucesso: needs_rehash → atualiza password_hash na mesma transação; session::rotate (revoga a sessão anterior deste browser, se houver); sessão criada no tenant do Host. Fora deste cartão: recuperação de password e "lembrar-me" (precisam de email; épico notificações).
Auditoria (síncrona; falha a gravar → 503 e o login NÃO acontece):
  sucesso: audit::record 'auth.login' outcome success, ator = o cliente, target_id = id da sessão.
  falha: 'auth.login' outcome denied, ator 'anonymous', reason ∈ {bad_credentials, captcha, throttled}, target_type 'account_hash', target_id = sha256(email normalizado) em hex. Nunca a password, nunca o email, nunca dizer se a conta existe. 429 segue a regra do middleware (Redis Stream).
```

## Feito quando
- [ ] `login`: credenciais certas → 204, cookie `__Host-ptm_session`, sessão nova e evento `auth.login` success com o ator; a sessão anterior fica revogada; PHC fraco é regravado; `" João@X.pt "` e a forma NFD do mesmo email entram na mesma conta
- [ ] Email inexistente, password errada e conta sem password → resposta byte a byte igual (estado, código, corpo, cabeçalhos relevantes), Argon2 executado nos três casos (contador do hasher falso no teste) e 1 evento `denied` cada, sem email em claro
- [ ] 3 falhas → o pedido seguinte sem captcha devolve `captcha_required`; com captcha válido e password certa entra; 6.ª falha → 429 com `Retry-After`; passado o TTL volta a aceitar (nunca permanente); 21 tentativas do mesmo IP num minuto → 429; 11 para o mesmo email de IPs diferentes → `captcha_required`
- [ ] Falhas contra a conta de X a partir de outro IP não impedem X de entrar com captcha (sem DoS à conta alheia); login no Host A não cria sessão válida no Host B
- [ ] BD de auditoria em baixo → 503 e nenhuma sessão criada; `openapi.json` sem diff

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test login` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `customers`, `session`, `audit_layer` — `cargo test -p ptmarket-api --test customers --test session --test audit_layer`
