# 15 — `identity::password`: Argon2id + verificação de passwords vazadas (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** — · **Paralelo com:** 01, 05

## Objetivo
Um módulo puro (sem BD, sem HTTP próprio) que faz hash e verificação de passwords com parâmetros OWASP e recusa passwords conhecidas em fugas.

## Pode alterar
- `backend-rust/src/identity/{mod,password,breach}.rs` (criar/editar); `Cargo.toml` (`argon2`, `sha1`, `reqwest` só com `rustls-tls`, `zeroize`)

## Não tocar
- `src/tenancy/`, `src/outbox.rs`, `src/http/`, `src/audit/` — outros cartões em paralelo; `migrations/`, `workers-go/`, `frontend-web/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 12 §3: passwords com Argon2id (parâmetros OWASP), verificação contra passwords vazadas (k-anonymity HIBP) no registo. ASVS 5.0 nível 3 em identity.
Parâmetros: Argon2id v=19, m=19456 KiB (19 MiB), t=2, p=1, sal aleatório de 16 bytes (OsRng), saída 32 bytes, formato PHC ($argon2id$v=19$m=19456,t=2,p=1$…). Constantes num só sítio.
API: pub struct Password(SecretString)  — sem Debug/Display/Serialize do valor; apagada da memória (zeroize)
  Password::parse(&str) -> Result<Password, AppError::Validation>: 8 a 128 caracteres (contados em code points Unicode); sem regras de composição; aceita espaços e qualquer Unicode; não corta nem normaliza (guardam-se os bytes recebidos).
  async fn hash(&Password) -> Result<String, AppError>            // tokio::task::spawn_blocking + Semaphore (máx. 4 em simultâneo; anti-DoS)
  async fn verify(&Password, phc: Option<&str>) -> Result<Verified, AppError>   // Verified { ok: bool, needs_rehash: bool }
    phc = None (conta inexistente ou só passkey) → verifica contra um hash fictício fixo e devolve ok=false: o tempo de resposta não revela se a conta existe.
    needs_rehash = true quando os parâmetros do PHC são mais fracos que as constantes atuais.
  #[async_trait] pub trait BreachChecker { async fn is_breached(&self, p: &Password) -> bool }
    HibpRange: SHA-1 da password → envia SÓ os 5 primeiros hex para GET https://api.pwnedpasswords.com/range/{prefixo} com cabeçalho Add-Padding: true; compara o sufixo localmente. Timeout total 2 s; erro/timeout → false + log de aviso (não bloquear o registo por falha de terceiros). User-Agent genérico, sem nome do projeto nem dados do utilizador.
Privacidade: nunca sai mais do que os 5 hex; a password e o hash completo nunca vão para logs, erros ou eventos de auditoria. NullBreachChecker para testes; nenhum teste faz chamadas de rede.
Regras Rust: zero unwrap/expect/panic fora de testes; erros → AppError (falha do Argon2 = Internal, mensagem genérica).
```

## Feito quando
- [ ] Testes unitários: `hash` produz PHC com os parâmetros exatos; dois hashes da mesma password diferem; `verify` aceita a certa e recusa a errada; PHC corrompido → `ok=false` (sem panic); `format!("{:?}", password)` não contém o valor
- [ ] `verify(…, None)` devolve `ok=false` e demora o mesmo que uma verificação real (tolerância larga, teste não instável)
- [ ] PHC com `m=4096` verifica e devolve `needs_rehash=true`; password com 7 e com 129 caracteres → `Validation`; emoji e espaços aceites
- [ ] `HibpRange` contra um servidor HTTP local de teste: só o prefixo de 5 hex aparece no pedido; sufixo presente → true; timeout → false

## Prova (um comando)
`cd backend-rust && SQLX_OFFLINE=true cargo test -p ptmarket-api --lib identity::` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `cargo audit` e `cargo deny check` com 0 vulnerabilidades depois das dependências novas · `SQLX_OFFLINE=true cargo test -p ptmarket-api --lib`
