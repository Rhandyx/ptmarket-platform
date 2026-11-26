# 11b — Rust: portal pela view `portal_stores`, travão a Hosts desconhecidos e redator alinhado (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 11, 16 (supervisor: o 16 já estava em curso; partir do código dele), 10b (view), 03e (ficheiro de vetores) · **Paralelo com:** 09b · **Antes de:** 18

> Achados 6 (parte Rust), 12 e 13 da auditoria ASVS da onda 4. A BD de dev tem de estar na 0021 antes do `cargo sqlx prepare`.

## Objetivo
O portal nacional lê as lojas pela view da BD que não tem colunas sensíveis. Uma inundação de Hosts aleatórios deixa de custar uma query por pedido na réplica. O redator de logs passa nos mesmos vetores que a BD e o Go.

## Pode alterar
- `backend-rust/src/tenancy/{portal,resolver,http}.rs`, `src/http/{telemetry,client_ip}.rs`, `src/error.rs` (só a variante 429, se faltar), `src/state.rs`, `src/config.rs`, `tests/{tenant_host,rls_isolation}.rs`, `.sqlx/**`, `openapi.json` (só se o 429 entrar no contrato)

## Não tocar
- `src/audit/`, `src/http/audit_layer.rs` — aprovados (usar, não alterar); `src/identity/`; `docs/testdata/redaction-vectors.json` (só leitura: se um vetor parecer errado, parar e reportar); `migrations/`, `infra/`, `workers-go/`; nunca ler `.env`

## Contexto exato
```
6. BD (cartão 10b, migration 0021): a policy portal_read de stores para a app DEIXOU de existir. Em modo portal, as lojas de outros tenants leem-se só em portal_stores (view security_barrier, já filtrada por publicada + ativa + mesmo país; colunas: id, tenant_id, name, slug, legal_name, nif, email, phone, address_json, geo_lat, geo_lng, business_hours, is_vacation_mode, vacation_message, supports_click_collect, supports_local_courier, supports_national_shipping, vat_exempt_art53). Produtos e variantes continuam nas tabelas.
   → portal.rs: published_stores passa a ler FROM portal_stores; PortalStore mantém os 4 campos. PORTAL_FORBIDDEN_COLUMNS passa a 6: iban, invoicing_credentials_enc, eupago_split_key, stripe_account_id, custom_commission_bps, kyc_verified. Os dois testes unitários do módulo continuam a valer para as 6.
12. tenancy/http.rs resolve_host → resolver.rs resolve: cada Host fora da cache faz 1 SELECT na réplica, e Hosts aleatórios nunca acertam na cache.
   → Só quando o Host NÃO está em cache (um acerto de cache não toca no Redis): ler o contador Redis host:miss:<ip> (TTL 60 s). Acima de 30 → sem query: ResolvedHost ganha um estado "limitado" e os extractores devolvem 429 com Retry-After por DENTRO da caixa negra (a layer continua a nunca recusar; o 429 segue a regra de resumo do middleware). Abaixo do limite: faz o SELECT e só incrementa se o Host for desconhecido (um tenant válido nunca gasta o limite).
   → <ip> = IP do cliente pela API pública de http::client_ip (proxies de confiança), IPv4 inteiro e IPv6 pelo /64. A normalização /64 hoje é privada em audit_layer.rs (ip_subject): criar uma função pública pura em client_ip.rs com o mesmo resultado e teste; NÃO editar audit_layer.rs.
   → Redis indisponível: falha ABERTA (faz o SELECT; a cache negativa de 10 s e o teto de 10 000 entradas continuam) + log Warn sem o Host nem o IP. Nunca 5xx por causa do Redis neste caminho: um Redis em baixo não pode tirar as Câmaras do ar. AppError sem variante 429: acrescentar TooManyRequests { retry_after_s } em src/error.rs (corpo genérico + Retry-After), com teste.
   Nota de infra (NÃO é deste cartão; épico de produção): Cloudflare Authenticated Origin Pulls (mTLS) + firewall da origem só para os IPs da Cloudflare, para ninguém falar com a origem com um Host arbitrário.
13. src/http/telemetry.rs (redact_str, redact, is_sensitive) tem cobertura diferente da BD. → Teste que lê ../docs/testdata/redaction-vectors.json (a partir de CARGO_MANIFEST_DIR) e corre os vetores com "rust" em layers. kind "text": redact_str(input) não contém nenhuma das must_not_contain; must_equal_input → igual à entrada. kind "json": redact(&mut valor), mesma verificação.
   → Corrigir até passarem: e-mail, telefone PT/E.164, NIB de 21 dígitos, IBAN em qualquer caixa e com espaço(s), NBSP, "-" e "."; chaves normalizadas (camelCase → snake_case): tax_id, vat_id, national_id, vat_number, mobile, phone, email, nib, account_number, card_pan; pares etiquetados e tuplos de 2. Mascarar a mais é aceitável; deixar passar não. Regex que não compila continua a falhar fechado.
```

## Feito quando
- [ ] `tenant_host`: `PortalReadTx` lê as lojas publicadas de A e B pela view; pela ligação de testes, em modo portal, `SELECT iban FROM stores` de outro tenant → 0 linhas e `SELECT iban FROM portal_stores` → erro 42703 (repetir para as 6 colunas); tenant municipal → `Forbidden` + evento `denied`
- [ ] Teste: 31 Hosts desconhecidos diferentes do mesmo IP num minuto → o 31.º não faz query e responde 429 com `Retry-After`; outro IP não é afetado; dois IPv6 do mesmo /64 partilham o contador; um Host válido em cache responde 200 ao IP limitado
- [ ] Teste: Redis parado → Host válido responde 200 e Host desconhecido 404 (sem 5xx)
- [ ] Teste dos vetores verde (todos os de layers `rust`); `cargo clippy --all-targets --all-features -- -D warnings` limpo; `openapi.json` sem diff não intencional

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --all-features` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `rls_isolation`, `audit_ctx`, `audit_layer`, `tenant_host` e os testes de `http::telemetry` — incluídos no comando acima
