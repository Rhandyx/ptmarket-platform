# 07b — Middleware de auditoria: achados da auditoria ASVS da onda 3 (26/11) (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 07 · **Paralelo com:** 03d, 04 · **Antes de:** 11

## Objetivo
Nenhum pedido consegue impedir a gravação do seu evento, encher a fila morta ou esgotar a pool com escritas síncronas. A correlação forense não pode ser escolhida pelo cliente.

## Pode alterar
- `backend-rust/src/http/{audit_layer,client_ip}.rs`, `src/audit/{ctx,record}.rs`, `src/config.rs`, `tests/audit_layer.rs`, `tests/audit_ctx.rs`

## Não tocar
- `migrations/`, `infra/`, `workers-go/`, `src/tenancy/` (exceto se o ponto 8 o exigir: só visibilidade); nunca ler `.env`

## Contexto exato (achados, ficheiro:linha do commit 4795b23)
```
1 ALTO audit_layer.rs:~226 — path params com %00 → "\u0000" no JSON → o jsonb recusa (22P05): na via síncrona dá 503 e o
  evento não é gravado (recusa/IDOR sem rasto); na via ReadAsync vai para a fila morta (inundação). → Sanitizar TODOS os
  textos que entram no evento (path params, rota, user agent antes do hash não interessa, reason, target_id): \0 → U+FFFD;
  limitar o tamanho de cada valor (256 chars) e o número de params (16).
2 ALTO audit_layer.rs:~343 (decide, ramos 1 e 3) — cada 401/403 e cada mutação anónima é uma escrita síncrona na cabeça
  da cadeia: um flood sem credenciais serializa no FOR UPDATE e esgota a pool. → A mesma lógica do 429 (1.º síncrono por
  chave/minuto, os restantes contados e resumidos), com a chave = IP normalizado (ponto 9) + classe ('auth_fail',
  'anon_mutation'). Uma recusa de utilizador AUTENTICADO (403/IDOR) continua sempre síncrona.
3 MÉDIO record.rs — sem limite de tamanho: changes serializado ≤ 64 KiB, reason ≤ 1 KiB, target_id ≤ 256; acima disso
  → AppError::Validation (nunca truncar em silêncio).
4 MÉDIO audit_layer.rs:~384 outcome_for — 401 e 403 → 'denied' por omissão; 404/400/409 sem Denied ficam 'success'
  (a app marca IDOR com Denied, regra do cartão 07).
5 MÉDIO audit_layer.rs:~244 — a Cloudflare não apaga o x-request-id do cliente. → O request_id da caixa negra é SEMPRE
  gerado no servidor (UUIDv7); o do cliente (só se for UUID) vai em changes.client_request_id. A SetRequestIdLayer usa o
  mesmo id gerado (os logs e a caixa negra coincidem sempre).
6 MÉDIO config.rs trusted_proxies — recusar prefixos IPv4 < /8 e IPv6 < /16 (não só /0); erro de arranque com mensagem clara.
8 MÉDIO ctx.rs:~93 — AuditCtx::system é pub: qualquer handler abre transação como 'system'. → pub(crate); os jobs Rust
  futuros vivem no crate.
9 MÉDIO rate_limit_key — IPv6 por /128: rodar endereços de um /64 contorna a janela. → normalizar IPv6 para /64.
B  BAIXO — decide corre no future do pedido: um timeout ou o abort do cliente cancela a gravação. → tokio::spawn da
  gravação e await do JoinHandle (o pedido continua a esperar pelo resultado: fecha com 503 se falhar).
```

## Feito quando
- [ ] Teste: `GET /x/%00abc` autenticado e `DELETE` anónimo com `%00` → evento gravado (sem 503), valor com U+FFFD
- [ ] Teste: 50 × 401 do mesmo IP num minuto → 1 evento síncrono + 1 resumo com contagem 49; 403 autenticado → sempre 1 evento cada
- [ ] Teste: `x-request-id` do cliente nunca é o `request_id` gravado; aparece em `changes.client_request_id`; os logs e o evento têm o mesmo id
- [ ] Testes: `TRUSTED_PROXY_CIDRS=0.0.0.0/1` → erro de arranque; dois IPv6 do mesmo /64 partilham a janela; `record` com changes > 64 KiB → Validation
- [ ] `AuditCtx::system` não é visível em `tests/` (doctest compile_fail)
- [ ] Cliente que fecha a ligação a meio de uma mutação → o evento fica gravado

## Prova (um comando)
`cd backend-rust && cargo test -p ptmarket-api --all-features` → verde; `cargo clippy --all-targets --all-features -- -D warnings` limpo
