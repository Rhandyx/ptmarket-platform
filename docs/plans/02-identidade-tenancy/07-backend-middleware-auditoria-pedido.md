# 07 — Middleware: 1 `audit_event` por pedido autenticado, recusas e Redis Stream (épico: 02-identidade-tenancy)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 06 · **Paralelo com:** 10

## Objetivo
Todo o pedido de utilizador autenticado, toda a recusa e toda a mutação anónima geram um evento; síncrono com 503 se falhar, ou via Redis Stream nas leituras comuns. Não há interruptor.

## Pode alterar
- `backend-rust/src/http/{audit_layer,client_ip}.rs`, `backend-rust/tests/audit_layer.rs` (criar); `src/http/mod.rs`, `src/audit/mod.rs`, `src/config.rs`, `src/error.rs` (só a variante `ServiceUnavailable` → 503), `Cargo.toml` (`sha2`, `ipnet`), `.sqlx/**` (editar)

## Não tocar
- `src/tenancy/`, `src/identity/` — cartões 11 e 16 (aqui `Actor` e tenant chegam por extensões do pedido; nos testes injetam-se com uma layer de teste); `migrations/`, `workers-go/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §1: cada pedido HTTP de um utilizador autenticado gera um audit_event. Mudanças e recusas são síncronas. Leituras e ações sem BD são assíncronas com entrega garantida (Redis Stream → worker). Exceção: leituras de admin/superadmin e de dados pessoais são SÍNCRONAS; se a gravação falhar, a resposta é 503. Recusas (outcome 'denied'): 401/403, tentativas IDOR, login falhado, rate-limit, CSRF, webhook com assinatura inválida. Anónimo: só logs/métricas, exceto mudança ou recusa. Não existe papel, flag ou endpoint para desligar, filtrar ou editar a auditoria.
Extensões do pedido: Actor { actor_type, actor_id, impersonator_id } (ausente = Anonymous) · AuditClass { ReadAsync, ReadSync } posta por router (ausente = ReadSync: falha fechado) · marca Denied(reason) posta pelos handlers (IDOR devolve 404 mas é recusa).
O extractor AuditCtx (FromRequestParts) nasce aqui: request_id do x-request-id, ip, user_agent_hash = sha256(User-Agent). IP: CF-Connecting-IP só se o peer TCP estiver em TRUSTED_PROXY_CIDRS (config; vazio = nunca confiar); senão o peer.
Decisão depois do handler (por esta ordem):
  1. status 401/403 ou Denied → SÍNCRONO outcome 'denied' (transação própria; a do handler fez rollback). Falhou → 503.
  2. status 429 → Redis Stream (assíncrono; evita amplificação de escrita sob ataque — desvio à spec, a confirmar pelo owner).
  3. método ≠ GET/HEAD: se ctx.recorded já está marcado → nada; senão SÍNCRONO. Vale também para anónimos (actor 'anonymous'). 5xx → outcome 'error'.
  4. GET autenticado + ReadSync → SÍNCRONO; falhou → descarta o corpo e responde 503.
  5. GET autenticado + ReadAsync → XADD; falhou → tenta síncrono; falhou → 503.
  6. GET anónimo com sucesso → nada.
Evento: action = 'http.' || método minúsculo; target_type 'route'; target_id = rota-modelo (MatchedPath, ex. /api/v1/stores/{id}); changes = {"status": n, "path_params": {...}, "query_keys": [...]} (valores de query nunca; tudo por telemetry::redact).
Stream (contrato com o cartão 08 e com audit_append_event): XADD audit:stream * event <JSON>; sem MAXLEN (só o worker apaga, depois do ACK). JSON: {"id" (Uuid::now_v7), "tenant_id", "store_id", "actor_type", "actor_id", "actor_label", "impersonator_id", "action", "target_type", "target_id", "outcome", "reason", "changes", "request_id", "ip", "user_agent_hash" (hex), "occurred_at" (RFC 3339)}; ausentes = null.
Exceção consciente à regra "um handler nunca publica no Redis": só este middleware, só neste stream. /healthz e /readyz ficam fora (sem utilizador).
```

## Feito quando
- [ ] `audit_layer` (PG + Redis reais): cada linha da tabela de decisão tem um teste; mutação com `audit::record` não duplica; IDOR (`Denied` + 404) grava `denied` com o ator
- [ ] Falha fechado: BD de auditoria indisponível → ReadSync e mutação devolvem 503 e o corpo original não sai; Redis em baixo → ReadAsync é gravado de forma síncrona (200)
- [ ] `no_kill_switch`: não existe variável/feature que desligue; router sem `AuditClass` trata GET autenticado como ReadSync; `CF-Connecting-IP` de peer não confiável é ignorado; o evento nunca contém cookies, corpo, nem valores de query

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test audit_layer` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `/healthz`, `/readyz`, request-id, limite de corpo e timeout — `cargo test -p ptmarket-api --lib http` · `audit_ctx` e `rls_isolation` (cartão 06)
