# 08 — Worker Go: Redis Stream de auditoria → `audit_events` (ACK só depois de gravar) (épico: 02-identidade-tenancy)

**Agente:** go-integrations · **Modelo:** opus · **Depende de:** 02 · **Paralelo com:** 03

> **Mudou no 01b:** as funções da caixa negra estão no schema `audit` (ex.: `audit.audit_append`, `audit.audit_append_event`); chamar sempre com o schema e com tipos exatos (`::text`, `::uuid`), para nunca resolver para uma sobrecarga plantada. A app e o worker só têm EXECUTE nas funções previstas e USAGE no schema.

## Objetivo
O worker consome `audit:stream`, grava em lote dentro da cadeia de hash e só então faz ACK; nenhum evento se perde nem se duplica, nem com crash a meio.

## Pode alterar
- `workers-go/internal/audit/{stream,store,actor}.go`, `workers-go/internal/audit/stream_test.go` (criar); `workers-go/cmd/worker/main.go`, `workers-go/internal/config/config.go`, `go.mod`/`go.sum` (editar)

## Não tocar
- `workers-go/internal/outbox/`, `internal/logx/` — aprovados; `migrations/` (só leitura), `backend-rust/`, `infra/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §1: o evento vai para um Redis Stream, o worker grava-o em lote em audit_events dentro da cadeia de hash e só depois faz ACK. §3.1: os workers Go usam actor_type = 'system'.
Stream: chave audit:stream, campo `event` = JSON (produzido pela API Rust). Grupo de consumidores `audit-writers`, criado com XGROUP CREATE … MKSTREAM (ignorar BUSYGROUP); nome do consumidor = hostname + pid.
JSON: {"id" uuidv7, "tenant_id", "store_id", "actor_type", "actor_id", "actor_label", "impersonator_id", "action", "target_type", "target_id", "outcome", "reason", "changes", "request_id", "ip", "user_agent_hash" hex, "occurred_at" RFC 3339}. O worker NÃO altera nem enriquece o JSON: passa-o tal e qual.
BD (papel ptmarket_worker, sem SELECT/INSERT em audit_events): SELECT audit_append_event($1::jsonb) → true = gravou, false = já existia (idempotente por id). JSON inválido → SQLSTATE 'PTA02'.
Ciclo: XREADGROUP COUNT <AUDIT_BATCH, default 200> BLOCK 2 s → UMA transação pgx com todas as chamadas → COMMIT → XACK + XDEL dos ids gravados. Erro antes do COMMIT → sem ACK (fica pendente).
  Pendentes de consumidores mortos: XAUTOCLAIM com min-idle 60 s em cada ciclo.
  Mensagem venenosa (PTA02 ou JSON ilegível): repetir o lote um a um com SAVEPOINT; a venenosa vai para audit:stream:dead (XADD com o original + erro) e só então XACK. Nunca descartar; log de erro pelo logx (sem o payload).
  Sem MAXLEN/XTRIM em audit:stream. Paragem limpa no SIGTERM: acaba o lote em curso. Métrica em log a cada minuto: pendentes (XPENDING) e tamanho da fila morta.
Helper para os próximos cartões Go que mutem a BD: audit.SetSystemActor(ctx, tx, job string) → SELECT set_config('app.actor_type','system',true), set_config('app.actor_label',$1,true). Sem ele, qualquer INSERT/UPDATE/DELETE do worker (exceto outbox_events) aborta com 'PTA01'.
Regras Go: context com timeout em toda a chamada; segredos só por ambiente; nunca float; cliente Redis = github.com/redis/go-redis/v9 (já é dependência do asynq).
Sem interruptor: o consumidor arranca sempre com o worker; não há variável para o desligar.
```

## Feito quando
- [ ] `stream_test` (PG + Redis reais, BD migrada): 500 eventos no stream → 500 linhas em `audit_events`, `audit_verify_chain` sem quebras, stream vazio e 0 pendentes
- [ ] Crash simulado depois do COMMIT e antes do XACK → na reentrega não há linhas duplicadas e o ACK acontece
- [ ] Falha da BD a meio do lote → nenhum XACK, nada gravado; ao recuperar grava tudo
- [ ] Mensagem venenosa no meio de um lote → as outras gravam, a venenosa aparece em `audit:stream:dead`, nada se perde
- [ ] Mutação de uma tabela de prova como `ptmarket_worker` sem `SetSystemActor` falha; com ele grava evento `actor_type = 'system'`

## Prova (um comando)
`cd workers-go && WORKER_DATABASE_URL=postgres://ptmarket_worker:dev_worker@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 go test ./internal/audit/...` → esperado: `ok`, 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Publicador outbox → Asynq — `cd workers-go && go test ./internal/outbox/... ./internal/logx/...` · `govulncheck ./...` com 0 vulnerabilidades
