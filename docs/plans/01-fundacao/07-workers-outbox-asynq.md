# 07 — Esqueleto Go: publicador do outbox → Asynq (épico: 01-fundacao)

**Agente:** go-integrations · **Modelo:** sonnet · **Depende de:** — · **Paralelo com:** 01, 02, 04, 08

## Objetivo
`workers-go/` compila e tem um publicador que lê `outbox_events` e enfileira no Asynq sem perder nem duplicar eventos, provado com testes sem BD nem Redis.

## Pode alterar
- `workers-go/**` (criar): `go.mod`, `go.sum`, `.env.example`, `cmd/worker/main.go`, `internal/{config,logx,outbox}/`

## Não tocar
- `migrations/`, `infra/`, `backend-rust/`, `frontend-web/` — outros cartões; qualquer `.env` real
- Pacotes de fornecedores (`payments/*`, `invoicing/*`, `shipping/*`) e consumidores — épicos seguintes

## Contexto exato (colado da spec; não ler a spec)
```
D3: outbox_events(id UUID, tenant_id UUID NULL, aggregate, aggregate_id UUID, event_type, payload JSONB, created_at, published_at NULL). É escrito pelo Rust na mesma transação do negócio; o publicador lê-o e envia para Redis/Asynq; consumidores idempotentes por `id`. Zero eventos perdidos entre o commit e a fila.
Papel de BD: ptmarket_worker — só SELECT e UPDATE(published_at) em outbox_events; não vê mais nenhuma tabela.
Ciclo (uma transação por lote):
  SELECT id, tenant_id, aggregate, aggregate_id, event_type, payload, created_at FROM outbox_events WHERE published_at IS NULL ORDER BY created_at, id LIMIT $1 FOR UPDATE SKIP LOCKED
  por evento: asynq.NewTask(event_type, envelope) + EnqueueContext(ctx, t, asynq.TaskID(id), asynq.Queue("events"), asynq.MaxRetry(10), asynq.Retention(24h))
  envelope JSON = {"id","tenant_id","aggregate","aggregate_id","event_type","created_at","payload"}; asynq.ErrTaskIDConflict / ErrDuplicateTask = já enfileirado = sucesso
  UPDATE outbox_events SET published_at = now() WHERE id = ANY($ids_enfileirados); COMMIT
  falha ao enfileirar → esse evento NÃO é marcado, fica para o ciclo seguinte (pelo-menos-uma-vez); nunca marcar antes de enfileirar
Env: WORKER_DATABASE_URL, REDIS_URL, OUTBOX_POLL_INTERVAL (1s), OUTBOX_BATCH (100). Segredos só por env; nunca em logs — `logx` redige password, token, NIF, IBAN, URLs com credenciais.
Regras: context.Context com timeout (5 s) em toda a chamada a BD/Redis; nada de http.DefaultClient; dinheiro em int64 (nunca float64); paragem limpa em SIGTERM; servidor Asynq arranca com ServeMux vazio (retries exponenciais por omissão).
Desenho testável: interfaces `Store` (FetchUnpublished/MarkPublished numa tx) e `Enqueuer`; implementações pgx v5 e asynq; testes com duplos.
```

## Feito quando
- [ ] `go build ./...` e `go vet ./...` limpos; `go.sum` no git; versões fixadas
- [ ] Teste novo `outbox.TestPublisher`: lote de 3 → 3 enfileirados com TaskID = id e 3 marcados; envelope contém `id` e `tenant_id`
- [ ] Casos de erro: falha no 2.º evento → só o 1.º e o 3.º são marcados e não há panic; `ErrTaskIDConflict` conta como publicado; contexto cancelado → nada é marcado
- [ ] Teste novo `logx.TestRedact`: password, token, NIF, IBAN e `postgres://user:pass@…` saem mascarados

## Prova (um comando)
`cd workers-go && go test ./...` → esperado: `ok` em todos os pacotes, 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- —
