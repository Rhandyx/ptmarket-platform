# 09 — Worker Go: raiz diária em WORM, `verify-audit` e alerta de ações superadmin (épico: 02-identidade-tenancy)

**Agente:** go-integrations · **Modelo:** opus · **Depende de:** 02, 05, 08 · **Paralelo com:** 04, 06

## Objetivo
A cadeia fica ancorada fora da BD todos os dias, há um comando que deteta adulteração, e cada ação de superadmin vai para WORM em minutos e gera alerta ao owner.

## Pode alterar
- `workers-go/internal/audit/{root,verify,superadmin,worm,alert}.go` + testes, `workers-go/cmd/verify-audit/main.go` (criar); `workers-go/cmd/worker/main.go`, `internal/config/config.go`, `go.mod`/`go.sum` (editar)

## Não tocar
- `workers-go/internal/audit/stream.go`, `internal/outbox/` — aprovados; `migrations/`, `infra/` (só leitura), `backend-rust/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §3.4: um job diário publica a raiz do dia num armazenamento WORM externo (R2/S3 Object Lock); um comando verify-audit recalcula a cadeia e assinala qualquer quebra.
Spec 13 §1: as ações de superadmin são enviadas também para WORM quase em tempo real (minutos, não só a raiz diária); cada ação de superadmin gera um alerta para o owner. Não existe forma de desligar.
BD (papel ptmarket_worker): audit_day_root(p_day date) → (chain_key, retention_class, first_seq, last_seq, last_hash bytea, events) · audit_chains() → (chain_key, retention_class, last_seq) · audit_verify_chain(chain_key, class, from, to) → (broken_id, broken_seq, problem) · audit_ensure_partitions(3) · audit_default_partition_rows() → bigint.
WORM: interface WormStore { Put(ctx, key, body, retainUntil) error; Get(ctx, key) ([]byte, error) } + implementação S3 compatível (Object Lock modo COMPLIANCE). Config: WORM_ENDPOINT, WORM_REGION, WORM_BUCKET, WORM_ACCESS_KEY, WORM_SECRET_KEY, WORM_RETENTION_DAYS (default 3650). Dev: bucket `ptmarket-audit-worm` do cartão 05.
Raiz diária (tarefa periódica Asynq, 00:10 UTC, do dia anterior; TaskID = 'audit-root-YYYY-MM-DD'): manifesto JSON {"day", "generated_at", "chains": [{chain_key, retention_class, first_seq, last_seq, last_hash hex, events}], "prev_manifest_sha256"} → Put roots/YYYY/MM/DD.json. Já existe → comparar; igual = ok, diferente = ALERTA e erro (nunca sobrescrever). Dias em falta são recuperados por ordem.
  No mesmo job: audit_ensure_partitions(3); audit_default_partition_rows() > 0 → alerta.
verify-audit (binário próprio; código de saída ≠ 0 se houver quebra): por cada cadeia chama audit_verify_chain em janelas de 1 dia e confirma que o last_hash de cada dia bate com o manifesto no WORM; imprime as quebras (id, seq, problema), nunca o conteúdo dos eventos.
Superadmin: handler Asynq do tipo `audit.superadmin_action` (vem do outbox; TaskID = id do evento → idempotente; envelope {id, tenant_id, aggregate, aggregate_id, event_type, created_at, payload}): Put superadmin/YYYY/MM/DD/<aggregate_id>.json com o payload, depois Alerter.Notify. Falha de qualquer dos dois → erro (Asynq repete, até 10 vezes; esgotado → log de erro + alerta).
Alerter: interface { Notify(ctx, Alert{Kind, Summary, EventID}) error }; implementação webhook HTTP POST JSON para ALERT_WEBHOOK_URL (timeout 5 s, cliente próprio, sem dados pessoais: só ator-id, ação, alvo, hora). O worker NÃO arranca sem WORM_* e sem ALERT_WEBHOOK_URL; em dev aceita ALERT_WEBHOOK_URL=log:// (escreve no log). Canal real = decisão do owner.
Regras Go: context com timeout em toda a chamada externa; segredos só por ambiente e nunca em logs; cliente S3 = dependência nova, justificar no PR (preferir a mais pequena com Object Lock).
```

## Feito quando
- [ ] Teste da raiz (PG + WORM reais): manifesto do dia gravado com retenção; 2.ª execução é idempotente; manifesto divergente → erro + alerta, objeto intacto
- [ ] `verify-audit` sai 0 com a cadeia íntegra e ≠ 0 quando o manifesto do WORM não bate com a BD (simular trocando o manifesto de um bucket de teste)
- [ ] Evento `audit.superadmin_action` → objeto no WORM + 1 alerta (servidor HTTP de teste); reentrega da mesma tarefa não duplica o alerta nem falha
- [ ] Arranque sem `WORM_BUCKET` ou sem `ALERT_WEBHOOK_URL` → o worker termina com erro claro (sem interruptor silencioso)

## Prova (um comando)
`cd workers-go && WORKER_DATABASE_URL=postgres://ptmarket_worker:dev_worker@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 go test ./internal/audit/... ./cmd/...` → esperado: `ok` (com `infra/scripts/dev-check.sh` verde e as variáveis `WORM_*` de dev exportadas)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Stream de auditoria (cartão 08) e publicador outbox — `cd workers-go && go test ./...` · `govulncheck ./...`
