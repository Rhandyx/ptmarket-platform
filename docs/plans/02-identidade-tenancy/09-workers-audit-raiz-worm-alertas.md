# 09 — Worker Go: raiz diária em WORM, `verify-audit` e alerta de ações superadmin (épico: 02-identidade-tenancy)

**Agente:** go-integrations · **Modelo:** opus · **Depende de:** 01b, 05, 08, 09a · **Paralelo com:** 04, 06

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
Destinos (owner 25/11): cada tenant com linha em audit.worm_targets (cartão 09a) tem a sua raiz diária (manifesto só com as cadeias desse tenant) e os seus alertas superadmin gravados NO BUCKET DA CÂMARA, com as credenciais da plataforma (a bucket policy da Câmara autoriza o nosso principal IAM; não há segredos por tenant). Os eventos de plataforma (tenant NULL) e os tenants sem linha em worm_targets (comércio direto, dev, demo) vão para o bucket da plataforma (WORM_*). Retenção por objeto: raízes roots_retention_days (default 3650), detalhes details_retention_days (default 730); na plataforma, WORM_ROOTS_RETENTION_DAYS=3650 e WORM_DETAILS_RETENTION_DAYS=730. Se o bucket de uma Câmara falhar, não há fallback para o nosso (seria guardar dados dela): repete e, ao fim de 15 min, alerta 'audit.worm_target_down'.
WORM: interface WormStore { Put(ctx, key, body, retainUntil) error; Get(ctx, key) ([]byte, error) } + implementação S3 compatível (Object Lock modo COMPLIANCE). Config: WORM_ENDPOINT, WORM_REGION, WORM_BUCKET, WORM_ACCESS_KEY, WORM_SECRET_KEY, WORM_RETENTION_DAYS (default 3650). Dev: bucket `ptmarket-audit-worm` do cartão 05. Produção (decisão do owner 25/11; custo em docs/CUSTOS.md): S3 Object Lock COMPLIANCE numa conta AWS separada da Cloudflare; os bucket locks do R2 podem ser removidos pelo admin da conta, por isso não chegam. O código só fala S3, logo serve para os dois.
Raiz diária (tarefa periódica Asynq, 00:10 UTC, do dia anterior; TaskID = 'audit-root-YYYY-MM-DD'): manifesto JSON {"day", "generated_at", "chains": [{chain_key, retention_class, first_seq, last_seq, last_hash hex, events}], "prev_manifest_sha256"} → Put roots/YYYY/MM/DD.json. Já existe → comparar; igual = ok, diferente = ALERTA e erro (nunca sobrescrever). Dias em falta são recuperados por ordem.
  No mesmo job: audit_ensure_partitions(3); audit_default_partition_rows() > 0 → alerta.
verify-audit (binário próprio; código de saída ≠ 0 se houver quebra): por cada cadeia chama audit_verify_chain em janelas de 1 dia e confirma que o last_hash de cada dia bate com o manifesto no WORM; imprime as quebras (id, seq, problema), nunca o conteúdo dos eventos.
Superadmin (mudou no 01b: o sinal deixou de passar pelo outbox): relay que lê `audit.audit_alerts WHERE published_at IS NULL ORDER BY created_at` (FOR UPDATE SKIP LOCKED, lotes de 100, a cada 30 s e no arranque) → Put superadmin/YYYY/MM/DD/<id>.json com o payload (idempotente: se já existe, compara) → Alerter.Notify → UPDATE published_at. Falha de qualquer passo → a linha fica por publicar e volta na ronda seguinte; se tiver mais de 15 min sem publicar → alerta 'audit.alert_backlog'. O worker não consegue apagar nem alterar alertas (só o published_at de NULL para um valor).
Alerter: interface { Notify(ctx, Alert{Kind, Summary, EventID}) error }; implementação webhook HTTP POST JSON para ALERT_WEBHOOK_URL (timeout 5 s, cliente próprio, sem dados pessoais: só ator-id, ação, alvo, hora). O worker NÃO arranca sem WORM_* e sem ALERT_WEBHOOK_URL; em dev aceita ALERT_WEBHOOK_URL=log:// (escreve no log). Canais (owner 25/11): email (SMTP), Telegram (bot) e Discord (webhook); o Alerter envia para TODOS os configurados (fan-out, um por ação de superadmin) e o worker não arranca sem pelo menos um. Config: ALERT_EMAIL_*, ALERT_TELEGRAM_*, ALERT_DISCORD_WEBHOOK_URL. WhatsApp fica para depois (exige API Business). Em dev, log://.
Regras Go: context com timeout em toda a chamada externa; segredos só por ambiente e nunca em logs; cliente S3 = dependência nova, justificar no PR (preferir a mais pequena com Object Lock).
```

## Feito quando
- [ ] Teste da raiz (PG + WORM reais): manifesto do dia gravado com retenção; 2.ª execução é idempotente; manifesto divergente → erro + alerta, objeto intacto
- [ ] `verify-audit` sai 0 com a cadeia íntegra e ≠ 0 quando o manifesto do WORM não bate com a BD (simular trocando o manifesto de um bucket de teste)
- [ ] Evento `audit.superadmin_action` → objeto no WORM + 1 alerta (servidor HTTP de teste); reentrega da mesma tarefa não duplica o alerta nem falha
- [ ] Dois tenants, um com destino próprio (2.º bucket de teste) e outro sem: cada manifesto e alerta vai para o bucket certo, e o manifesto da Câmara só contém as cadeias dela
- [ ] Arranque sem `WORM_BUCKET` ou sem `ALERT_WEBHOOK_URL` → o worker termina com erro claro (sem interruptor silencioso)

## Prova (um comando)
`cd workers-go && WORKER_DATABASE_URL=postgres://ptmarket_worker:dev_worker@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 go test ./internal/audit/... ./cmd/...` → esperado: `ok` (com `infra/scripts/dev-check.sh` verde e as variáveis `WORM_*` de dev exportadas)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Stream de auditoria (cartão 08) e publicador outbox — `cd workers-go && go test ./...` · `govulncheck ./...`
