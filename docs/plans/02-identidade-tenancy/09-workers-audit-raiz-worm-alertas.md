# 09 — Worker Go: raiz diária em WORM, `verify-audit` e alerta de ações superadmin (épico: 02-identidade-tenancy)

**Agente:** go-integrations · **Modelo:** opus · **Depende de:** 01b, 03b, 03c, 05, 08, 08b, 09a · **Paralelo com:** 04, 06

## Objetivo
A cadeia fica ancorada fora da BD todos os dias, há um comando que deteta adulteração, e cada ação de superadmin vai para WORM em minutos e gera alerta ao owner.

## Pode alterar
- `workers-go/internal/audit/{root,verify,superadmin,worm,alert}.go` + testes, `workers-go/cmd/verify-audit/main.go` (criar); `workers-go/cmd/worker/main.go`, `internal/config/config.go`, `go.mod`/`go.sum` (editar)

## Não tocar
- `workers-go/internal/audit/stream.go`, `internal/outbox/` — aprovados; `migrations/`, `infra/` (só leitura), `backend-rust/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §3.4: um job diário publica a raiz do dia num armazenamento WORM externo (R2/S3 Object Lock); um comando verify-audit recalcula a cadeia e assinala qualquer quebra.
Spec 13 §1 (owner 26/11): as ações de superadmin e os eventos críticos vão para o WORM quase em tempo real (minutos); alertas imediatos Telegram/Discord SÓ para eventos críticos (mudança de IBAN, falhas de pagamento/faturação, login de superadmin, falha do verify-audit). Não existe forma de desligar.
BD (papel ptmarket_worker): audit_day_root(p_day date) → (chain_key, retention_class, first_seq, last_seq, last_hash bytea, events) · audit_chains() → (chain_key, retention_class, last_seq) · audit_verify_chain(chain_key, class, from, to) → (broken_id, broken_seq, problem) · audit_ensure_partitions(3) · audit_default_partition_rows() → bigint.
Destino (owner 26/11): UM só bucket da plataforma para todos os tenants, com prefixo por tenant: t/<tenant_id|platform>/roots/YYYY/MM/DD.json e t/<tenant_id|platform>/events/YYYY/MM/DD/<id>.json (manifesto por tenant, só com as cadeias desse tenant). Sem buckets das Câmaras; override externo = futuro, fora deste cartão.
WORM: interface WormStore { Put(ctx, key, body, retainUntil) error; Get(ctx, key) ([]byte, error) } + implementação S3 compatível (Backblaze B2 com Object Lock em modo GOVERNANCE, nunca COMPLIANCE; a chave da app só tem PutObject/GetObject, sem Delete nem bypass). Config: WORM_ENDPOINT, WORM_REGION, WORM_BUCKET, WORM_ACCESS_KEY, WORM_SECRET_KEY, WORM_ROOTS_RETENTION_DAYS (default 3650), WORM_EVENTS_RETENTION_DAYS (default 730). Dev: bucket `ptmarket-audit-worm` do cartão 05. pgaudit NÃO vai para o WORM.
Raiz diária (tarefa periódica Asynq, 00:10 UTC, do dia anterior; TaskID = 'audit-root-YYYY-MM-DD'): manifesto JSON {"day", "generated_at", "chains": [{chain_key, retention_class, first_seq, last_seq, last_hash hex, events}], "prev_manifest_sha256"} → Put roots/YYYY/MM/DD.json. Já existe → comparar; igual = ok, diferente = ALERTA e erro (nunca sobrescrever). Dias em falta são recuperados por ordem.
  No mesmo job: audit_ensure_partitions(3); audit_default_partition_rows() > 0 → alerta.
verify-audit (binário próprio; código de saída ≠ 0 se houver quebra): por cada cadeia chama audit_verify_chain em janelas de 1 dia e confirma que o last_hash de cada dia bate com o manifesto no WORM; imprime as quebras (id, seq, problema), nunca o conteúdo dos eventos. Por cada cadeia/janela chama também audit.audit_verify_actors(chain_key, class, from, to) (cartão 03b: ator incoerente com o papel LOGIN = forja) e, uma vez por execução, audit.audit_guc_defaults() se o cartão 03c a criou (linhas = default de app.* na BD/papel). Qualquer linha = falha do verify (alerta crítico). Contador `dead` da fila morta do stream (cartão 08b) > 0 → alerta crítico 'audit.stream_dead_letter'. Varredura periódica (a cada 60 s) dos resumos de 429 das janelas já fechadas (cartão 07: a API só os publica quando chega o próximo pedido; o worker garante-os mesmo que a instância morra): mesma chave Redis e o mesmo script Lua do 07, idempotente.
Relay (o sinal vem da caixa negra, não do outbox): lê `audit.audit_alerts WHERE published_at IS NULL ORDER BY created_at` (FOR UPDATE SKIP LOCKED, lotes de 100, a cada 30 s e no arranque) → Put events/… (idempotente: se já existe, compara) → se `kind` estiver na lista de críticos (cartão 09a) → Alerter.Notify → UPDATE published_at. Falha de qualquer passo → a linha fica por publicar e volta na ronda seguinte; mais de 15 min sem publicar → alerta 'audit.alert_backlog'. O worker não apaga nem altera alertas (só published_at de NULL para um valor). Falha do verify-audit → alerta crítico direto.
Alerter: interface { Notify(ctx, Alert{Kind, Summary, EventID}) error }; implementações Telegram (bot API) e Discord (webhook), fan-out para os configurados (timeout 5 s, cliente próprio, sem dados pessoais: só ator-id, ação, alvo, hora; IBAN nunca, nem mascarado). O worker não arranca sem pelo menos um canal. Config: ALERT_TELEGRAM_BOT_TOKEN, ALERT_TELEGRAM_CHAT_ID, ALERT_DISCORD_WEBHOOK_URL. Em dev aceita ALERT_SINK=log://.
Regras Go: context com timeout em toda a chamada externa; segredos só por ambiente e nunca em logs; cliente S3 = dependência nova, justificar no PR (preferir a mais pequena com Object Lock).
```

## Feito quando
- [ ] Teste da raiz (PG + WORM reais): manifesto do dia gravado com retenção; 2.ª execução é idempotente; manifesto divergente → erro + alerta, objeto intacto
- [ ] `verify-audit` sai 0 com a cadeia íntegra e ≠ 0 quando o manifesto do WORM não bate com a BD (simular trocando o manifesto de um bucket de teste)
- [ ] Linha em audit_alerts → objeto em t/<tenant>/events/… + 1 alerta (servidores HTTP de teste para Telegram e Discord) só se `kind` for crítico; ação de superadmin não crítica → só WORM; reentrega não duplica o alerta nem falha
- [ ] Dois tenants: cada manifesto fica no prefixo do seu tenant e só contém as cadeias dele; a chave de teste com só Put/Get não consegue apagar nem encurtar a retenção
- [ ] Arranque sem `WORM_BUCKET` ou sem nenhum canal de alerta → o worker termina com erro claro (sem interruptor silencioso)

## Prova (um comando)
`cd workers-go && WORKER_DATABASE_URL=postgres://ptmarket_worker:dev_worker@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 go test ./internal/audit/... ./cmd/...` → esperado: `ok` (com `infra/scripts/dev-check.sh` verde e as variáveis `WORM_*` de dev exportadas)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Stream de auditoria (cartão 08) e publicador outbox — `cd workers-go && go test ./...` · `govulncheck ./...`
