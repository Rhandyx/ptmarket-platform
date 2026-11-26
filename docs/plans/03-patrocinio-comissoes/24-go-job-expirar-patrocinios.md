# 24 — Go: job de higiene `active` → `expired` dos patrocínios (épico: 03-patrocinio-comissoes)

**Agente:** go-integrations · **Modelo:** sonnet · **Depende de:** 06, 11 (BD fechada) · **Paralelo com:** 13–23 (Rust) e 26 (frontend); em série com o 25 (o mesmo `cmd/worker/main.go`)

## Objetivo
De hora a hora o worker marca como `expired` os patrocínios `active` cuja vigência já acabou. É só higiene: nenhum cálculo depende deste job.

## Pode alterar
- `workers-go/internal/sponsorship/{expire.go,expire_test.go}` (criar); `workers-go/cmd/worker/main.go` (registar a tarefa e o agendamento); `workers-go/internal/config/config.go` (só se precisar do intervalo)

## Não tocar
- `workers-go/internal/audit/**` (aprovado: só se usa `audit.SetSystemActor`), `internal/outbox/**`; `migrations/`, `backend-rust/`. Nunca ler `.env`.

## Contexto exato (spec 14 §2, §9 + cartão 06)
```
"Ativo" no cálculo = status = 'active' AND now() <@ tstzrange(valid_from, valid_to). O job que passa a expired é só higiene: o cálculo nunca depende dele. Evento: sponsorship.expired.
BD: o papel do worker (ptmarket_worker) só vê e só altera linhas com status = 'active' AND valid_to <= now(), e só para status = 'expired' (policies + GRANT SELECT, UPDATE (status, updated_at)). A BD recusa qualquer outra transição.
Em cada execução, por lotes de 500 até não haver mais (máximo 20 lotes), cada lote numa transação:
  1. audit.SetSystemActor(ctx, tx, "sponsorship_expire") — ator de sistema na caixa negra, antes de qualquer escrita
  2. UPDATE store_sponsorships SET status = 'expired', updated_at = now() WHERE id IN (SELECT id FROM store_sponsorships WHERE status = 'active' AND valid_to <= now() ORDER BY valid_to LIMIT 500 FOR UPDATE SKIP LOCKED) RETURNING id, tenant_id, store_id, sponsor_entity_id
A caixa negra L1 grava cada linha ('store_sponsorships.update', ator de sistema). Evento nomeado 'sponsorship.expired': confirmar em internal/audit/store.go e na 0009 se o worker tem uma função para gravar eventos nomeados; se tiver, gravar um por linha na mesma transação; se não tiver, NÃO inventar SQL sobre audit.*: ficar pela L1 e dizê-lo no relatório.
Agendamento: seguir o padrão já usado em cmd/worker/main.go para a tarefa periódica das raízes (audit.RootTaskType); tarefa "sponsorship:expire", de hora a hora, única (sem execuções sobrepostas), numa fila existente.
Idempotente: correr duas vezes seguidas não muda nada na 2.ª. Erro num lote → rollback desse lote, log estruturado (logx) sem dados pessoais, e a tarefa falha para o asynq repetir. Contexto com timeout; sem goroutines soltas. Sem dinheiro neste job: não toca em comissões nem em valores.
```

## Feito quando
- [ ] `expire_test` (BD real de teste, como os testes de `internal/audit`): um `active` vencido passa a `expired`; um `active` vigente, um `active` sem fim (`valid_to` NULL), um `pending` e um `revoked` ficam iguais
- [ ] **Co-patrocínio:** loja com Câmara vencida e Junta vigente → só o da Câmara expira; o da Junta continua `active`
- [ ] 1.200 linhas vencidas → todas expiram em 3 lotes; segunda execução → 0 linhas; duas execuções em paralelo não dão erro (`SKIP LOCKED`)
- [ ] O evento da caixa negra tem ator de sistema com o nome do job; o relatório diz se o evento nomeado `sponsorship.expired` foi gravado ou se ficou só a L1

## Prova (um comando)
`cd workers-go && go test -race ./...` → esperado: `ok` em todos os pacotes

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Worker (stream de auditoria, raízes, alertas, arranque) — o mesmo comando cobre `internal/audit` e `cmd/worker`
