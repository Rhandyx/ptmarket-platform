# 08b — Worker Go: endurecer o escritor do Redis Stream (achados da auditoria ASVS, 26/11) (épico: 02-identidade-tenancy)

**Agente:** go-integrations · **Modelo:** opus · **Depende de:** 08 · **Paralelo com:** 03b, 03c, 06 · **Antes de:** 09

## Objetivo
O escritor nunca bloqueia as cadeias dos tenants, não entra em deadlock nem fica preso num lote, e não põe dados pessoais nos logs.

## Pode alterar
- `workers-go/internal/audit/{stream,store}.go` + testes; `workers-go/cmd/worker/main.go`

## Não tocar
- `migrations/`, `backend-rust/`, `infra/`; nunca ler `.env`

## Contexto exato
```
Achados (ficheiro:linha do commit 28cfa6e):
- stream.go:203,245 — pe.Msg (SQLERRM) vai para o log e para o campo error da fila morta; os erros de conversão citam
  o valor (PII). → gravar só SQLSTATE + chave/campo, nunca a mensagem do Postgres nem o payload.
- stream.go:119-137, store.go:56-110 — um lote de vários tenants segura FOR UPDATE nas cabeças de cadeia até ao COMMIT:
  o audit_append das transações de negócio (lock_timeout 2 s) falha com 55P03; dois workers com ordens diferentes →
  40P01. → ordenar o lote por (chain_key = COALESCE(tenant_id, uuid zero), classe), lotes curtos (tempo máximo do
  lote ≤ 1 s) e, em 55P03/40P01, repetir com backoff exponencial com jitter.
- stream.go — um erro não classificado como veneno reentrega o lote para sempre (cabeça de linha). → contador de
  entregas (XPENDING/XCLAIM delivery count): ao fim de 5 tentativas a mensagem vai para a fila morta.
- SQLSTATE 'PTA03' (cartão 03c: id repetido com conteúdo diferente) = veneno.
- Fila morta: XADD com MAXLEN ~ 100000. Contador `dead` exposto para o cartão 09 ligar ao alerta Telegram/Discord
  (aqui: log Error estruturado, sem payload).
- cmd/worker/main.go — log.Error("REDIS_URL inválido", "err", err.Error()) pode conter a password do URL → mensagem fixa.
```

## Feito quando
- [ ] Teste: um lote com eventos de 3 tenants por ordem aleatória → escritos por ordem de (chain_key, classe); dois escritores em paralelo sobre os mesmos tenants → sem 40P01 em 100 rondas
- [ ] Teste: erro transitório repetido → fila morta ao fim de 5 entregas; o lote seguinte avança
- [ ] Teste: evento com uuid inválido → a entrada na fila morta e o log não contêm o valor (grep pelo valor nos logs capturados = 0)
- [ ] `go vet ./...` limpo

## Prova (um comando)
`cd workers-go && go test ./... -race` → verde

## Fora de âmbito (dívida para o épico de infra/produção)
- Redis com ACL (app só XADD; worker só XREADGROUP/XACK/XDEL), TLS e HMAC por mensagem verificado no worker.
