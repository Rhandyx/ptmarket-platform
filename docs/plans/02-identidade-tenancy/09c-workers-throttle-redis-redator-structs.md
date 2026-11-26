# 09c — Worker Go: agrupamento de alertas persistente e sem esconder críticos, redator para structs e bytes (épico: 02-identidade-tenancy)

**Agente:** go-integrations · **Modelo:** opus · **Depende de:** 09b · **Paralelo com:** 10c

> Achados médios 1 e 4 e o residual do `reNIF`/`rePhonePT` da auditoria ASVS do 10b/09b (26/11). O `audit.Throttle` está em `internal/audit/alert.go`.

## Objetivo
O agrupamento nunca esconde um alerta da própria caixa negra nem mistura tenants, o resumo diz QUAIS eventos ficaram retidos, e nada se perde num crash ou com várias réplicas. O redator de logs não deixa passar segredos dentro de structs, `[]byte` ou `json.RawMessage`.

## Pode alterar
- `workers-go/internal/audit/{alert,superadmin}.go` + testes; `workers-go/internal/logx/{logx,logx_test}.go`; `workers-go/cmd/worker/{main,main_test}.go`; `workers-go/cmd/verify-audit/main.go` (só a ligação do Throttle, se precisar)

## Não tocar
- `internal/audit/{stream,store,root,verify,worm}.go`, `internal/outbox/`; `docs/testdata/redaction-vectors.json` (só leitura); `migrations/`, `infra/`, `backend-rust/`; nunca ler `.env`

## Contexto exato
```
1. Throttle (alert.go):
   a. Kinds com prefixo "audit." (audit.root_mismatch, audit.verify_failed, …) NUNCA são agrupados: saem sempre um a um.
   b. Chave do agrupamento = (kind, tenant_id). Alert ganha TenantID (só se tiver forma de UUID; senão "-"); o relay (superadmin.go) preenche-o a partir do evento.
   c. O resumo lista os event_id retidos (só UUIDs; até 20, depois "+N"), além da contagem, do kind e do tenant.
   d. Estado no Redis (o worker já o tem), não em memória: contagem e lista de event_id por janela com TTL (janela + margem); o envio do resumo de uma janela fechada é feito por UMA réplica (SET NX com TTL); no arranque, resumos de janelas já fechadas e não enviados saem. Redis em baixo → fail-open: o alerta sai um a um (nunca se perde um alerta por causa do agrupamento) e um log Warn.
   e. Mantém-se: 5 por (kind, tenant) em 5 min saem um a um; falha de envio não gasta lugar; nada se perde no WORM.
4. logx (logx.go:255): valor KindAny que não seja mapa/lista → struct: json.Marshal → Unmarshal em any → redactValue (chaves sensíveis mascaradas pelo nome do campo JSON); []byte e json.RawMessage → se for JSON válido, o mesmo caminho; senão Redact(string(b)); error → Redact(err.Error()). Falha de Marshal → "***".
5. reNIF / rePhonePT: apanham também um número colado a "_" ou letras (ex.: id_123456789, nif123456789). Os UUIDs continuam intactos. Mascarar a mais é aceitável.
```

## Feito quando
- [ ] Teste: 8 `iban_change` do tenant A + 1 do tenant B em 5 min → A: 5 um a um + 1 resumo com os 3 event_id; B: 1 um a um
- [ ] Teste: 10 `audit.verify_failed` seguidos → 10 alertas um a um
- [ ] Teste: duas instâncias do Throttle no mesmo Redis (simula 2 réplicas) → o resumo sai uma só vez; instância nova depois de "crash" (sem Flush) → envia o resumo pendente da janela fechada
- [ ] Teste: Redis inacessível → os alertas saem um a um, sem erro de arranque
- [ ] Teste: `slog` com `struct{Password string; Email string}`, `[]byte("iban PT50…")` e `json.RawMessage({"nif":"123456789"})` → a linha não contém nenhum dos valores; `id_123456789` mascarado; um UUID intacto
- [ ] Vetores `go` continuam verdes; `go vet ./...` limpo; `govulncheck ./...` limpo

## Prova (um comando)
`cd workers-go && WORKER_DATABASE_URL=postgres://ptmarket_worker:dev_worker@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 go test ./... -race -count=1` → `ok` (com as `WORM_*` de dev de `infra/.env.example`)

## Re-provar
- cartões 08, 08b, 09, 09b — o mesmo `go test ./... -race`
