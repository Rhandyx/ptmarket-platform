# 24a — Worker Go: `APP_ENV` obrigatório e recusa de configurações de dev em produção (épico: 02-identidade-tenancy)

**Agente:** go-integrations · **Modelo:** sonnet · **Depende de:** 09c · **Paralelo com:** 17

> Dívida das auditorias de 09b/09c/11b: hoje nada impede o worker de arrancar em produção com `ALERT_DEV_LOG_ONLY=1`, que faz os alertas críticos irem só para o log, onde ninguém os vê.

## Objetivo
O worker e o `verify-audit` só arrancam com `APP_ENV` explícito. Em `production` e `staging` recusam as válvulas de dev, com uma mensagem clara e sem imprimir segredos.

## Pode alterar
- `workers-go/internal/config/{config,config_test}.go` (criar o teste); `workers-go/cmd/worker/{main,main_test}.go`; `workers-go/cmd/verify-audit/{main,main_test}.go` (só a ligação); `workers-go/.env.example`

## Não tocar
- `internal/audit/`, `internal/outbox/`, `internal/logx/`; `backend-rust/`, `migrations/`, `infra/`. Nunca ler `.env`.

## Contexto exato
```
APP_ENV ∈ {development, test, staging, production} (exato, minúsculas). Ausente, vazio ou outro valor → erro de arranque
  "APP_ENV obrigatória: development | test | staging | production".
config.Env (tipo) + config.LoadEnv() (Env, error) + método Strict() bool (true em staging e production).
Em Strict:
  - ALERT_DEV_LOG_ONLY=1 → erro "ALERT_DEV_LOG_ONLY não é permitido com APP_ENV=<v>".
  - WORM_ENDPOINT tem de começar por https:// → senão erro (a chave do B2 não pode viajar em claro).
  - ALERT_SINK=log:// continua aceite como canal ADICIONAL (a validação "pelo menos um canal real" já existe em audit.NewChannels).
As validações ficam em config (LoadWorm/LoadAlerts recebem o Env ou há um Validate(env)); os dois binários chamam LoadEnv primeiro e saem com código ≠ 0.
A mensagem de erro nunca inclui o valor de tokens/URLs com segredo (WORM_ENDPOINT pode aparecer: não é segredo).
.env.example: APP_ENV=development, com um comentário que explica as regras de produção.
```

## Feito quando
- [ ] Testes de tabela em `config_test.go`: sem APP_ENV, `APP_ENV=prod`, `APP_ENV=Production` → erro; `production` + `ALERT_DEV_LOG_ONLY=1` → erro; `staging` + `WORM_ENDPOINT=http://…` → erro; `production` + https + Telegram → ok; `development` + `ALERT_DEV_LOG_ONLY=1` + http → ok
- [ ] Os dois binários falham ao arrancar sem `APP_ENV` (teste de subprocesso no `cmd/worker/main_test.go`, no padrão `PTM_WORKER_MAIN` que já existe)
- [ ] Os testes existentes continuam verdes (definem `APP_ENV=test` onde arrancam binários)

## Prova (um comando)
`cd workers-go && go vet ./... && go test -race ./...` → esperado: ok em todos os pacotes
