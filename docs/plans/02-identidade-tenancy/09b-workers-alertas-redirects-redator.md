# 09b — Worker Go: alertas sem dados pessoais nem markdown, sem redirects, `log://` só em dev e redator alinhado (épico: 02-identidade-tenancy)

**Agente:** go-integrations · **Modelo:** opus · **Depende de:** 09, 03e (ficheiro de vetores) · **Paralelo com:** 10b, 11b

> Achados 4, 10, 11 e 13 da auditoria ASVS da onda 4 (linhas do commit 154c897).

## Objetivo
O resumo de um alerta nunca leva um e-mail nem um link disfarçado para o Telegram/Discord. Os clientes HTTP do worker nunca seguem redirects. O worker não arranca em produção só com alertas para o log. O redator de logs passa nos mesmos vetores que a BD e o Rust.

## Pode alterar
- `workers-go/internal/audit/{superadmin,alert,worm}.go` + testes; `workers-go/internal/logx/{logx,logx_test}.go`; `workers-go/internal/config/config.go`; `workers-go/cmd/worker/{main,main_test}.go`; `workers-go/.env.example`

## Não tocar
- `workers-go/internal/audit/{stream,store,root,verify}.go`, `internal/outbox/` — aprovados; `docs/testdata/redaction-vectors.json` (só leitura: se um vetor parecer errado, parar e reportar); `migrations/`, `infra/`, `backend-rust/`; nunca ler `.env`

## Contexto exato
```
4. superadmin.go:187 (relayOne) monta o resumo com f.ActorID e f.TargetID em claro. target_id é texto livre na caixa negra (pode ser um e-mail) e o Discord renderiza markdown ([texto](url) = link mascarado).
   → ActorID e TargetID só entram se tiverem forma de UUID (8-4-4-4-12 hex); senão "-". ActorType, Action e TargetType só se casarem ^[a-z0-9_.:-]{1,64}$; senão "-". Regra do cartão 09 que se mantém: sem dados pessoais (só ator-id, ação, alvo, hora); o IBAN nunca, nem mascarado.
   → Discord (alert.go, Send): o texto vai dentro de um bloco de código, com os acentos graves do conteúdo substituídos antes; manter allowed_mentions vazio e respeitar o limite de 2000 caracteres. Telegram continua texto simples, sem parse_mode. O LogSink recebe o mesmo resumo já limpo.
10. worm.go:76 e :106 e alert.go:76 criam http.Client sem CheckRedirect: um 3xx do destino leva o pedido (corpo do alerta, cabeçalhos assinados do S3) para outro host.
   → Em todos os clientes criados pelo worker, CheckRedirect devolve http.ErrUseLastResponse. Um 3xx conta como falha ("<canal>: HTTP 3xx"); o Location nunca vai para o log nem para a mensagem de erro. Clientes injetados nos testes ficam como estão.
11. alert.go NewChannels: ALERT_SINK=log:// sozinho satisfaz "pelo menos um canal", também em produção (alertas críticos só no log = ninguém é avisado).
   → log:// como ÚNICO canal só é aceite com ALERT_DEV_LOG_ONLY=1 (lida em internal/config); sem ela, erro de arranque com mensagem clara. Com Telegram ou Discord configurado, log:// continua aceite como canal extra. Arranque em modo só-log: um log Warn fixo. Atualizar .env.example (comentário: nunca em produção) e os casos de main_test.go que usam ALERT_SINK=log://.
13. logx.Redact e isSensitiveKey têm cobertura diferente da BD. → logx_test.go lê ../../../docs/testdata/redaction-vectors.json e corre os vetores com "go" em layers. kind "text": Redact(input) não contém nenhuma das must_not_contain; must_equal_input → saída igual à entrada. kind "json": cada par chave/valor passa pelo redator de atributos do slog (o handler de New()); mesma verificação sobre a linha de log produzida.
   → Corrigir o redator até passarem: e-mail, telefone PT/E.164, NIF, PAN com Luhn (maskPAN já existe), IBAN em qualquer caixa e com espaço(s), NBSP, "-" e ".", NIB de 21 dígitos; chaves normalizadas (camelCase → snake_case, minúsculas): tax_id, vat_id, national_id, vat_number, mobile, phone, email, nib, account_number, card_pan. Mascarar a mais é aceitável; deixar passar não. A máscara de Go continua "***".
```

## Feito quando
- [ ] Teste: alerta com `target_id` = `joao@x.pt` e com `[clique](http://evil)` → o corpo recebido pelos servidores HTTP de teste (Telegram e Discord) não contém o e-mail nem o link; com UUID → contém o UUID; o Discord recebe o texto num bloco de código
- [ ] Teste: servidor de teste que responde 302 para um segundo servidor → o segundo recebe 0 pedidos (alertas e WORM) e a chamada devolve erro sem o URL
- [ ] Teste: `ALERT_SINK=log://` sozinho → erro de arranque; com `ALERT_DEV_LOG_ONLY=1` → arranca; com Discord + `log://` → arranca sem a variável
- [ ] Teste (decisão do supervisor 26/11: INSERT de loja com IBAN também é iban_change, por isso o onboarding em massa não pode inundar os canais): mais de 5 alertas do mesmo kind em 5 min → só os 5 primeiros saem um a um e o resto sai num único resumo com a contagem no fim da janela; nada se perde no WORM
- [ ] Teste dos vetores verde (todos os de layers `go`); `go vet ./...` limpo; context com timeout em todas as chamadas externas mantido

## Prova (um comando)
`cd workers-go && WORKER_DATABASE_URL=postgres://ptmarket_worker:dev_worker@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 go test ./... -race` → esperado: `ok` (com as variáveis `WORM_*` de dev exportadas)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Raiz diária, `verify-audit`, relay de alertas e stream (cartões 08, 08b, 09) — o mesmo `go test ./... -race` · `govulncheck ./...`
