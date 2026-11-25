---
paths:
  - "workers-go/**"
---
# Go (workers-go) — specs: 03, 05, 11 §D3, 12 §3

- Um pacote por fornecedor (`payments/eupago`, `payments/stripe`, `invoicing/moloni`, `shipping/ctt`, `migration/*`, `ai/catalog`).
- Consome eventos do `outbox_events` (via publicador → Asynq); consumidores **idempotentes** pelo `id` do evento; retries exponenciais.
- Webhooks: assinatura HMAC (tempo constante) + valor/moeda + destinatário + idempotência + janela anti-replay ≤ 5 min. Falha em qualquer = estado `review` + alerta, nunca `paid`.
- Dinheiro em `int64` cêntimos; nunca `float64`.
- `context.Context` com timeout em toda a chamada externa; nada de `http.DefaultClient` sem timeout.
- Segredos só por variáveis de ambiente; nunca em logs (usar o redator de logs).
- Antes de terminar: `go test ./<pacote>/...` do pacote tocado; o hook já corre `gofmt` + `go vet`.
