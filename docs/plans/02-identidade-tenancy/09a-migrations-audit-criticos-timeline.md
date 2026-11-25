# 09a — Eventos críticos e índices da timeline (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 01b, 03b, 03c, 04 (numeração 0014) · **Paralelo com:** 06, 08

> **Mudou no 01b (ler antes de começar):** a caixa negra vive no schema `audit` (dono NOLOGIN). O migrator só tem USAGE + CREATE em `audit`. Qualquer migration que crie objetos em `audit` termina com `SELECT audit_admin.audit_seal();`. Uma função SECURITY DEFINER nova em `audit` só passa a selagem se a sua assinatura estiver na allowlist da `audit_seal()` em `infra/postgres/init/03-audit-bootstrap.sh`. Nenhuma função DEFINER de `audit.*` toca em objetos de papéis com LOGIN. Escrever na cadeia: só através de `audit._chain_insert`.

> **Mudou no 03b (26/11):** o migrator NÃO consegue alterar objetos selados (`ALTER TABLE audit.audit_alerts`, `CREATE INDEX` em `audit.audit_events`, `CREATE OR REPLACE audit._chain_insert`). Tudo isso vai numa **alteração aprovada** `0014_critical_timeline` no bootstrap (`audit_admin.sealed_changes`), disparada na migration por `audit_admin.audit_upgrade(nome, sha256)`; ver `infra/README.md`. Parte do `_chain_insert` atual (com `db_user`, máscara e dedupe dos cartões 03b/03c), não do texto da 0008. `critical_kind` é função nova: pode nascer na própria migration.

## Objetivo
A caixa negra sabe quais são os eventos críticos (vão para o WORM e geram alerta Telegram/Discord) e tem os índices de que a timeline do Super-Admin precisa (filtros por tenant, loja, utilizador e encomenda). Decisão do owner, 26/11/2026: um só bucket da plataforma, sem buckets das Câmaras; por isso já não existe `audit.worm_targets`.

## Pode alterar
- `migrations/0014_audit_critical_timeline.sql`, `migrations/tests/audit_critical.sql` (criar); `migrations/tests/run.sh` (só para incluir o teste); `infra/postgres/init/03-audit-bootstrap.sh` (alteração aprovada `0014_critical_timeline` + allowlist)

## Não tocar
- `migrations/0001–0013`, `backend-rust/`, `workers-go/`; nunca ler `.env`

## Contexto exato
```
audit.critical_kind(p_action text, p_outcome text, p_actor_type text) RETURNS text IMMUTABLE (NULL = não crítico). Lista fixa no corpo (mudar = migration + selagem):
  'iban_change'      ← action com prefixo stores.iban, payout_accounts., merchants.iban (qualquer outcome)
  'payment_failure'  ← prefixo payments. ou refunds. com outcome 'error', ou action payments.failed
  'invoice_failure'  ← prefixo invoices. com outcome 'error', ou action invoices.failed
  'superadmin_login' ← action auth.login com actor_type 'admin' (sucesso ou recusa)
  'verify_failure'   ← action audit.verify_failed (gravado pelo worker do cartão 09)
audit_alerts ganha a coluna kind TEXT NULL. audit._chain_insert passa a inserir em audit_alerts quando actor_type = 'admin' OU impersonator_id não nulo (export WORM, kind NULL se não for crítico) OU critical_kind(...) não nulo (kind preenchido). Nada de dados pessoais em claro no payload do alerta: o IBAN nunca, nem mascarado.
Índices novos em audit.audit_events para a timeline: (store_id, created_at), (actor_id, created_at). A encomenda filtra-se por (target_type, target_id, created_at), que já existe. Correlação de eventos de uma encomenda (pagamento, fatura, envio): a app grava target_type 'order' e target_id = id da encomenda, ou o id da encomenda em changes->>'order_id'; índice de expressão em ((changes->>'order_id'), created_at) WHERE changes ? 'order_id'.
```

## Feito quando
- [ ] `critical_kind` devolve o kind certo para cada regra e NULL para ações normais (tabela de casos no teste)
- [ ] Evento crítico (ator customer/merchant) → 1 linha em audit_alerts com kind; ação admin não crítica → linha com kind NULL; ação normal → nenhuma
- [ ] EXPLAIN das 4 consultas da timeline (tenant, loja, utilizador, encomenda; intervalo de datas, ORDER BY created_at DESC LIMIT 50) usa índice, sem Seq Scan no pai
- [ ] `audit_seal()` continua a passar; o migrator não tem privilégios nos objetos novos

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0
