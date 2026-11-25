# 02 — Funções da caixa negra para o worker: gravação assíncrona, verificação e raiz diária (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 01 · **Paralelo com:** —

## Objetivo
O worker Go consegue gravar eventos vindos do Redis Stream dentro da cadeia (sem duplicar), verificar a cadeia e obter a raiz do dia, sem nunca ter SELECT/INSERT direto em `audit_events`.

## Pode alterar
- `migrations/0009_audit_worker_functions.sql`, `migrations/tests/audit_worker.sql` (criar)

## Não tocar
- `migrations/0001–0008` — imutáveis (se `audit_append` precisar de ser refatorada para partilhar código, parar e reportar); `workers-go/`, `backend-rust/`, `infra/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §1: leituras e ações sem BD são assíncronas com entrega garantida: o evento vai para um Redis Stream, o worker grava-o em lote em audit_events DENTRO da cadeia de hash e só depois faz ACK. §3.4: job diário publica a raiz do dia em WORM; comando verify-audit recalcula a cadeia e assinala qualquer quebra.
Todas: SECURITY DEFINER, SET search_path = pg_catalog, public, dono ptmarket_audit_writer, REVOKE de PUBLIC, EXECUTE só ptmarket_worker (a app NÃO as pode chamar).
audit_append_event(p_event jsonb) RETURNS boolean  -- true = gravou, false = já existia
  p_event (contrato fixo, igual ao do Redis Stream dos cartões 07/08): {"id": uuidv7, "tenant_id": uuid|null, "store_id": uuid|null, "actor_type": "customer|merchant|municipal|admin|api_key|anonymous|system", "actor_id": uuid|null, "actor_label": text|null, "impersonator_id": uuid|null, "action": text, "target_type": text|null, "target_id": text|null, "outcome": "success|denied|error", "reason": text|null, "changes": object|null, "request_id": uuid, "ip": text|null, "user_agent_hash": hex|null, "occurred_at": RFC 3339}
  Aqui o ator vem do JSON (o pedido HTTP já acabou), não do contexto. actor_type 'db', chave desconhecida, campo obrigatório em falta ou tipo errado → RAISE SQLSTATE 'PTA02' (o worker manda para a fila morta, nunca descarta).
  Idempotência: depois do advisory lock da cadeia, se já existir linha com este id e created_at >= occurred_at - interval '1 day' → devolve false sem gravar. (A PK inclui created_at; não há UNIQUE global por id.)
  Mesma cadeia, mesmo hash e mesma regra do outbox 'audit.superadmin_action' de audit_append (0008): created_at = clock_timestamp() depois do lock; occurred_at = o do evento (> now() + 5 min ou < now() - 7 dias → PTA02).
audit_verify_chain(p_chain_key uuid, p_class text, p_from timestamptz, p_to timestamptz) RETURNS TABLE (broken_id uuid, broken_seq bigint, problem text)
  Recalcula sha256(prev_hash || linha canónica) por ordem de chain_seq; uma linha por quebra: 'hash' (hash ≠ recalculado), 'link' (prev_hash ≠ hash anterior), 'gap' (salto em chain_seq). Zero linhas = íntegra. A 1.ª linha do intervalo aceita o prev_hash gravado (âncora = raiz diária em WORM).
audit_day_root(p_day date) RETURNS TABLE (chain_key uuid, retention_class text, first_seq bigint, last_seq bigint, last_hash bytea, events bigint)  -- por cadeia, eventos com created_at nesse dia UTC
audit_chains() RETURNS TABLE (chain_key uuid, retention_class text, last_seq bigint) · audit_default_partition_rows() RETURNS bigint  -- > 0 = faltam partições mensais (o worker alerta)
Proibido: função que apague, altere ou filtre eventos; parâmetro para saltar a cadeia.
```

## Feito quando
- [ ] `audit_worker.sql`: `audit_append_event` como `ptmarket_worker` grava e encadeia; repetir o mesmo `id` devolve false sem 2.ª linha; JSON inválido ou `actor_type = 'db'` → PTA02; ator `admin` gera `audit.superadmin_action` no outbox
- [ ] `ptmarket_app` não executa nenhuma destas funções (42501); `ptmarket_worker` continua sem SELECT direto em `audit_events`
- [ ] `audit_verify_chain` devolve 0 linhas na cadeia íntegra e assinala `hash`/`link` numa cadeia adulterada (cópia para tabela de prova, ou dono com o trigger desligado numa BD descartável)
- [ ] `audit_day_root` de um dia com 3 eventos em 2 cadeias devolve 2 linhas com o `last_hash` da última linha de cada cadeia

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Cartão 01 — `audit_core.sql` (incluído no `run.sh`)
