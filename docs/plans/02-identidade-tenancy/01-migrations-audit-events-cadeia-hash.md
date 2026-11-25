# 01 — `audit_events` particionada, só de acréscimo, com cadeia de hash (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** — · **Paralelo com:** 05, 15

## Objetivo
Existe a tabela única da caixa negra: particionada, escrita só por função `SECURITY DEFINER`, imutável e encadeada por hash. Ainda sem triggers nas outras tabelas (cartão 03).

## Pode alterar
- `migrations/0008_audit_events.sql`, `migrations/tests/audit_core.sql` (criar)

## Não tocar
- `migrations/0001–0007` — imutáveis; `migrations/tests/{rls,omnibus}.sql`, `run.sh` — cartão 03; `infra/`, `backend-rust/`, `workers-go/`, `frontend-web/`

## Contexto exato (colado da spec; não ler a spec)
```
Papéis (padrão de 0007: NOLOGIN, sem SUPERUSER/BYPASSRLS, GRANT ao migrator WITH INHERIT FALSE, SET TRUE; USAGE em public): ptmarket_audit_writer = dono das funções DEFINER, só INSERT + SELECT em audit_events e INSERT em outbox_events · ptmarket_audit_retention = criado SEM privilégios (retenção = decisão do owner).
audit_events(id UUID NOT NULL, tenant_id UUID /*NULL = plataforma; sem FK*/, chain_key UUID NOT NULL /*COALESCE(tenant_id, uuid zero)*/, store_id UUID, actor_type VARCHAR(16) NOT NULL CHECK IN ('customer','merchant','municipal','admin','system','api_key','db','anonymous'), actor_id UUID, actor_label TEXT /*'db': papel/session_user; 'system': job*/, impersonator_id UUID, action VARCHAR(96) NOT NULL, target_type VARCHAR(64), target_id TEXT, outcome VARCHAR(8) NOT NULL CHECK IN ('success','denied','error'), reason TEXT, changes JSONB,
  request_id UUID, ip INET, user_agent_hash BYTEA, retention_class VARCHAR(8) NOT NULL CHECK IN ('fiscal','standard','security'), occurred_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL, chain_seq BIGINT NOT NULL, prev_hash BYTEA NOT NULL, hash BYTEA NOT NULL, PRIMARY KEY (retention_class, created_at, id))
  PARTITION BY LIST (retention_class) → 3 filhas, cada uma PARTITION BY RANGE (created_at) mensal `audit_events_<classe>_yYYYYmMM` + 1 DEFAULT por classe (um INSERT nunca falha por falta de partição). Porquê: a retenção faz-se por DROP de partição e os prazos diferem (default 10 anos fiscal / 2 standard / 1 security) → uma cadeia por (chain_key, retention_class), para o DROP não partir cadeias. Índices: (tenant_id, created_at) · (target_type, target_id, created_at) · (chain_key, chain_seq DESC) · (id).
audit_retention_class(p_action text, p_outcome text) IMMUTABLE: 'denied' → 'security'; action com prefixo orders. sub_orders. sub_order_items. payments. refunds. payouts. invoices. loyalty_ledger. product_price_history. product_variants. order. payment. refund. payout. invoice. price. → 'fiscal'; resto → 'standard'.
audit_ensure_partitions(p_months_ahead int): cria (IF NOT EXISTS) o mês corrente + N nas 3 classes; a migration chama-a com 3. DEFINER, dono = dono da tabela; EXECUTE só ptmarket_worker.
audit_append(p_action text, p_target_type text, p_target_id text, p_outcome text, p_reason text, p_changes jsonb, p_store_id uuid, p_tenant_id uuid DEFAULT NULL) RETURNS uuid — SECURITY DEFINER, SET search_path = pg_catalog, public, dono ptmarket_audit_writer; EXECUTE: REVOKE de PUBLIC, GRANT a ptmarket_app, ptmarket_worker, ptmarket_price_writer.
  Ator SÓ do contexto, nunca por parâmetro: app.actor_type (vazio → RAISE SQLSTATE 'PTA01'), app.actor_id, app.actor_label, app.impersonator_id, app.request_id, app.ip, app.user_agent_hash (hex). Tenant = app.current_tenant_id; se vazio usa p_tenant_id; se ambos existem e diferem → RAISE.
  Cadeia: pg_advisory_xact_lock(hashtextextended('audit:'||chain_key||':'||classe, 0)) → created_at := clock_timestamp() (depois do lock) → último (chain_seq, hash) da cadeia (procurar primeiro nos 2 meses mais recentes) → chain_seq + 1. Génese: seq 1, prev_hash = 32 bytes a zero. id = uuidv7(); occurred_at = created_at.
  hash = sha256(prev_hash || convert_to(jsonb_build_array(id, tenant_id, store_id, actor_type, actor_id, actor_label, impersonator_id, action, target_type, target_id, outcome, reason, changes, request_id, host(ip), encode(user_agent_hash,'hex'), retention_class, epoch µs de occurred_at, epoch µs de created_at, chain_seq)::text, 'UTF8')).
  Se actor_type = 'admin' OU impersonator_id não nulo: na mesma transação INSERT em outbox_events (tenant_id NULL, aggregate 'audit', aggregate_id = id, event_type 'audit.superadmin_action', payload = a linha em JSON, hashes em hex). Policy nova em outbox_events: FOR INSERT TO ptmarket_audit_writer WITH CHECK (aggregate = 'audit').
Imutável: REVOKE UPDATE, DELETE, TRUNCATE de todos (dono incluído) + trigger BEFORE UPDATE OR DELETE (linha) e BEFORE TRUNCATE (pai e cada partição, também as criadas por audit_ensure_partitions) que faz sempre RAISE. Não existe GUC, coluna nem função para desligar.
RLS ENABLE + FORCE: INSERT WITH CHECK (true) e SELECT USING (true) TO ptmarket_audit_writer; tenant_read FOR SELECT TO ptmarket_app USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) + GRANT SELECT. Leitura global do admin = épico admin. `changes` chega já mascarado (cartões 03/06). Rollback mental no topo.
```

## Feito quando
- [ ] `audit_core.sql` (sempre com `SET ROLE`): sem `app.actor_type` → PTA01; com ator grava e encadeia (`chain_seq`, `prev_hash`); tenants e classes diferentes têm cadeias independentes; recalcular o hash em SQL dá o valor gravado
- [ ] INSERT direto, UPDATE, DELETE e TRUNCATE falham para `ptmarket_app`, `ptmarket_worker` e para o dono; tenant A não lê eventos de B (anti-IDOR); app sem contexto lê 0 linhas
- [ ] Ator `admin` deixa 1 linha `audit.superadmin_action` no outbox; data fora das partições mensais cai na DEFAULT; `audit_ensure_partitions(3)` é idempotente

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- RLS base e Omnibus (0002–0007) — incluídos em `migrations/tests/run.sh`; outbox Go — `cd workers-go && go test ./...`
