# 06 — BD: `store_sponsorships` (5 estados, EXCLUDE só em `active`) (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 03, 05 · **Paralelo com:** —

## Objetivo
Existe a relação N:N loja ↔ entidade com estado e vigência, sem dois períodos ativos sobrepostos para o mesmo par, com as transições trancadas na BD e a app sem poder mexer no `commission_override_bps`.

## Pode alterar
- `migrations/0031_store_sponsorships.sql`, `migrations/tests/store_sponsorships.sql` (criar)

## Não tocar
- `migrations/0001–0030`; `portal_stores` e policies `portal_*` (cartão 08); `audit.*` (kinds críticos: cartão 11). Nunca ler `.env`.

## Contexto exato (spec 14 §2, §3)
```
Estados: pending (pedido do lojista ou convite da entidade), active, rejected, expired, revoked. "Ativo" no cálculo = status = 'active' AND now() <@ tstzrange(valid_from, valid_to); o job que passa a expired é só higiene. Uma loja pode ter 0, 1, 2 ou mais patrocínios ativos em simultâneo (ex.: Câmara + Junta), com vigências independentes.
CREATE EXTENSION IF NOT EXISTS btree_gist;   -- se o migrator não a puder criar: PARAR e reportar (passa para o bootstrap)
CREATE TABLE store_sponsorships (id UUID PRIMARY KEY DEFAULT uuidv7(), tenant_id UUID NOT NULL, store_id UUID NOT NULL, sponsor_entity_id UUID NOT NULL REFERENCES sponsor_entities (id) ON DELETE RESTRICT,
    status VARCHAR(12) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','rejected','expired','revoked')), initiated_by VARCHAR(8) NOT NULL DEFAULT 'store' CHECK (initiated_by IN ('store','sponsor')),
    valid_from TIMESTAMPTZ, valid_to TIMESTAMPTZ /* NULL = sem fim */, commission_override_bps INT NOT NULL DEFAULT 0 CHECK (commission_override_bps BETWEEN 0 AND 10000),
    requested_by UUID REFERENCES users (id), decided_by UUID REFERENCES users (id), decided_at TIMESTAMPTZ, decision_reason VARCHAR(500), created_at/updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, store_id) REFERENCES stores (tenant_id, id) ON UPDATE CASCADE ON DELETE CASCADE, CHECK (valid_to IS NULL OR valid_from < valid_to), CHECK (status IN ('pending','rejected') OR valid_from IS NOT NULL),
    EXCLUDE USING gist (store_id WITH =, sponsor_entity_id WITH =, tstzrange(valid_from, valid_to) WITH &&) WHERE (status = 'active'));
UNIQUE INDEX (store_id, sponsor_entity_id) WHERE status = 'pending'; índices (sponsor_entity_id, status) e (tenant_id, store_id).
Trigger BEFORE INSERT/UPDATE (INVOKER, search_path = pg_catalog, pg_temp): INSERT só nasce 'pending'; transições permitidas: pending → active | rejected; active → revoked | expired; mais nenhuma. tenant_id, store_id, sponsor_entity_id e initiated_by são imutáveis; commission_override_bps só muda em pending. Em revoked: valid_to = LEAST(COALESCE(valid_to, now()), now()). O país da entidade tem de ser o do tenant da loja.
RLS ENABLE + FORCE. ptmarket_app: tenant_isolation (mesmo texto da de stores); GRANT SELECT; INSERT (id, tenant_id, store_id, sponsor_entity_id, initiated_by, requested_by); UPDATE (status, valid_from, valid_to, decided_by, decided_at, decision_reason, updated_at). Sem DELETE. A app NÃO recebe commission_override_bps (dinheiro: fica 0 até decisão do owner).
ptmarket_worker (cartão 24): policies SELECT/UPDATE USING (status = 'active' AND valid_to <= now()) WITH CHECK (status = 'expired'); GRANT SELECT, UPDATE (status, updated_at). Bloco L1 condicional (0018, linhas 77–98). Nunca SET ROLE para papéis sem acesso a audit.
```

## Feito quando
- [ ] Teste `store_sponsorships`, **co-patrocínio**: a mesma loja com Câmara e Junta ativas ao mesmo tempo passa; o mesmo par com dois `active` sobrepostos → 23P01; períodos consecutivos passam; `pending`/`expired`/`revoked` sobrepostos com um `active` passam
- [ ] Transições proibidas falham (`rejected → active`, `expired → active`, INSERT já `active`); mudar `store_id` falha
- [ ] Como `ptmarket_app`: outro tenant não vê nem escreve; INSERT/UPDATE de `commission_override_bps` e DELETE → 42501
- [ ] Como `ptmarket_worker`: só consegue `active` vencido → `expired`; um `active` vigente ou um `pending` não se alteram (0 linhas)

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `store_sponsorships` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `stores_national_channel`, `sponsor_entities`, `audit_l1` — incluídos no `run.sh`
