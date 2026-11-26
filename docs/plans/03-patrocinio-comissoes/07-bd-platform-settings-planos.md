# 07 — BD: `platform_settings` + `billing_plan_tiers` com o seed dos dois planos (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 06 · **Paralelo com:** —

## Objetivo
A comissão base (800 bps) e os escalões dos dois planos vivem na BD, só de leitura para a app, com escalões contíguos garantidos pela BD.

## Pode alterar
- `migrations/0032_platform_settings_billing_tiers.sql`, `migrations/tests/billing_tiers.sql` (criar)

## Não tocar
- `migrations/0001–0031`; `audit.*` (kinds críticos: cartão 11); `backend-rust/` (o cálculo é o cartão 12). Nunca ler `.env`.

## Contexto exato (spec 14 §3, §4)
```
A base é 800 bps e configurável, nunca hardcoded. Escalões: tabela editável só pelo super_admin, auditada. A comissão marginal aplica-se SÓ à parte do volume mensal dentro do escalão (tipo IRS). Dinheiro: BIGINT em cêntimos; percentagens INT em bps.
CREATE TABLE platform_settings (id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id) /* uma só linha */, base_commission_bps INT NOT NULL DEFAULT 800 CHECK (base_commission_bps BETWEEN 0 AND 10000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_by UUID REFERENCES users (id));   INSERT INTO platform_settings DEFAULT VALUES;
CREATE TABLE billing_plan_tiers (id UUID PRIMARY KEY DEFAULT uuidv7(), plan_code VARCHAR(32) NOT NULL CHECK (plan_code IN ('commission_payg', 'tiered_subscription')),
    gmv_from_cents BIGINT NOT NULL CHECK (gmv_from_cents >= 0) /* o escalão cobre o volume em ]from, to] */, gmv_to_cents BIGINT CHECK (gmv_to_cents > gmv_from_cents) /* NULL = sem teto */,
    monthly_fee_cents BIGINT NOT NULL CHECK (monthly_fee_cents >= 0), marginal_commission_bps INT NOT NULL CHECK (marginal_commission_bps BETWEEN 0 AND 10000),
    EXCLUDE USING gist (plan_code WITH =, int8range(gmv_from_cents, gmv_to_cents, '(]') WITH &&));   -- btree_gist já existe (cartão 06)
CONSTRAINT TRIGGER DEFERRABLE INITIALLY DEFERRED, por plano: o 1.º escalão começa em 0, cada from = to do anterior (sem buracos), só o último tem to NULL, e existe pelo menos um.
Seed (from, to, mensalidade, bps) — commission_payg: (0, 2000000, 0, 800) · (2000000, NULL, 0, 600)
  tiered_subscription: (0, 100000, 500, 0) · (100000, 500000, 1000, 0) · (500000, 1000000, 5000, 0) · (1000000, 2000000, 5000, 800) · (2000000, NULL, 85000, 600)
  Leitura: até 1.000 € paga 5 €; 1.000,01–5.000 € 10 €; 5.000,01–10.000 € 50 €; 10.000,01–20.000 € 50 € + 8% só do excedente acima de 10.000 €; acima de 20.000 € 850 € + 6% só do excedente (850 € = 50 € + 8% × 10.000 €: sem saltos).
RLS ENABLE + FORCE nas duas: SELECT para ptmarket_app USING (true), GRANT SELECT. Nenhuma escrita para app nem worker (a edição pelo super_admin é do épico de backoffice, por função identity_* com 2FA).
Bloco L1 condicional (0018, linhas 77–98) nas duas: é a L1 que gera 'platform_settings.update' e 'billing_plan_tiers.*'. Nunca SET ROLE para papéis sem acesso a audit.
```

## Feito quando
- [ ] Teste `billing_tiers`: o seed tem 2 + 5 linhas com os valores acima; a continuidade 85000 = 5000 + 800 bps × 1.000.000 é verificada em SQL só com inteiros
- [ ] Escalão sobreposto → 23P01; buraco, plano sem escalão aberto ou 1.º escalão que não começa em 0 → erro no COMMIT; segunda linha em `platform_settings` → erro; bps 10001 → erro
- [ ] Como `ptmarket_app`: lê as duas tabelas sem tenant no contexto e qualquer escrita → 42501; um UPDATE de `base_commission_bps` pelo migrator deixa um evento `platform_settings.update` na caixa negra

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `billing_tiers` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Caixa negra L1 e patrocínios — `audit_l1`, `store_sponsorships` no `run.sh`
