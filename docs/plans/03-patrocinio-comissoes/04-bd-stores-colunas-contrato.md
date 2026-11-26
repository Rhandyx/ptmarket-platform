# 04 — BD: colunas novas de `stores` (entrega, plano, contrato, moradas) (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 01, 03 · **Paralelo com:** —

## Objetivo
`stores` guarda o âmbito de entrega, o plano de faturação, a aceitação do contrato e a morada física com DICOFRE; a app deixa de poder escrever a exceção de comissão.

## Pode alterar
- `migrations/0029_stores_channel_columns.sql`, `migrations/tests/stores_columns.sql` (criar); testes existentes em `migrations/tests/` só se os grants por coluna os partirem (ajuste mínimo, sem mudar o que provam)

## Não tocar
- `migrations/0001–0028`; a view `portal_stores` e as policies `portal_*` (cartão 08); o `tenant_id` dos dados (cartão 05). Não apagar `address_json` nem `publish_to_national_portal`. Nunca ler `.env`.

## Contexto exato (spec 14 §1.1, §3, §4, §5, §6)
```
ALTER TABLE stores ADD COLUMN
  shipping_scope VARCHAR(16) NOT NULL DEFAULT 'national' CHECK (shipping_scope IN ('national', 'local_only', 'pickup_only')),   -- não esconde a loja: o checkout só oferece o que o âmbito permite
  billing_plan_code VARCHAR(32) NOT NULL DEFAULT 'commission_payg' CHECK (billing_plan_code IN ('commission_payg', 'tiered_subscription')),
  accepted_base_commission_bps INT CHECK (accepted_base_commission_bps BETWEEN 0 AND 10000), terms_version VARCHAR(32), terms_accepted_at TIMESTAMPTZ,
  fiscal_address JSONB NOT NULL DEFAULT '{}' /* faturação */, storefront_address JSONB NOT NULL DEFAULT '{}' /* morada física: dá elegibilidade ao patrocínio */,
  storefront_dicofre VARCHAR(6) REFERENCES geo_dicofre (code) ON DELETE RESTRICT CHECK (length(storefront_dicofre) = 6);
CHECK stores_contract_all_or_none: accepted_base_commission_bps, terms_version e terms_accepted_at são os três NULL (lojas de dev antigas) ou os três preenchidos (a aceitação grava-se na transação do registo da loja).
Índice: stores (storefront_dicofre).
COMMENT ON COLUMN: address_json 'DEPRECADO (spec 14 §5): usar fiscal_address/storefront_address'; publish_to_national_portal 'DEPRECADO (spec 14 §1.1): já não é lido; sai numa migration posterior'; custom_commission_bps 'Exceção negociada; NULL = sem exceção. Só o super_admin a define (auditada). Já NÃO herda do tenant'; tenants.default_commission_bps 'DEPRECADO: a base vem de platform_settings.base_commission_bps'.
Trinco de dinheiro (hoje: GRANT SELECT, INSERT, UPDATE, DELETE ON stores TO ptmarket_app): REVOKE INSERT, UPDATE ON stores FROM ptmarket_app e voltar a dar por coluna (lista tirada de information_schema, com as colunas novas):
  INSERT em todas menos custom_commission_bps e kyc_verified; UPDATE em todas menos id, tenant_id, custom_commission_bps, kyc_verified, created_at. SELECT e DELETE ficam como estão. O ptmarket_portal não recebe nada aqui (cartão 08).
Sem tabelas novas (não há bloco L1): os triggers zz_audit_* de stores já existem e continuam a gravar. Nunca SET ROLE para papéis sem acesso a audit.
```

## Feito quando
- [ ] BD limpa e BD com L2: a 0029 aplica; uma loja antiga fica com `shipping_scope = 'national'`, `billing_plan_code = 'commission_payg'` e contrato NULL
- [ ] Teste `stores_columns`: valores fora dos CHECK falham; contrato com só 1 ou 2 dos 3 campos falha; `storefront_dicofre` de concelho (4 dígitos) ou inexistente falha
- [ ] Como `ptmarket_app` no tenant da loja: UPDATE de `name` e de `shipping_scope` passa; UPDATE de `custom_commission_bps`, `kyc_verified` ou `tenant_id` → 42501; INSERT com `custom_commission_bps` → 42501
- [ ] `rls`, `portal` e `identity_portal_hardening` continuam verdes sem mudar o que provam

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `stores_columns` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Isolamento e RBAC em Rust — `cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test rls_isolation --test rbac`
