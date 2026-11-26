# 18 — Rust: `effective_commission_bps` com dados da BD + pré-visualização para o registo (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 12, 14, 17 · **Paralelo com:** — (Rust em série)

## Objetivo
Dada uma loja, um instante e o volume mensal acumulado, o backend devolve a comissão efetiva lendo patrocínios, exceção, base e escalões da BD; o formulário de registo recebe a âncora (referência e planos) sem valores hardcoded.

## Pode alterar
- `backend-rust/src/payments/commission.rs`, `src/sponsors/sponsorships.rs`, `src/tenancy/store_terms.rs` (criar); `src/payments/mod.rs`, `src/sponsors/{mod,http}.rs`, `src/tenancy/mod.rs`, `src/http/{mod,openapi}.rs`, `openapi.json`, `.sqlx/**`; `backend-rust/tests/commission.rs` (criar)

## Não tocar
- `src/money/` (fechado no 12: só se chama); `src/identity/`; `src/tenancy/db.rs` (fechado no 14); `src/orders/` (o snapshot é do épico de encomendas); `migrations/`.

## Contexto exato (spec 14 §3, §4, §6)
```
"Ativo" = status = 'active' AND at <@ tstzrange(valid_from, valid_to). O cálculo NUNCA depende do job que passa a expired. A comissão NÃO depende do domínio onde a compra foi feita.
Precedência: patrocinada → MIN(commission_override_bps) dos ativos; senão stores.custom_commission_bps; senão o plano (stores.billing_plan_code) com o volume mensal já acumulado. reference_bps = COALESCE(custom_commission_bps, platform_settings.base_commission_bps).
RLS por loja (cartões 08b/14): `stores` e `store_sponsorships` só se leem dentro de um tx com âmbito dessa loja (begin_store_tx com o StoreScope do extractor) ou com ator admin. Por isso a função recebe um tx JÁ com âmbito; nos testes, o âmbito cria-se com o construtor de test-support.
Cada módulo lê só as suas tabelas:
  sponsors::sponsorships::active_at(tx, store_id, at) -> Vec<ActiveSponsorship { sponsor_entity_id, override_bps: Bps }>
  tenancy::store_terms::commission_terms(tx, store_id) -> StoreCommissionTerms { custom_commission_bps: Option<Bps>, billing_plan_code: String, storefront_dicofre: Option<String> }   // nunca iban nem chaves
  payments::commission (dono de platform_settings e billing_plan_tiers):
    pub async fn effective_commission_bps(tx: &mut TenantTx, store_id: Uuid, at: OffsetDateTime, store_monthly_gmv_cents: Cents, subtotal: Cents) -> Result<CommissionSnapshot, AppError>
    CommissionSnapshot { quote: money::CommissionQuote, billing_plan_code, store_monthly_gmv_before: Cents, active_sponsor_ids: Vec<Uuid> /* ordenados, sem repetidos */, store_dicofre: Option<String> }   // os campos que o épico de encomendas congela em sub_orders; aqui NÃO se grava nada
  Converte as linhas em money::PlanTier e chama money::effective_commission: nenhuma conta de dinheiro fora de money. Fail closed: loja não visível no tx (0 linhas), sem linha em platform_settings, plano sem escalões ou escalões inválidos → erro (nunca 0%).
Endpoint público para o formulário (sem sessão; replica; não lê `stores`; Cache-Control: public, max-age=60):
  GET /api/v1/signup/commission-preview?dicofre=DDCCFF → {"reference_bps": 800, "sponsored": {"applied_bps": 0, "sponsors": [{"id","kind","name","slug","logo_key"}]} | null, "plans": [{"plan_code","is_default","tiers":[{"gmv_from_cents","gmv_to_cents","monthly_fee_cents","marginal_commission_bps"}]}]}
  dicofre é opcional (sem ele, ou sem entidades elegíveis, "sponsored": null). is_default = (plan_code = 'commission_payg'). Só inteiros (cêntimos, bps). "sponsored" é uma PREVISÃO sujeita a validação da entidade: o endpoint não cria nem promete nada (dizê-lo na descrição utoipa).
```

## Feito quando
- [ ] `commission`: loja com patrocínio ativo → regra Sponsored, fee 0, desconto = 8% do subtotal; **co-patrocínio Câmara + Junta** → um só desconto e `active_sponsor_ids` com os 2 ids ordenados
- [ ] Patrocínio `active` com `valid_to < at`, com `valid_from > at`, `pending` ou `revoked` não conta; com `at` no passado (dentro da vigência antiga) conta; todos cessados → regra Plan com os escalões da BD
- [ ] Mudar `base_commission_bps` e um escalão na BD (como migrator) muda o resultado sem recompilar; plano sem escalões → erro; tx com âmbito de L1 a pedir a comissão de L2 → erro, não 0%
- [ ] Preview: sem `dicofre` → `sponsored: null`; freguesia com Câmara + Junta → 2 sponsors pela ordem fixa; `dicofre` inválido → 400

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test commission` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suite completa `cargo test -p ptmarket-api` (mesmas variáveis), que inclui `money`, `sponsors_public` e `store_scope`
