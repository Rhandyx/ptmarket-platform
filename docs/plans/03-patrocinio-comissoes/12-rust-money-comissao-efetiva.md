# 12 — Rust `money`: comissão efetiva com escalões marginais (função pura) (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** — · **Paralelo com:** 01–11 (sem BD nem `query!`: é o único cartão Rust que pode correr com as migrations a mudar)

## Objetivo
O módulo `money` calcula, sem BD e sem floats, a comissão de uma venda pela precedência patrocínio → exceção → plano, partindo a venda nos limites dos escalões.

## Pode alterar
- `backend-rust/src/money/commission.rs`, `backend-rust/src/money/commission_tests.rs` (criar); `backend-rust/src/money/mod.rs` (só `pub mod` + reexport)

## Não tocar
- `half_up`, `mul_bps`, `split_vat`, `effective_vat_bps`, `Cents`, `Bps` e `money/no_float.rs` — aprovados (reutilizar, não alterar); o resto do backend; `migrations/`.

## Contexto exato (spec 14 §3, §4)
```
Precedência por venda (sub_order): 1) patrocinada (≥ 1 patrocínio ativo): applied = MIN(commission_override_bps) dos ativos (por defeito 0); 2) senão a exceção negociada stores.custom_commission_bps; 3) senão o plano, com o volume mensal já acumulado. reference_bps = COALESCE(custom_commission_bps, base_commission_bps).
Base de cálculo: subtotal dos produtos (PVP com IVA), SEM portes. Arredondamento half-up, só em money. platform_fee_cents = round(subtotal × applied), com escalões marginais se for o caso. sponsored_discount_cents = round(subtotal × reference_bps) − platform_fee_cents, nunca negativo, e 0 quando não há patrocínio.
Escalão: cobre o volume mensal em ]gmv_from, gmv_to] (None = sem teto); a comissão marginal aplica-se só à parte da venda dentro do escalão; a venda que atravessa um ou mais limites é partida.
API (nomes fixos: o cartão 18 e o épico de encomendas dependem deles):
  pub struct PlanTier { pub gmv_from: Cents, pub gmv_to: Option<Cents>, pub monthly_fee: Cents, pub marginal_bps: Bps }
  pub struct CommissionInput<'a> { pub subtotal: Cents, pub active_sponsor_overrides: &'a [Bps], pub custom_commission_bps: Option<Bps>, pub base_commission_bps: Bps, pub plan_tiers: &'a [PlanTier], pub store_monthly_gmv_before: Cents }
  pub enum CommissionRule { Sponsored, Custom, Plan } · pub struct CommissionQuote { pub rule: CommissionRule, pub base_commission_bps: Bps /* a referência */, pub applied_commission_bps: Bps, pub platform_fee: Cents, pub sponsored_discount: Cents }
  pub fn effective_commission(i: &CommissionInput) -> Result<CommissionQuote, MoneyError> · pub fn monthly_fee_for(tiers: &[PlanTier], gmv_month_total: Cents) -> Result<Cents, MoneyError>  // escalão atingido no fim do mês; 0 → 1.º escalão
Decisões de arquitetura (pôr no doc-comment): no plano, somar as partes em Decimal exato e arredondar UMA vez por venda; applied_commission_bps numa venda partida = half_up(fee exata ÷ subtotal × 10000) (informativo: a verdade é platform_fee); subtotal 0 → fee 0 e applied = marginal do escalão corrente. Os escalões são validados a cada chamada (começa em 0, contíguos, só o último aberto, não vazio): se falhar → MoneyError (fail closed, nunca 0% por engano). Sem unwrap/expect/panic; sem f32/f64.
Tabela mínima (payg = ]0, 2000000] 800 bps · ]2000000, ∞[ 600 bps; tiered = (0,100000,500,0) (100000,500000,1000,0) (500000,1000000,5000,0) (1000000,2000000,5000,800) (2000000,None,85000,600); base 800):
  payg: gmv 0, subtotal 10000 → fee 800 · gmv 1990000, 20000 → 1400 (applied 700) · gmv 2000000, 100 → 6 · gmv 1999999, 2 → 0 · gmv 2000000, 25 → 2 (1,5 arredonda para cima)
  tiered: gmv 0, 1000000 → 0 · gmv 990000, 20000 → 800 · gmv 900000, 1200000 → 86000 (3 escalões) · monthly_fee_for: 0 → 500 · 100000 → 500 · 100001 → 1000 · 1000001 → 5000 · 2000001 → 85000 (payg → sempre 0)
  patrocinada [0], 12345 → fee 0, desconto 988 · co-patrocínio Câmara + Junta [0, 0] → igual (o desconto NÃO duplica) · [300, 200] → applied 200, fee 247, desconto 741 · [0] com custom 500 → referência 500, desconto 617 · [900] com base 800 → fee 1111, desconto 0 · custom 500 sem patrocínio → fee 617, desconto 0
```

## Feito quando
- [ ] `commission_tests` cobre a tabela acima linha a linha, mais: cada limite exato de cada escalão (−1, 0, +1 cêntimo) nos dois planos; as 3 regras presentes ao mesmo tempo (ganha o patrocínio); lista de overrides vazia
- [ ] Propriedades (proptest ou ciclo determinístico): partir uma venda em duas consecutivas difere no máximo 1 cêntimo da venda única; a fee nunca é negativa nem maior que o subtotal; o desconto nunca é negativo
- [ ] Erros: escalões com buraco, sobrepostos, vazios ou sem escalão aberto → `Err`; overflow de `i64` → `Err`, nunca panic; `money/no_float.rs` continua a passar

## Prova (um comando)
`cd backend-rust && SQLX_OFFLINE=true cargo test -p ptmarket-api --lib money` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- IVA, Art. 53.º e `no_float` — o mesmo comando (`money::tests`)
