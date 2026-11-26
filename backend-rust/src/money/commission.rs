//! Comissão efetiva de uma venda (sub_order), função pura sem BD (spec 14 §3, §4).
//!
//! Precedência por venda:
//! 1. **Patrocinada** (≥ 1 patrocínio ativo): `applied = MIN(commission_override_bps)`
//!    dos patrocínios ativos. O desconto é calculado uma vez (não duplica no co-patrocínio).
//! 2. Senão a **exceção negociada** `stores.custom_commission_bps`.
//! 3. Senão o **plano**, com o volume mensal já acumulado da loja.
//!
//! `reference_bps = COALESCE(custom_commission_bps, base_commission_bps)`.
//!
//! Base de cálculo: subtotal dos produtos (PVP com IVA), **sem** portes.
//! `platform_fee = half_up(subtotal × applied)`;
//! `sponsored_discount = half_up(subtotal × reference) − platform_fee`, nunca negativo,
//! e `0` quando não há patrocínio.
//!
//! Decisões de arquitetura:
//! - Escalões marginais: o escalão cobre o volume mensal em `]gmv_from, gmv_to]`
//!   (`None` = sem teto). A venda ocupa o volume `]antes, antes + subtotal]` e é partida
//!   nos limites; cada parte paga a `marginal_bps` do seu escalão. As partes somam-se em
//!   `Decimal` exato e arredonda-se **uma** vez por venda (half-up, via [`half_up`]).
//! - `applied_commission_bps` no plano = `half_up(fee exata ÷ subtotal × 10000)`. É
//!   informativo: a verdade é `platform_fee`. Numa venda dentro de um só escalão coincide
//!   com a `marginal_bps` desse escalão.
//! - Subtotal `0` → fee `0` e `applied` = `marginal_bps` do escalão corrente (o que cobraria
//!   o cêntimo seguinte: `gmv_from <= antes < gmv_to`).
//! - Os escalões são validados a **cada** chamada, mesmo quando a regra ganhadora não é o
//!   plano (começa em 0, contíguos, cada um não vazio, só o último aberto, lista não vazia).
//!   Se falhar → `MoneyError` (fail closed: nunca 0 % por engano).
//! - Sem `unwrap`/`expect`/`panic`; sem vírgula flutuante; overflow de `i64` → `Err`.

use rust_decimal::Decimal;

use super::{BPS_DENOMINATOR, Bps, Cents, MoneyError, half_up, mul_bps};

/// Erro devolvido quando a tabela de escalões é inválida (vira 500, nunca 4xx).
const INVALID_TIERS: MoneyError = MoneyError::InvalidPlanTiers;

/// Escalão de um plano: volume mensal em `]gmv_from, gmv_to]` (`None` = sem teto).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanTier {
    pub gmv_from: Cents,
    pub gmv_to: Option<Cents>,
    pub monthly_fee: Cents,
    pub marginal_bps: Bps,
}

/// Entrada do cálculo de comissão de uma venda.
#[derive(Debug, Clone, Copy)]
pub struct CommissionInput<'a> {
    /// Subtotal dos produtos (PVP com IVA), sem portes.
    pub subtotal: Cents,
    /// `commission_override_bps` de cada patrocínio `active` da loja (vazio = não patrocinada).
    pub active_sponsor_overrides: &'a [Bps],
    /// Exceção negociada `stores.custom_commission_bps`.
    pub custom_commission_bps: Option<Bps>,
    /// Comissão base do plano.
    pub base_commission_bps: Bps,
    /// Escalões do plano da loja.
    pub plan_tiers: &'a [PlanTier],
    /// Volume mensal da loja já acumulado antes desta venda.
    pub store_monthly_gmv_before: Cents,
}

/// Regra que determinou a comissão aplicada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissionRule {
    Sponsored,
    Custom,
    Plan,
}

/// Resultado do cálculo de comissão de uma venda.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommissionQuote {
    pub rule: CommissionRule,
    /// A referência: `COALESCE(custom_commission_bps, base_commission_bps)`.
    pub base_commission_bps: Bps,
    pub applied_commission_bps: Bps,
    pub platform_fee: Cents,
    pub sponsored_discount: Cents,
}

/// Comissão efetiva de uma venda pela precedência patrocínio → exceção → plano.
pub fn effective_commission(i: &CommissionInput) -> Result<CommissionQuote, MoneyError> {
    validate_tiers(i.plan_tiers)?;
    let reference = i.custom_commission_bps.unwrap_or(i.base_commission_bps);

    if let Some(&applied) = i.active_sponsor_overrides.iter().min() {
        let fee = mul_bps(i.subtotal, applied)?;
        let at_reference = mul_bps(i.subtotal, reference)?;
        let discount = at_reference
            .get()
            .checked_sub(fee.get())
            .ok_or(MoneyError::Overflow)?
            .max(0);
        return Ok(CommissionQuote {
            rule: CommissionRule::Sponsored,
            base_commission_bps: reference,
            applied_commission_bps: applied,
            platform_fee: fee,
            sponsored_discount: Cents::new(discount)?,
        });
    }

    if let Some(custom) = i.custom_commission_bps {
        return Ok(CommissionQuote {
            rule: CommissionRule::Custom,
            base_commission_bps: reference,
            applied_commission_bps: custom,
            platform_fee: mul_bps(i.subtotal, custom)?,
            sponsored_discount: Cents::ZERO,
        });
    }

    let (fee, applied) = plan_fee(i.plan_tiers, i.store_monthly_gmv_before, i.subtotal)?;
    Ok(CommissionQuote {
        rule: CommissionRule::Plan,
        base_commission_bps: reference,
        applied_commission_bps: applied,
        platform_fee: fee,
        sponsored_discount: Cents::ZERO,
    })
}

/// Mensalidade do escalão atingido no fim do mês (`]gmv_from, gmv_to]`); volume `0` → 1.º escalão.
pub fn monthly_fee_for(tiers: &[PlanTier], gmv_month_total: Cents) -> Result<Cents, MoneyError> {
    validate_tiers(tiers)?;
    if gmv_month_total == Cents::ZERO {
        return tiers.first().map(|t| t.monthly_fee).ok_or(INVALID_TIERS);
    }
    tiers
        .iter()
        .find(|t| t.gmv_from < gmv_month_total && t.gmv_to.is_none_or(|to| gmv_month_total <= to))
        .map(|t| t.monthly_fee)
        .ok_or(INVALID_TIERS)
}

/// Começa em 0, contíguos, cada escalão não vazio, só o último aberto, lista não vazia.
fn validate_tiers(tiers: &[PlanTier]) -> Result<(), MoneyError> {
    let first = tiers.first().ok_or(INVALID_TIERS)?;
    if first.gmv_from != Cents::ZERO {
        return Err(INVALID_TIERS);
    }
    let last_idx = tiers.len() - 1;
    for (idx, tier) in tiers.iter().enumerate() {
        match tier.gmv_to {
            None if idx == last_idx => {}
            None => return Err(INVALID_TIERS),
            Some(to) => {
                if idx == last_idx || to <= tier.gmv_from {
                    return Err(INVALID_TIERS);
                }
                match tiers.get(idx + 1) {
                    Some(next) if next.gmv_from == to => {}
                    _ => return Err(INVALID_TIERS),
                }
            }
        }
    }
    Ok(())
}

/// Fee do plano com escalões marginais e a comissão aplicada (informativa).
/// Pressupõe escalões já validados.
fn plan_fee(
    tiers: &[PlanTier],
    before: Cents,
    subtotal: Cents,
) -> Result<(Cents, Bps), MoneyError> {
    let start = before.get();
    let end = start
        .checked_add(subtotal.get())
        .ok_or(MoneyError::Overflow)?;

    if subtotal == Cents::ZERO {
        let current = tiers
            .iter()
            .find(|t| t.gmv_from.get() <= start && t.gmv_to.is_none_or(|to| start < to.get()))
            .ok_or(INVALID_TIERS)?;
        return Ok((Cents::ZERO, current.marginal_bps));
    }

    // Σ parte × marginal_bps (inteiro exato em Decimal; ÷ 10000 dá a fee exata em cêntimos).
    let mut weighted = Decimal::ZERO;
    for tier in tiers {
        let lo = start.max(tier.gmv_from.get());
        let hi = tier.gmv_to.map_or(end, |to| end.min(to.get()));
        if hi <= lo {
            continue;
        }
        let part = hi.checked_sub(lo).ok_or(MoneyError::Overflow)?;
        let contribution = Decimal::from(part)
            .checked_mul(Decimal::from(tier.marginal_bps.get()))
            .ok_or(MoneyError::Overflow)?;
        weighted = weighted
            .checked_add(contribution)
            .ok_or(MoneyError::Overflow)?;
    }

    let exact_fee = weighted
        .checked_div(Decimal::from(BPS_DENOMINATOR))
        .ok_or(MoneyError::Overflow)?;
    let fee = Cents::new(half_up(exact_fee)?)?;

    // fee exata ÷ subtotal × 10000 = Σ(parte × bps) ÷ subtotal.
    let applied_exact = weighted
        .checked_div(Decimal::from(subtotal.get()))
        .ok_or(MoneyError::Overflow)?;
    let applied = i32::try_from(half_up(applied_exact)?).map_err(|_| MoneyError::Overflow)?;
    Ok((fee, Bps::new(applied)?))
}

#[cfg(test)]
#[path = "commission_tests.rs"]
mod commission_tests;
