//! `money`: o único sítio do backend onde se faz aritmética e arredondamento de dinheiro.
//!
//! - Montantes em cêntimos inteiros ([`Cents`], `i64`, nunca negativos).
//! - Percentagens em pontos base ([`Bps`], `i32`, `0..=10000`; `2300` = 23 %).
//! - Cálculos intermédios em `rust_decimal::Decimal`; arredondamento aritmético
//!   (half-up, metade afasta-se do zero) **por linha**, só via [`half_up`].
//! - Preços B2C são PVP com IVA incluído; [`split_vat`] separa base e IVA.
//!
//! Nenhuma função faz panic nem dá a volta (wrap): entradas inválidas ou overflow
//! devolvem [`MoneyError`], convertível em [`AppError::Validation`].

use std::fmt;

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::{Decimal, RoundingStrategy};

use crate::error::{AppError, FieldError};

pub mod commission;
pub use commission::{
    CommissionInput, CommissionQuote, CommissionRule, PlanTier, effective_commission,
    monthly_fee_due, monthly_fee_for,
};

#[cfg(test)]
mod no_float;
#[cfg(test)]
mod no_loose_round;
#[cfg(test)]
mod tests;

/// Denominador dos pontos base: `10000` bps = 100 %.
const BPS_DENOMINATOR: i32 = 10_000;

/// Erro de dinheiro: entrada inválida ou resultado fora do intervalo de `i64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MoneyError {
    #[error("montante negativo")]
    NegativeCents,
    #[error("percentagem fora de 0..=10000 bps")]
    BpsOutOfRange,
    #[error("overflow no cálculo de dinheiro")]
    Overflow,
    /// Configuração de escalões de plano inválida (erro da plataforma, não do pedido): 500.
    #[error("escalões de plano inválidos")]
    InvalidPlanTiers,
}

impl From<MoneyError> for AppError {
    fn from(e: MoneyError) -> Self {
        if e == MoneyError::InvalidPlanTiers {
            return AppError::Internal(anyhow::anyhow!(e));
        }
        let field = match e {
            MoneyError::NegativeCents | MoneyError::Overflow => "amount",
            MoneyError::BpsOutOfRange => "bps",
            MoneyError::InvalidPlanTiers => "plan_tiers",
        };
        AppError::Validation(vec![FieldError {
            field: field.to_owned(),
            message: e.to_string(),
        }])
    }
}

/// Montante em cêntimos de euro, sempre `>= 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Cents(i64);

impl Cents {
    pub const ZERO: Cents = Cents(0);

    /// Valida `value >= 0`.
    pub fn new(value: i64) -> Result<Self, MoneyError> {
        if value < 0 {
            return Err(MoneyError::NegativeCents);
        }
        Ok(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for Cents {
    type Error = MoneyError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Formato pt-PT (`12,30 €`), sem separador de milhares. Só para logs e testes;
/// a apresentação ao utilizador é do frontend.
impl fmt::Display for Cents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{:02} €", self.0 / 100, self.0 % 100)
    }
}

/// Percentagem em pontos base, `0..=10000` (`650` = 6,5 %).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bps(i32);

impl Bps {
    pub const ZERO: Bps = Bps(0);

    /// Valida `0..=10000`.
    pub fn new(value: i32) -> Result<Self, MoneyError> {
        if !(0..=BPS_DENOMINATOR).contains(&value) {
            return Err(MoneyError::BpsOutOfRange);
        }
        Ok(Self(value))
    }

    pub fn get(self) -> i32 {
        self.0
    }
}

impl TryFrom<i32> for Bps {
    type Error = MoneyError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Arredondamento aritmético às unidades (metade afasta-se do zero).
/// `Err(Overflow)` se o resultado não couber em `i64`.
pub fn half_up(d: Decimal) -> Result<i64, MoneyError> {
    d.round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero)
        .to_i64()
        .ok_or(MoneyError::Overflow)
}

fn to_cents(d: Decimal) -> Result<Cents, MoneyError> {
    Cents::new(half_up(d)?)
}

/// `half_up(c × bps / 10000)` — comissões, cashback.
pub fn mul_bps(c: Cents, bps: Bps) -> Result<Cents, MoneyError> {
    let v = Decimal::from(c.0)
        .checked_mul(Decimal::from(bps.0))
        .and_then(|x| x.checked_div(Decimal::from(BPS_DENOMINATOR)))
        .ok_or(MoneyError::Overflow)?;
    to_cents(v)
}

/// Total da linha `unit × qty`, com verificação de overflow.
pub fn line_total(unit: Cents, qty: u32) -> Result<Cents, MoneyError> {
    unit.0
        .checked_mul(i64::from(qty))
        .map(Cents)
        .ok_or(MoneyError::Overflow)
}

/// Separa o total bruto (IVA incluído) de uma **linha** em `(base, iva)`:
/// `base = half_up(bruto × 10000 / (10000 + bps))`, `iva = bruto − base`.
/// Garante `base + iva == bruto`.
///
/// PROVISÓRIO: a paridade ao cêntimo com faturas reais do Moloni é validada no
/// 1.º cartão de pagamentos; até lá esta fórmula pode mudar.
pub fn split_vat(gross: Cents, bps: Bps) -> Result<(Cents, Cents), MoneyError> {
    let denominator = BPS_DENOMINATOR
        .checked_add(bps.0)
        .ok_or(MoneyError::Overflow)?;
    let net = Decimal::from(gross.0)
        .checked_mul(Decimal::from(BPS_DENOMINATOR))
        .and_then(|x| x.checked_div(Decimal::from(denominator)))
        .ok_or(MoneyError::Overflow)?;
    let net = to_cents(net)?;
    let vat = gross.0.checked_sub(net.0).ok_or(MoneyError::Overflow)?;
    Ok((net, Cents::new(vat)?))
}

/// Taxa de IVA efetiva: `0` se a loja estiver isenta pelo Art. 53.º do CIVA,
/// senão a taxa do produto.
pub fn effective_vat_bps(store_vat_exempt_art53: bool, product_bps: Bps) -> Bps {
    if store_vat_exempt_art53 {
        Bps::ZERO
    } else {
        product_bps
    }
}
