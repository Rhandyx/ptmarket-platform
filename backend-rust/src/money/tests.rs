#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use super::*;

fn c(v: i64) -> Cents {
    Cents::new(v).unwrap()
}

fn b(v: i32) -> Bps {
    Bps::new(v).unwrap()
}

fn mul(cents: i64, bps: i32) -> i64 {
    mul_bps(c(cents), b(bps)).unwrap().get()
}

fn split(gross: i64, bps: i32) -> (i64, i64) {
    let (net, vat) = split_vat(c(gross), b(bps)).unwrap();
    (net.get(), vat.get())
}

#[test]
fn mul_bps_vectors() {
    assert_eq!(mul(1000, 650), 65);
    assert_eq!(mul(1999, 650), 130); // 129,935
    assert_eq!(mul(50, 500), 3); // 2,5
    assert_eq!(mul(10, 500), 1); // 0,5
    assert_eq!(mul(9, 500), 0); // 0,45
    for x in [0, 1, 999, 1234, i64::MAX] {
        assert_eq!(mul(x, 0), 0);
        assert_eq!(mul(x, 10_000), x);
    }
}

#[test]
fn split_vat_vectors() {
    assert_eq!(split(1230, 2300), (1000, 230));
    assert_eq!(split(999, 2300), (812, 187));
    assert_eq!(split(999, 600), (942, 57));
    assert_eq!(split(100, 1300), (88, 12));
    assert_eq!(split(2100, 2100), (1736, 364)); // IVA ES 21 %
    assert_eq!(split(999, 0), (999, 0)); // Art. 53.º
}

#[test]
fn effective_vat_art53() {
    assert_eq!(effective_vat_bps(true, b(2300)), Bps::ZERO);
    assert_eq!(effective_vat_bps(false, b(2300)), b(2300));
    let gross = c(999);
    let (net, vat) = split_vat(gross, effective_vat_bps(true, b(2300))).unwrap();
    assert_eq!((net.get(), vat.get()), (999, 0));
}

#[test]
fn line_total_ok() {
    assert_eq!(line_total(c(1230), 3).unwrap().get(), 3690);
    assert_eq!(line_total(c(1230), 0).unwrap(), Cents::ZERO);
}

#[test]
fn error_cases() {
    assert_eq!(Cents::new(-1), Err(MoneyError::NegativeCents));
    assert_eq!(Cents::try_from(i64::MIN), Err(MoneyError::NegativeCents));
    assert_eq!(Bps::new(10_001), Err(MoneyError::BpsOutOfRange));
    assert_eq!(Bps::new(-1), Err(MoneyError::BpsOutOfRange));
    assert_eq!(Bps::try_from(i32::MAX), Err(MoneyError::BpsOutOfRange));
    assert_eq!(line_total(c(i64::MAX), 2), Err(MoneyError::Overflow));
    assert_eq!(
        half_up(rust_decimal::Decimal::MAX),
        Err(MoneyError::Overflow)
    );
}

#[test]
fn error_converts_to_validation() {
    let e: AppError = MoneyError::BpsOutOfRange.into();
    assert!(matches!(e, AppError::Validation(ref f) if f.len() == 1 && f[0].field == "bps"));
}

#[test]
fn display_pt_pt() {
    assert_eq!(c(1230).to_string(), "12,30 €");
    assert_eq!(c(5).to_string(), "0,05 €");
    assert_eq!(c(0).to_string(), "0,00 €");
    assert_eq!(c(123_456).to_string(), "1234,56 €");
}

proptest! {
    #[test]
    fn split_vat_sums_to_gross(gross in 0..=i64::MAX, bps in 0..=10_000i32) {
        let (net, vat) = split_vat(c(gross), b(bps)).unwrap();
        prop_assert_eq!(net.get().checked_add(vat.get()), Some(gross));
    }

    #[test]
    fn mul_bps_bounded(cents in 0..=i64::MAX, bps in 0..=10_000i32) {
        let r = mul(cents, bps);
        prop_assert!(0 <= r && r <= cents);
    }

    #[test]
    fn mul_bps_monotonic_in_cents(x in 0..=i64::MAX, y in 0..=i64::MAX, bps in 0..=10_000i32) {
        let (lo, hi) = if x <= y { (x, y) } else { (y, x) };
        prop_assert!(mul(lo, bps) <= mul(hi, bps));
    }
}
