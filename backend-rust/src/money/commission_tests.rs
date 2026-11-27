#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use super::*;

fn c(v: i64) -> Cents {
    Cents::new(v).unwrap()
}

fn b(v: i32) -> Bps {
    Bps::new(v).unwrap()
}

fn tier(from: i64, to: Option<i64>, fee: i64, bps: i32) -> PlanTier {
    PlanTier {
        gmv_from: c(from),
        gmv_to: to.map(c),
        monthly_fee: c(fee),
        marginal_bps: b(bps),
    }
}

const BASE: i32 = 800;

fn payg() -> Vec<PlanTier> {
    vec![
        tier(0, Some(2_000_000), 0, 800),
        tier(2_000_000, None, 0, 600),
    ]
}

/// `tiered_subscription` (0034): só mensalidade fixa por escalão, 0 % de comissão em todos.
fn tiered() -> Vec<PlanTier> {
    vec![
        tier(0, Some(100_000), 500, 0),
        tier(100_000, Some(500_000), 1_000, 0),
        tier(500_000, Some(1_000_000), 5_000, 0),
        tier(1_000_000, Some(2_500_000), 10_000, 0),
        tier(2_500_000, Some(5_000_000), 17_500, 0),
        tier(5_000_000, Some(10_000_000), 30_000, 0),
        tier(10_000_000, None, 50_000, 0),
    ]
}

/// Limites do `tiered_subscription` e mensalidades de cada lado: `(limite, abaixo, acima)`.
const TIERED_LIMITS: [(i64, i64, i64); 6] = [
    (100_000, 500, 1_000),
    (500_000, 1_000, 5_000),
    (1_000_000, 5_000, 10_000),
    (2_500_000, 10_000, 17_500),
    (5_000_000, 17_500, 30_000),
    (10_000_000, 30_000, 50_000),
];

/// Plano híbrido (mensalidade + comissão marginal), como o super_admin pode configurar: prova que o cálculo
/// marginal continua operacional além do `commission_payg` (era o seed da 0032).
fn hybrid() -> Vec<PlanTier> {
    vec![
        tier(0, Some(100_000), 500, 0),
        tier(100_000, Some(500_000), 1000, 0),
        tier(500_000, Some(1_000_000), 5000, 0),
        tier(1_000_000, Some(2_000_000), 5000, 800),
        tier(2_000_000, None, 85_000, 600),
    ]
}

fn quote_full(
    subtotal: i64,
    overrides: &[i32],
    custom: Option<i32>,
    tiers: &[PlanTier],
    before: i64,
) -> Result<CommissionQuote, MoneyError> {
    let overrides: Vec<Bps> = overrides.iter().copied().map(b).collect();
    effective_commission(&CommissionInput {
        subtotal: c(subtotal),
        active_sponsor_overrides: &overrides,
        custom_commission_bps: custom.map(b),
        base_commission_bps: b(BASE),
        plan_tiers: tiers,
        store_monthly_gmv_before: c(before),
    })
}

/// Plano sem patrocínio nem exceção: `(fee, applied)`.
fn plan(tiers: &[PlanTier], before: i64, subtotal: i64) -> (i64, i32) {
    let q = quote_full(subtotal, &[], None, tiers, before).unwrap();
    assert_eq!(q.rule, CommissionRule::Plan);
    assert_eq!(q.base_commission_bps, b(BASE));
    assert_eq!(q.sponsored_discount, Cents::ZERO);
    (q.platform_fee.get(), q.applied_commission_bps.get())
}

fn fee_of(tiers: &[PlanTier], before: i64, subtotal: i64) -> i64 {
    plan(tiers, before, subtotal).0
}

fn monthly(tiers: &[PlanTier], total: i64) -> i64 {
    monthly_fee_for(tiers, c(total)).unwrap().get()
}

// ---------- Tabela do cartão, linha a linha ----------

#[test]
fn table_payg() {
    let t = payg();
    assert_eq!(plan(&t, 0, 10_000), (800, 800));
    assert_eq!(plan(&t, 1_990_000, 20_000), (1400, 700));
    assert_eq!(fee_of(&t, 2_000_000, 100), 6);
    assert_eq!(fee_of(&t, 1_999_999, 2), 0); // 0,08 + 0,06
    assert_eq!(fee_of(&t, 2_000_000, 25), 2); // 1,5 arredonda para cima
}

#[test]
fn table_tiered() {
    let t = tiered();
    assert_eq!(plan(&t, 0, 1_000_000), (0, 0));
    assert_eq!(plan(&t, 990_000, 20_000), (0, 0));
    assert_eq!(plan(&t, 900_000, 12_000_000), (0, 0)); // atravessa 5 limites
    assert_eq!(plan(&t, 50_000_000, 12_345), (0, 0));
}

/// Loja em `tiered_subscription` sem patrocínio: fee 0, applied 0 e nunca poupança de patrocínio.
#[test]
fn tiered_without_sponsorship_is_zero_everywhere() {
    let t = tiered();
    for before in [
        0, 1, 99_999, 100_000, 1_500_000, 2_500_001, 9_999_999, 10_000_000, 99_000_000,
    ] {
        for subtotal in [0, 1, 25, 12_345, 1_000_000, 20_000_000] {
            let q = quote_full(subtotal, &[], None, &t, before).unwrap();
            assert_eq!(q.rule, CommissionRule::Plan);
            assert_eq!(
                q.platform_fee,
                Cents::ZERO,
                "before {before}, subtotal {subtotal}"
            );
            assert_eq!(q.applied_commission_bps, Bps::ZERO);
            assert_eq!(q.sponsored_discount, Cents::ZERO);
        }
    }
}

#[test]
fn table_hybrid() {
    let t = hybrid();
    assert_eq!(fee_of(&t, 0, 1_000_000), 0);
    assert_eq!(fee_of(&t, 990_000, 20_000), 800);
    assert_eq!(fee_of(&t, 900_000, 1_200_000), 86_000); // 3 escalões
}

#[test]
fn table_monthly_fee() {
    let t = tiered();
    assert_eq!(monthly(&t, 0), 500);
    assert_eq!(monthly(&t, 100_000), 500);
    assert_eq!(monthly(&t, 100_001), 1_000);
    assert_eq!(monthly(&t, 500_000), 1_000);
    assert_eq!(monthly(&t, 500_001), 5_000);
    assert_eq!(monthly(&t, 1_000_001), 10_000);
    assert_eq!(monthly(&t, 2_500_001), 17_500);
    assert_eq!(monthly(&t, 5_000_001), 30_000);
    assert_eq!(monthly(&t, 10_000_000), 30_000);
    assert_eq!(monthly(&t, 10_000_001), 50_000);
    assert_eq!(monthly(&t, i64::MAX), 50_000);
    let h = hybrid();
    assert_eq!(monthly(&h, 1_000_001), 5000);
    assert_eq!(monthly(&h, 2_000_001), 85_000);
    let p = payg();
    for total in [0, 1, 1_999_999, 2_000_000, 2_000_001, i64::MAX] {
        assert_eq!(monthly(&p, total), 0);
    }
}

#[test]
fn table_sponsored_and_custom() {
    let p = payg();

    let q = quote_full(12_345, &[0], None, &p, 0).unwrap();
    assert_eq!(q.rule, CommissionRule::Sponsored);
    assert_eq!(q.base_commission_bps, b(800));
    assert_eq!(q.applied_commission_bps, b(0));
    assert_eq!(q.platform_fee, c(0));
    assert_eq!(q.sponsored_discount, c(988));

    // Co-patrocínio Câmara + Junta: o desconto NÃO duplica.
    assert_eq!(quote_full(12_345, &[0, 0], None, &p, 0).unwrap(), q);

    let q = quote_full(12_345, &[300, 200], None, &p, 0).unwrap();
    assert_eq!(q.applied_commission_bps, b(200));
    assert_eq!(q.platform_fee, c(247));
    assert_eq!(q.sponsored_discount, c(741));

    let q = quote_full(12_345, &[0], Some(500), &p, 0).unwrap();
    assert_eq!(q.rule, CommissionRule::Sponsored);
    assert_eq!(q.base_commission_bps, b(500));
    assert_eq!(q.platform_fee, c(0));
    assert_eq!(q.sponsored_discount, c(617));

    let q = quote_full(12_345, &[900], None, &p, 0).unwrap();
    assert_eq!(q.applied_commission_bps, b(900));
    assert_eq!(q.platform_fee, c(1111));
    assert_eq!(q.sponsored_discount, c(0));

    let q = quote_full(12_345, &[], Some(500), &p, 0).unwrap();
    assert_eq!(q.rule, CommissionRule::Custom);
    assert_eq!(q.base_commission_bps, b(500));
    assert_eq!(q.applied_commission_bps, b(500));
    assert_eq!(q.platform_fee, c(617));
    assert_eq!(q.sponsored_discount, c(0));
}

// ---------- Limites exatos de cada escalão (−1, 0, +1) ----------

/// Para cada limite `l` entre escalões `lower_bps` / `upper_bps`:
/// o cêntimo `]l-1, l]` é do escalão de baixo; `]l, l+1]` é do de cima.
fn check_boundary(t: &[PlanTier], l: i64, lower_bps: i32, upper_bps: i32, fees: (i64, i64)) {
    // applied com subtotal 1 = marginal do escalão que cobra esse cêntimo.
    assert_eq!(plan(t, l - 2, 1).1, lower_bps, "limite {l}: antes = l-2");
    assert_eq!(plan(t, l - 1, 1).1, lower_bps, "limite {l}: antes = l-1");
    assert_eq!(plan(t, l, 1).1, upper_bps, "limite {l}: antes = l");
    assert_eq!(plan(t, l + 1, 1).1, upper_bps, "limite {l}: antes = l+1");

    // Subtotal 0: marginal do escalão corrente.
    assert_eq!(plan(t, l - 1, 0), (0, lower_bps));
    assert_eq!(plan(t, l, 0), (0, upper_bps));
    assert_eq!(plan(t, l + 1, 0), (0, upper_bps));

    // Vendas de 10000 que acabam em l-1, l e l+1.
    let full_lower = i64::from(lower_bps); // 10000 × bps / 10000
    let full_upper = i64::from(upper_bps);
    assert_eq!(fee_of(t, l - 10_001, 10_000), full_lower);
    assert_eq!(fee_of(t, l - 10_000, 10_000), full_lower);
    let mixed = (9_999 * i64::from(lower_bps) + i64::from(upper_bps) + 5_000) / 10_000;
    assert_eq!(fee_of(t, l - 9_999, 10_000), mixed);
    assert_eq!(fee_of(t, l, 10_000), full_upper);

    // Mensalidade: l-1 e l → escalão de baixo; l+1 → de cima.
    assert_eq!(monthly(t, l - 1), fees.0, "mensalidade em {l}-1");
    assert_eq!(monthly(t, l), fees.0, "mensalidade em {l}");
    assert_eq!(monthly(t, l + 1), fees.1, "mensalidade em {l}+1");
}

#[test]
fn boundaries_payg() {
    let t = payg();
    check_boundary(&t, 2_000_000, 800, 600, (0, 0));
    // Limite 0 (início do 1.º escalão).
    assert_eq!(plan(&t, 0, 0), (0, 800));
    assert_eq!(plan(&t, 0, 1), (0, 800));
    assert_eq!(plan(&t, 1, 1), (0, 800));
    assert_eq!(monthly(&t, 0), 0);
    assert_eq!(monthly(&t, 1), 0);
}

#[test]
fn boundaries_tiered() {
    let t = tiered();
    for (l, below, above) in TIERED_LIMITS {
        check_boundary(&t, l, 0, 0, (below, above));
    }
    // Limite 0.
    assert_eq!(plan(&t, 0, 0), (0, 0));
    assert_eq!(plan(&t, 0, 1), (0, 0));
    assert_eq!(monthly(&t, 0), 500);
    assert_eq!(monthly(&t, 1), 500);
}

#[test]
fn boundaries_hybrid() {
    let t = hybrid();
    check_boundary(&t, 100_000, 0, 0, (500, 1000));
    check_boundary(&t, 500_000, 0, 0, (1000, 5000));
    check_boundary(&t, 1_000_000, 0, 800, (5000, 5000));
    check_boundary(&t, 2_000_000, 800, 600, (5000, 85_000));
    // Limite 0.
    assert_eq!(plan(&t, 0, 0), (0, 0));
    assert_eq!(plan(&t, 0, 1), (0, 0));
    assert_eq!(monthly(&t, 0), 500);
    assert_eq!(monthly(&t, 1), 500);
}

#[test]
fn split_sale_applied_is_informative() {
    // 10000 a 800 + 10000 a 600 = 1400 → 700 bps.
    assert_eq!(plan(&payg(), 1_990_000, 20_000), (1400, 700));
    // 1 a 800 + 2 a 600 = 0,2 → fee 0; applied = half_up(2000/3) = 667.
    assert_eq!(plan(&payg(), 1_999_999, 3), (0, 667));
}

// ---------- Patrocínio ativo sobre o plano (decisão do owner, 27/11) ----------

/// Loja patrocinada com `tiered_subscription` guardado: o plano não entra; a poupança mede-se contra a âncora
/// (`COALESCE(custom, base)`), não contra os 0 % do plano.
#[test]
fn sponsored_tiered_store_discount_uses_anchor() {
    let t = tiered();
    for before in [0, 1_500_000, 50_000_000] {
        let q = quote_full(12_345, &[0], None, &t, before).unwrap();
        assert_eq!(q.rule, CommissionRule::Sponsored);
        assert_eq!(q.base_commission_bps, b(BASE));
        assert_eq!(q.platform_fee, c(0));
        assert_eq!(q.sponsored_discount, c(988));

        let q = quote_full(12_345, &[0], Some(500), &t, before).unwrap();
        assert_eq!(q.sponsored_discount, c(617));
    }
}

/// Com ≥ 1 patrocínio ativo não há mensalidade, qualquer que seja o plano guardado e o volume.
#[test]
fn monthly_fee_due_is_zero_when_sponsored() {
    for t in [tiered(), hybrid(), payg()] {
        for total in [0, 1, 100_000, 100_001, 1_000_001, 10_000_001, i64::MAX] {
            assert_eq!(monthly_fee_due(&t, c(total), true).unwrap(), Cents::ZERO);
            assert_eq!(
                monthly_fee_due(&t, c(total), false).unwrap(),
                monthly_fee_for(&t, c(total)).unwrap()
            );
        }
    }
    assert_eq!(
        monthly_fee_due(&tiered(), c(10_000_001), false).unwrap(),
        c(50_000)
    );
}

/// Fail closed: escalões inválidos dão erro mesmo com patrocínio (nunca 0 € por engano de configuração).
#[test]
fn monthly_fee_due_validates_tiers_even_when_sponsored() {
    let bad = vec![tier(0, Some(100), 0, 800), tier(101, None, 0, 600)];
    for sponsored in [true, false] {
        assert_eq!(
            monthly_fee_due(&bad, c(0), sponsored),
            Err(MoneyError::InvalidPlanTiers)
        );
    }
}

// ---------- Precedência ----------

#[test]
fn all_three_rules_present_sponsorship_wins() {
    let q = quote_full(10_000, &[100], Some(500), &tiered(), 1_500_000).unwrap();
    assert_eq!(q.rule, CommissionRule::Sponsored);
    assert_eq!(q.base_commission_bps, b(500));
    assert_eq!(q.applied_commission_bps, b(100));
    assert_eq!(q.platform_fee, c(100));
    assert_eq!(q.sponsored_discount, c(400));
}

#[test]
fn empty_override_list_is_not_sponsored() {
    let q = quote_full(10_000, &[], None, &hybrid(), 1_500_000).unwrap();
    assert_eq!(q.rule, CommissionRule::Plan);
    assert_eq!(q.platform_fee, c(800));
    assert_eq!(q.sponsored_discount, c(0));

    let q = quote_full(10_000, &[], Some(500), &hybrid(), 1_500_000).unwrap();
    assert_eq!(q.rule, CommissionRule::Custom);
    assert_eq!(q.platform_fee, c(500));
}

#[test]
fn custom_ignores_plan_tiers_and_volume() {
    for before in [0, 1_000_000, 2_000_000, 5_000_000] {
        let q = quote_full(12_345, &[], Some(500), &tiered(), before).unwrap();
        assert_eq!(q.platform_fee, c(617));
    }
}

// ---------- Erros ----------

#[test]
fn invalid_tiers_fail_closed() {
    let cases: Vec<(&str, Vec<PlanTier>)> = vec![
        ("vazio", vec![]),
        (
            "buraco",
            vec![tier(0, Some(100), 0, 800), tier(101, None, 0, 600)],
        ),
        (
            "sobreposto",
            vec![tier(0, Some(100), 0, 800), tier(99, None, 0, 600)],
        ),
        (
            "sem escalão aberto",
            vec![tier(0, Some(100), 0, 800), tier(100, Some(200), 0, 600)],
        ),
        (
            "aberto antes do fim",
            vec![tier(0, None, 0, 800), tier(100, None, 0, 600)],
        ),
        ("não começa em 0", vec![tier(1, None, 0, 800)]),
        (
            "escalão vazio",
            vec![
                tier(0, Some(100), 0, 800),
                tier(100, Some(100), 0, 700),
                tier(100, None, 0, 600),
            ],
        ),
        (
            "fora de ordem",
            vec![tier(100, None, 0, 600), tier(0, Some(100), 0, 800)],
        ),
    ];
    for (name, t) in cases {
        assert!(
            monthly_fee_for(&t, c(0)).err() == Some(MoneyError::InvalidPlanTiers),
            "{name}: monthly_fee_for"
        );
        assert!(
            monthly_fee_for(&t, c(150)).err() == Some(MoneyError::InvalidPlanTiers),
            "{name}: monthly_fee_for"
        );
        assert!(
            quote_full(1000, &[], None, &t, 0).err() == Some(MoneyError::InvalidPlanTiers),
            "{name}: plano"
        );
        // Fail closed mesmo quando a regra ganhadora não é o plano.
        assert!(
            quote_full(1000, &[0], None, &t, 0).err() == Some(MoneyError::InvalidPlanTiers),
            "{name}: patrocinada"
        );
        assert!(
            quote_full(1000, &[], Some(500), &t, 0).err() == Some(MoneyError::InvalidPlanTiers),
            "{name}: exceção"
        );
    }
}

#[test]
fn single_open_tier_is_valid() {
    let t = vec![tier(0, None, 0, 500)];
    assert_eq!(plan(&t, 0, 12_345), (617, 500));
    assert_eq!(monthly(&t, 0), 0);
}

#[test]
fn overflow_is_err_not_panic() {
    for t in [payg(), tiered(), hybrid()] {
        assert_eq!(
            quote_full(1, &[], None, &t, i64::MAX),
            Err(MoneyError::Overflow)
        );
        assert_eq!(
            quote_full(i64::MAX, &[], None, &t, 1),
            Err(MoneyError::Overflow)
        );
        // No limite exato ainda cabe.
        assert!(quote_full(i64::MAX, &[], None, &t, 0).is_ok());
        assert!(quote_full(0, &[], None, &t, i64::MAX).is_ok());
        assert!(quote_full(i64::MAX, &[10_000], Some(10_000), &t, i64::MAX).is_ok());
        assert!(monthly_fee_for(&t, c(i64::MAX)).is_ok());
    }
}

// ---------- Propriedades ----------

fn plans() -> impl Strategy<Value = Vec<PlanTier>> {
    prop_oneof![Just(payg()), Just(tiered()), Just(hybrid())]
}

/// Volumes concentrados perto dos limites e espalhados.
fn volume() -> impl Strategy<Value = i64> {
    prop_oneof![
        0i64..3_000_000,
        prop::sample::select(vec![
            100_000i64, 500_000, 1_000_000, 2_000_000, 2_500_000, 5_000_000, 10_000_000
        ])
        .prop_flat_map(|l| (l - 50)..(l + 50)),
        0i64..(i64::MAX / 4),
    ]
}

fn amount() -> impl Strategy<Value = i64> {
    prop_oneof![0i64..50_000, 0i64..3_000_000, 0i64..(i64::MAX / 4)]
}

proptest! {
    #[test]
    fn split_sale_differs_at_most_one_cent(t in plans(), before in volume(), a in amount(), b2 in amount()) {
        let single = fee_of(&t, before, a + b2);
        let split = fee_of(&t, before, a) + fee_of(&t, before + a, b2);
        prop_assert!((single - split).abs() <= 1, "single {single} vs split {split}");
    }

    #[test]
    fn fee_bounded_and_discount_non_negative(
        t in plans(),
        before in volume(),
        subtotal in amount(),
        overrides in prop::collection::vec(0i32..=10_000, 0..4),
        custom in prop::option::of(0i32..=10_000),
    ) {
        let q = quote_full(subtotal, &overrides, custom, &t, before).unwrap();
        prop_assert!(q.platform_fee.get() >= 0);
        prop_assert!(q.platform_fee.get() <= subtotal);
        prop_assert!(q.sponsored_discount.get() >= 0);
        if overrides.is_empty() {
            prop_assert_eq!(q.sponsored_discount, Cents::ZERO);
        }
    }
}
