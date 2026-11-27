//! Comissão efetiva de uma venda com os dados da BD (spec 14 §3, §4, §6).
//!
//! Dono de `platform_settings` (comissão base) e `billing_plan_tiers` (escalões). Os patrocínios
//! vêm de `sponsors::sponsorships`, as condições da loja de `tenancy::store_terms`; a conta é só a
//! de `money::effective_commission` (nenhuma aritmética de dinheiro aqui). A comissão não depende
//! do domínio onde a compra foi feita.
//!
//! Fail closed (nunca 0 % por engano): loja invisível no tx → `NotFound`; sem `platform_settings`,
//! plano sem escalões ou escalões inválidos → `Internal`. Aqui não se grava nada: o snapshot é
//! congelado em `sub_orders` pelo épico de encomendas.

use std::time::SystemTime;

use serde::Serialize;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    error::AppError,
    money::{self, Bps, Cents, CommissionInput, CommissionQuote, PlanTier},
    sponsors::sponsorships,
    tenancy::{TenantTx, db::db_error, store_terms},
};

/// Plano por defeito de uma loja nova (DEFAULT de `stores.billing_plan_code`, 0029).
pub const DEFAULT_PLAN_CODE: &str = "commission_payg";

/// O que o épico de encomendas congela em `sub_orders` para uma venda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommissionSnapshot {
    pub quote: CommissionQuote,
    pub billing_plan_code: String,
    pub store_monthly_gmv_before: Cents,
    /// Entidades com patrocínio ativo no instante, ordenadas e sem repetidos.
    pub active_sponsor_ids: Vec<Uuid>,
    pub store_dicofre: Option<String>,
}

/// Escalão para mostrar (só inteiros: cêntimos e bps). Cobre o volume mensal em `]from, to]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PlanTierView {
    pub gmv_from_cents: i64,
    /// `null` = sem teto.
    pub gmv_to_cents: Option<i64>,
    pub monthly_fee_cents: i64,
    pub marginal_commission_bps: i32,
}

/// Plano com os seus escalões, por ordem de volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PlanView {
    pub plan_code: String,
    /// `true` só para o plano com que uma loja nasce.
    pub is_default: bool,
    pub tiers: Vec<PlanTierView>,
}

/// Valor da BD fora do domínio de `money`: erro da plataforma (500), nunca do pedido.
fn bad_data(e: money::MoneyError) -> AppError {
    AppError::Internal(anyhow::anyhow!("dados de comissão inválidos: {e}"))
}

/// `platform_settings.base_commission_bps`; sem a linha → `Internal`.
pub async fn base_commission_bps(db: &mut PgConnection) -> Result<Bps, AppError> {
    let bps = sqlx::query_scalar!("SELECT base_commission_bps FROM platform_settings WHERE id")
        .fetch_optional(db)
        .await
        .map_err(db_error)?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("platform_settings sem linha")))?;
    Bps::new(bps).map_err(bad_data)
}

/// Escalões do plano por ordem de volume; plano sem escalões → `Internal`.
pub async fn plan_tiers(db: &mut PgConnection, plan_code: &str) -> Result<Vec<PlanTier>, AppError> {
    let rows = sqlx::query!(
        "SELECT gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps
         FROM billing_plan_tiers WHERE plan_code = $1 ORDER BY gmv_from_cents",
        plan_code
    )
    .fetch_all(db)
    .await
    .map_err(db_error)?;
    if rows.is_empty() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "plano {plan_code} sem escalões"
        )));
    }
    rows.into_iter()
        .map(|r| {
            Ok(PlanTier {
                gmv_from: Cents::new(r.gmv_from_cents).map_err(bad_data)?,
                gmv_to: r
                    .gmv_to_cents
                    .map(Cents::new)
                    .transpose()
                    .map_err(bad_data)?,
                monthly_fee: Cents::new(r.monthly_fee_cents).map_err(bad_data)?,
                marginal_bps: Bps::new(r.marginal_commission_bps).map_err(bad_data)?,
            })
        })
        .collect()
}

/// Todos os planos com escalões (o por defeito primeiro, depois por código), para o registo.
pub async fn plans(db: &mut PgConnection) -> Result<Vec<PlanView>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT plan_code, (plan_code = $1) AS "is_default!", gmv_from_cents, gmv_to_cents,
                  monthly_fee_cents, marginal_commission_bps
           FROM billing_plan_tiers
           ORDER BY (plan_code = $1) DESC, plan_code, gmv_from_cents"#,
        DEFAULT_PLAN_CODE
    )
    .fetch_all(db)
    .await
    .map_err(db_error)?;
    let mut out: Vec<PlanView> = Vec::new();
    for r in rows {
        let tier = PlanTierView {
            gmv_from_cents: r.gmv_from_cents,
            gmv_to_cents: r.gmv_to_cents,
            monthly_fee_cents: r.monthly_fee_cents,
            marginal_commission_bps: r.marginal_commission_bps,
        };
        match out.last_mut() {
            Some(p) if p.plan_code == r.plan_code => p.tiers.push(tier),
            _ => out.push(PlanView {
                plan_code: r.plan_code,
                is_default: r.is_default,
                tiers: vec![tier],
            }),
        }
    }
    Ok(out)
}

/// Comissão efetiva da venda de `subtotal` (produtos com IVA, sem portes) da loja `store_id` no
/// instante `at`, com `store_monthly_gmv_cents` já acumulado no mês antes desta venda.
///
/// `tx` TEM de vir com o âmbito da loja (`begin_store_tx`) ou com ator admin: outra loja → `NotFound`.
/// Precedência (em `money`): patrocinada (MIN dos overrides ativos) → exceção → plano.
pub async fn effective_commission_bps(
    tx: &mut TenantTx,
    store_id: Uuid,
    at: SystemTime,
    store_monthly_gmv_cents: Cents,
    subtotal: Cents,
) -> Result<CommissionSnapshot, AppError> {
    // A loja primeiro: invisível no tx → erro antes de qualquer outra leitura.
    let terms = store_terms::commission_terms(tx, store_id).await?;
    let active = sponsorships::active_at(tx, store_id, at).await?;
    let base = base_commission_bps(tx).await?;
    let tiers = plan_tiers(tx, &terms.billing_plan_code).await?;

    let overrides: Vec<Bps> = active.iter().map(|s| s.override_bps).collect();
    let quote = money::effective_commission(&CommissionInput {
        subtotal,
        active_sponsor_overrides: &overrides,
        custom_commission_bps: terms.custom_commission_bps,
        base_commission_bps: base,
        plan_tiers: &tiers,
        store_monthly_gmv_before: store_monthly_gmv_cents,
    })?;

    let mut active_sponsor_ids: Vec<Uuid> = active.iter().map(|s| s.sponsor_entity_id).collect();
    active_sponsor_ids.sort_unstable();
    active_sponsor_ids.dedup();

    Ok(CommissionSnapshot {
        quote,
        billing_plan_code: terms.billing_plan_code,
        store_monthly_gmv_before: store_monthly_gmv_cents,
        active_sponsor_ids,
        store_dicofre: terms.storefront_dicofre,
    })
}
