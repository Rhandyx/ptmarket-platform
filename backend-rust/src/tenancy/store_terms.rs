//! Condições comerciais de uma loja para o cálculo da comissão (spec 14 §3): exceção negociada,
//! plano de faturação e freguesia da montra. Nunca IBAN, NIF nem chaves.
//!
//! A leitura exige um `TenantTx` já com o âmbito da loja (ou ator admin): sem isso a RLS (0035)
//! esconde a linha e a função falha fechado (`NotFound`), nunca devolve valores por defeito.

use uuid::Uuid;

use crate::{
    error::AppError,
    money::Bps,
    tenancy::{TenantTx, db::db_error},
};

/// O que a comissão precisa de saber da loja.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreCommissionTerms {
    pub custom_commission_bps: Option<Bps>,
    pub billing_plan_code: String,
    pub storefront_dicofre: Option<String>,
}

/// Condições da loja `store_id` no tenant do tx; loja invisível no tx (outra loja, outro tenant ou
/// inexistente) → `NotFound`.
pub async fn commission_terms(
    tx: &mut TenantTx,
    store_id: Uuid,
) -> Result<StoreCommissionTerms, AppError> {
    let tenant = tx.tenant().as_uuid();
    let row = sqlx::query!(
        "SELECT custom_commission_bps, billing_plan_code, storefront_dicofre FROM stores
         WHERE id = $1 AND tenant_id = $2",
        store_id,
        tenant
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or(AppError::NotFound)?;
    let custom_commission_bps = row
        .custom_commission_bps
        .map(Bps::new)
        .transpose()
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    Ok(StoreCommissionTerms {
        custom_commission_bps,
        billing_plan_code: row.billing_plan_code,
        storefront_dicofre: row.storefront_dicofre,
    })
}
