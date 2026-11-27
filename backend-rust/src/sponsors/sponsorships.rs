//! Patrocínios de uma loja (`store_sponsorships`) vistos pelo cálculo da comissão (spec 14 §3).
//!
//! "Ativo" = `status = 'active' AND at <@ tstzrange(valid_from, valid_to)`: nunca depende do job que
//! passa a `expired`. A leitura exige um `TenantTx` já com o âmbito da loja (ou ator admin): a RLS
//! (0035) esconde os patrocínios das outras lojas; o filtro por `tenant_id` e `store_id` vai na query.

use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::{
    error::AppError,
    money::Bps,
    tenancy::{TenantTx, db::db_error},
};

/// `commission_override_bps` com que nasce um patrocínio (DEFAULT da coluna, 0031): a previsão do
/// formulário de registo mostra este valor; o efetivo é sempre o da linha `active`.
pub const NEW_SPONSORSHIP_OVERRIDE_BPS: Bps = Bps::ZERO;

/// Patrocínio ativo no instante pedido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveSponsorship {
    pub sponsor_entity_id: Uuid,
    pub override_bps: Bps,
}

/// Microssegundos desde a época Unix (negativos antes de 1970); fora de `i64` → erro.
pub(crate) fn epoch_micros(at: SystemTime) -> Result<i64, AppError> {
    let out_of_range = || AppError::Internal(anyhow::anyhow!("instante fora do intervalo"));
    match at.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_micros()).map_err(|_| out_of_range()),
        Err(e) => i64::try_from(e.duration().as_micros())
            .map(|m| -m)
            .map_err(|_| out_of_range()),
    }
}

/// Patrocínios `active` da loja com `at` dentro da vigência, ordenados pela entidade.
pub async fn active_at(
    tx: &mut TenantTx,
    store_id: Uuid,
    at: SystemTime,
) -> Result<Vec<ActiveSponsorship>, AppError> {
    let tenant = tx.tenant().as_uuid();
    let at = epoch_micros(at)?;
    let rows = sqlx::query!(
        "SELECT sponsor_entity_id, commission_override_bps FROM store_sponsorships
         WHERE tenant_id = $1 AND store_id = $2 AND status = 'active'
           AND ('epoch'::timestamptz + $3::int8 * interval '1 microsecond')
               <@ tstzrange(valid_from, valid_to)
         ORDER BY sponsor_entity_id",
        tenant,
        store_id,
        at
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    rows.into_iter()
        .map(|r| {
            Ok(ActiveSponsorship {
                sponsor_entity_id: r.sponsor_entity_id,
                override_bps: Bps::new(r.commission_override_bps)
                    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?,
            })
        })
        .collect()
}
