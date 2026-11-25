//! Outbox transacional (D3): o evento é gravado NA MESMA transação que a alteração
//! de negócio. Um worker publica-o depois; um handler nunca publica no Redis.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppError,
    tenancy::{TenantId, db::db_error},
};

/// Evento a gravar. `tenant_id = None` = evento global.
#[derive(Debug, Clone)]
pub struct NewEvent {
    pub tenant_id: Option<TenantId>,
    pub aggregate: String,
    pub aggregate_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
}

/// Grava o evento na transação recebida e devolve o id (UUIDv7 gerado em Rust).
///
/// Sem `RETURNING`: a app só tem INSERT em `outbox_events` (o RLS bloqueia a leitura).
/// Um `tenant_id` diferente do contexto da transação é recusado pelo RLS (`Err`).
pub async fn append(tx: &mut Transaction<'_, Postgres>, ev: NewEvent) -> Result<Uuid, AppError> {
    let id = Uuid::now_v7();
    let tenant_id = ev.tenant_id.map(|t| t.as_uuid());
    sqlx::query!(
        "INSERT INTO outbox_events (id, tenant_id, aggregate, aggregate_id, event_type, payload)
         VALUES ($1, $2, $3, $4, $5, $6)",
        id,
        tenant_id,
        ev.aggregate,
        ev.aggregate_id,
        ev.event_type,
        ev.payload
    )
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(id)
}
