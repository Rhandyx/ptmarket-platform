//! Outbox transacional (D3): o evento é gravado NA MESMA transação que a alteração
//! de negócio. Um worker publica-o depois; um handler nunca publica no Redis.
//!
//! O tenant do evento nunca vem do chamador: `append` usa o da `TenantTx`; `append_global`
//! (módulos de sistema) recebe uma transação sem contexto de tenant. O RLS recusa (42501)
//! evento global com contexto de tenant e evento de tenant fora do seu contexto.

use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppError,
    tenancy::{TenantTx, db::db_error},
};

/// Evento a gravar (o tenant vem da transação, não daqui).
#[derive(Debug, Clone)]
pub struct NewEvent {
    pub aggregate: String,
    pub aggregate_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
}

/// Grava um evento do tenant da transação e devolve o id (UUIDv7 gerado em Rust).
pub async fn append(tx: &mut TenantTx, ev: NewEvent) -> Result<Uuid, AppError> {
    let tenant_id = tx.tenant().as_uuid();
    insert(tx, Some(tenant_id), ev).await
}

/// Grava um evento global (`tenant_id = NULL`) numa transação SEM contexto de tenant.
/// Uma `TenantTx` não é aceite por tipo; numa transação com contexto o RLS devolve `Err`.
pub async fn append_global(
    tx: &mut Transaction<'_, Postgres>,
    ev: NewEvent,
) -> Result<Uuid, AppError> {
    insert(tx, None, ev).await
}

/// Sem `RETURNING`: a app só tem INSERT em `outbox_events` (o RLS bloqueia a leitura).
async fn insert(
    conn: &mut PgConnection,
    tenant_id: Option<Uuid>,
    ev: NewEvent,
) -> Result<Uuid, AppError> {
    let id = Uuid::now_v7();
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
    .execute(conn)
    .await
    .map_err(db_error)?;
    Ok(id)
}
