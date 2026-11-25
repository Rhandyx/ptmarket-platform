//! Única forma permitida de abrir uma transação com contexto de tenant.
//!
//! O contexto vive em `app.current_tenant_id` com `is_local = true`: morre no
//! COMMIT/ROLLBACK e nunca passa para o pedido seguinte que reutilize a ligação da pool.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::AppError;

/// Identificador de tenant (Câmara). Só se obtém a partir de um `Uuid` já validado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

impl TenantId {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for TenantId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

/// Erros da BD nunca saem para o cliente: viram `AppError::Internal` (mensagem genérica).
pub(crate) fn db_error(e: sqlx::Error) -> AppError {
    AppError::Internal(anyhow::Error::new(e))
}

/// Abre uma transação e fixa o tenant só para ela (`set_config(..., true)` = `SET LOCAL`).
pub async fn begin_tenant_tx(
    pool: &PgPool,
    tenant: TenantId,
) -> Result<Transaction<'static, Postgres>, AppError> {
    let mut tx = pool.begin().await.map_err(db_error)?;
    let tenant_text = tenant.0.to_string();
    sqlx::query!(
        "SELECT set_config('app.current_tenant_id', $1, true)",
        tenant_text
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(db_error)?;
    Ok(tx)
}
