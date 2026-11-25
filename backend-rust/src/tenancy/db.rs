//! Única forma permitida de abrir uma transação com contexto de tenant.
//!
//! O contexto vive em `app.current_tenant_id` com `is_local = true`: morre no
//! COMMIT/ROLLBACK e nunca passa para o pedido seguinte que reutilize a ligação da pool.

use std::ops::{Deref, DerefMut};

use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::AppError;

/// Identificador de tenant (Câmara). Só se cria dentro do crate (extractor que resolve o Host);
/// fora dele, só com a feature `test-support` (testes de integração).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

impl TenantId {
    #[allow(
        dead_code,
        reason = "consumido pelo extractor que resolve o Host (cartão futuro)"
    )]
    pub(crate) fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Só para testes de integração (`tests/`); não existe em `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn for_tests(id: Uuid) -> Self {
        Self::new(id)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

/// Erros da BD nunca saem para o cliente: viram `AppError::Internal` (mensagem genérica).
pub(crate) fn db_error(e: sqlx::Error) -> AppError {
    AppError::Internal(anyhow::Error::new(e))
}

/// Transação com contexto de tenant fixado. Guarda o `TenantId` (fonte única do tenant para
/// `outbox::append`) e dá acesso à ligação por `Deref`; a `Transaction` interna nunca sai daqui,
/// por isso não pode ser passada a `outbox::append_global`.
#[derive(Debug)]
pub struct TenantTx {
    tenant: TenantId,
    tx: Transaction<'static, Postgres>,
}

impl TenantTx {
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub async fn commit(self) -> Result<(), AppError> {
        self.tx.commit().await.map_err(db_error)
    }

    pub async fn rollback(self) -> Result<(), AppError> {
        self.tx.rollback().await.map_err(db_error)
    }
}

impl Deref for TenantTx {
    type Target = PgConnection;

    fn deref(&self) -> &PgConnection {
        &self.tx
    }
}

impl DerefMut for TenantTx {
    fn deref_mut(&mut self) -> &mut PgConnection {
        &mut self.tx
    }
}

/// Abre uma transação e fixa o tenant só para ela (`set_config(..., true)` = `SET LOCAL`).
pub async fn begin_tenant_tx(pool: &PgPool, tenant: TenantId) -> Result<TenantTx, AppError> {
    let mut tx = pool.begin().await.map_err(db_error)?;
    let tenant_text = tenant.0.to_string();
    sqlx::query!(
        "SELECT set_config('app.current_tenant_id', $1, true)",
        tenant_text
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(db_error)?;
    Ok(TenantTx { tenant, tx })
}
