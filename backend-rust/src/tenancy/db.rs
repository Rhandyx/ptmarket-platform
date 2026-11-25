//! Única forma permitida de abrir uma transação: sempre com ator (`AuditCtx`).
//!
//! `begin_tenant_tx` fixa o tenant e o ator; `begin_platform_tx` fixa o ator e deixa o tenant vazio
//! (tabelas globais). Tudo vive em `app.*` com `is_local = true`: morre no COMMIT/ROLLBACK e nunca
//! passa para o pedido seguinte que reutilize a ligação da pool. Nenhuma `Transaction` crua sai daqui.
//!
//! Sem `AuditCtx` não compila:
//! ```compile_fail
//! # async fn f(pool: &sqlx::PgPool, tenant: ptmarket_api::tenancy::TenantId) {
//! let _tx = ptmarket_api::tenancy::begin_tenant_tx(pool, tenant).await;
//! # }
//! ```
//! ```compile_fail
//! # async fn f(pool: &sqlx::PgPool) {
//! let _tx = ptmarket_api::tenancy::db::begin_platform_tx(pool).await;
//! # }
//! ```

use std::ops::{Deref, DerefMut};

use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{audit::AuditCtx, error::AppError};

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

/// Transação com contexto de tenant e de ator fixados. Guarda o `TenantId` (fonte única do tenant
/// para `outbox::append`) e o `AuditCtx` (para `audit::record`); dá acesso à ligação por `Deref`.
#[derive(Debug)]
pub struct TenantTx {
    tenant: TenantId,
    ctx: AuditCtx,
    tx: Transaction<'static, Postgres>,
}

impl TenantTx {
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn audit_ctx(&self) -> &AuditCtx {
        &self.ctx
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

/// Transação de plataforma (sem tenant: `app.current_tenant_id` vazio), com ator fixado.
/// É a única que `outbox::append_global` aceita.
#[derive(Debug)]
pub struct PlatformTx {
    ctx: AuditCtx,
    tx: Transaction<'static, Postgres>,
}

impl PlatformTx {
    pub fn audit_ctx(&self) -> &AuditCtx {
        &self.ctx
    }

    pub async fn commit(self) -> Result<(), AppError> {
        self.tx.commit().await.map_err(db_error)
    }

    pub async fn rollback(self) -> Result<(), AppError> {
        self.tx.rollback().await.map_err(db_error)
    }
}

impl Deref for PlatformTx {
    type Target = PgConnection;

    fn deref(&self) -> &PgConnection {
        &self.tx
    }
}

impl DerefMut for PlatformTx {
    fn deref_mut(&mut self) -> &mut PgConnection {
        &mut self.tx
    }
}

pub(crate) mod sealed {
    use sqlx::PgConnection;

    use crate::audit::AuditCtx;

    /// Fora do crate não se nomeia: só `TenantTx` e `PlatformTx` implementam `AuditedTx`.
    pub trait Sealed {
        fn parts(&mut self) -> (&mut PgConnection, &AuditCtx);
    }
}

/// Transação com ator fixado (`TenantTx` ou `PlatformTx`); selada.
pub trait AuditedTx: sealed::Sealed {}

impl sealed::Sealed for TenantTx {
    fn parts(&mut self) -> (&mut PgConnection, &AuditCtx) {
        (&mut self.tx, &self.ctx)
    }
}
impl AuditedTx for TenantTx {}

impl sealed::Sealed for PlatformTx {
    fn parts(&mut self) -> (&mut PgConnection, &AuditCtx) {
        (&mut self.tx, &self.ctx)
    }
}
impl AuditedTx for PlatformTx {}

/// Fixa tenant e ator só para esta transação: uma query, `set_config(..., true)` (= `SET LOCAL`),
/// valores sempre por parâmetro. `''` = sem valor (as funções da BD fazem `NULLIF(..., '')`).
async fn set_context(
    conn: &mut PgConnection,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
) -> Result<(), AppError> {
    fn text<T: ToString>(v: Option<T>) -> String {
        v.map(|x| x.to_string()).unwrap_or_default()
    }
    let tenant_id = text(tenant.map(|t| t.0));
    let actor_type = ctx.actor_type().as_str();
    let actor_id = text(ctx.actor_id());
    let actor_label = ctx.actor_label().unwrap_or_default();
    let impersonator_id = text(ctx.impersonator_id());
    let request_id = ctx.request_id().to_string();
    let ip = text(ctx.ip());
    let ua_hash = ctx.user_agent_hash_hex();
    sqlx::query!(
        "SELECT set_config('app.current_tenant_id', $1, true) AS tenant_id,
                set_config('app.actor_type', $2, true) AS actor_type,
                set_config('app.actor_id', $3, true) AS actor_id,
                set_config('app.actor_label', $4, true) AS actor_label,
                set_config('app.impersonator_id', $5, true) AS impersonator_id,
                set_config('app.request_id', $6, true) AS request_id,
                set_config('app.ip', $7, true) AS ip,
                set_config('app.user_agent_hash', $8, true) AS user_agent_hash",
        tenant_id,
        actor_type,
        actor_id,
        actor_label,
        impersonator_id,
        request_id,
        ip,
        ua_hash
    )
    .fetch_one(conn)
    .await
    .map_err(db_error)?;
    Ok(())
}

/// Abre uma transação com o tenant e o ator fixados só para ela.
pub async fn begin_tenant_tx(
    pool: &PgPool,
    tenant: TenantId,
    ctx: &AuditCtx,
) -> Result<TenantTx, AppError> {
    let mut tx = pool.begin().await.map_err(db_error)?;
    set_context(&mut tx, Some(tenant), ctx).await?;
    Ok(TenantTx {
        tenant,
        ctx: ctx.clone(),
        tx,
    })
}

/// Abre uma transação de plataforma (sem tenant; tabelas globais) com o ator fixado só para ela.
pub async fn begin_platform_tx(pool: &PgPool, ctx: &AuditCtx) -> Result<PlatformTx, AppError> {
    let mut tx = pool.begin().await.map_err(db_error)?;
    set_context(&mut tx, None, ctx).await?;
    Ok(PlatformTx {
        ctx: ctx.clone(),
        tx,
    })
}
