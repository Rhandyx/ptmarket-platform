//! Única forma permitida de abrir uma transação: sempre com ator (`AuditCtx`).
//!
//! `begin_tenant_tx` fixa o tenant e o ator; `begin_platform_tx` fixa o ator e deixa o tenant vazio
//! (tabelas globais). Tudo vive em `app.*` com `is_local = true`: morre no COMMIT/ROLLBACK e nunca
//! passa para o pedido seguinte que reutilize a ligação da pool. Nenhuma `Transaction` crua sai daqui.
//!
//! Âmbito por loja/entidade (0035, cartão 03/14): todas as lojas de um país partilham o tenant; as
//! policies RESTRICTIVE comparam `store_id` com `app.store_id` e `sponsor_entity_id` com
//! `app.sponsor_entity_id`. `begin_store_tx` só aceita um `StoreScope` e `begin_sponsor_tx` só um
//! `SponsorScope` (ambos só nascem nos extractores de `identity::rbac`). Todas as transações põem os
//! dois GUCs (`''` = sem âmbito): sem âmbito, `begin_tenant_tx` serve para leitura pública e para o
//! que não é de loja; escrever numa tabela de loja falha na BD (salvo o ator `admin`).
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

use crate::{
    audit::AuditCtx,
    error::AppError,
    identity::rbac::{SponsorScope, StoreScope},
};

/// Identificador de tenant (Câmara). Só se cria no resolver do `Host` (`tenancy::resolver`);
/// fora do crate, só com a feature `test-support` (testes de integração).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

impl TenantId {
    /// Chamado SÓ em `tenancy::resolver` (o tenant vem sempre do `Host`).
    pub(crate) fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Só para testes de integração (`tests/`); não existe em `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn for_tests(id: Uuid) -> Self {
        Self(id)
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
    /// `audit::record` gravou nesta transação; o `AuditCtx` só fica marcado depois do COMMIT.
    recorded: bool,
}

impl TenantTx {
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn audit_ctx(&self) -> &AuditCtx {
        &self.ctx
    }

    /// Confirma; só então o `AuditCtx` fica marcado como registado (se `audit::record` gravou).
    pub async fn commit(self) -> Result<(), AppError> {
        commit_and_mark(self.tx, &self.ctx, self.recorded).await
    }

    pub async fn rollback(self) -> Result<(), AppError> {
        self.tx.rollback().await.map_err(db_error)
    }
}

/// COMMIT e, só se passou, promove a marca pendente de `audit::record` para o `AuditCtx`.
async fn commit_and_mark(
    tx: Transaction<'static, Postgres>,
    ctx: &AuditCtx,
    recorded: bool,
) -> Result<(), AppError> {
    tx.commit().await.map_err(db_error)?;
    if recorded {
        ctx.mark_recorded();
    }
    Ok(())
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
    /// Ver `TenantTx::recorded`.
    recorded: bool,
}

impl PlatformTx {
    pub fn audit_ctx(&self) -> &AuditCtx {
        &self.ctx
    }

    /// Confirma; só então o `AuditCtx` fica marcado como registado (se `audit::record` gravou).
    pub async fn commit(self) -> Result<(), AppError> {
        commit_and_mark(self.tx, &self.ctx, self.recorded).await
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
        /// Chamado por `audit::record` depois de gravar: a marca só passa ao `AuditCtx` no COMMIT.
        fn mark_recorded_on_commit(&mut self);
    }
}

/// Transação com ator fixado (`TenantTx` ou `PlatformTx`); selada.
pub trait AuditedTx: sealed::Sealed {}

impl sealed::Sealed for TenantTx {
    fn parts(&mut self) -> (&mut PgConnection, &AuditCtx) {
        (&mut self.tx, &self.ctx)
    }
    fn mark_recorded_on_commit(&mut self) {
        self.recorded = true;
    }
}
impl AuditedTx for TenantTx {}

impl sealed::Sealed for PlatformTx {
    fn parts(&mut self) -> (&mut PgConnection, &AuditCtx) {
        (&mut self.tx, &self.ctx)
    }
    fn mark_recorded_on_commit(&mut self) {
        self.recorded = true;
    }
}
impl AuditedTx for PlatformTx {}

/// Modo da transação quanto ao portal nacional (`app.portal_national`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PortalMode {
    /// `''`: a flag fica explicitamente desligada (só o tenant do contexto).
    Off,
    /// `'on'`: só tem efeito se o tenant do contexto for um `national_portal` ativo (BD, 0016).
    On,
}

/// Âmbito da transação (GUCs `app.store_id` / `app.sponsor_entity_id`, policies da 0035).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    None,
    Store(Uuid),
    Sponsor(Uuid),
}

/// Como `set_context_scoped`, sem âmbito de loja nem de entidade (portal e transações sem loja).
pub(super) async fn set_context(
    conn: &mut PgConnection,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    portal: PortalMode,
) -> Result<(), AppError> {
    set_context_scoped(conn, tenant, ctx, portal, Scope::None).await
}

/// Fixa tenant, ator, sessão (`app.session_id`), modo portal e âmbito (`app.store_id`,
/// `app.sponsor_entity_id`) só para esta transação: uma query, `set_config(..., true)`
/// (= `SET LOCAL`), valores sempre por parâmetro. `''` = sem valor (as funções da BD fazem
/// `NULLIF(..., '')`); os dois GUCs de âmbito são sempre postos (nunca herdados).
async fn set_context_scoped(
    conn: &mut PgConnection,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    portal: PortalMode,
    scope: Scope,
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
    let session_id = text(ctx.session_id());
    let portal = match portal {
        PortalMode::Off => "",
        PortalMode::On => "on",
    };
    let (store_id, sponsor_entity_id) = match scope {
        Scope::None => (String::new(), String::new()),
        Scope::Store(id) => (id.to_string(), String::new()),
        Scope::Sponsor(id) => (String::new(), id.to_string()),
    };
    sqlx::query!(
        "SELECT set_config('app.current_tenant_id', $1, true) AS tenant_id,
                set_config('app.actor_type', $2, true) AS actor_type,
                set_config('app.actor_id', $3, true) AS actor_id,
                set_config('app.actor_label', $4, true) AS actor_label,
                set_config('app.impersonator_id', $5, true) AS impersonator_id,
                set_config('app.request_id', $6, true) AS request_id,
                set_config('app.ip', $7, true) AS ip,
                set_config('app.user_agent_hash', $8, true) AS user_agent_hash,
                set_config('app.portal_national', $9, true) AS portal_national,
                set_config('app.session_id', $10, true) AS session_id,
                set_config('app.store_id', $11, true) AS store_id,
                set_config('app.sponsor_entity_id', $12, true) AS sponsor_entity_id",
        tenant_id,
        actor_type,
        actor_id,
        actor_label,
        impersonator_id,
        request_id,
        ip,
        ua_hash,
        portal,
        session_id,
        store_id,
        sponsor_entity_id
    )
    .fetch_one(conn)
    .await
    .map_err(db_error)?;
    Ok(())
}

/// Abre uma transação com o tenant e o ator fixados só para ela, sem âmbito de loja nem de entidade
/// (leitura pública e o que não é de loja; escrever numa tabela de loja falha na BD).
pub async fn begin_tenant_tx(
    pool: &PgPool,
    tenant: TenantId,
    ctx: &AuditCtx,
) -> Result<TenantTx, AppError> {
    begin_scoped(pool, tenant, ctx, Scope::None).await
}

/// Abre uma transação no tenant da loja com `app.store_id` = a loja do `StoreScope` (provado por
/// `RequireStoreRole`/`RequireStoreOwner`): só lê e escreve as linhas dessa loja (0035).
pub async fn begin_store_tx(
    pool: &PgPool,
    scope: &StoreScope,
    ctx: &AuditCtx,
) -> Result<TenantTx, AppError> {
    begin_scoped(pool, scope.tenant(), ctx, Scope::Store(scope.store_id())).await
}

/// Abre uma transação com `app.sponsor_entity_id` = a entidade do `SponsorScope` (provado por
/// `RequireSponsorAdmin`). `tenant` TEM de ser o canal nacional do país da entidade (onde vivem as
/// lojas e os patrocínios); outro tenant não vê patrocínio nenhum (`tenant_isolation`).
pub async fn begin_sponsor_tx(
    pool: &PgPool,
    tenant: TenantId,
    scope: &SponsorScope,
    ctx: &AuditCtx,
) -> Result<TenantTx, AppError> {
    begin_scoped(pool, tenant, ctx, Scope::Sponsor(scope.entity_id())).await
}

async fn begin_scoped(
    pool: &PgPool,
    tenant: TenantId,
    ctx: &AuditCtx,
    scope: Scope,
) -> Result<TenantTx, AppError> {
    let mut tx = pool.begin().await.map_err(db_error)?;
    set_context_scoped(&mut tx, Some(tenant), ctx, PortalMode::Off, scope).await?;
    Ok(TenantTx {
        tenant,
        ctx: ctx.clone(),
        tx,
        recorded: false,
    })
}

/// Abre uma transação de plataforma (sem tenant; tabelas globais) com o ator fixado só para ela.
pub async fn begin_platform_tx(pool: &PgPool, ctx: &AuditCtx) -> Result<PlatformTx, AppError> {
    let mut tx = pool.begin().await.map_err(db_error)?;
    set_context(&mut tx, None, ctx, PortalMode::Off).await?;
    Ok(PlatformTx {
        ctx: ctx.clone(),
        tx,
        recorded: false,
    })
}
