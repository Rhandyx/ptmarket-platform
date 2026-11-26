//! Peças partilhadas pelo 2FA (cartão 02/20) e pelas passkeys (cartão 02/21): a transação do
//! próprio no tenant do host ou na plataforma, a sessão nova já elevada e a recusa de sessões de
//! impersonação nas ações de segurança da conta.

use axum::{
    Extension,
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use sqlx::PgConnection;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    audit::{Actor, ActorType, AuditCtx, AuditEvent, Denied, Outcome, record},
    error::AppError,
    identity::{
        http::CurrentSession,
        login::{ACTION_LOGOUT, REASON_SUPERSEDED},
        session::{self, CookieValue, SessionId, Subject},
    },
    outbox::{self, NewEvent},
    tenancy::{
        TenantId, TenantTx, begin_tenant_tx,
        db::{PlatformTx, begin_platform_tx, db_error},
    },
};

/// Sessão de impersonação numa ação de segurança da conta (2FA, passkeys).
pub const DENIED_IMPERSONATION: Denied = Denied("impersonation");

/// Recusa sessões de impersonação: 403 + `Denied("impersonation")` (gravado pela caixa negra).
/// Pôr DEPOIS do extractor de staff (sem sessão → 401 primeiro).
#[derive(Debug, Clone, Copy)]
pub struct NoImpersonation;

impl<S: Send + Sync> FromRequestParts<S> for NoImpersonation {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let impersonated = parts
            .extensions
            .get::<Actor>()
            .is_some_and(|a| a.impersonator_id.is_some());
        if impersonated {
            return Err((Extension(DENIED_IMPERSONATION), AppError::Forbidden).into_response());
        }
        Ok(Self)
    }
}

/// Transação do próprio: no tenant do host (`Some`) ou na plataforma (`None`).
pub(crate) enum OwnTx {
    Tenant(TenantTx),
    Platform(PlatformTx),
}

impl OwnTx {
    pub(crate) async fn begin(
        db: &PgPool,
        tenant: Option<TenantId>,
        ctx: &AuditCtx,
    ) -> Result<Self, AppError> {
        Ok(match tenant {
            Some(t) => Self::Tenant(begin_tenant_tx(db, t, ctx).await?),
            None => Self::Platform(begin_platform_tx(db, ctx).await?),
        })
    }

    pub(crate) fn conn(&mut self) -> &mut PgConnection {
        match self {
            Self::Tenant(t) => t,
            Self::Platform(p) => p,
        }
    }

    pub(crate) async fn record(&mut self, ev: AuditEvent) -> Result<(), AppError> {
        match self {
            Self::Tenant(t) => record(t, ev).await.map(|_| ()),
            Self::Platform(p) => record(p, ev).await.map(|_| ()),
        }
    }

    /// Evento no outbox na MESMA transação (do tenant ou global, conforme a transação).
    pub(crate) async fn outbox(&mut self, ev: NewEvent) -> Result<(), AppError> {
        match self {
            Self::Tenant(t) => outbox::append(t, ev).await.map(|_| ()),
            Self::Platform(p) => outbox::append_global(p, ev).await.map(|_| ()),
        }
    }

    pub(crate) async fn revoke(&mut self, id: SessionId) -> Result<(), AppError> {
        match self {
            Self::Tenant(t) => session::revoke(t, id).await.map(|_| ()),
            Self::Platform(p) => session::revoke(p, id).await.map(|_| ()),
        }
    }

    /// `session::rotate` (revoga `old`, se houver) + `mfa_verified_at = now()` na sessão nova.
    pub(crate) async fn open_elevated(
        &mut self,
        old: Option<SessionId>,
        user: Uuid,
        tenant: Option<TenantId>,
        ctx: &AuditCtx,
    ) -> Result<(SessionId, CookieValue), AppError> {
        let subject = Subject::User(user);
        let (sid, value) = match self {
            Self::Tenant(t) => session::rotate(t, old, subject, tenant, ctx).await?,
            Self::Platform(p) => session::rotate(p, old, subject, tenant, ctx).await?,
        };
        let r = sqlx::query!(
            "UPDATE sessions SET mfa_verified_at = now() WHERE id = $1 AND revoked_at IS NULL",
            sid.as_uuid()
        )
        .execute(self.conn())
        .await
        .map_err(db_error)?;
        if r.rows_affected() != 1 {
            return Err(AppError::Internal(anyhow::anyhow!(
                "sessão nova não elevada"
            )));
        }
        Ok((sid, value))
    }

    pub(crate) async fn commit(self) -> Result<(), AppError> {
        match self {
            Self::Tenant(t) => t.commit().await,
            Self::Platform(p) => p.commit().await,
        }
    }
}

/// Sessão anterior deste browser, se for do mesmo sujeito (revogada na transação do login).
pub(crate) fn own_previous(cur: &CurrentSession, subject: Subject) -> Option<SessionId> {
    let actor = cur.actor()?;
    let same = match subject {
        Subject::Customer(id) => {
            actor.actor_type == ActorType::Customer && actor.actor_id == Some(id)
        }
        Subject::User(id) => {
            matches!(
                actor.actor_type,
                ActorType::Merchant | ActorType::Municipal | ActorType::Admin
            ) && actor.actor_id == Some(id)
        }
    };
    same.then(|| cur.info().map(|i| i.id)).flatten()
}

/// O browser tinha a sessão de OUTRO sujeito: revogada com o ator dela (`ctx`, o do pedido) e
/// `auth.logout` (`superseded_by_login`) na mesma transação. O cookie já foi substituído; uma
/// falha aqui só fica no log (a sessão antiga deixa de ter cookie).
pub(crate) async fn revoke_foreign_session(
    db: &PgPool,
    cur: &CurrentSession,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    subject: Subject,
) {
    let (Some(info), Some(_)) = (cur.info(), cur.actor()) else {
        return;
    };
    if own_previous(cur, subject).is_some() {
        return;
    }
    let res = async {
        let mut tx = OwnTx::begin(db, tenant, ctx).await?;
        tx.revoke(info.id).await?;
        tx.record(AuditEvent {
            action: ACTION_LOGOUT,
            target_type: Some("session"),
            target_id: Some(info.id.as_uuid().to_string()),
            outcome: Outcome::Success,
            reason: Some(REASON_SUPERSEDED.to_owned()),
            changes: None,
            store_id: None,
        })
        .await?;
        tx.commit().await
    }
    .await;
    match res {
        Ok(()) => forget(cur, info.id).await,
        Err(e) => {
            tracing::warn!(error = ?e, "login: sessão anterior de outro sujeito não revogada")
        }
    }
}

/// Esquece a inatividade da sessão `id` (a revogação na BD é o que vale; isto só limpa).
pub(crate) async fn forget(cur: &CurrentSession, id: SessionId) {
    let s = cur.sessions();
    if let Err(e) = session::forget(s.redis(), s.ns(), id).await {
        tracing::warn!(error = ?e, "login: chave de inatividade da sessão anterior não apagada");
    }
}
