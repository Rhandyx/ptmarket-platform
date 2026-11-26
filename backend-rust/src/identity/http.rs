//! HTTP das sessões (cartão 02/16): layer de autenticação, extractores e
//! `GET /api/v1/auth/session` / `POST /api/v1/auth/logout`.
//!
//! Ordem (de fora para dentro): `resolve_host` → `authenticate` (esta; nunca recusa, salvo 503
//! com a BD/Redis em baixo) → `AuditClass` → caixa negra → `csrf_guard` → handler.
//!
//! `authenticate`: cookie do host (`__Host-ptm_session` em tenant, `__Host-ptm_admin` na
//! plataforma) → sha256 → `identity_session_lookup` → a sessão só vale se `tenant_id` = tenant do
//! `Host` (ou NULL no host de plataforma) e se estiver ativa no Redis → põe `Actor` + `SessionInfo`
//! nas extensões. Cookie inválido, expirado, revogado, inativo ou de outro tenant = anónimo, e o
//! cookie é limpo na resposta.

use std::{sync::Arc, time::Duration, time::SystemTime};

use axum::{
    Json, Router,
    extract::{FromRequestParts, Request, State},
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL, header::SET_COOKIE, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use secrecy::SecretString;
use serde::Serialize;
use tower_http::request_id::RequestId;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    audit::{Actor, ActorType, AuditCtx, AuditEvent, Outcome, record},
    error::AppError,
    identity::{
        csrf::{CsrfKey, capture_host, csrf_guard},
        customers::Registration,
        login::Login,
        rbac::{StaffRoles, load_roles},
        session::{self, CookieKind, CookieRead, SessionId, SessionKind, Subject},
        totp::Totp,
    },
    tenancy::{ResolvedHost, TenantId, begin_tenant_tx, db::begin_platform_tx},
};

/// Dependências das sessões: BD primária (lookup e revogação: nunca a réplica, uma revogação vale
/// já), Redis (inatividade) e a chave CSRF. Leva também as dependências do registo de clientes
/// (`Registration`: captcha e passwords vazadas); sem elas, `POST /api/v1/auth/register` → 503.
#[derive(Clone)]
pub struct Sessions {
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    db: sqlx::PgPool,
    redis: deadpool_redis::Pool,
    csrf: CsrfKey,
    /// Prefixo das chaves Redis: vazio em produção; só os testes o mudam (isolamento).
    ns: String,
    /// Inatividade fixa para todos os tipos: só nos testes; em produção, `SessionKind::idle`.
    idle: Option<Duration>,
    /// `INTERNAL_PROXY_TOKEN` (o mesmo do `HostResolver`): host efetivo e SSR sem `Origin` (CSRF).
    internal_token: Option<SecretString>,
    /// Captcha e verificação de passwords vazadas do registo (cartão 02/17).
    registration: Option<Registration>,
    /// Captcha, verificação de passwords e limites do login (cartão 02/18).
    login: Option<Login>,
    /// Chave de cifra dos segredos TOTP e limites do 2FA (cartão 02/20).
    totp: Option<Totp>,
}

impl Sessions {
    pub fn new(db: sqlx::PgPool, redis: deadpool_redis::Pool, csrf_key: SecretString) -> Self {
        Self::build(db, redis, csrf_key, String::new(), None)
    }

    /// Só para testes: prefixo próprio nas chaves Redis e inatividade curta. Não existe em
    /// `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn for_tests(
        db: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        csrf_key: SecretString,
        namespace: &str,
        idle: Option<Duration>,
    ) -> Self {
        Self::build(db, redis, csrf_key, namespace.to_owned(), idle)
    }

    fn build(
        db: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        csrf_key: SecretString,
        ns: String,
        idle: Option<Duration>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                redis,
                csrf: CsrfKey::new(csrf_key),
                ns,
                idle,
                internal_token: None,
                registration: None,
                login: None,
                totp: None,
            }),
        }
    }

    /// Token do proxy interno (`INTERNAL_PROXY_TOKEN`, o mesmo passado ao `HostResolver`): o CSRF
    /// compara a `Origin` com o mesmo host efetivo que decide o tenant e aceita o SSR sem `Origin`.
    pub fn with_internal_token(self, token: Option<SecretString>) -> Self {
        let mut inner = Arc::unwrap_or_clone(self.inner);
        inner.internal_token = token;
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Dependências do registo de clientes (`Registration::from_config` em produção; fakes nos
    /// testes). Sem esta chamada o registo responde 503 (falha fechado: nunca sem captcha).
    pub fn with_registration(self, registration: Registration) -> Self {
        let mut inner = Arc::unwrap_or_clone(self.inner);
        inner.registration = Some(registration);
        Self {
            inner: Arc::new(inner),
        }
    }

    pub(crate) fn registration(&self) -> Option<&Registration> {
        self.inner.registration.as_ref()
    }

    /// Dependências do login de clientes (`Login::from_config` em produção; fakes nos testes). Sem
    /// esta chamada o login responde 503 (falha fechado: nunca sem captcha).
    pub fn with_login(self, login: Login) -> Self {
        let mut inner = Arc::unwrap_or_clone(self.inner);
        inner.login = Some(login);
        Self {
            inner: Arc::new(inner),
        }
    }

    pub(crate) fn login(&self) -> Option<&Login> {
        self.inner.login.as_ref()
    }

    /// Dependências do 2FA TOTP (`Totp::from_config` em produção). Sem esta chamada as rotas
    /// `/api/v1/staff/mfa/*` respondem 503 (falha fechado).
    pub fn with_totp(self, totp: Totp) -> Self {
        let mut inner = Arc::unwrap_or_clone(self.inner);
        inner.totp = Some(totp);
        Self {
            inner: Arc::new(inner),
        }
    }

    pub(crate) fn totp(&self) -> Option<&Totp> {
        self.inner.totp.as_ref()
    }

    /// BD primária (lookup de sessões e papéis; nunca a réplica).
    pub(crate) fn db(&self) -> &sqlx::PgPool {
        &self.inner.db
    }

    pub(crate) fn redis(&self) -> &deadpool_redis::Pool {
        &self.inner.redis
    }

    pub(crate) fn ns(&self) -> &str {
        &self.inner.ns
    }

    pub(crate) fn internal_token(&self) -> Option<&SecretString> {
        self.inner.internal_token.as_ref()
    }

    pub(crate) fn csrf(&self) -> &CsrfKey {
        &self.inner.csrf
    }

    fn idle(&self, kind: SessionKind) -> Duration {
        self.inner.idle.unwrap_or_else(|| kind.idle())
    }

    /// Valida a sessão do cookie para o host do pedido.
    async fn resolve(
        &self,
        hash: &[u8; 32],
        tenant: Option<TenantId>,
        request_id: Uuid,
    ) -> Result<Resolution, AppError> {
        let Some(row) = session::lookup(&self.inner.db, hash).await? else {
            return Ok(Resolution::Invalid);
        };
        // Anti-IDOR entre tenants: a sessão nasceu neste host (ou na plataforma).
        if row.tenant != tenant.map(|t| t.as_uuid()) {
            return Ok(Resolution::Invalid);
        }
        if !session::touch(
            &self.inner.redis,
            &self.inner.ns,
            &row,
            self.idle(row.kind()),
        )
        .await?
        {
            return Ok(Resolution::Invalid);
        }
        let (actor, staff) = match row.subject {
            Subject::Customer(id) => (
                Actor {
                    actor_type: ActorType::Customer,
                    actor_id: Some(id),
                    impersonator_id: row.impersonator_id,
                },
                None,
            ),
            // Papéis lidos uma vez por pedido (cache em `StaffRoles`); o tipo de ator depende deles
            // e do host (cartão 02/19).
            Subject::User(id) => {
                let roles = load_roles(&self.inner.db, id, request_id).await?;
                let staff = StaffRoles::new(id, tenant, roles);
                let actor = Actor {
                    actor_type: staff.actor_type(),
                    actor_id: Some(id),
                    impersonator_id: row.impersonator_id,
                };
                (actor, Some(staff))
            }
        };
        Ok(Resolution::Valid(
            actor,
            SessionInfo {
                id: row.id,
                mfa_verified_at: row.mfa_verified_at,
                tenant,
            },
            staff,
        ))
    }
}

enum Resolution {
    /// Sessão válida; `StaffRoles` só nas sessões `user`.
    Valid(Actor, SessionInfo, Option<StaffRoles>),
    /// Inválida para este pedido: anónimo e cookie limpo.
    Invalid,
}

/// Sessão do pedido (extensão posta por `authenticate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    pub mfa_verified_at: Option<SystemTime>,
    /// Tenant da sessão (= o do `Host`); `None` = plataforma.
    tenant: Option<TenantId>,
}

impl SessionInfo {
    pub fn tenant(&self) -> Option<TenantId> {
        self.tenant
    }
}

/// Cookie que vale no host resolvido (e o tenant); `None` = host sem sessões (desconhecido).
fn cookie_for(host: Option<&ResolvedHost>) -> Option<(CookieKind, Option<TenantId>)> {
    match host? {
        ResolvedHost::Tenant(t) => Some((CookieKind::Tenant, Some(t.id()))),
        ResolvedHost::Platform => Some((CookieKind::Platform, None)),
        ResolvedHost::Unknown | ResolvedHost::Unavailable => None,
    }
}

/// Layer (`from_fn_with_state`) de autenticação: por dentro de `resolve_host`, POR FORA da caixa
/// negra. BD ou Redis em baixo com um cookie presente → 503 (falha fechado).
pub async fn authenticate(State(s): State<Sessions>, mut req: Request, next: Next) -> Response {
    req.extensions_mut().insert(s.clone());
    let Some((kind, tenant)) = cookie_for(req.extensions().get::<ResolvedHost>()) else {
        return next.run(req).await;
    };
    let hash = match session::read_cookie(req.headers(), kind.name()) {
        CookieRead::Absent => return next.run(req).await,
        CookieRead::Invalid => return cleared(next.run(req).await, kind),
        CookieRead::Token(h) => h,
    };
    // O mesmo `request_id` da caixa negra (`SetRequestIdLayer`, sempre UUIDv7).
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .and_then(|r| r.header_value().to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok())
        .unwrap_or_else(Uuid::now_v7);
    match s.resolve(&hash, tenant, request_id).await {
        Ok(Resolution::Valid(actor, info, staff)) => {
            req.extensions_mut().insert(actor);
            req.extensions_mut().insert(info);
            if let Some(staff) = staff {
                req.extensions_mut().insert(staff);
            }
            next.run(req).await
        }
        Ok(Resolution::Invalid) => cleared(next.run(req).await, kind),
        Err(e) => e.into_response(),
    }
}

fn cleared(mut resp: Response, kind: CookieKind) -> Response {
    resp.headers_mut()
        .append(SET_COOKIE, session::clear_cookie(kind));
    resp
}

/// Aplica `authenticate` às rotas de `router` (chamar ANTES de `with_host_resolution`, para ficar
/// por dentro dela).
pub fn with_sessions<S>(router: Router<S>, sessions: Sessions) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.route_layer(axum::middleware::from_fn_with_state(sessions, authenticate))
}

/// Aplica `capture_host` às rotas de `router` (chamar DEPOIS de `with_host_resolution`, para ficar
/// por fora dela: o `X-Internal-Token` ainda está no pedido).
pub fn with_request_host<S>(router: Router<S>, sessions: Sessions) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.route_layer(axum::middleware::from_fn_with_state(sessions, capture_host))
}

/// Aplica o `csrf_guard` às rotas de `router` (chamar ANTES de `audited`, para ficar por dentro).
pub fn with_csrf<S>(router: Router<S>, sessions: Sessions) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.route_layer(axum::middleware::from_fn_with_state(sessions, csrf_guard))
}

/// Cliente autenticado; sem ele → 401 (`AppError::Unauthorized`, recusa gravada pela caixa negra).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequireCustomer {
    pub customer_id: Uuid,
}

impl<S: Send + Sync> FromRequestParts<S> for RequireCustomer {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<Actor>() {
            Some(Actor {
                actor_type: ActorType::Customer,
                actor_id: Some(id),
                ..
            }) => Ok(Self { customer_id: *id }),
            _ => Err(AppError::Unauthorized),
        }
    }
}

/// Estado de sessão do pedido (pode ser anónimo). Sem a layer `authenticate` → 500.
pub struct CurrentSession {
    sessions: Sessions,
    actor: Option<Actor>,
    info: Option<SessionInfo>,
    cookie: Option<CookieKind>,
}

impl CurrentSession {
    pub(crate) fn sessions(&self) -> &Sessions {
        &self.sessions
    }

    pub(crate) fn actor(&self) -> Option<Actor> {
        self.actor
    }

    pub(crate) fn info(&self) -> Option<SessionInfo> {
        self.info
    }
}

impl<S: Send + Sync> FromRequestParts<S> for CurrentSession {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let sessions = parts.extensions.get::<Sessions>().cloned().ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("Sessions em falta: rota sem authenticate"))
        })?;
        Ok(Self {
            sessions,
            actor: parts.extensions.get::<Actor>().copied(),
            info: parts.extensions.get::<SessionInfo>().copied(),
            cookie: cookie_for(parts.extensions.get::<ResolvedHost>()).map(|(k, _)| k),
        })
    }
}

/// Estado da sessão do pedido.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionStatus {
    pub authenticated: bool,
    /// `customer`, `merchant`, `municipal` ou `admin`; `null` se anónimo.
    #[schema(required = true)]
    pub actor_type: Option<String>,
    /// Token a enviar em `X-CSRF-Token` (ou no campo `_csrf`) em todas as mutações; `null` se
    /// anónimo.
    #[schema(required = true)]
    pub csrf_token: Option<String>,
}

pub(crate) fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

// Leitura síncrona na caixa negra (`AuditClass::ReadSync`, posta em `http::api`): leva o token CSRF.
/// Estado da sessão e token CSRF.
#[utoipa::path(
    get,
    path = "/api/v1/auth/session",
    tag = "auth",
    responses(
        (status = 200, description = "Estado da sessão (anónimo incluído)", body = SessionStatus),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn session_status(cur: CurrentSession) -> Result<Response, AppError> {
    let body = match (cur.actor, cur.info) {
        (Some(actor), Some(info)) => SessionStatus {
            authenticated: true,
            actor_type: Some(actor.actor_type.as_str().to_owned()),
            csrf_token: Some(cur.sessions.csrf().token(info.id)?),
        },
        _ => SessionStatus {
            authenticated: false,
            actor_type: None,
            csrf_token: None,
        },
    };
    Ok(no_store(Json(body).into_response()))
}

/// Termina a sessão do pedido: revoga-a, limpa o cookie e grava `auth.logout`. Sem sessão: 204 na
/// mesma (idempotente).
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    params(
        ("X-CSRF-Token" = Option<String>, Header,
         description = "Token CSRF da sessão (obrigatório com sessão)")
    ),
    responses(
        (status = 204, description = "Sessão terminada; cookie limpo"),
        (status = 403, description = "Token CSRF ou Origin inválidos"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn logout(ctx: AuditCtx, cur: CurrentSession) -> Result<Response, AppError> {
    if let Some(info) = cur.info {
        let ev = AuditEvent {
            action: "auth.logout",
            target_type: Some("session"),
            target_id: Some(info.id.as_uuid().to_string()),
            outcome: Outcome::Success,
            reason: None,
            changes: None,
            store_id: None,
        };
        let db = &cur.sessions.inner.db;
        match info.tenant {
            Some(t) => {
                let mut tx = begin_tenant_tx(db, t, &ctx).await?;
                session::revoke(&mut tx, info.id).await?;
                record(&mut tx, ev).await?;
                tx.commit().await?;
            }
            None => {
                let mut tx = begin_platform_tx(db, &ctx).await?;
                session::revoke(&mut tx, info.id).await?;
                record(&mut tx, ev).await?;
                tx.commit().await?;
            }
        }
        let inner = &cur.sessions.inner;
        if let Err(e) = session::forget(&inner.redis, &inner.ns, info.id).await {
            // A revogação na BD já vale; a chave de inatividade expira sozinha.
            tracing::warn!(error = ?e, "logout: chave de inatividade não apagada");
        }
    }
    let mut resp = no_store(StatusCode::NO_CONTENT.into_response());
    if let Some(kind) = cur.cookie {
        resp.headers_mut()
            .append(SET_COOKIE, session::clear_cookie(kind));
    }
    Ok(resp)
}
