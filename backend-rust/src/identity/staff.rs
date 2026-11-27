//! Login de utilizadores de backoffice (cartões 02/19 e 03/13): `POST /api/v1/staff/auth/login` e
//! `GET /api/v1/staff/me`.
//!
//! O login reutiliza o de clientes (`login::check`): mesma resposta uniforme, mesmo travão (com o
//! prefixo próprio `staff:`), mesmo captcha e Argon2 falso; eventos `auth.staff_login`.
//! - `Origin` obrigatória mesmo sem sessão (login CSRF): o `csrf_guard` recusa sem ela (403 +
//!   `Denied("csrf")`; rota em `ANONYMOUS_ORIGIN_PATHS`).
//! - Painel único: só no `PLATFORM_ADMIN_HOST`, onde entra quem tiver PELO MENOS um papel (lojistas,
//!   `sponsor_admin`, `tenant_admin`, `super_admin`); cookie sempre `__Host-ptm_admin`,
//!   `SameSite=Strict`. Num Host de canal, ou sem papéis → o mesmo 401 de uma password errada +
//!   `denied` (`no_role_here`), contado no travão como falha (não revela se a conta existe).
//! - Duração: a inatividade segue o papel (`StaffRoles::session_kind`); a absoluta fica no máximo
//!   que o CHECK `sessions_max_lifetime` (0019) permite a uma sessão sem tenant (8 h).
//! - Sucesso → sessão `user` com `mfa_verified_at` NULL e `last_login_at` (gatilho:
//!   `users.update`); 200 `{"mfa_required": bool}` (o 2FA é do cartão 20).

use axum::{
    Extension, Json,
    extract::{State, rejection::JsonRejection},
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    audit::AuditCtx,
    error::AppError,
    identity::{
        csrf::RequestHost,
        http::{CurrentSession, no_store},
        login::{Accounts, Attempt, Checked, LoginRequest, wipe},
        rbac::{RequireStaffPreMfa, RoleGrant, StaffRoles, load_roles},
        session::{self, CookieKind, Subject},
    },
    state::AppState,
    tenancy::{
        PlatformHost, ResolvedTenant, TenantId,
        db::{begin_platform_tx, db_error},
    },
};

/// Credenciais certas, mas sem papel ou num Host de canal.
pub const REASON_NO_ROLE_HERE: &str = "no_role_here";

/// Resposta do login de staff.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StaffLoginResponse {
    /// `true`: completar o 2FA antes de qualquer ação (super_admin, tenant_admin, sponsor_admin ou
    /// TOTP ligado).
    pub mfa_required: bool,
}

/// Inicia sessão de backoffice (só no host de plataforma). Falha → 401 sempre igual (exista ou não
/// a conta, tenha ou não papéis, seja ou não um Host de canal).
#[utoipa::path(
    post,
    path = "/api/v1/staff/auth/login",
    operation_id = "staff_login",
    tag = "staff",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Sessão iniciada (cookie `__Host-ptm_admin`, só no host de plataforma); `mfa_required` diz se falta o 2FA", body = StaffLoginResponse),
        (status = 401, description = "Credenciais inválidas, sem papéis ou fora do host de plataforma (corpo sempre igual). Com `\"captcha_required\": true` no corpo: repetir com `turnstile_token`"),
        (status = 403, description = "Origin ausente ou de outro site (com sessão: também o token CSRF)"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 422, description = "Dados inválidos"),
        (status = 429, description = "Demasiadas tentativas; repetir depois de `Retry-After` segundos"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
#[allow(
    clippy::too_many_arguments,
    reason = "um extractor por dependência do pedido"
)]
pub async fn login(
    State(st): State<AppState>,
    tenant: Result<ResolvedTenant, AppError>,
    platform: Result<PlatformHost, AppError>,
    ctx: AuditCtx,
    cur: CurrentSession,
    host: Option<Extension<RequestHost>>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let tenant: Option<TenantId> = match (tenant, platform) {
        (Ok(t), _) => Some(t.id()),
        (Err(_), Ok(PlatformHost)) => None,
        (Err(e), Err(_)) => return Err(e),
    };
    // Login CSRF: a `Origin` já foi exigida pelo `csrf_guard` (`ANONYMOUS_ORIGIN_PATHS`).
    let rh = host.map(|Extension(h)| h);
    let Some(deps) = cur.sessions().login().cloned() else {
        tracing::error!("login de staff sem captcha configurado (Sessions::with_login); 503");
        return Err(AppError::ServiceUnavailable);
    };
    let Ok(Json(mut req)) = body else {
        return Err(AppError::Validation(vec![crate::error::FieldError {
            field: "body".to_owned(),
            message: "Corpo JSON inválido, com campos em falta ou desconhecidos.".to_owned(),
        }]));
    };
    let expected_host = rh.and_then(|h| h.host).unwrap_or_default();
    let attempt = Attempt {
        st: &st,
        tenant,
        ctx: &ctx,
        cur: &cur,
        deps: &deps,
        expected_host: &expected_host,
        accounts: Accounts::Users,
    };
    let result = staff_login(&attempt, &req).await;
    wipe(&mut req);
    result
}

async fn staff_login(a: &Attempt<'_>, req: &LoginRequest) -> Result<Response, AppError> {
    let passed = match crate::identity::login::check(a, req).await? {
        Checked::Refused(resp) => return Ok(resp),
        Checked::Passed(p) => p,
    };
    let access = load_roles(&a.st.db_primary, passed.id, a.ctx.request_id())
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "login de staff: papéis ilegíveis; 503");
            AppError::ServiceUnavailable
        })?;
    // Num Host de canal nenhum papel vale (`may_log_in_here` falso): o mesmo 401 + `no_role_here`.
    let staff = StaffRoles::new(passed.id, a.tenant, access);
    if a.tenant.is_some() || !staff.may_log_in_here() {
        return a.refuse_passed(&passed, REASON_NO_ROLE_HERE).await;
    }
    let subject = Subject::User(passed.id);
    let value = a.open_session(staff.actor_type(), subject, &passed).await?;
    let kind = CookieKind::Platform;
    let body = StaffLoginResponse {
        mfa_required: staff.needs_mfa() || passed.totp_enabled,
    };
    let mut resp = no_store((StatusCode::OK, Json(body)).into_response());
    resp.headers_mut().append(
        SET_COOKIE,
        session::set_cookie(kind, &value, a.lifetime(subject))?,
    );
    Ok(resp)
}

/// Utilizador de backoffice da sessão: nunca hashes nem segredos.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StaffMe {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub full_name: String,
    /// Todos os papéis do utilizador, com o âmbito (loja, tenant ou entidade).
    pub roles: Vec<RoleGrant>,
    /// A sessão já passou o 2FA.
    pub mfa_verified: bool,
}

/// Dados do utilizador de backoffice autenticado (leitura síncrona na caixa negra).
#[utoipa::path(
    get,
    path = "/api/v1/staff/me",
    tag = "staff",
    responses(
        (status = 200, description = "Utilizador, papéis e estado do 2FA", body = StaffMe),
        (status = 401, description = "Sem sessão de backoffice (num Host de canal, sempre)"),
        (status = 403, description = "Sem papéis"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn me(
    State(st): State<AppState>,
    RequireStaffPreMfa(staff): RequireStaffPreMfa,
    ctx: AuditCtx,
) -> Result<Response, AppError> {
    // `users` é global: transação de plataforma com o próprio como ator (RLS `self_select`).
    let mut tx = begin_platform_tx(&st.db_primary, &ctx).await?;
    let full_name = sqlx::query_scalar!("SELECT full_name FROM users WHERE id = $1", staff.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.rollback().await?;
    let Some(full_name) = full_name else {
        return Err(AppError::Unauthorized);
    };
    let body = StaffMe {
        id: staff.user_id,
        full_name,
        roles: staff.roles,
        mfa_verified: staff.mfa_verified,
    };
    Ok(no_store(Json(body).into_response()))
}
