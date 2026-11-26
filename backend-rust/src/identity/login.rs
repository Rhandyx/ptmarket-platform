//! Login de clientes (cartão 02/18): `POST /api/v1/auth/login`.
//!
//! Ordem: DTO → `email::normalize` → travão (Redis; 429 sem tocar na BD) → captcha (só se
//! exigido) → `identity_customer_credentials` → Argon2 (SEMPRE: sem conta ou sem password corre o
//! hash falso) → sucesso ou falha.
//! - Falha de credenciais (email inexistente, password errada, conta só com passkey) → 401 genérico
//!   byte a byte igual + `auth.login` `denied` (`bad_credentials`) com o ator `anonymous` e
//!   `target_id` = sha256 do email normalizado. Captcha exigido e em falta/errado → o mesmo 401 com
//!   `"captcha_required": true` + `denied` (`captcha`). 429 → só o middleware (contado no Redis).
//! - Sucesso → na MESMA transação (ator = o cliente): PHC fraco regravado, `session::rotate` (a
//!   sessão anterior deste browser é revogada), `auth.login` `success` com o id da sessão. Falha a
//!   gravar → 503 e nada fica (rollback). Sessão no tenant do `Host`.
//! - Sem tempo mínimo de resposta (ao contrário do registo): os três casos de falha fazem o mesmo
//!   trabalho (lookup + Argon2 + evento) e o 401 do captcha depende só dos contadores, nunca de a
//!   conta existir.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Extension, Json,
    body::Body,
    extract::{State, rejection::JsonRejection},
    http::{StatusCode, header::CONTENT_LENGTH, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    audit::{ActorType, AuditCtx, AuditEvent, Outcome, record},
    config::Config,
    error::{AppError, FieldError},
    identity::{
        captcha::{CaptchaVerifier, TurnstileVerifier},
        csrf::RequestHost,
        customers::MAX_CAPTCHA_TOKEN_CHARS,
        email,
        http::{CurrentSession, no_store},
        password::{self, PASSWORD_MAX_CHARS, PASSWORD_MIN_CHARS, Password, Verified},
        session::{self, CookieKind, SessionId, SessionKind, Subject},
        throttle::{self, AccountKey, Gate, Keys, Limits, account_hash},
    },
    state::AppState,
    tenancy::{ResolvedTenant, TenantId, TenantTx, begin_tenant_tx, db::db_error},
};

/// Ação na caixa negra (sucesso e falha).
pub const ACTION_LOGIN: &str = "auth.login";
/// Motivos da recusa.
pub const REASON_BAD_CREDENTIALS: &str = "bad_credentials";
pub const REASON_CAPTCHA: &str = "captcha";
/// Sessão de outro sujeito no mesmo browser, terminada pelo login.
pub const ACTION_LOGOUT: &str = "auth.logout";
pub const REASON_SUPERSEDED: &str = "superseded_by_login";

// ---------------------------------------------------------------------------------------------
// Dependências
// ---------------------------------------------------------------------------------------------

/// Verificação da password contra o PHC guardado (`None` = sem conta ou sem password: hash falso).
/// Produção: `Argon2Check`; os testes envolvem-no para contar as execuções.
#[async_trait]
pub trait PasswordCheck: Send + Sync {
    async fn verify(&self, password: &Password, phc: Option<&str>) -> Result<Verified, AppError>;
}

/// `password::verify` (Argon2id).
pub struct Argon2Check;

#[async_trait]
impl PasswordCheck for Argon2Check {
    async fn verify(&self, password: &Password, phc: Option<&str>) -> Result<Verified, AppError> {
        password::verify(password, phc).await
    }
}

/// Dependências do login: captcha (Turnstile em produção), verificação de passwords e limites do
/// travão.
#[derive(Clone)]
pub struct Login {
    captcha: Arc<dyn CaptchaVerifier>,
    passwords: Arc<dyn PasswordCheck>,
    limits: Limits,
    /// `ACCOUNT_HASH_KEY`: identificador da conta na caixa negra e no travão.
    account: AccountKey,
}

impl Login {
    pub fn new(captcha: Arc<dyn CaptchaVerifier>, account: AccountKey) -> Self {
        Self {
            captcha,
            passwords: Arc::new(Argon2Check),
            limits: Limits::default(),
            account,
        }
    }

    /// Produção: Turnstile com `TURNSTILE_SECRET` (obrigatório) e `ACCOUNT_HASH_KEY`.
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let secret = cfg.require_turnstile_secret()?;
        let captcha = TurnstileVerifier::new(secret)
            .map_err(|_| anyhow::anyhow!("cliente Turnstile indisponível"))?;
        Ok(Self::new(
            Arc::new(captcha),
            AccountKey::new(cfg.account_hash_key()),
        ))
    }

    /// Só para testes: outra verificação de passwords (ex.: um contador à volta do Argon2).
    #[cfg(feature = "test-support")]
    pub fn with_password_check_for_tests(mut self, check: Arc<dyn PasswordCheck>) -> Self {
        self.passwords = check;
        self
    }

    /// Só para testes: limites do travão mais curtos.
    #[cfg(feature = "test-support")]
    pub fn with_limits_for_tests(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

// ---------------------------------------------------------------------------------------------
// DTO
// ---------------------------------------------------------------------------------------------

/// Pedido de login. Sem `Debug`: leva a password.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// Até 255 caracteres; comparado normalizado (trim, NFC, minúsculas).
    pub email: String,
    /// 1 a 128 caracteres; nunca normalizada nem aparada.
    #[schema(format = Password)]
    pub password: String,
    /// Token do widget Cloudflare Turnstile; obrigatório quando uma resposta anterior trouxe
    /// `captcha_required: true` (até 2048 caracteres).
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

fn field(name: &str, message: &str) -> FieldError {
    FieldError {
        field: name.to_owned(),
        message: message.to_owned(),
    }
}

/// Corpo ilegível, com campos em falta ou desconhecidos → 422.
fn json_body(body: Result<Json<LoginRequest>, JsonRejection>) -> Result<LoginRequest, AppError> {
    body.map(|Json(v)| v).map_err(|_| {
        AppError::Validation(vec![field(
            "body",
            "Corpo JSON inválido, com campos em falta ou desconhecidos.",
        )])
    })
}

/// Email normalizado; limites da password e do token.
fn validate(req: &LoginRequest) -> Result<String, AppError> {
    let mut errors = Vec::new();
    let email = match email::normalize(&req.email) {
        Ok(e) => Some(e),
        Err(AppError::Validation(f)) => {
            errors.extend(f);
            None
        }
        Err(e) => return Err(e),
    };
    let n = req.password.chars().count();
    if n == 0 || n > PASSWORD_MAX_CHARS {
        errors.push(field(
            "password",
            &format!("Indique a password (até {PASSWORD_MAX_CHARS} caracteres)."),
        ));
    }
    if req
        .turnstile_token
        .as_deref()
        .is_some_and(|t| t.chars().count() > MAX_CAPTCHA_TOKEN_CHARS)
    {
        errors.push(field("turnstile_token", "Confirmação anti-robô inválida."));
    }
    match email {
        Some(e) if errors.is_empty() => Ok(e),
        _ => Err(AppError::Validation(errors)),
    }
}

// ---------------------------------------------------------------------------------------------
// BD
// ---------------------------------------------------------------------------------------------

/// Falha na BD (incluindo a caixa negra) durante o login → 503: o login não acontece.
fn unavailable(e: AppError) -> AppError {
    match e {
        AppError::Internal(err) => {
            tracing::error!(error = ?err, "login: BD/caixa negra indisponível; 503");
            AppError::ServiceUnavailable
        }
        other => other,
    }
}

/// id + PHC pela única leitura por email (`identity_customer_credentials`, 0017/0021).
///
/// Exceção à regra `query!` (como `session::lookup`): o EXPLAIN da macro exige EXECUTE na função,
/// que o migrator não tem (dono `ptmarket_identity`). SQL estático, função qualificada, argumento e
/// colunas com o tipo exato; verificado no teste `login`.
async fn credentials(db: &PgPool, email: &str) -> Result<Option<(Uuid, Option<String>)>, AppError> {
    sqlx::query_as(
        "SELECT c.id::uuid, c.password_hash::text
         FROM public.identity_customer_credentials($1::text) AS c",
    )
    .bind(email)
    .fetch_optional(db)
    .await
    .map_err(db_error)
}

/// Regrava o PHC (parâmetros atuais) na transação do próprio cliente (RLS: só a sua linha).
async fn update_hash(tx: &mut TenantTx, id: Uuid, phc: &str) -> Result<(), AppError> {
    let r = sqlx::query!(
        "UPDATE customers SET password_hash = $2, updated_at = now() WHERE id = $1",
        id,
        phc
    )
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    if r.rows_affected() != 1 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "login: PHC não regravado (linha do cliente não visível)"
        )));
    }
    Ok(())
}

/// Ator `anonymous` com o pedido, o IP e o user-agent do pedido (as falhas nunca levam ator).
fn anonymous_ctx(ctx: &AuditCtx) -> AuditCtx {
    if ctx.actor_type() == ActorType::Anonymous {
        return ctx.clone();
    }
    AuditCtx::new(
        ActorType::Anonymous,
        None,
        None,
        None,
        ctx.request_id(),
        ctx.ip(),
        ctx.user_agent_hash().copied(),
    )
}

/// `auth.login` `denied` (transação própria, ator anónimo). Falhou → 503.
async fn record_denied(
    db: &PgPool,
    tenant: TenantId,
    ctx: &AuditCtx,
    account_hash: &str,
    reason: &str,
) -> Result<(), AppError> {
    let anon = anonymous_ctx(ctx);
    let mut tx = begin_tenant_tx(db, tenant, &anon).await?;
    record(
        &mut tx,
        AuditEvent {
            action: ACTION_LOGIN,
            target_type: Some("account_hash"),
            target_id: Some(account_hash.to_owned()),
            outcome: Outcome::Denied,
            reason: Some(reason.to_owned()),
            changes: None,
            store_id: None,
        },
    )
    .await?;
    tx.commit().await
}

// ---------------------------------------------------------------------------------------------
// Respostas
// ---------------------------------------------------------------------------------------------

/// 401 genérico de `AppError::Unauthorized` (o mesmo nos três casos de falha de credenciais).
fn unauthorized() -> Response {
    no_store(AppError::Unauthorized.into_response())
}

/// O mesmo 401 com o campo extra `"captcha_required": true` (único sinal permitido).
async fn captcha_required() -> Result<Response, AppError> {
    let (mut parts, body) = AppError::Unauthorized.into_response().into_parts();
    let bytes = axum::body::to_bytes(body, 4096)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("corpo do 401 ilegível: {e}")))?;
    let mut v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("corpo do 401 não é JSON: {e}")))?;
    v["captcha_required"] = serde_json::Value::Bool(true);
    let out = serde_json::to_vec(&v)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("corpo do 401 não serializa: {e}")))?;
    parts.headers.remove(CONTENT_LENGTH);
    Ok(no_store(Response::from_parts(parts, Body::from(out))))
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

/// Inicia sessão de cliente no tenant do `Host`. Falha → 401 sempre igual (exista ou não a conta).
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 204, description = "Sessão iniciada; cookie `__Host-ptm_session` (a sessão anterior deste browser é revogada)"),
        (status = 401, description = "Credenciais inválidas (corpo sempre igual). Com `\"captcha_required\": true` no corpo: repetir com `turnstile_token`"),
        (status = 403, description = "Origin ausente ou de outro site (com sessão: também o token CSRF)"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 422, description = "Dados inválidos"),
        (status = 429, description = "Demasiadas tentativas; repetir depois de `Retry-After` segundos"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn login(
    State(st): State<AppState>,
    tenant: ResolvedTenant,
    ctx: AuditCtx,
    cur: CurrentSession,
    host: Option<Extension<RequestHost>>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(deps) = cur.sessions().login().cloned() else {
        tracing::error!("login sem captcha configurado (Sessions::with_login); 503");
        return Err(AppError::ServiceUnavailable);
    };
    let mut req = json_body(body)?;
    let expected_host = host.and_then(|Extension(h)| h.host).unwrap_or_default();
    let result = login_steps(&st, tenant.id(), &ctx, &cur, &deps, &req, &expected_host).await;
    req.password.zeroize();
    if let Some(t) = req.turnstile_token.as_mut() {
        t.zeroize();
    }
    result
}

async fn login_steps(
    st: &AppState,
    tenant: TenantId,
    ctx: &AuditCtx,
    cur: &CurrentSession,
    deps: &Login,
    req: &LoginRequest,
    expected_host: &str,
) -> Result<Response, AppError> {
    let email = validate(req)?;
    let account_hash = account_hash(&deps.account, &email);
    let redis = cur.sessions().redis();
    let keys = Keys::new(cur.sessions().ns(), &account_hash, ctx.ip());

    // 1. Travão (só Redis): 429 sem tocar na BD; o middleware conta-o.
    let captcha = match throttle::decide(
        throttle::begin(redis, &keys, &deps.limits).await,
        &deps.limits,
    ) {
        Gate::TooMany { retry_after_s } => {
            // Não houve tentativa de credenciais: desconta-a nos contadores de falhas.
            throttle::not_attempted(redis, &keys).await;
            return Err(AppError::TooManyRequests { retry_after_s });
        }
        Gate::Proceed { captcha } => captcha,
    };

    // 2. Captcha (só quando exigido; o token é de uso único).
    if captcha {
        let ok = match req.turnstile_token.as_deref() {
            Some(t) if !t.is_empty() => deps.captcha.verify(t, ctx.ip(), expected_host).await,
            _ => false,
        };
        if !ok {
            throttle::not_attempted(redis, &keys).await;
            record_denied(&st.db_primary, tenant, ctx, &account_hash, REASON_CAPTCHA)
                .await
                .map_err(unavailable)?;
            return captcha_required().await;
        }
    }

    // 3. Credenciais: Argon2 SEMPRE (sem conta / sem password → hash falso).
    let n = req.password.chars().count();
    let found = credentials(&st.db_primary, &email)
        .await
        .map_err(unavailable)?;
    let (id, phc) = match found {
        Some((id, phc)) => (Some(id), phc),
        None => (None, None),
    };
    let (verified, pw) = if n >= PASSWORD_MIN_CHARS {
        let pw = Password::parse(&req.password)?;
        let v = deps.passwords.verify(&pw, phc.as_deref()).await?;
        (v, Some(pw))
    } else {
        // Mais curta do que qualquer password aceite no registo: nunca confere. Mesmo custo.
        let filler = Password::parse(&"\u{0}".repeat(PASSWORD_MIN_CHARS))?;
        deps.passwords.verify(&filler, None).await?;
        (
            Verified {
                ok: false,
                needs_rehash: false,
            },
            None,
        )
    };

    let (Some(id), Some(pw), true) = (id, pw, verified.ok) else {
        throttle::failed(redis, &keys, &deps.limits).await;
        record_denied(
            &st.db_primary,
            tenant,
            ctx,
            &account_hash,
            REASON_BAD_CREDENTIALS,
        )
        .await
        .map_err(unavailable)?;
        return Ok(unauthorized());
    };

    // 4. Sucesso.
    let new_phc = if verified.needs_rehash {
        Some(password::hash(&pw).await?)
    } else {
        None
    };
    drop(pw);
    let subject = Subject::Customer(id);
    let (sid, value) = open_session(st, tenant, ctx, cur, subject, new_phc.as_deref())
        .await
        .map_err(unavailable)?;
    revoke_foreign_session(st, tenant, ctx, cur, id).await;
    throttle::succeeded(redis, &keys).await;

    let lifetime = SessionKind::of(subject, Some(tenant)).max_lifetime();
    let mut resp = no_store(StatusCode::NO_CONTENT.into_response());
    resp.headers_mut().append(
        SET_COOKIE,
        session::set_cookie(CookieKind::Tenant, &value, lifetime)?,
    );
    tracing::debug!(session = %sid.as_uuid(), "login: sessão criada");
    Ok(resp)
}

/// Sessão anterior deste browser, se for do mesmo cliente (revogada na transação do login).
fn own_previous(cur: &CurrentSession, id: Uuid) -> Option<SessionId> {
    let actor = cur.actor()?;
    (actor.actor_type == ActorType::Customer && actor.actor_id == Some(id))
        .then(|| cur.info().map(|i| i.id))
        .flatten()
}

/// Transação do cliente: PHC regravado (se fraco), rotação da sessão e `auth.login` `success`.
async fn open_session(
    st: &AppState,
    tenant: TenantId,
    ctx: &AuditCtx,
    cur: &CurrentSession,
    subject: Subject,
    new_phc: Option<&str>,
) -> Result<(SessionId, session::CookieValue), AppError> {
    let Subject::Customer(id) = subject else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "login de cliente com sujeito não cliente"
        )));
    };
    let customer = AuditCtx::new(
        ActorType::Customer,
        Some(id),
        None,
        None,
        ctx.request_id(),
        ctx.ip(),
        ctx.user_agent_hash().copied(),
    );
    let old = own_previous(cur, id);
    let mut tx = begin_tenant_tx(&st.db_primary, tenant, &customer).await?;
    if let Some(phc) = new_phc {
        update_hash(&mut tx, id, phc).await?;
    }
    let (sid, value) = session::rotate(&mut tx, old, subject, Some(tenant), &customer).await?;
    record(
        &mut tx,
        AuditEvent {
            action: ACTION_LOGIN,
            target_type: Some("session"),
            target_id: Some(sid.as_uuid().to_string()),
            outcome: Outcome::Success,
            reason: None,
            changes: None,
            store_id: None,
        },
    )
    .await?;
    tx.commit().await?;
    if let Some(old) = old {
        forget(cur, old).await;
    }
    Ok((sid, value))
}

/// O browser tinha a sessão de OUTRO sujeito: revogada com o ator dela (o do pedido) e
/// `auth.logout` (`superseded_by_login`) na mesma transação. O cookie já foi substituído; uma
/// falha aqui só fica no log (a sessão antiga deixa de ter cookie).
async fn revoke_foreign_session(
    st: &AppState,
    tenant: TenantId,
    ctx: &AuditCtx,
    cur: &CurrentSession,
    id: Uuid,
) {
    let (Some(info), Some(_)) = (cur.info(), cur.actor()) else {
        return;
    };
    if own_previous(cur, id).is_some() {
        return;
    }
    let res = async {
        let mut tx = begin_tenant_tx(&st.db_primary, tenant, ctx).await?;
        session::revoke(&mut tx, info.id).await?;
        record(
            &mut tx,
            AuditEvent {
                action: ACTION_LOGOUT,
                target_type: Some("session"),
                target_id: Some(info.id.as_uuid().to_string()),
                outcome: Outcome::Success,
                reason: Some(REASON_SUPERSEDED.to_owned()),
                changes: None,
                store_id: None,
            },
        )
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

async fn forget(cur: &CurrentSession, id: SessionId) {
    let s = cur.sessions();
    if let Err(e) = session::forget(s.redis(), s.ns(), id).await {
        tracing::warn!(error = ?e, "login: chave de inatividade da sessão anterior não apagada");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(email: &str, pw: &str, token: Option<&str>) -> LoginRequest {
        LoginRequest {
            email: email.into(),
            password: pw.into(),
            turnstile_token: token.map(str::to_owned),
        }
    }

    #[test]
    fn email_is_normalized_and_password_kept_verbatim() {
        assert_eq!(
            validate(&req(" João@X.pt ", " pw ", None)).ok().as_deref(),
            Some("joão@x.pt")
        );
        let nfd = "joa\u{0303}o@x.pt";
        assert_eq!(
            validate(&req(nfd, "x", None)).ok().as_deref(),
            Some("joão@x.pt")
        );
    }

    #[test]
    fn limits_are_422() {
        let long_pw = "a".repeat(PASSWORD_MAX_CHARS + 1);
        let long_tok = "t".repeat(MAX_CAPTCHA_TOKEN_CHARS + 1);
        for r in [
            req("sem-arroba", "x", None),
            req("a@x.pt", "", None),
            req("a@x.pt", &long_pw, None),
            req("a@x.pt", "x", Some(&long_tok)),
            req(&format!("{}@x.pt", "a".repeat(260)), "x", None),
        ] {
            assert!(matches!(validate(&r), Err(AppError::Validation(_))));
        }
        assert!(validate(&req("a@x.pt", &"a".repeat(PASSWORD_MAX_CHARS), None)).is_ok());
    }
}
