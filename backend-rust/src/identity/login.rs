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

use std::{ops::DerefMut, sync::Arc};

use async_trait::async_trait;
use axum::{
    Extension, Json,
    body::Body,
    extract::{State, rejection::JsonRejection},
    http::{StatusCode, header::CONTENT_LENGTH, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::{PgConnection, PgPool};
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
        elevate::{forget, own_previous, revoke_foreign_session},
        email,
        http::{CurrentSession, no_store},
        password::{self, PASSWORD_MAX_CHARS, PASSWORD_MIN_CHARS, Password, Verified},
        rbac::load_roles,
        session::{self, CookieKind, SessionId, SessionKind, Subject},
        throttle::{self, AccountKey, Gate, Keys, Limits, account_hash},
    },
    state::AppState,
    tenancy::{
        ResolvedTenant, TenantId, begin_tenant_tx,
        db::{AuditedTx, begin_platform_tx, db_error},
    },
};

/// Ação na caixa negra (sucesso e falha).
pub const ACTION_LOGIN: &str = "auth.login";
/// Motivos da recusa.
pub const REASON_BAD_CREDENTIALS: &str = "bad_credentials";
pub const REASON_CAPTCHA: &str = "captcha";
/// Sessão de outro sujeito no mesmo browser, terminada pelo login.
pub const ACTION_LOGOUT: &str = "auth.logout";
pub const REASON_SUPERSEDED: &str = "superseded_by_login";
/// Login de staff (cartão 02/19): ação própria, mesmos motivos.
pub const ACTION_STAFF_LOGIN: &str = "auth.staff_login";

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

    /// O próximo login de staff com este email exige captcha (cartão 02/20: sessão revogada por
    /// falhas de 2FA). Mesmas chaves do travão do login de staff (`ACCOUNT_HASH_KEY`, `staff:`).
    pub(crate) async fn force_staff_captcha(
        &self,
        redis: &deadpool_redis::Pool,
        ns: &str,
        raw_email: &str,
    ) -> Result<(), AppError> {
        let email = email::normalize(raw_email)?;
        let h = account_hash(&self.account, &email);
        let prefix = Accounts::Users.throttle_prefix();
        let keys = Keys::new(&format!("{ns}{prefix}"), &h, None);
        throttle::force_captcha(redis, &keys, &self.limits).await
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

/// Que contas o login verifica: clientes (`/api/v1/auth/login`) ou utilizadores de backoffice
/// (`/api/v1/staff/auth/login`, cartão 02/19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accounts {
    Customers,
    Users,
}

impl Accounts {
    /// Ação na caixa negra.
    fn action(self) -> &'static str {
        match self {
            Self::Customers => ACTION_LOGIN,
            Self::Users => ACTION_STAFF_LOGIN,
        }
    }

    /// Prefixo próprio das chaves do travão (contadores separados dos de clientes).
    fn throttle_prefix(self) -> &'static str {
        match self {
            Self::Customers => "",
            Self::Users => "staff:",
        }
    }
}

/// Conta encontrada pelo email (`password_hash` NULL = só passkey).
struct Found {
    id: Uuid,
    phc: Option<String>,
    totp_enabled: bool,
}

/// id + PHC (+ `totp_enabled` dos utilizadores) pela única leitura por email
/// (`identity_customer_credentials` 0017/0021; `identity_user_credentials` 0018/0021, só ativos).
///
/// Exceção à regra `query!` (como `session::lookup`): o EXPLAIN da macro exige EXECUTE na função,
/// que o migrator não tem (dono `ptmarket_identity`). SQL estático, função qualificada, argumento e
/// colunas com o tipo exato; verificado nos testes `login` e `rbac`.
async fn credentials(
    db: &PgPool,
    accounts: Accounts,
    email: &str,
) -> Result<Option<Found>, AppError> {
    let row: Option<(Uuid, Option<String>, bool)> = match accounts {
        Accounts::Customers => sqlx::query_as(
            "SELECT c.id::uuid, c.password_hash::text, false::boolean
             FROM public.identity_customer_credentials($1::text) AS c",
        ),
        Accounts::Users => sqlx::query_as(
            "SELECT u.id::uuid, u.password_hash::text, u.totp_enabled::boolean
             FROM public.identity_user_credentials($1::text) AS u",
        ),
    }
    .bind(email)
    .fetch_optional(db)
    .await
    .map_err(db_error)?;
    Ok(row.map(|(id, phc, totp_enabled)| Found {
        id,
        phc,
        totp_enabled,
    }))
}

/// Regrava o PHC (parâmetros atuais) na transação do próprio cliente (RLS: só a sua linha).
async fn update_hash<T>(tx: &mut T, id: Uuid, phc: &str) -> Result<(), AppError>
where
    T: AuditedTx + DerefMut<Target = PgConnection>,
{
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

/// `last_login_at` (e o PHC, se fraco) na transação do próprio utilizador (RLS `self_update`: só a
/// sua linha, ativa). O gatilho da caixa negra grava `users.update`.
async fn update_user<T>(tx: &mut T, id: Uuid, phc: Option<&str>) -> Result<(), AppError>
where
    T: AuditedTx + DerefMut<Target = PgConnection>,
{
    let r = sqlx::query!(
        "UPDATE users
         SET last_login_at = now(), password_hash = COALESCE($2, password_hash), updated_at = now()
         WHERE id = $1",
        id,
        phc
    )
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    if r.rows_affected() != 1 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "login: last_login_at não gravado (linha do utilizador não visível)"
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

/// Grava `ev` numa transação própria com o ator `ctx`: no tenant ou, sem ele, na plataforma.
async fn record_alone(
    db: &PgPool,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    ev: AuditEvent,
) -> Result<(), AppError> {
    match tenant {
        Some(t) => {
            let mut tx = begin_tenant_tx(db, t, ctx).await?;
            record(&mut tx, ev).await?;
            tx.commit().await
        }
        None => {
            let mut tx = begin_platform_tx(db, ctx).await?;
            record(&mut tx, ev).await?;
            tx.commit().await
        }
    }
}

/// `auth.login`/`auth.staff_login` `denied` (transação própria, ator anónimo). Falhou → 503.
async fn record_denied(
    db: &PgPool,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    action: &'static str,
    account_hash: &str,
    reason: &str,
) -> Result<(), AppError> {
    let ev = AuditEvent {
        action,
        target_type: Some("account_hash"),
        target_id: Some(account_hash.to_owned()),
        outcome: Outcome::Denied,
        reason: Some(reason.to_owned()),
        changes: None,
        store_id: None,
    };
    record_alone(db, tenant, &anonymous_ctx(ctx), ev).await
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
    let attempt = Attempt {
        st: &st,
        tenant: Some(tenant.id()),
        ctx: &ctx,
        cur: &cur,
        deps: &deps,
        expected_host: &expected_host,
        accounts: Accounts::Customers,
    };
    let result = customer_login(&attempt, &req).await;
    wipe(&mut req);
    result
}

/// Apaga da memória a password e o token do captcha.
pub(crate) fn wipe(req: &mut LoginRequest) {
    req.password.zeroize();
    if let Some(t) = req.turnstile_token.as_mut() {
        t.zeroize();
    }
}

async fn customer_login(a: &Attempt<'_>, req: &LoginRequest) -> Result<Response, AppError> {
    let passed = match check(a, req).await? {
        Checked::Refused(resp) => return Ok(resp),
        Checked::Passed(p) => p,
    };
    let subject = Subject::Customer(passed.id);
    let value = a
        .open_session(ActorType::Customer, subject, &passed)
        .await?;
    let mut resp = no_store(StatusCode::NO_CONTENT.into_response());
    resp.headers_mut().append(
        SET_COOKIE,
        session::set_cookie(CookieKind::Tenant, &value, a.lifetime(subject))?,
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------------------------
// Tentativa (partilhada com o login de staff, cartão 02/19)
// ---------------------------------------------------------------------------------------------

/// Uma tentativa de login: onde decorre (`tenant` `None` = `PLATFORM_ADMIN_HOST`), quem pede e que
/// contas verifica.
pub(crate) struct Attempt<'a> {
    pub st: &'a AppState,
    pub tenant: Option<TenantId>,
    pub ctx: &'a AuditCtx,
    pub cur: &'a CurrentSession,
    pub deps: &'a Login,
    pub expected_host: &'a str,
    pub accounts: Accounts,
}

/// Credenciais certas: a conta, o PHC novo (se o guardado era fraco) e as chaves do travão.
pub(crate) struct Passed {
    pub id: Uuid,
    pub totp_enabled: bool,
    new_phc: Option<String>,
    keys: Keys,
    account_hash: String,
}

pub(crate) enum Checked {
    Passed(Passed),
    /// Resposta final já decidida (401 genérico ou com `captcha_required`; evento gravado).
    Refused(Response),
}

/// Travão → captcha (se exigido) → credenciais (Argon2 SEMPRE). Não cria sessão.
pub(crate) async fn check(a: &Attempt<'_>, req: &LoginRequest) -> Result<Checked, AppError> {
    let email = validate(req)?;
    let account_hash = account_hash(&a.deps.account, &email);
    let redis = a.cur.sessions().redis();
    let ns = format!("{}{}", a.cur.sessions().ns(), a.accounts.throttle_prefix());
    let keys = Keys::new(&ns, &account_hash, a.ctx.ip());
    let limits = &a.deps.limits;

    // 1. Travão (só Redis): 429 sem tocar na BD; o middleware conta-o.
    let captcha = match throttle::decide(throttle::begin(redis, &keys, limits).await, limits) {
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
            Some(t) if !t.is_empty() => a.deps.captcha.verify(t, a.ctx.ip(), a.expected_host).await,
            _ => false,
        };
        if !ok {
            throttle::not_attempted(redis, &keys).await;
            record_denied(
                &a.st.db_primary,
                a.tenant,
                a.ctx,
                a.accounts.action(),
                &account_hash,
                REASON_CAPTCHA,
            )
            .await
            .map_err(unavailable)?;
            return Ok(Checked::Refused(captcha_required().await?));
        }
    }

    // 3. Credenciais: Argon2 SEMPRE (sem conta / sem password → hash falso).
    let n = req.password.chars().count();
    let found = credentials(&a.st.db_primary, a.accounts, &email)
        .await
        .map_err(unavailable)?;
    let (id, phc, totp_enabled) = match found {
        Some(f) => (Some(f.id), f.phc, f.totp_enabled),
        None => (None, None, false),
    };
    let (verified, pw) = if n >= PASSWORD_MIN_CHARS {
        let pw = Password::parse(&req.password)?;
        let v = a.deps.passwords.verify(&pw, phc.as_deref()).await?;
        (v, Some(pw))
    } else {
        // Mais curta do que qualquer password aceite no registo: nunca confere. Mesmo custo.
        let filler = Password::parse(&"\u{0}".repeat(PASSWORD_MIN_CHARS))?;
        a.deps.passwords.verify(&filler, None).await?;
        (
            Verified {
                ok: false,
                needs_rehash: false,
            },
            None,
        )
    };

    // Staff: a falha corre a mesma leitura de papéis do sucesso (id encontrado ou `Uuid::nil()`),
    // para que o tempo não revele se a password estava certa num host sem papel.
    if a.accounts == Accounts::Users && !(id.is_some() && verified.ok) {
        let who = id.unwrap_or(Uuid::nil());
        if let Err(e) = load_roles(&a.st.db_primary, who, a.ctx.request_id()).await {
            tracing::warn!(error = ?e, "login de staff: leitura de igualação falhou");
        }
    }
    let (Some(id), Some(pw), true) = (id, pw, verified.ok) else {
        return a
            .refuse(&keys, &account_hash, REASON_BAD_CREDENTIALS)
            .await
            .map(Checked::Refused);
    };
    let new_phc = if verified.needs_rehash {
        Some(password::hash(&pw).await?)
    } else {
        None
    };
    drop(pw);
    Ok(Checked::Passed(Passed {
        id,
        totp_enabled,
        new_phc,
        keys,
        account_hash,
    }))
}

impl Attempt<'_> {
    /// Falha: conta no travão, `denied` com `reason` (ator anónimo) e o 401 genérico.
    async fn refuse(
        &self,
        keys: &Keys,
        account_hash: &str,
        reason: &str,
    ) -> Result<Response, AppError> {
        throttle::failed(self.cur.sessions().redis(), keys, &self.deps.limits).await;
        record_denied(
            &self.st.db_primary,
            self.tenant,
            self.ctx,
            self.accounts.action(),
            account_hash,
            reason,
        )
        .await
        .map_err(unavailable)?;
        Ok(unauthorized())
    }

    /// Credenciais certas mas recusadas depois (ex.: staff sem papel neste host): exatamente o
    /// mesmo 401 e a mesma contagem de uma password errada.
    pub(crate) async fn refuse_passed(
        &self,
        passed: &Passed,
        reason: &str,
    ) -> Result<Response, AppError> {
        self.refuse(&passed.keys, &passed.account_hash, reason)
            .await
    }

    /// Duração absoluta do cookie da sessão de `subject` neste host.
    pub(crate) fn lifetime(&self, subject: Subject) -> std::time::Duration {
        SessionKind::of(subject, self.tenant).max_lifetime()
    }

    /// Sucesso: transação do próprio (`actor` com o id do sujeito) com o PHC regravado (se fraco),
    /// `last_login_at` (utilizadores), `session::rotate` e o evento `success`; depois revoga a
    /// sessão de outro sujeito deste browser e limpa os contadores. Falha a gravar → 503.
    pub(crate) async fn open_session(
        &self,
        actor: ActorType,
        subject: Subject,
        passed: &Passed,
    ) -> Result<session::CookieValue, AppError> {
        let me = AuditCtx::new(
            actor,
            Some(passed.id),
            None,
            None,
            self.ctx.request_id(),
            self.ctx.ip(),
            self.ctx.user_agent_hash().copied(),
        );
        let old = own_previous(self.cur, subject);
        let db = &self.st.db_primary;
        let phc = passed.new_phc.as_deref();
        let opened = match self.tenant {
            Some(t) => {
                async {
                    let mut tx = begin_tenant_tx(db, t, &me).await?;
                    let r = self.in_session_tx(&mut tx, old, subject, phc, &me).await?;
                    tx.commit().await?;
                    Ok(r)
                }
                .await
            }
            None => {
                async {
                    let mut tx = begin_platform_tx(db, &me).await?;
                    let r = self.in_session_tx(&mut tx, old, subject, phc, &me).await?;
                    tx.commit().await?;
                    Ok(r)
                }
                .await
            }
        };
        let (sid, value) = opened.map_err(unavailable)?;
        if let Some(old) = old {
            forget(self.cur, old).await;
        }
        revoke_foreign_session(
            &self.st.db_primary,
            self.cur,
            self.tenant,
            self.ctx,
            subject,
        )
        .await;
        throttle::succeeded(self.cur.sessions().redis(), &passed.keys).await;
        tracing::debug!(session = %sid.as_uuid(), "login: sessão criada");
        Ok(value)
    }

    async fn in_session_tx<T>(
        &self,
        tx: &mut T,
        old: Option<SessionId>,
        subject: Subject,
        new_phc: Option<&str>,
        me: &AuditCtx,
    ) -> Result<(SessionId, session::CookieValue), AppError>
    where
        T: AuditedTx + DerefMut<Target = PgConnection>,
    {
        match subject {
            Subject::Customer(id) => {
                if let Some(phc) = new_phc {
                    update_hash(tx, id, phc).await?;
                }
            }
            Subject::User(id) => update_user(tx, id, new_phc).await?,
        }
        let (sid, value) = session::rotate(tx, old, subject, self.tenant, me).await?;
        record(
            tx,
            AuditEvent {
                action: self.accounts.action(),
                target_type: Some("session"),
                target_id: Some(sid.as_uuid().to_string()),
                outcome: Outcome::Success,
                reason: None,
                changes: None,
                store_id: None,
            },
        )
        .await?;
        Ok((sid, value))
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
