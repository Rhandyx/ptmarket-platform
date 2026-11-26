//! Clientes (cartão 02/17): registo `POST /api/v1/auth/register` e perfil `GET`/`PATCH /api/v1/me`.
//!
//! - `customers` é global (spec 11 D4): uma conta para todas as Câmaras. O registo corre numa
//!   transação do tenant do `Host` (o evento de auditoria e o de outbox ficam nessa Câmara), com o
//!   ator `anonymous` (a única que a RLS deixa inserir): INSERT sem RETURNING e sem ON CONFLICT.
//! - Sem enumeração de emails: o registo responde SEMPRE 202 `{"status":"ok"}`, exista ou não a
//!   conta; o hash Argon2id é calculado nos dois casos. Email repetido (23505) → transação nova com
//!   o evento de outbox `customer.duplicate_registration` (o épico notificações avisa o titular).
//! - Ordem do registo: DTO → `email::normalize` → honeypot/tempo → captcha → `Password::parse` →
//!   passwords vazadas → hash → INSERT. Honeypot, tempo ou captcha falhados → 422 genérico +
//!   `Denied("bot")`.
//! - `/me`: a linha vem SEMPRE de `WHERE id = <ator>` (nunca de um id do pedido) e a RLS repete o
//!   filtro. Leitura síncrona na caixa negra (dados pessoais).

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Extension, Json,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::Connection;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    audit::{ActorType, AuditCtx, AuditEvent, Denied, Outcome, record},
    config::Config,
    error::{AppError, FieldError},
    identity::{
        breach::{BreachChecker, HibpRange},
        captcha::{CaptchaVerifier, TurnstileVerifier},
        csrf::RequestHost,
        email,
        http::{CurrentSession, RequireCustomer, no_store},
        nif,
        password::{self, Password},
        throttle::{AccountKey, account_hash},
    },
    outbox::{self, NewEvent},
    state::AppState,
    tenancy::{CountryCode, ResolvedTenant, TenantId, TenantTx, begin_tenant_tx, db::db_error},
};

/// Tempo mínimo de preenchimento do formulário; menos do que isto = bot.
pub const MIN_FILL_TIME: Duration = Duration::from_secs(2);
/// Tempo mínimo de resposta do registo, medido desde o início do processamento: a conta nova, o
/// email repetido e as recusas (bot, validação, password vazada) demoram o mesmo visto de fora.
pub const REGISTER_MIN_RESPONSE: Duration = Duration::from_secs(1);
pub const MAX_NAME_CHARS: usize = 255;
pub const MAX_PHONE_CHARS: usize = 50;
/// Versões dos termos e da política de privacidade aceites.
pub const MAX_VERSION_CHARS: usize = 64;
/// Tokens Turnstile têm no máximo 2048 caracteres.
pub const MAX_CAPTCHA_TOKEN_CHARS: usize = 2048;
/// Motivo da recusa na caixa negra (honeypot, tempo ou captcha).
pub const DENIED_BOT: Denied = Denied("bot");
/// Índice único do email (0005): o único 23505 que é "conta já existe".
const EMAIL_UNIQUE_INDEX: &str = "customers_email_lower_key";

// ---------------------------------------------------------------------------------------------
// Dependências
// ---------------------------------------------------------------------------------------------

/// Dependências do registo: captcha (Turnstile em produção) e passwords vazadas (HIBP).
#[derive(Clone)]
pub struct Registration {
    captcha: Arc<dyn CaptchaVerifier>,
    breach: Arc<dyn BreachChecker>,
    /// `REGISTER_MIN_RESPONSE`; só os testes o mudam.
    min_response: Duration,
    /// `ACCOUNT_HASH_KEY`: identificador da conta no evento do email repetido.
    account: AccountKey,
}

impl Registration {
    pub fn new(
        captcha: Arc<dyn CaptchaVerifier>,
        breach: Arc<dyn BreachChecker>,
        account: AccountKey,
    ) -> Self {
        Self {
            captcha,
            breach,
            min_response: REGISTER_MIN_RESPONSE,
            account,
        }
    }

    /// Só para testes: outro tempo mínimo de resposta (testes rápidos). Não existe em
    /// `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn with_min_response_for_tests(mut self, min: Duration) -> Self {
        self.min_response = min;
        self
    }

    /// Produção: Turnstile com `TURNSTILE_SECRET` (obrigatório), HIBP e `ACCOUNT_HASH_KEY`.
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let secret = cfg.require_turnstile_secret()?;
        let captcha = TurnstileVerifier::new(secret)
            .map_err(|_| anyhow::anyhow!("cliente Turnstile indisponível"))?;
        let breach = HibpRange::new().map_err(|_| anyhow::anyhow!("cliente HIBP indisponível"))?;
        Ok(Self::new(
            Arc::new(captcha),
            Arc::new(breach),
            AccountKey::new(cfg.account_hash_key()),
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// Consentimentos do registo. `marketing` ausente = `false` (nunca pré-assinalado).
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentsInput {
    /// Versão dos termos aceites (obrigatória; 1–64 caracteres).
    pub terms_version: String,
    /// Versão da política de privacidade aceite (obrigatória; 1–64 caracteres).
    pub privacy_version: String,
    #[serde(default)]
    pub marketing: bool,
}

/// Pedido de registo. Sem `Debug`: leva a password.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    /// Até 255 caracteres; gravado normalizado (trim, NFC, minúsculas).
    pub email: String,
    /// 8 a 128 caracteres.
    #[schema(format = Password)]
    pub password: String,
    /// 1 a 255 caracteres.
    pub name: String,
    pub consents: ConsentsInput,
    /// Token do widget Cloudflare Turnstile (verificado no servidor; uso único).
    pub turnstile_token: String,
    /// Honeypot: campo invisível; tem de vir vazio (ou ausente).
    #[serde(default)]
    pub website: String,
    /// Instante em que o formulário foi aberto (ms desde 1970-01-01 UTC).
    pub form_started_at: i64,
}

/// Resposta do registo: sempre a mesma, exista ou não a conta.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegisterAccepted {
    /// Sempre `ok`.
    pub status: String,
}

/// Perfil do cliente autenticado.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CustomerProfile {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub email: String,
    #[schema(required = true)]
    pub name: Option<String>,
    #[schema(required = true)]
    pub phone: Option<String>,
    #[schema(required = true)]
    pub nif: Option<String>,
    /// `{"terms": {"version", "at"}, "privacy": {"version", "at"}, "marketing": {"granted", "at"}}`
    /// (`at` em RFC 3339 UTC).
    #[schema(value_type = Object)]
    pub consents: serde_json::Value,
    /// RFC 3339 UTC.
    pub created_at: String,
}

/// Alteração do perfil: só os campos presentes mudam. `phone`/`nif` = `""` apagam o valor.
/// Email e password ficam fora (exigem reautenticação).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfilePatch {
    /// 1 a 255 caracteres.
    pub name: Option<String>,
    /// Até 50 caracteres; `""` apaga.
    pub phone: Option<String>,
    /// PT: 9 dígitos com dígito de controlo; ES: 9 caracteres alfanuméricos; `""` apaga.
    pub nif: Option<String>,
    /// Consentimento de marketing (datado no servidor).
    pub marketing: Option<bool>,
}

// ---------------------------------------------------------------------------------------------
// Validação
// ---------------------------------------------------------------------------------------------

fn field(name: &str, message: &str) -> FieldError {
    FieldError {
        field: name.to_owned(),
        message: message.to_owned(),
    }
}

/// Corpo JSON ilegível, com tipos errados, campos em falta ou desconhecidos → 422.
fn json_body<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, AppError> {
    body.map(|Json(v)| v).map_err(|_| {
        AppError::Validation(vec![field(
            "body",
            "Corpo JSON inválido, com campos em falta ou desconhecidos.",
        )])
    })
}

/// Texto aparado com `min..=max` caracteres e sem caracteres de controlo.
fn text(
    errors: &mut Vec<FieldError>,
    name: &str,
    raw: &str,
    min: usize,
    max: usize,
) -> Option<String> {
    let v = raw.trim();
    let n = v.chars().count();
    if n < min || n > max || v.chars().any(char::is_control) {
        errors.push(field(
            name,
            &format!("Entre {min} e {max} caracteres, sem caracteres de controlo."),
        ));
        return None;
    }
    Some(v.to_owned())
}

/// Registo validado (password ainda em texto; só `Password::parse` depois do captcha).
struct ValidRegistration {
    email: String,
    name: String,
    terms_version: String,
    privacy_version: String,
    marketing: bool,
}

fn validate_registration(req: &RegisterRequest) -> Result<ValidRegistration, AppError> {
    let mut errors = Vec::new();
    let name = text(&mut errors, "name", &req.name, 1, MAX_NAME_CHARS);
    let terms = text(
        &mut errors,
        "consents.terms_version",
        &req.consents.terms_version,
        1,
        MAX_VERSION_CHARS,
    );
    let privacy = text(
        &mut errors,
        "consents.privacy_version",
        &req.consents.privacy_version,
        1,
        MAX_VERSION_CHARS,
    );
    let n = req.turnstile_token.chars().count();
    if n == 0 || n > MAX_CAPTCHA_TOKEN_CHARS {
        errors.push(field("turnstile_token", "Confirmação anti-robô em falta."));
    }
    let email = match email::normalize(&req.email) {
        Ok(e) => Some(e),
        Err(AppError::Validation(f)) => {
            errors.extend(f);
            None
        }
        Err(e) => return Err(e),
    };
    match (email, name, terms, privacy) {
        (Some(email), Some(name), Some(terms_version), Some(privacy_version))
            if errors.is_empty() =>
        {
            Ok(ValidRegistration {
                email,
                name,
                terms_version,
                privacy_version,
                marketing: req.consents.marketing,
            })
        }
        _ => Err(AppError::Validation(errors)),
    }
}

/// Honeypot preenchido ou formulário enviado há menos de `MIN_FILL_TIME` (ou no futuro).
fn looks_like_bot(req: &RegisterRequest, now: SystemTime) -> bool {
    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let min_ms = i64::try_from(MIN_FILL_TIME.as_millis()).unwrap_or(i64::MAX);
    let elapsed = now_ms.saturating_sub(req.form_started_at);
    !req.website.is_empty() || elapsed < min_ms
}

/// 422 genérico (não diz o que falhou) + recusa `bot` na caixa negra.
fn bot() -> Response {
    let mut resp = AppError::Validation(vec![]).into_response();
    resp.extensions_mut().insert(DENIED_BOT);
    resp
}

/// Telefone: só `[0-9 +()-]`.
fn phone_chars_ok(v: &str) -> bool {
    v.chars()
        .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '+' | '(' | ')' | '-'))
}

/// `phone`/`nif` do PATCH: ausente = não mexe; `""` = apaga; resto = valor validado.
enum Change {
    Keep,
    Set(Option<String>),
}

impl Change {
    fn flag(&self) -> bool {
        matches!(self, Self::Set(_))
    }

    fn value(&self) -> Option<&str> {
        match self {
            Self::Set(v) => v.as_deref(),
            Self::Keep => None,
        }
    }
}

struct ValidPatch {
    name: Option<String>,
    phone: Change,
    nif: Change,
    marketing: Option<bool>,
}

impl ValidPatch {
    fn is_empty(&self) -> bool {
        self.name.is_none() && !self.phone.flag() && !self.nif.flag() && self.marketing.is_none()
    }
}

fn validate_patch(p: &ProfilePatch, country: CountryCode) -> Result<ValidPatch, AppError> {
    let mut errors = Vec::new();
    let name = match &p.name {
        None => None,
        Some(n) => text(&mut errors, "name", n, 1, MAX_NAME_CHARS),
    };
    let phone = match p.phone.as_deref().map(str::trim) {
        None => Change::Keep,
        Some("") => Change::Set(None),
        Some(v) => {
            let v = text(&mut errors, "phone", v, 1, MAX_PHONE_CHARS);
            if v.as_deref().is_some_and(|t| !phone_chars_ok(t)) {
                errors.push(field("phone", "Só algarismos, espaços e + ( ) -."));
            }
            Change::Set(v)
        }
    };
    let nif = match p.nif.as_deref().map(str::trim) {
        None => Change::Keep,
        Some("") => Change::Set(None),
        Some(v) => {
            let v = v.to_ascii_uppercase();
            let ok = match country {
                CountryCode::Pt => nif::validate_pt(&v),
                CountryCode::Es => nif::plausible_es(&v),
            };
            if !ok {
                errors.push(field("nif", "NIF inválido."));
            }
            Change::Set(Some(v))
        }
    };
    if errors.is_empty() {
        Ok(ValidPatch {
            name,
            phone,
            nif,
            marketing: p.marketing,
        })
    } else {
        Err(AppError::Validation(errors))
    }
}

// ---------------------------------------------------------------------------------------------
// BD
// ---------------------------------------------------------------------------------------------

/// O INSERT falhou porque o email já tem conta.
fn is_duplicate_email(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db) => {
            db.code().as_deref() == Some("23505") && db.constraint() == Some(EMAIL_UNIQUE_INDEX)
        }
        _ => false,
    }
}

/// Insere a conta (ator anónimo; sem RETURNING) dentro de um SAVEPOINT. `Ok(false)` = email já
/// registado: ROLLBACK TO SAVEPOINT e a transação continua utilizável (o caso duplicado segue na
/// MESMA transação, com o mesmo número de idas à BD que o caso novo, para não se distinguir pelo
/// tempo).
async fn insert_customer(
    tx: &mut TenantTx,
    id: Uuid,
    v: &ValidRegistration,
    phc: &str,
) -> Result<bool, AppError> {
    let mut sp = Connection::begin(&mut **tx).await.map_err(db_error)?;
    let res = sqlx::query!(
        r#"INSERT INTO customers (id, email, name, password_hash, consents)
           VALUES ($1, $2, $3, $4, jsonb_build_object(
               'terms', jsonb_build_object('version', $5::text,
                   'at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
               'privacy', jsonb_build_object('version', $6::text,
                   'at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')),
               'marketing', jsonb_build_object('granted', $7::bool,
                   'at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))))"#,
        id,
        v.email,
        v.name,
        phc,
        v.terms_version,
        v.privacy_version,
        v.marketing
    )
    .execute(&mut *sp)
    .await;
    match res {
        Ok(_) => {
            sp.commit().await.map_err(db_error)?;
            Ok(true)
        }
        Err(e) if is_duplicate_email(&e) => {
            sp.rollback().await.map_err(db_error)?;
            Ok(false)
        }
        Err(e) => Err(db_error(e)),
    }
}

/// Id da conta com este email (já normalizado), pela única leitura por email
/// (`identity_customer_credentials`, 0017/0021).
///
/// Exceção à regra `query!` (como `session::lookup`): a verificação em compilação faz EXPLAIN, que
/// exige EXECUTE na função; o migrator não o tem (dono `ptmarket_identity`). SQL estático, função
/// qualificada pelo schema, argumento e coluna com o tipo exato; verificado no teste `customers`.
async fn customer_id_by_email(tx: &mut TenantTx, email: &str) -> Result<Option<Uuid>, AppError> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT c.id::uuid FROM public.identity_customer_credentials($1::text) AS c",
    )
    .bind(email)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(row.map(|(id,)| id))
}

/// Email repetido (na transação do registo, depois do ROLLBACK TO SAVEPOINT): evento de outbox para
/// o titular (sem email no payload) e `customer.register_duplicate` com o `account_hash` (HMAC com
/// `ACCOUNT_HASH_KEY`) do email normalizado (nunca o email).
async fn record_duplicate(
    tx: &mut TenantTx,
    email: &str,
    account: &AccountKey,
) -> Result<(), AppError> {
    if let Some(id) = customer_id_by_email(tx, email).await? {
        outbox::append(
            tx,
            NewEvent {
                aggregate: "customer".to_owned(),
                aggregate_id: id,
                event_type: "customer.duplicate_registration".to_owned(),
                payload: serde_json::json!({ "customer_id": id }),
            },
        )
        .await?;
    }
    record(
        tx,
        AuditEvent {
            action: "customer.register_duplicate",
            target_type: Some("account_hash"),
            target_id: Some(account_hash(account, email)),
            outcome: Outcome::Success,
            reason: None,
            changes: None,
            store_id: None,
        },
    )
    .await?;
    Ok(())
}

struct ProfileRow {
    id: Uuid,
    email: Option<String>,
    name: Option<String>,
    phone: Option<String>,
    nif: Option<String>,
    consents: serde_json::Value,
    created_at: String,
}

/// Perfil do ator da transação (`id` = o ator; a RLS só mostra a própria linha).
async fn load_profile(tx: &mut TenantTx, id: Uuid) -> Result<CustomerProfile, AppError> {
    let row = sqlx::query_as!(
        ProfileRow,
        r#"SELECT id, email, name, phone, nif, consents,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
                      AS "created_at!"
           FROM customers WHERE id = $1"#,
        id
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or(AppError::NotFound)?;
    Ok(CustomerProfile {
        id: row.id,
        email: row.email.unwrap_or_default(),
        name: row.name,
        phone: row.phone,
        nif: row.nif,
        consents: row.consents,
        created_at: row.created_at,
    })
}

/// Aplica a alteração à linha do ator. `false` se a linha não existir (ou não for do ator).
async fn update_profile(tx: &mut TenantTx, id: Uuid, p: &ValidPatch) -> Result<bool, AppError> {
    let r = sqlx::query!(
        r#"UPDATE customers SET
               name = CASE WHEN $2::bool THEN $3::text ELSE name END,
               phone = CASE WHEN $4::bool THEN $5::text ELSE phone END,
               nif = CASE WHEN $6::bool THEN $7::text ELSE nif END,
               consents = CASE WHEN $8::bool IS NULL THEN consents
                   ELSE jsonb_set(consents, '{marketing}', jsonb_build_object('granted', $8::bool,
                       'at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')))
                   END,
               updated_at = now()
           WHERE id = $1"#,
        id,
        p.name.is_some(),
        p.name.as_deref(),
        p.phone.flag(),
        p.phone.value(),
        p.nif.flag(),
        p.nif.value(),
        p.marketing
    )
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(r.rows_affected() == 1)
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Regista um cliente (conta global). Responde sempre 202 com o mesmo corpo, exista ou não o
/// email; não inicia sessão.
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 202, description = "Pedido aceite (sempre igual, exista ou não a conta)",
            body = RegisterAccepted),
        (status = 403, description = "Pedido com sessão iniciada, ou Origin ausente ou de outro site"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 422, description = "Dados inválidos, password vazada ou verificação anti-robô falhada"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn register(
    State(st): State<AppState>,
    tenant: ResolvedTenant,
    ctx: AuditCtx,
    cur: CurrentSession,
    host: Option<Extension<RequestHost>>,
    body: Result<Json<RegisterRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(reg) = cur.sessions().registration().cloned() else {
        tracing::error!("registo sem captcha configurado (Sessions::with_registration); 503");
        return Err(AppError::ServiceUnavailable);
    };
    // A RLS só deixa o ator anónimo registar; com sessão não há registo.
    if cur.actor().is_some() || ctx.actor_type() != ActorType::Anonymous {
        return Err(AppError::Forbidden);
    }
    let mut req = json_body(body)?;
    // Host efetivo do pedido (o do tenant, normalizado; `capture_host`): o captcha tem de ter sido
    // resolvido nele. Sem host → o captcha falha (falha fechado).
    let expected_host = host.and_then(|Extension(h)| h.host).unwrap_or_default();
    let result = register_inner(&st, tenant.id(), &ctx, &reg, &req, &expected_host).await;
    req.password.zeroize();
    result
}

/// Tempo mínimo fixo de resposta (`Registration::min_response`) para TODOS os resultados do
/// registo: 202 (conta nova ou repetida), 422 (validação, bot, password vazada) e erros.
async fn register_inner(
    st: &AppState,
    tenant: TenantId,
    ctx: &AuditCtx,
    reg: &Registration,
    req: &RegisterRequest,
    expected_host: &str,
) -> Result<Response, AppError> {
    let t0 = tokio::time::Instant::now();
    let result = register_steps(st, tenant, ctx, reg, req, expected_host).await;
    tokio::time::sleep_until(t0 + reg.min_response).await;
    result
}

async fn register_steps(
    st: &AppState,
    tenant: TenantId,
    ctx: &AuditCtx,
    reg: &Registration,
    req: &RegisterRequest,
    expected_host: &str,
) -> Result<Response, AppError> {
    let valid = validate_registration(req)?;
    if looks_like_bot(req, SystemTime::now()) {
        return Ok(bot());
    }
    if !reg
        .captcha
        .verify(&req.turnstile_token, ctx.ip(), expected_host)
        .await
    {
        return Ok(bot());
    }
    let pw = Password::parse(&req.password)?;
    if reg.breach.is_breached(&pw).await {
        return Err(AppError::Validation(vec![field(
            "password",
            "Esta password aparece em fugas de dados conhecidas. Escolha outra.",
        )]));
    }
    // Calculado SEMPRE (também se o email já existir): o tempo de resposta não revela a conta.
    let phc = password::hash(&pw).await?;
    drop(pw);

    let id = Uuid::now_v7();
    let mut tx = begin_tenant_tx(&st.db_primary, tenant, ctx).await?;
    if insert_customer(&mut tx, id, &valid, &phc).await? {
        record(
            &mut tx,
            AuditEvent {
                action: "customer.registered",
                target_type: Some("customer"),
                target_id: Some(id.to_string()),
                outcome: Outcome::Success,
                reason: None,
                changes: Some(serde_json::json!({
                    "consents": {
                        "terms_version": valid.terms_version,
                        "privacy_version": valid.privacy_version,
                        "marketing": valid.marketing,
                    }
                })),
                store_id: None,
            },
        )
        .await?;
    } else {
        // O 23505 só desfez o SAVEPOINT: a mesma transação grava o outbox e o evento.
        record_duplicate(&mut tx, &valid.email, &reg.account).await?;
    }
    tx.commit().await?;
    Ok(accepted())
}

/// 202 `{"status":"ok"}` (byte a byte igual em todos os casos de sucesso).
fn accepted() -> Response {
    no_store(
        (
            StatusCode::ACCEPTED,
            Json(RegisterAccepted {
                status: "ok".to_owned(),
            }),
        )
            .into_response(),
    )
}

/// Perfil do cliente autenticado (só o próprio: não há id no pedido).
#[utoipa::path(
    get,
    path = "/api/v1/me",
    tag = "customers",
    responses(
        (status = 200, description = "Perfil do cliente da sessão", body = CustomerProfile),
        (status = 401, description = "Sem sessão de cliente"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn get_me(
    who: RequireCustomer,
    State(st): State<AppState>,
    tenant: ResolvedTenant,
    ctx: AuditCtx,
) -> Result<Response, AppError> {
    let mut tx = begin_tenant_tx(&st.db_primary, tenant.id(), &ctx).await?;
    let profile = load_profile(&mut tx, who.customer_id).await?;
    tx.commit().await?;
    Ok(no_store(Json(profile).into_response()))
}

/// Altera nome, telefone, NIF e consentimento de marketing do cliente autenticado.
#[utoipa::path(
    patch,
    path = "/api/v1/me",
    tag = "customers",
    request_body = ProfilePatch,
    params(
        ("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")
    ),
    responses(
        (status = 200, description = "Perfil depois da alteração", body = CustomerProfile),
        (status = 401, description = "Sem sessão de cliente"),
        (status = 403, description = "Token CSRF ou Origin inválidos"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 422, description = "Dados inválidos (ex.: NIF com dígito de controlo errado)"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn patch_me(
    who: RequireCustomer,
    State(st): State<AppState>,
    tenant: ResolvedTenant,
    ctx: AuditCtx,
    body: Result<Json<ProfilePatch>, JsonRejection>,
) -> Result<Response, AppError> {
    let patch = validate_patch(&json_body(body)?, tenant.country_code())?;
    let mut tx = begin_tenant_tx(&st.db_primary, tenant.id(), &ctx).await?;
    if !patch.is_empty() && !update_profile(&mut tx, who.customer_id, &patch).await? {
        return Err(AppError::NotFound);
    }
    let profile = load_profile(&mut tx, who.customer_id).await?;
    tx.commit().await?;
    Ok(no_store(Json(profile).into_response()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(website: &str, started_ms_ago: i64) -> RegisterRequest {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
            .unwrap_or(0);
        RegisterRequest {
            email: " Ana@X.pt ".into(),
            password: "uma-password-longa".into(),
            name: " Ana ".into(),
            consents: ConsentsInput {
                terms_version: "2026-11".into(),
                privacy_version: "2026-11".into(),
                marketing: false,
            },
            turnstile_token: "tok".into(),
            website: website.into(),
            form_started_at: now - started_ms_ago,
        }
    }

    #[test]
    fn honeypot_and_fill_time() {
        let now = SystemTime::now();
        assert!(!looks_like_bot(&req("", 5_000), now));
        assert!(looks_like_bot(&req("http://spam", 5_000), now));
        assert!(looks_like_bot(&req(" ", 5_000), now));
        assert!(looks_like_bot(&req("", 500), now));
        // No futuro também é bot.
        assert!(looks_like_bot(&req("", -60_000), now));
    }

    #[test]
    fn registration_is_trimmed_and_email_normalized() {
        let v = validate_registration(&req("", 5_000));
        assert!(v.is_ok());
        if let Ok(v) = v {
            assert_eq!(v.email, "ana@x.pt");
            assert_eq!(v.name, "Ana");
        }
        let mut r = req("", 5_000);
        r.consents.terms_version = " ".into();
        r.name = String::new();
        r.email = "sem-arroba".into();
        if let Err(AppError::Validation(f)) = validate_registration(&r) {
            let names: Vec<&str> = f.iter().map(|e| e.field.as_str()).collect();
            assert_eq!(names, ["name", "consents.terms_version", "email"]);
        } else {
            unreachable!("devia falhar a validação");
        }
    }

    #[test]
    fn patch_nif_per_country_and_clearing() {
        let p = |nif: &str| ProfilePatch {
            name: None,
            phone: Some(String::new()),
            nif: Some(nif.into()),
            marketing: None,
        };
        assert!(validate_patch(&p("123456789"), CountryCode::Pt).is_ok());
        assert!(validate_patch(&p("123456788"), CountryCode::Pt).is_err());
        assert!(validate_patch(&p("12345678z"), CountryCode::Pt).is_err());
        let es = validate_patch(&p("12345678z"), CountryCode::Es);
        assert!(
            es.as_ref()
                .is_ok_and(|v| v.nif.value() == Some("12345678Z"))
        );
        assert!(es.is_ok_and(|v| v.phone.flag() && v.phone.value().is_none()));
        let cleared = validate_patch(&p(""), CountryCode::Pt);
        assert!(cleared.is_ok_and(|v| v.nif.flag() && v.nif.value().is_none()));
        let long = ProfilePatch {
            name: Some(String::new()),
            phone: Some("9".repeat(MAX_PHONE_CHARS + 1)),
            nif: None,
            marketing: None,
        };
        if let Err(AppError::Validation(f)) = validate_patch(&long, CountryCode::Pt) {
            assert_eq!(f.len(), 2);
        } else {
            unreachable!("devia falhar a validação");
        }
    }

    #[test]
    fn phone_only_digits_spaces_and_plus_parens_dash() {
        let p = |phone: &str| ProfilePatch {
            name: None,
            phone: Some(phone.into()),
            nif: None,
            marketing: None,
        };
        for ok in ["+351 912 345 678", "(+34) 600-123-456", "912345678", ""] {
            assert!(validate_patch(&p(ok), CountryCode::Pt).is_ok(), "{ok:?}");
        }
        for bad in [
            "912 abc",
            "912.345.678",
            "912/345",
            "+351 ９12",
            "912#1",
            "<script>",
        ] {
            assert!(validate_patch(&p(bad), CountryCode::Pt).is_err(), "{bad:?}");
        }
    }
}
