//! Passkeys (WebAuthn) de backoffice (cartão 02/21; spec 12 §3, ASVS L3 em identity).
//!
//! - Relying Party = o host do pedido JÁ resolvido pela tenancy (domínio da Câmara ou
//!   `PLATFORM_ADMIN_HOST`; nunca um cabeçalho cru): `rp_id` = host, origin = `https://<host>`
//!   (`http://<host>` com qualquer porta só com `APP_ENV` development/test). Um `Webauthn` por host,
//!   em cache. Uma passkey só serve no host onde foi registada: o `rp_id` fica guardado com a
//!   credencial (`credential` = `{"v":1,"rp_id":…,"passkey":<serialização da biblioteca>}`) e é
//!   comparado no login, além da verificação do `rpIdHash` pela biblioteca.
//! - Estado da cerimónia só no Redis: `<ns>webauthn:<reg|auth>:<id aleatório de 256 bits>`, TTL
//!   5 min, uso único (`GETDEL`). Nunca em cookie nem no cliente; o cliente só recebe o id.
//! - Registo (`RequireStaff` + CSRF: o 2FA obrigatório do cartão 19 já foi exigido): user
//!   verification obrigatória, resident key `preferred`, credenciais já registadas excluídas.
//! - Login (anónimo, `Origin` obrigatória): descoberta (sem lista de credenciais); credencial
//!   procurada por `identity_passkey_lookup` (só utilizadores ativos); `userHandle` = id do dono;
//!   mesmas regras de host/papel e o mesmo travão por IP/64 do login de staff (`throttle`, chaves
//!   `staff:`). Sucesso → sessão rodada com `mfa_verified_at = now()` (houve user verification).
//!   Falha → 401 genérico + `auth.passkey_login` `denied`.
//! - Contador: recebido ≤ guardado com ambos > 0 → recusa (`cloned_authenticator`), atómico no
//!   `UPDATE` (dois logins em paralelo com o mesmo contador: só um entra).
//! - Caixa negra: `passkey.registered`, `passkey.removed`, `auth.passkey_login`. Nunca a
//!   credencial, o challenge, a assinatura nem a etiqueta: só ids.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use axum::{
    Extension, Json,
    extract::{
        Path, State,
        rejection::{JsonRejection, PathRejection},
    },
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_redis::redis;
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Webauthn, WebauthnBuilder,
};

use crate::{
    audit::{ActorType, AuditCtx, AuditEvent, Outcome},
    config::{AppEnv, Config},
    error::{AppError, FieldError},
    http::audit_layer::Denied,
    identity::{
        csrf::{RequestHost, is_dev_host},
        elevate::{NoImpersonation, OwnTx, forget, own_previous, revoke_foreign_session},
        http::{CurrentSession, SessionInfo, no_store},
        rbac::{DENIED_IDOR, RequireStaff, StaffRoles, load_roles},
        session::{self, CookieKind, CookieValue, SessionKind, Subject},
        staff::REASON_NO_ROLE_HERE,
        throttle::{self, Gate, Keys, Limits},
    },
    outbox::NewEvent,
    state::AppState,
    tenancy::{
        PlatformHost, ResolvedTenant, TenantId,
        db::{begin_platform_tx, db_error},
    },
};

/// Vida do estado de uma cerimónia no Redis.
pub const CEREMONY_TTL: Duration = Duration::from_secs(300);
/// Etiqueta da passkey: 1–64 caracteres (`VARCHAR(64)`).
pub const MAX_LABEL_CHARS: usize = 64;
/// Id da cerimónia: 32 bytes do CSPRNG em base64url sem padding.
pub const CEREMONY_ID_CHARS: usize = 43;
/// Hosts com `Webauthn` em cache (só hosts conhecidos chegam aqui; acima disto a cache recomeça).
const MAX_CACHED_HOSTS: usize = 4096;
const RP_NAME: &str = "PT Market";
const REDIS_TIMEOUT: Duration = Duration::from_secs(1);
/// Versão do formato guardado em `user_passkeys.credential`.
const STORED_VERSION: u64 = 1;

/// Ações na caixa negra.
pub const ACTION_REGISTERED: &str = "passkey.registered";
pub const ACTION_REMOVED: &str = "passkey.removed";
pub const ACTION_LOGIN: &str = "auth.passkey_login";
/// Motivos das recusas.
pub const REASON_CEREMONY: &str = "ceremony";
pub const REASON_UNKNOWN_CREDENTIAL: &str = "unknown_credential";
pub const REASON_RP_MISMATCH: &str = "rp_mismatch";
pub const REASON_VERIFICATION: &str = "verification";
pub const REASON_CLONED: &str = "cloned_authenticator";
pub const REASON_VERSION: &str = "credential_version";
pub const REASON_UNREADABLE: &str = "credential_unreadable";
/// Recusas com sessão (gravadas pela caixa negra).
pub const DENIED_CEREMONY: Denied = Denied("passkey_ceremony");
pub const DENIED_VERIFICATION: Denied = Denied("passkey_verification");
/// Registo de uma credencial NÃO detetável (`credProps.rk = false`): 422.
pub const DENIED_NOT_DISCOVERABLE: Denied = Denied("not_discoverable");

// ---------------------------------------------------------------------------------------------
// Dependências
// ---------------------------------------------------------------------------------------------

/// Relying Parties por host e limites do travão do login por passkey.
#[derive(Clone)]
pub struct Passkeys {
    /// `http://<host>` (qualquer porta) também aceite: só development/test.
    allow_http: bool,
    limits: Limits,
    cache: Arc<Mutex<HashMap<String, Arc<Webauthn>>>>,
}

impl Passkeys {
    pub fn new(env: AppEnv) -> Self {
        Self {
            allow_http: matches!(env, AppEnv::Development | AppEnv::Test),
            limits: Limits::default(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_config(cfg: &Config) -> Self {
        Self::new(cfg.app_env)
    }

    /// Só para testes: limites do travão mais curtos.
    #[cfg(feature = "test-support")]
    pub fn with_limits_for_tests(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// `Webauthn` do host (já normalizado e conhecido): `rp_id` = host.
    fn rp(&self, host: &str) -> Result<Arc<Webauthn>, AppError> {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(w) = cache.get(host) {
            return Ok(Arc::clone(w));
        }
        let built = Arc::new(build_rp(host, self.allow_http)?);
        if cache.len() >= MAX_CACHED_HOSTS {
            cache.clear();
        }
        cache.insert(host.to_owned(), Arc::clone(&built));
        Ok(built)
    }
}

fn build_rp(host: &str, allow_http: bool) -> Result<Webauthn, AppError> {
    let bad = |what: &str| {
        tracing::error!(what, "passkeys: Relying Party inválida para o host");
        AppError::ServiceUnavailable
    };
    let https = Url::parse(&format!("https://{host}")).map_err(|_| bad("origin"))?;
    let mut b = WebauthnBuilder::new(host, &https)
        .map_err(|_| bad("rp_id"))?
        .rp_name(RP_NAME);
    let http;
    // `http://` só em development/test E só nos hosts locais (os mesmos do CSRF).
    if allow_http && is_dev_host(host) {
        http = Url::parse(&format!("http://{host}")).map_err(|_| bad("origin http"))?;
        b = b.append_allowed_origin(&http).allow_any_port(true);
    }
    b.build().map_err(|_| bad("build"))
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// Opções da cerimónia (para `navigator.credentials.create/get`) e o id a devolver no `finish`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CeremonyOptions {
    pub ceremony_id: String,
    /// `{"publicKey": …}` (binários em base64url).
    #[schema(value_type = Object)]
    pub options: serde_json::Value,
}

/// Fim do registo: id da cerimónia, etiqueta (1–64) e a resposta do autenticador.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishRequest {
    pub ceremony_id: String,
    pub label: String,
    /// `PublicKeyCredential` de `navigator.credentials.create` (binários em base64url).
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
}

/// Passkey criada.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PasskeyCreated {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub label: String,
}

/// Passkey do próprio (sem a credencial).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PasskeyItem {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub label: String,
    /// RFC 3339, UTC.
    pub created_at: String,
    /// RFC 3339, UTC; `null` = nunca usada.
    pub last_used_at: Option<String>,
}

/// Fim do login: id da cerimónia e a resposta do autenticador.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRequest {
    pub ceremony_id: String,
    /// `PublicKeyCredential` de `navigator.credentials.get` (binários em base64url).
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
}

fn invalid(field: &str, message: &str) -> AppError {
    AppError::Validation(vec![FieldError {
        field: field.to_owned(),
        message: message.to_owned(),
    }])
}

fn body<T>(b: Result<Json<T>, JsonRejection>) -> Result<T, AppError> {
    b.map(|Json(v)| v).map_err(|_| {
        invalid(
            "body",
            "Corpo JSON inválido, com campos em falta ou desconhecidos.",
        )
    })
}

fn valid_label(raw: &str) -> Result<String, AppError> {
    let label = raw.trim();
    let n = label.chars().count();
    if n == 0 || n > MAX_LABEL_CHARS || label.chars().any(char::is_control) {
        return Err(invalid(
            "label",
            "Entre 1 e 64 caracteres, sem caracteres de controlo.",
        ));
    }
    Ok(label.to_owned())
}

/// `clientExtensionResults.credProps.rk` (resident key = credencial detetável), lido do JSON cru
/// (a biblioteca não expõe o valor). `false` → a passkey não serve no login por descoberta;
/// ausente → aceite (nem todos os browsers enviam `credProps`).
fn discoverable(credential: &serde_json::Value) -> bool {
    let rk = ["clientExtensionResults", "extensions"]
        .iter()
        .find_map(|k| credential.get(*k))
        .and_then(|e| e.get("credProps"))
        .and_then(|p| p.get("rk"));
    !matches!(rk, Some(serde_json::Value::Bool(false)))
}

fn credential<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, AppError> {
    serde_json::from_value(v).map_err(|_| invalid("credential", "Credencial WebAuthn inválida."))
}

// ---------------------------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------------------------

/// Host conhecido do pedido: tenant (`None` = plataforma) e o host normalizado (= `rp_id`).
struct Site {
    tenant: Option<TenantId>,
    host: String,
}

fn site(
    tenant: Result<ResolvedTenant, AppError>,
    platform: Result<PlatformHost, AppError>,
    host: Option<Extension<RequestHost>>,
) -> Result<Site, AppError> {
    let tenant = match (tenant, platform) {
        (Ok(t), _) => Some(t.id()),
        (Err(_), Ok(PlatformHost)) => None,
        (Err(e), Err(_)) => return Err(e),
    };
    let Some(host) = host.and_then(|Extension(h)| h.host) else {
        return Err(AppError::NotFound);
    };
    Ok(Site { tenant, host })
}

// ---------------------------------------------------------------------------------------------
// Cerimónias no Redis
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct RegCeremony {
    user: Uuid,
    /// Sessão que iniciou a cerimónia (o `finish` tem de vir da mesma).
    session: Uuid,
    host: String,
    state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
struct AuthCeremony {
    host: String,
    state: DiscoverableAuthentication,
}

#[derive(Clone, Copy)]
enum Kind {
    Reg,
    Auth,
}

fn ceremony_key(ns: &str, kind: Kind, id: &str) -> String {
    let k = match kind {
        Kind::Reg => "reg",
        Kind::Auth => "auth",
    };
    format!("{ns}webauthn:{k}:{id}")
}

fn new_ceremony_id() -> Result<String, AppError> {
    let mut raw = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("CSPRNG do SO indisponível")))?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn valid_ceremony_id(id: &str) -> bool {
    id.len() == CEREMONY_ID_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

async fn redis_query<T: redis::FromRedisValue>(
    pool: &deadpool_redis::Pool,
    cmd: redis::Cmd,
) -> Result<T, AppError> {
    let fut = async {
        let mut conn = pool.get().await.map_err(|e| {
            tracing::error!(error = %e, "passkeys: Redis indisponível");
            AppError::ServiceUnavailable
        })?;
        cmd.query_async::<T>(&mut conn).await.map_err(|e| {
            tracing::error!(error = %e, "passkeys: comando Redis falhou");
            AppError::ServiceUnavailable
        })
    };
    tokio::time::timeout(REDIS_TIMEOUT, fut)
        .await
        .map_err(|_| AppError::ServiceUnavailable)?
}

/// Guarda o estado com TTL; devolve o id novo.
async fn put<T: Serialize>(
    cur: &CurrentSession,
    kind: Kind,
    state: &T,
) -> Result<String, AppError> {
    let id = new_ceremony_id()?;
    let value = serde_json::to_string(state)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("estado WebAuthn não serializa: {e}")))?;
    let s = cur.sessions();
    let mut cmd = redis::cmd("SET");
    cmd.arg(ceremony_key(s.ns(), kind, &id))
        .arg(value)
        .arg("PX")
        .arg(u64::try_from(CEREMONY_TTL.as_millis()).unwrap_or(300_000))
        .arg("NX");
    let r: Option<String> = redis_query(s.redis(), cmd).await?;
    if r.is_none() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "id de cerimónia repetido"
        )));
    }
    Ok(id)
}

/// Lê e apaga (uso único). Id malformado, desconhecido, expirado ou já usado → `None`.
async fn take<T: serde::de::DeserializeOwned>(
    cur: &CurrentSession,
    kind: Kind,
    id: &str,
) -> Result<Option<T>, AppError> {
    if !valid_ceremony_id(id) {
        return Ok(None);
    }
    let s = cur.sessions();
    let mut cmd = redis::cmd("GETDEL");
    cmd.arg(ceremony_key(s.ns(), kind, id));
    let raw: Option<String> = redis_query(s.redis(), cmd).await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

fn event(
    action: &'static str,
    target_type: &'static str,
    target: Option<Uuid>,
    outcome: Outcome,
    reason: Option<&str>,
) -> AuditEvent {
    AuditEvent {
        action,
        target_type: target.map(|_| target_type),
        target_id: target.map(|t| t.to_string()),
        outcome,
        reason: reason.map(str::to_owned),
        changes: None,
        store_id: None,
    }
}

/// Recusa de uma ação sensível da conta sem login/2FA nos últimos `REAUTH_WINDOW`.
pub const DENIED_REAUTH: Denied = Denied("reauth_required");

/// Sessão do pedido (o extractor já exigiu uma sessão `user`; `NoImpersonation` já recusou a
/// impersonação) com autenticação recente (≤ `REAUTH_WINDOW`); senão 403 `reauth_required`.
fn recent_session(cur: &CurrentSession) -> Result<SessionInfo, Box<Response>> {
    let Some(info) = cur.info() else {
        return Err(Box::new(no_store(AppError::Unauthorized.into_response())));
    };
    if !info.recently_authenticated() {
        return Err(Box::new(refused(DENIED_REAUTH, AppError::Forbidden)));
    }
    Ok(info)
}

/// `staff.security_notice` no outbox (só ids; o email é do épico de notificações).
fn notice(user: Uuid, kind: &str) -> NewEvent {
    NewEvent {
        aggregate: "user".to_owned(),
        aggregate_id: user,
        event_type: "staff.security_notice".to_owned(),
        payload: serde_json::json!({ "user_id": user, "kind": kind }),
    }
}

fn refused(d: Denied, err: AppError) -> Response {
    no_store((Extension(d), err).into_response())
}

/// Conteúdo de `user_passkeys.credential`.
#[derive(Serialize, Deserialize)]
struct Stored {
    v: u64,
    rp_id: String,
    passkey: serde_json::Value,
}

// ---------------------------------------------------------------------------------------------
// Registo e gestão (sessão de staff)
// ---------------------------------------------------------------------------------------------

/// Inicia o registo de uma passkey no host do pedido (user verification obrigatória; resident key
/// preferida; as passkeys já registadas ficam excluídas).
#[utoipa::path(
    post,
    path = "/api/v1/staff/passkeys/register/start",
    tag = "staff",
    params(("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")),
    responses(
        (status = 200, description = "Opções de criação e id da cerimónia (válida 5 min, uso único)", body = CeremonyOptions),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Sem papel neste host, 2FA em falta, token CSRF/Origin inválidos, sessão de impersonação (`impersonation`) ou login/2FA há mais de 10 min (`reauth_required`)"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
#[allow(
    clippy::too_many_arguments,
    reason = "um extractor por dependência do pedido"
)]
pub async fn register_start(
    State(st): State<AppState>,
    staff: RequireStaff,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    cur: CurrentSession,
    tenant: Result<ResolvedTenant, AppError>,
    platform: Result<PlatformHost, AppError>,
    host: Option<Extension<RequestHost>>,
) -> Result<Response, AppError> {
    let info = match recent_session(&cur) {
        Ok(i) => i,
        Err(r) => return Ok(*r),
    };
    let site = site(tenant, platform, host)?;
    let rp = cur.sessions().passkeys().rp(&site.host)?;
    let user = staff.user_id;
    let mut tx = begin_platform_tx(&st.db_primary, &ctx).await?;
    let me = sqlx::query!("SELECT email, full_name FROM users WHERE id = $1", user)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    let exclude = sqlx::query_scalar!(
        "SELECT credential_id FROM user_passkeys WHERE user_id = $1",
        user
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(db_error)?;
    tx.rollback().await?;
    let Some(me) = me else {
        return Err(AppError::Unauthorized);
    };
    let (ccr, state) = rp
        .start_passkey_registration(user, &me.email, &me.full_name, Some(exclude))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("WebAuthn: registo não iniciado: {e}")))?;
    let mut options = serde_json::to_value(&ccr)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("opções WebAuthn: {e}")))?;
    if let Some(sel) = options
        .get_mut("publicKey")
        .and_then(|p| p.get_mut("authenticatorSelection"))
        .and_then(serde_json::Value::as_object_mut)
    {
        sel.insert("residentKey".to_owned(), "preferred".into());
    }
    let ceremony = RegCeremony {
        user,
        session: info.id.as_uuid(),
        host: site.host,
        state,
    };
    let ceremony_id = put(&cur, Kind::Reg, &ceremony).await?;
    let out = CeremonyOptions {
        ceremony_id,
        options,
    };
    Ok(no_store(Json(out).into_response()))
}

/// Conclui o registo: verifica a resposta do autenticador contra a cerimónia (do próprio, neste
/// host) e guarda a credencial pública.
#[utoipa::path(
    post,
    path = "/api/v1/staff/passkeys/register/finish",
    tag = "staff",
    params(("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")),
    request_body = RegisterFinishRequest,
    responses(
        (status = 201, description = "Passkey registada", body = PasskeyCreated),
        (status = 401, description = "Sem sessão, cerimónia desconhecida/expirada/já usada, ou credencial recusada"),
        (status = 403, description = "Sem papel neste host, 2FA em falta, token CSRF/Origin inválidos, sessão de impersonação (`impersonation`) ou login/2FA há mais de 10 min (`reauth_required`)"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 409, description = "Credencial já registada"),
        (status = 422, description = "Dados inválidos, ou passkey não detetável (`credProps.rk = false`: `not_discoverable`)"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
#[allow(
    clippy::too_many_arguments,
    reason = "um extractor por dependência do pedido"
)]
pub async fn register_finish(
    State(st): State<AppState>,
    staff: RequireStaff,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    cur: CurrentSession,
    tenant: Result<ResolvedTenant, AppError>,
    platform: Result<PlatformHost, AppError>,
    host: Option<Extension<RequestHost>>,
    req: Result<Json<RegisterFinishRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let req = body(req)?;
    let label = valid_label(&req.label)?;
    if !discoverable(&req.credential) {
        let err = invalid(
            "credential",
            "A passkey não é detetável (credProps.rk = false): não serviria para entrar.",
        );
        return Ok(refused(DENIED_NOT_DISCOVERABLE, err));
    }
    let cred: RegisterPublicKeyCredential = credential(req.credential)?;
    let info = match recent_session(&cur) {
        Ok(i) => i,
        Err(r) => return Ok(*r),
    };
    let site = site(tenant, platform, host)?;
    let user = staff.user_id;
    let ceremony: Option<RegCeremony> = take(&cur, Kind::Reg, &req.ceremony_id).await?;
    let same = |c: &RegCeremony| {
        c.user == user && c.session == info.id.as_uuid() && c.host == site.host
    };
    let Some(c) = ceremony.filter(same) else {
        return Ok(refused(DENIED_CEREMONY, AppError::Unauthorized));
    };
    let rp = cur.sessions().passkeys().rp(&site.host)?;
    let Ok(pk) = rp.finish_passkey_registration(&cred, &c.state) else {
        return Ok(refused(DENIED_VERIFICATION, AppError::Unauthorized));
    };
    let passkey = serde_json::to_value(&pk)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("passkey não serializa: {e}")))?;
    // Contador do registo (W3C §7.1: guardado com a credencial).
    let sign_count = passkey["cred"]["counter"].as_i64().unwrap_or(0).max(0);
    let stored = Stored {
        v: STORED_VERSION,
        rp_id: site.host,
        passkey,
    };
    let stored = serde_json::to_value(&stored)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("passkey não serializa: {e}")))?;
    let id = Uuid::now_v7();
    let mut tx = OwnTx::begin(&st.db_primary, info.tenant(), &ctx).await?;
    let inserted = sqlx::query!(
        "INSERT INTO user_passkeys (id, user_id, credential_id, credential, sign_count, label)
         VALUES ($1, $2, $3, $4, $5, $6)",
        id,
        user,
        pk.cred_id().as_slice(),
        stored,
        sign_count,
        label
    )
    .execute(tx.conn())
    .await;
    if let Err(e) = inserted {
        if e.as_database_error()
            .is_some_and(|d| d.code().as_deref() == Some("23505"))
        {
            return Err(AppError::Conflict);
        }
        return Err(db_error(e));
    }
    tx.record(event(
        ACTION_REGISTERED,
        "passkey",
        Some(id),
        Outcome::Success,
        None,
    ))
    .await?;
    tx.outbox(notice(user, "passkey_registered")).await?;
    tx.commit().await?;
    let out = PasskeyCreated { id, label };
    Ok(no_store((StatusCode::CREATED, Json(out)).into_response()))
}

/// As passkeys do próprio (nunca as de outro utilizador).
#[utoipa::path(
    get,
    path = "/api/v1/staff/passkeys",
    tag = "staff",
    responses(
        (status = 200, description = "Passkeys do utilizador da sessão", body = [PasskeyItem]),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Sem papel neste host, 2FA em falta ou sessão de impersonação (`impersonation`)"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn list(
    State(st): State<AppState>,
    staff: RequireStaff,
    _ni: NoImpersonation,
    ctx: AuditCtx,
) -> Result<Response, AppError> {
    let mut tx = begin_platform_tx(&st.db_primary, &ctx).await?;
    let rows = sqlx::query!(
        r#"SELECT id, label,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS "created_at!",
                  to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS "last_used_at?"
           FROM user_passkeys WHERE user_id = $1 ORDER BY created_at, id"#,
        staff.user_id
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(db_error)?;
    tx.rollback().await?;
    let out: Vec<PasskeyItem> = rows
        .into_iter()
        .map(|r| PasskeyItem {
            id: r.id,
            label: r.label,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
        })
        .collect();
    Ok(no_store(Json(out).into_response()))
}

/// Apaga uma passkey do próprio. De outro utilizador (ou inexistente) → 404. A última passkey de
/// uma conta sem password não se apaga (409).
#[utoipa::path(
    delete,
    path = "/api/v1/staff/passkeys/{id}",
    tag = "staff",
    params(
        ("id" = String, Path, description = "Id da passkey"),
        ("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")
    ),
    responses(
        (status = 204, description = "Passkey apagada"),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Sem papel neste host, 2FA em falta, token CSRF/Origin inválidos, sessão de impersonação (`impersonation`) ou login/2FA há mais de 10 min (`reauth_required`)"),
        (status = 404, description = "Passkey inexistente ou de outro utilizador"),
        (status = 409, description = "Última credencial de uma conta sem password"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn remove(
    State(st): State<AppState>,
    staff: RequireStaff,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    cur: CurrentSession,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Response, AppError> {
    let info = match recent_session(&cur) {
        Ok(i) => i,
        Err(r) => return Ok(*r),
    };
    let Ok(Path(id)) = id else {
        return Err(AppError::NotFound);
    };
    let user = staff.user_id;
    let mut tx = OwnTx::begin(&st.db_primary, info.tenant(), &ctx).await?;
    // Trava a conta: dois DELETE em paralelo não apagam juntos a última credencial.
    let has_password = sqlx::query_scalar!(
        r#"SELECT (password_hash IS NOT NULL) AS "has!" FROM users WHERE id = $1 FOR UPDATE"#,
        user
    )
    .fetch_optional(tx.conn())
    .await
    .map_err(db_error)?;
    let Some(has_password) = has_password else {
        return Err(AppError::Unauthorized);
    };
    let own = sqlx::query_scalar!(
        "SELECT id FROM user_passkeys WHERE id = $1 AND user_id = $2",
        id,
        user
    )
    .fetch_optional(tx.conn())
    .await
    .map_err(db_error)?;
    if own.is_none() {
        return Ok(refused(DENIED_IDOR, AppError::NotFound));
    }
    if !has_password {
        // Só contam as passkeys que servem no MESMO host (rp_id) da que se apaga.
        let n = sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM user_passkeys
               WHERE user_id = $1
                 AND credential->>'rp_id' = (SELECT credential->>'rp_id' FROM user_passkeys
                                            WHERE id = $2 AND user_id = $1)"#,
            user,
            id
        )
        .fetch_one(tx.conn())
        .await
        .map_err(db_error)?;
        if n <= 1 {
            return Err(AppError::Conflict);
        }
    }
    let r = sqlx::query!(
        "DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2",
        id,
        user
    )
    .execute(tx.conn())
    .await
    .map_err(db_error)?;
    if r.rows_affected() != 1 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "passkey não apagada (linha não visível)"
        )));
    }
    tx.record(event(
        ACTION_REMOVED,
        "passkey",
        Some(id),
        Outcome::Success,
        None,
    ))
    .await?;
    tx.outbox(notice(user, "passkey_removed")).await?;
    tx.commit().await?;
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}

// ---------------------------------------------------------------------------------------------
// Login (anónimo)
// ---------------------------------------------------------------------------------------------

/// Chaves do travão do login de staff (`staff:`), com a conta = hash do id da credencial.
fn throttle_keys(cur: &CurrentSession, ctx: &AuditCtx, account: &str) -> Keys {
    Keys::new(&format!("{}staff:", cur.sessions().ns()), account, ctx.ip())
}

/// Conta a tentativa (o mesmo travão do login de staff); espera em curso → 429.
async fn gate(cur: &CurrentSession, keys: &Keys) -> Result<(), AppError> {
    let redis = cur.sessions().redis();
    let limits = &cur.sessions().passkeys().limits;
    match throttle::decide(throttle::begin(redis, keys, limits).await, limits) {
        Gate::TooMany { retry_after_s } => {
            throttle::not_attempted(redis, keys).await;
            Err(AppError::TooManyRequests { retry_after_s })
        }
        // Sem captcha: a passkey não se adivinha; o travão por IP é o que conta.
        Gate::Proceed { .. } => Ok(()),
    }
}

/// Inicia um login por passkey neste host: credencial detetável, SEM lista de credenciais (não
/// enumera contas).
#[utoipa::path(
    post,
    path = "/api/v1/staff/auth/passkey/start",
    tag = "staff",
    responses(
        (status = 200, description = "Opções de autenticação e id da cerimónia (válida 5 min, uso único)", body = CeremonyOptions),
        (status = 403, description = "Origin ausente ou de outro site"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 429, description = "Demasiadas tentativas; repetir depois de `Retry-After` segundos"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn login_start(
    ctx: AuditCtx,
    cur: CurrentSession,
    tenant: Result<ResolvedTenant, AppError>,
    platform: Result<PlatformHost, AppError>,
    host: Option<Extension<RequestHost>>,
) -> Result<Response, AppError> {
    let site = site(tenant, platform, host)?;
    let keys = throttle_keys(&cur, &ctx, "passkey-start");
    gate(&cur, &keys).await?;
    throttle::not_attempted(cur.sessions().redis(), &keys).await;
    let rp = cur.sessions().passkeys().rp(&site.host)?;
    let (rcr, state) = rp
        .start_discoverable_authentication()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("WebAuthn: login não iniciado: {e}")))?;
    let options = serde_json::to_value(&rcr)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("opções WebAuthn: {e}")))?;
    let ceremony = AuthCeremony {
        host: site.host,
        state,
    };
    let ceremony_id = put(&cur, Kind::Auth, &ceremony).await?;
    let out = CeremonyOptions {
        ceremony_id,
        options,
    };
    Ok(no_store(Json(out).into_response()))
}

/// Um login por passkey: onde decorre, quem pede e as chaves do travão.
struct Attempt<'a> {
    st: &'a AppState,
    ctx: &'a AuditCtx,
    cur: &'a CurrentSession,
    tenant: Option<TenantId>,
    keys: Keys,
}

/// Contador recebido aceitável face ao guardado (W3C WebAuthn §7.2.21): maior do que o guardado,
/// ou ambos 0 (autenticador sem contador). Tudo o resto sugere um autenticador clonado.
fn counter_ok(received: i64, stored: i64) -> bool {
    received > stored || (received == 0 && stored == 0)
}

/// Resultado da transação do login.
enum Opened {
    Session(CookieValue),
    /// Contador não aceite (`cloned_authenticator`).
    Cloned,
    /// A credencial desapareceu entre o lookup e o bloqueio (`unknown_credential`).
    Gone,
}

/// Linha de `identity_passkey_lookup`.
struct Found {
    id: Uuid,
    user: Uuid,
    credential: serde_json::Value,
}

impl Attempt<'_> {
    /// Falha: conta no travão, `auth.passkey_login` `denied` (ator anónimo, transação própria) e
    /// o 401 genérico. Falha a gravar → 503.
    async fn refuse(&self, reason: &str, passkey: Option<Uuid>) -> Result<Response, AppError> {
        self.refuse_with(reason, passkey, None).await
    }

    /// Como `refuse`, com `staff.security_notice` no outbox na mesma transação do evento.
    async fn refuse_with(
        &self,
        reason: &str,
        passkey: Option<Uuid>,
        notice: Option<NewEvent>,
    ) -> Result<Response, AppError> {
        let s = self.cur.sessions();
        throttle::failed(s.redis(), &self.keys, &s.passkeys().limits).await;
        self.record_alone(Outcome::Denied, reason, passkey, notice)
            .await?;
        Ok(no_store(AppError::Unauthorized.into_response()))
    }

    /// Credencial guardada ilegível (defeito nosso, não do cliente): `error`, sem contar no
    /// travão, 503.
    async fn broken(&self, passkey: Uuid) -> Result<Response, AppError> {
        tracing::error!(passkey = %passkey, "login por passkey: credencial guardada ilegível");
        self.record_alone(Outcome::Error, REASON_UNREADABLE, Some(passkey), None)
            .await?;
        Err(AppError::ServiceUnavailable)
    }

    /// `auth.passkey_login` com o ator anónimo numa transação própria. Falha → 503.
    async fn record_alone(
        &self,
        outcome: Outcome,
        reason: &str,
        passkey: Option<Uuid>,
        notice: Option<NewEvent>,
    ) -> Result<(), AppError> {
        let anon = AuditCtx::new(
            ActorType::Anonymous,
            None,
            None,
            None,
            self.ctx.request_id(),
            self.ctx.ip(),
            self.ctx.user_agent_hash().copied(),
        );
        let ev = event(ACTION_LOGIN, "passkey", passkey, outcome, Some(reason));
        let res = async {
            let mut tx = OwnTx::begin(&self.st.db_primary, self.tenant, &anon).await?;
            tx.record(ev).await?;
            if let Some(n) = notice {
                tx.outbox(n).await?;
            }
            tx.commit().await
        }
        .await;
        res.map_err(|e| {
            tracing::error!(error = ?e, "login por passkey: evento não gravado; 503");
            AppError::ServiceUnavailable
        })
    }

    /// Credencial pela única leitura antes de haver sessão (`identity_passkey_lookup`, só
    /// utilizadores ativos). Exceção à regra `query!` (dono `ptmarket_identity`, como
    /// `identity_user_credentials`): SQL estático, argumento e colunas com o tipo exato.
    async fn lookup(&self, credential_id: &[u8]) -> Result<Option<Found>, AppError> {
        let row: Option<(Uuid, Uuid, serde_json::Value)> = sqlx::query_as(
            "SELECT p.id::uuid, p.user_id::uuid, p.credential::jsonb
             FROM public.identity_passkey_lookup($1::bytea) AS p",
        )
        .bind(credential_id)
        .fetch_optional(&self.st.db_primary)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "login por passkey: lookup falhou; 503");
            AppError::ServiceUnavailable
        })?;
        Ok(row.map(|(id, user, credential)| Found {
            id,
            user,
            credential,
        }))
    }

    /// Sucesso: na transação do próprio, o contador (atómico: regressivo → `None`),
    /// `last_login_at`, sessão rodada e elevada, `auth.passkey_login` `success`.
    async fn open_session(
        &self,
        staff: &StaffRoles,
        passkey: Uuid,
        counter: u32,
    ) -> Result<Opened, AppError> {
        let user = staff.user_id();
        let me = AuditCtx::new(
            staff.actor_type(),
            Some(user),
            None,
            None,
            self.ctx.request_id(),
            self.ctx.ip(),
            self.ctx.user_agent_hash().copied(),
        );
        let old = own_previous(self.cur, Subject::User(user));
        let mut tx = OwnTx::begin(&self.st.db_primary, self.tenant, &me).await?;
        let counter = i64::from(counter);
        // Lida com o bloqueio da linha: dois logins em paralelo com o mesmo contador → só um entra.
        let stored = sqlx::query_scalar!(
            "SELECT sign_count FROM user_passkeys WHERE id = $1 AND user_id = $2 FOR UPDATE",
            passkey,
            user
        )
        .fetch_optional(tx.conn())
        .await
        .map_err(db_error)?;
        let Some(stored) = stored else {
            return Ok(Opened::Gone);
        };
        if !counter_ok(counter, stored) {
            return Ok(Opened::Cloned);
        }
        let r = sqlx::query!(
            "UPDATE user_passkeys SET sign_count = $3, last_used_at = now()
             WHERE id = $1 AND user_id = $2",
            passkey,
            user,
            counter
        )
        .execute(tx.conn())
        .await
        .map_err(db_error)?;
        if r.rows_affected() != 1 {
            return Ok(Opened::Gone);
        }
        let r = sqlx::query!(
            "UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1",
            user
        )
        .execute(tx.conn())
        .await
        .map_err(db_error)?;
        if r.rows_affected() != 1 {
            return Err(AppError::Internal(anyhow::anyhow!(
                "login por passkey: last_login_at não gravado"
            )));
        }
        let (sid, value) = tx.open_elevated(old, user, self.tenant, &me).await?;
        let mut ev = event(
            ACTION_LOGIN,
            "session",
            Some(sid.as_uuid()),
            Outcome::Success,
            None,
        );
        ev.changes = Some(serde_json::json!({ "passkey_id": passkey }));
        tx.record(ev).await?;
        tx.commit().await?;
        if let Some(old) = old {
            forget(self.cur, old).await;
        }
        revoke_foreign_session(
            &self.st.db_primary,
            self.cur,
            self.tenant,
            self.ctx,
            Subject::User(user),
        )
        .await;
        let s = self.cur.sessions();
        throttle::succeeded(s.redis(), &self.keys).await;
        Ok(Opened::Session(value))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Conclui o login por passkey neste host. Falha → 401 sempre igual + `auth.passkey_login`
/// `denied`. Sucesso → 204 + cookie de uma sessão nova já com o 2FA feito.
#[utoipa::path(
    post,
    path = "/api/v1/staff/auth/passkey/finish",
    tag = "staff",
    request_body = LoginFinishRequest,
    responses(
        (status = 204, description = "Sessão iniciada e com o 2FA feito (cookie `__Host-ptm_session` no tenant, `__Host-ptm_admin` na plataforma)"),
        (status = 401, description = "Cerimónia ou credencial inválida, ou sem acesso a este site (corpo sempre igual)"),
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
pub async fn login_finish(
    State(st): State<AppState>,
    ctx: AuditCtx,
    cur: CurrentSession,
    tenant: Result<ResolvedTenant, AppError>,
    platform: Result<PlatformHost, AppError>,
    host: Option<Extension<RequestHost>>,
    req: Result<Json<LoginFinishRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let site = site(tenant, platform, host)?;
    let req = body(req)?;
    let cred: PublicKeyCredential = credential(req.credential)?;
    let keys = throttle_keys(&cur, &ctx, &format!("pk:{}", sha256_hex(&cred.raw_id)));
    gate(&cur, &keys).await?;
    let a = Attempt {
        st: &st,
        ctx: &ctx,
        cur: &cur,
        tenant: site.tenant,
        keys,
    };
    let ceremony: Option<AuthCeremony> = take(&cur, Kind::Auth, &req.ceremony_id).await?;
    let Some(c) = ceremony.filter(|c| c.host == site.host) else {
        return a.refuse(REASON_CEREMONY, None).await;
    };
    let Some(found) = a.lookup(&cred.raw_id).await? else {
        // Mesmo trabalho do caso com conta (leitura de papéis), para o tempo não a revelar.
        if let Err(e) = load_roles(&st.db_primary, Uuid::nil(), ctx.request_id()).await {
            tracing::warn!(error = ?e, "login por passkey: leitura de igualação falhou");
        }
        return a.refuse(REASON_UNKNOWN_CREDENTIAL, None).await;
    };
    let Ok(stored) = serde_json::from_value::<Stored>(found.credential) else {
        return a.broken(found.id).await;
    };
    if stored.v != STORED_VERSION {
        return a.refuse(REASON_VERSION, Some(found.id)).await;
    }
    if stored.rp_id != site.host {
        return a.refuse(REASON_RP_MISMATCH, Some(found.id)).await;
    }
    // Descoberta: o `userHandle` tem de existir e ser o dono da credencial.
    if cred.response.user_handle.as_deref() != Some(found.user.as_bytes().as_slice()) {
        return a.refuse(REASON_VERIFICATION, Some(found.id)).await;
    }
    // O contador guardado vive em `sign_count` (a credencial JSONB não muda depois do registo):
    // a biblioteca verifica com 0 e a regra do contador corre com a linha bloqueada.
    let mut pk = stored.passkey;
    if let Some(c) = pk
        .get_mut("cred")
        .and_then(serde_json::Value::as_object_mut)
    {
        c.insert("counter".to_owned(), 0.into());
    }
    let Ok(pk) = serde_json::from_value::<Passkey>(pk) else {
        return a.broken(found.id).await;
    };
    let rp = cur.sessions().passkeys().rp(&site.host)?;
    let res = match rp.finish_discoverable_authentication_v2(&cred, c.state, &pk) {
        Ok(r) if r.user_verified() => r,
        _ => return a.refuse(REASON_VERIFICATION, Some(found.id)).await,
    };
    let access = load_roles(&st.db_primary, found.user, ctx.request_id())
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "login por passkey: papéis ilegíveis; 503");
            AppError::ServiceUnavailable
        })?;
    let staff = StaffRoles::new(found.user, site.tenant, access);
    if !staff.may_log_in_here() {
        return a.refuse(REASON_NO_ROLE_HERE, Some(found.id)).await;
    }
    let opened = a.open_session(&staff, found.id, res.counter()).await;
    let value = match opened {
        Ok(Opened::Session(v)) => v,
        Ok(Opened::Cloned) => {
            let n = notice(found.user, REASON_CLONED);
            return a.refuse_with(REASON_CLONED, Some(found.id), Some(n)).await;
        }
        Ok(Opened::Gone) => return a.refuse(REASON_UNKNOWN_CREDENTIAL, Some(found.id)).await,
        Err(e) => {
            tracing::error!(error = ?e, "login por passkey: sessão não criada; 503");
            return Err(AppError::ServiceUnavailable);
        }
    };
    let subject = Subject::User(found.user);
    let kind = match site.tenant {
        Some(_) => CookieKind::Tenant,
        None => CookieKind::Platform,
    };
    let lifetime = SessionKind::of(subject, site.tenant).max_lifetime();
    let mut resp = no_store(StatusCode::NO_CONTENT.into_response());
    resp.headers_mut()
        .append(SET_COOKIE, session::set_cookie(kind, &value, lifetime)?);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_ids_are_random_and_strict() {
        let a = new_ceremony_id().ok().unwrap_or_default();
        let b = new_ceremony_id().ok().unwrap_or_default();
        assert!(valid_ceremony_id(&a) && valid_ceremony_id(&b) && a != b);
        assert!(!valid_ceremony_id("curto"));
        assert!(!valid_ceremony_id(&format!("{}*", &a[..42])));
        assert!(!valid_ceremony_id(&format!("{a}x")));
    }

    #[test]
    fn non_discoverable_credentials_are_refused() {
        use serde_json::json;
        assert!(discoverable(&json!({})));
        assert!(discoverable(&json!({"clientExtensionResults": {}})));
        assert!(discoverable(
            &json!({"clientExtensionResults": {"credProps": {"rk": true}}})
        ));
        assert!(!discoverable(
            &json!({"clientExtensionResults": {"credProps": {"rk": false}}})
        ));
        assert!(!discoverable(&json!({"extensions": {"credProps": {"rk": false}}})));
    }

    #[test]
    fn counter_follows_w3c_7_2_21() {
        assert!(counter_ok(1, 0) && counter_ok(6, 5) && counter_ok(0, 0));
        assert!(!counter_ok(0, 5) && !counter_ok(5, 5) && !counter_ok(2, 1_000));
    }

    #[test]
    fn labels_are_1_to_64_chars_without_controls() {
        assert_eq!(
            valid_label("  Portátil  ").ok().as_deref(),
            Some("Portátil")
        );
        assert!(valid_label(&"é".repeat(64)).is_ok());
        for bad in ["", "   ", "a\nb", &"x".repeat(65)] {
            assert!(matches!(valid_label(bad), Err(AppError::Validation(_))));
        }
    }

    #[test]
    fn rp_is_cached_per_host_and_http_only_in_dev() {
        let p = Passkeys::new(AppEnv::Production);
        let a = p.rp("loja.example.pt").ok();
        let b = p.rp("loja.example.pt").ok();
        assert!(matches!((&a, &b), (Some(x), Some(y)) if Arc::ptr_eq(x, y)));
        let prod = a.map(|w| w.get_allowed_origins().len());
        assert_eq!(prod, Some(1));
        let dev = Passkeys::new(AppEnv::Development)
            .rp("loja.localhost")
            .ok()
            .map(|w| w.get_allowed_origins().len());
        assert_eq!(dev, Some(2));
        let dev_public = Passkeys::new(AppEnv::Development)
            .rp("loja.example.pt")
            .ok()
            .map(|w| w.get_allowed_origins().len());
        assert_eq!(dev_public, Some(1));
    }
}
