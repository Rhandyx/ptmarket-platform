//! Sessões (spec 12 §3, cartão 02/16): token, cookie `__Host-`, criação/revogação na BD, lookup e
//! inatividade no Redis.
//!
//! - Token: 32 bytes do CSPRNG do SO, base64url sem padding (43 caracteres). Só o sha256 é gravado
//!   (`sessions.token_hash`); o token nunca entra em logs, eventos nem `Debug`.
//! - Duração absoluta (CHECK `sessions_max_lifetime` da 0019): cliente 168 h, staff 12 h,
//!   plataforma 8 h. `expires_at` é calculado na BD a partir de `now()` (= `created_at`).
//! - Inatividade (owner 25/11): `sess:idle:<id>` no Redis com TTL renovado a cada pedido; cliente
//!   7 dias, staff 30 min, plataforma 15 min. Chave ausente = inativa, EXCETO nos primeiros
//!   `idle` depois de `created_at` (a criação conta como atividade: assim `create` não precisa do
//!   Redis e uma chave que expirou implica sempre `created_at + idle < now`). Passado esse prazo,
//!   chave ausente (expirou, ou o Redis perdeu-a) = sessão inativa → anónimo; Redis inacessível →
//!   503. Falha sempre fechado (decisão do supervisor, 26/11).
//! - A app só cria sessões do próprio sujeito (o ator da transação; RLS `own_insert`), revoga-as
//!   (`revoked_at`) e nunca apaga (sem DELETE).

use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_redis::redis;
use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    audit::{ActorType, AuditCtx},
    error::AppError,
    tenancy::{
        TenantId,
        db::{AuditedTx, db_error},
    },
};

/// Cookie das sessões nos hosts de tenant.
pub const COOKIE_TENANT: &str = "__Host-ptm_session";
/// Cookie das sessões no `PLATFORM_ADMIN_HOST`.
pub const COOKIE_PLATFORM: &str = "__Host-ptm_admin";
/// Bytes de aleatoriedade do token.
pub const TOKEN_BYTES: usize = 32;
/// Comprimento do token em base64url sem padding.
pub const TOKEN_CHARS: usize = 43;
/// Limite para cada operação no Redis; passado isto, 503.
const REDIS_TIMEOUT: Duration = Duration::from_secs(1);

const HOUR: u64 = 3600;
/// Duração absoluta máxima (= CHECK `sessions_max_lifetime`).
pub const CUSTOMER_MAX_LIFETIME: Duration = Duration::from_secs(168 * HOUR);
pub const STAFF_MAX_LIFETIME: Duration = Duration::from_secs(12 * HOUR);
pub const PLATFORM_MAX_LIFETIME: Duration = Duration::from_secs(8 * HOUR);
/// Inatividade máxima (owner 25/11).
pub const CUSTOMER_IDLE: Duration = Duration::from_secs(168 * HOUR);
pub const STAFF_IDLE: Duration = Duration::from_secs(30 * 60);
pub const PLATFORM_IDLE: Duration = Duration::from_secs(15 * 60);

/// Id de uma sessão (`sessions.id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Só para testes; não existe em `cargo build --release`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(id: Uuid) -> Self {
        Self(id)
    }
}

/// Valor do cookie (o token em claro). Só sai para o `Set-Cookie`; `Debug` não o mostra.
#[derive(Clone, PartialEq, Eq)]
pub struct CookieValue(String);

impl CookieValue {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CookieValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CookieValue([redacted])")
    }
}

/// Titular da sessão (`sessions.subject_type`, `subject_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    Customer(Uuid),
    User(Uuid),
}

impl Subject {
    fn type_str(self) -> &'static str {
        match self {
            Self::Customer(_) => "customer",
            Self::User(_) => "user",
        }
    }

    fn id(self) -> Uuid {
        match self {
            Self::Customer(id) | Self::User(id) => id,
        }
    }

    /// O ator do contexto é este sujeito (o mesmo mapeamento da RLS da 0019).
    fn is_actor(self, ctx: &AuditCtx) -> bool {
        let type_ok = match self {
            Self::Customer(_) => ctx.actor_type() == ActorType::Customer,
            Self::User(_) => matches!(
                ctx.actor_type(),
                ActorType::Merchant | ActorType::Municipal | ActorType::Admin
            ),
        };
        type_ok && ctx.actor_id() == Some(self.id()) && ctx.impersonator_id().is_none()
    }
}

/// Classe da sessão: decide a duração absoluta e a inatividade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Customer,
    /// Utilizador com `tenant_id` (Câmara/loja).
    Staff,
    /// Utilizador sem `tenant_id` (consola de plataforma).
    Platform,
}

impl SessionKind {
    pub fn of(subject: Subject, tenant: Option<TenantId>) -> Self {
        match (subject, tenant) {
            (Subject::Customer(_), _) => Self::Customer,
            (Subject::User(_), Some(_)) => Self::Staff,
            (Subject::User(_), None) => Self::Platform,
        }
    }

    pub fn max_lifetime(self) -> Duration {
        match self {
            Self::Customer => CUSTOMER_MAX_LIFETIME,
            Self::Staff => STAFF_MAX_LIFETIME,
            Self::Platform => PLATFORM_MAX_LIFETIME,
        }
    }

    pub fn idle(self) -> Duration {
        match self {
            Self::Customer => CUSTOMER_IDLE,
            Self::Staff => STAFF_IDLE,
            Self::Platform => PLATFORM_IDLE,
        }
    }
}

/// Que cookie vale no host do pedido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieKind {
    /// Host de tenant: `__Host-ptm_session`, `SameSite=Lax`.
    Tenant,
    /// `PLATFORM_ADMIN_HOST`: `__Host-ptm_admin`, `SameSite=Strict`.
    Platform,
}

impl CookieKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tenant => COOKIE_TENANT,
            Self::Platform => COOKIE_PLATFORM,
        }
    }

    fn same_site(self) -> &'static str {
        match self {
            Self::Tenant => "Lax",
            Self::Platform => "Strict",
        }
    }
}

/// `Set-Cookie` da sessão: `__Host-` (Path=/, sem Domain), `HttpOnly`, `Secure`, `SameSite` do host.
pub fn set_cookie(
    kind: CookieKind,
    value: &CookieValue,
    max_age: Duration,
) -> Result<HeaderValue, AppError> {
    cookie_header(kind, value.expose(), max_age.as_secs())
}

/// `Set-Cookie` que apaga o cookie da sessão no browser.
pub fn clear_cookie(kind: CookieKind) -> HeaderValue {
    // Só texto constante: nunca falha; o `unwrap_or` é inalcançável.
    cookie_header(kind, "", 0).unwrap_or(HeaderValue::from_static(""))
}

fn cookie_header(kind: CookieKind, value: &str, max_age: u64) -> Result<HeaderValue, AppError> {
    HeaderValue::from_str(&format!(
        "{}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite={}",
        kind.name(),
        kind.same_site()
    ))
    .map_err(|_| AppError::Internal(anyhow::anyhow!("Set-Cookie inválido")))
}

/// O que veio no cabeçalho `Cookie` para o nome da sessão.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieRead {
    Absent,
    /// Repetido, ilegível ou fora do formato do token.
    Invalid,
    /// sha256 do token.
    Token([u8; 32]),
}

/// Lê o cookie `name` (todos os cabeçalhos `Cookie`); devolve o sha256 do token se tiver o formato.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> CookieRead {
    let mut found: Option<&str> = None;
    for value in headers.get_all(COOKIE) {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let Some((k, v)) = pair.trim().split_once('=') else {
                continue;
            };
            if k.trim() != name {
                continue;
            }
            if found.is_some() {
                return CookieRead::Invalid;
            }
            found = Some(v.trim());
        }
    }
    match found {
        None => CookieRead::Absent,
        Some(v) => token_hash(v).map_or(CookieRead::Invalid, CookieRead::Token),
    }
}

/// sha256 do token, só se for base64url sem padding de exatamente 32 bytes.
pub fn token_hash(token: &str) -> Option<[u8; 32]> {
    if token.len() != TOKEN_CHARS {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(token).ok()?;
    if raw.len() != TOKEN_BYTES {
        return None;
    }
    Some(sha256(token.as_bytes()))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Token novo (CSPRNG do SO) e o seu sha256.
fn new_token() -> Result<(CookieValue, [u8; 32]), AppError> {
    let mut raw = [0u8; TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("CSPRNG do SO indisponível")))?;
    let token = URL_SAFE_NO_PAD.encode(raw);
    raw.fill(0);
    let hash = sha256(token.as_bytes());
    Ok((CookieValue(token), hash))
}

/// Cria a sessão de `subject` na transação `tx` (o ator da transação TEM de ser o sujeito; a RLS
/// recusa o resto). `tenant` = host onde nasce (`None` = plataforma). Devolve o id e o valor do
/// cookie (`set_cookie` com `SessionKind::max_lifetime`).
pub async fn create<T: AuditedTx>(
    tx: &mut T,
    subject: Subject,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
) -> Result<(SessionId, CookieValue), AppError> {
    let lifetime = SessionKind::of(subject, tenant).max_lifetime();
    insert(tx, subject, tenant, ctx, lifetime).await
}

/// Só para testes: sessão com duração absoluta mais curta (ex.: para a ver expirar).
#[cfg(feature = "test-support")]
pub async fn create_for_tests<T: AuditedTx>(
    tx: &mut T,
    subject: Subject,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    lifetime: Duration,
) -> Result<(SessionId, CookieValue), AppError> {
    let max = SessionKind::of(subject, tenant).max_lifetime();
    insert(tx, subject, tenant, ctx, lifetime.min(max)).await
}

async fn insert<T: AuditedTx>(
    tx: &mut T,
    subject: Subject,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    lifetime: Duration,
) -> Result<(SessionId, CookieValue), AppError> {
    let (conn, tx_ctx) = tx.parts();
    if !subject.is_actor(ctx) || !subject.is_actor(tx_ctx) {
        return Err(AppError::Internal(anyhow::anyhow!(
            "sessão pedida para um sujeito que não é o ator da transação"
        )));
    }
    let lifetime_ms = i64::try_from(lifetime.as_millis())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("duração de sessão fora do limite")))?;
    let (value, hash) = new_token()?;
    let id = Uuid::now_v7();
    let ip = ctx.ip().map(|i| i.to_string());
    let ua = ctx.user_agent_hash().map(|h| h.to_vec());
    // created_at fica no DEFAULT now(): expires_at = now() + duração (o mesmo instante).
    sqlx::query!(
        "INSERT INTO sessions (id, subject_type, subject_id, token_hash, tenant_id, ip,
                               user_agent_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6::text::inet, $7,
                 now() + ($8::int8 * interval '1 millisecond'))",
        id,
        subject.type_str(),
        subject.id(),
        &hash[..],
        tenant.map(|t| t.as_uuid()),
        ip,
        ua,
        lifetime_ms
    )
    .execute(conn)
    .await
    .map_err(db_error)?;
    Ok((SessionId(id), value))
}

/// Revoga a sessão `id` (só as do próprio ator; uma revogada não muda). `true` se revogou agora.
pub async fn revoke<T: AuditedTx>(tx: &mut T, id: SessionId) -> Result<bool, AppError> {
    let (conn, _) = tx.parts();
    let r = sqlx::query!(
        "UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        id.0
    )
    .execute(conn)
    .await
    .map_err(db_error)?;
    Ok(r.rows_affected() == 1)
}

/// Revoga todas as sessões ativas de `subject` (só se for o ator). Devolve quantas.
pub async fn revoke_all<T: AuditedTx>(tx: &mut T, subject: Subject) -> Result<u64, AppError> {
    let (conn, _) = tx.parts();
    let r = sqlx::query!(
        "UPDATE sessions SET revoked_at = now()
         WHERE subject_type = $1 AND subject_id = $2 AND revoked_at IS NULL",
        subject.type_str(),
        subject.id()
    )
    .execute(conn)
    .await
    .map_err(db_error)?;
    Ok(r.rows_affected())
}

/// Rotação do id de sessão (login, elevação para 2FA): revoga `old` (se for do ator) e cria uma
/// nova na MESMA transação.
pub async fn rotate<T: AuditedTx>(
    tx: &mut T,
    old: Option<SessionId>,
    subject: Subject,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
) -> Result<(SessionId, CookieValue), AppError> {
    if let Some(old) = old {
        revoke(tx, old).await?;
    }
    create(tx, subject, tenant, ctx).await
}

/// Sessão válida devolvida por `identity_session_lookup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionRow {
    pub id: SessionId,
    pub subject: Subject,
    pub tenant: Option<Uuid>,
    pub impersonator_id: Option<Uuid>,
    pub mfa_verified_at: Option<SystemTime>,
    /// `now() - created_at` (relógio da BD).
    pub age: Duration,
}

impl SessionRow {
    pub fn kind(&self) -> SessionKind {
        match (self.subject, self.tenant) {
            (Subject::Customer(_), _) => SessionKind::Customer,
            (Subject::User(_), Some(_)) => SessionKind::Staff,
            (Subject::User(_), None) => SessionKind::Platform,
        }
    }
}

type LookupRow = (
    Uuid,
    String,
    Uuid,
    Option<Uuid>,
    Option<Uuid>,
    Option<i64>,
    Option<i64>,
);

/// Sessão válida (não revogada, não expirada, titular ativo) com este hash; `None` se não houver.
///
/// Exceção à regra `query!` (como `audit::record`): a verificação em compilação faz EXPLAIN, que
/// exige EXECUTE em `identity_session_lookup`; o migrator não o tem (dono `ptmarket_identity`, 0019).
/// SQL estático, função qualificada pelo schema, argumento com o tipo exato; os tipos verificam-se
/// no teste `session`.
pub(crate) async fn lookup(
    db: &sqlx::PgPool,
    hash: &[u8; 32],
) -> Result<Option<SessionRow>, AppError> {
    let row: Option<LookupRow> = sqlx::query_as(
        "SELECT l.id, l.subject_type::text, l.subject_id, l.tenant_id, l.impersonator_user_id,
                (extract(epoch FROM l.mfa_verified_at) * 1000000)::int8,
                (extract(epoch FROM (now() - l.created_at)) * 1000)::int8
         FROM public.identity_session_lookup($1::bytea) AS l",
    )
    .bind(&hash[..])
    .fetch_optional(db)
    .await
    .map_err(db_error)?;
    let Some((id, subject_type, subject_id, tenant, impersonator_id, mfa_us, age_ms)) = row else {
        return Ok(None);
    };
    let subject = match subject_type.as_str() {
        "customer" => Subject::Customer(subject_id),
        "user" => Subject::User(subject_id),
        _ => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "sessions.subject_type desconhecido"
            )));
        }
    };
    let mfa_verified_at = mfa_us
        .and_then(|us| u64::try_from(us).ok())
        .map(|us| UNIX_EPOCH + Duration::from_micros(us));
    let age = Duration::from_millis(age_ms.and_then(|ms| u64::try_from(ms).ok()).unwrap_or(0));
    Ok(Some(SessionRow {
        id: SessionId(id),
        subject,
        tenant,
        impersonator_id,
        mfa_verified_at,
        age,
    }))
}

// ---------------------------------------------------------------------------------------------
// Inatividade (Redis)
// ---------------------------------------------------------------------------------------------

/// KEYS: idle · ARGV: idle_ms, fresh (1 = criada há menos de `idle`).
/// 1 = ativa (TTL renovado); 0 = inativa.
const TOUCH_SCRIPT: &str = r#"
if redis.call('PEXPIRE', KEYS[1], ARGV[1]) == 1 then return 1 end
if ARGV[2] == '1' then
  redis.call('SET', KEYS[1], '1', 'PX', ARGV[1])
  return 1
end
return 0
"#;

pub(crate) fn idle_key(ns: &str, id: SessionId) -> String {
    format!("{ns}sess:idle:{}", id.0)
}

/// Renova a inatividade; `false` = sessão inativa. Redis em baixo → 503 (falha fechado).
pub(crate) async fn touch(
    redis: &deadpool_redis::Pool,
    ns: &str,
    row: &SessionRow,
    idle: Duration,
) -> Result<bool, AppError> {
    let idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX).max(1);
    let fresh = row.age < idle;
    let mut cmd = redis::cmd("EVAL");
    cmd.arg(TOUCH_SCRIPT)
        .arg(1)
        .arg(idle_key(ns, row.id))
        .arg(idle_ms)
        .arg(if fresh { "1" } else { "0" });
    let n: i64 = redis_query(redis, cmd).await?;
    Ok(n == 1)
}

/// Esquece a inatividade (logout). A revogação na BD é o que vale; isto só limpa.
pub(crate) async fn forget(
    redis: &deadpool_redis::Pool,
    ns: &str,
    id: SessionId,
) -> Result<(), AppError> {
    let mut cmd = redis::cmd("DEL");
    cmd.arg(idle_key(ns, id));
    redis_query::<i64>(redis, cmd).await.map(|_| ())
}

async fn redis_query<T: redis::FromRedisValue>(
    pool: &deadpool_redis::Pool,
    cmd: redis::Cmd,
) -> Result<T, AppError> {
    let fut = async {
        let mut conn = pool.get().await.map_err(|e| {
            tracing::error!(error = %e, "sessões: Redis indisponível");
            AppError::ServiceUnavailable
        })?;
        cmd.query_async::<T>(&mut conn).await.map_err(|e| {
            tracing::error!(error = %e, "sessões: comando Redis falhou");
            AppError::ServiceUnavailable
        })
    };
    tokio::time::timeout(REDIS_TIMEOUT, fut)
        .await
        .map_err(|_| AppError::ServiceUnavailable)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_43_chars_and_hash_matches() {
        let r = new_token();
        assert!(r.is_ok());
        if let Ok((v, h)) = r {
            assert_eq!(v.expose().len(), TOKEN_CHARS);
            assert_eq!(token_hash(v.expose()), Some(h));
            assert!(!format!("{v:?}").contains(v.expose()));
        }
    }

    #[test]
    fn token_hash_rejects_bad_format() {
        assert_eq!(token_hash(""), None);
        assert_eq!(token_hash(&"a".repeat(42)), None);
        assert_eq!(token_hash(&"a".repeat(44)), None);
        assert_eq!(token_hash(&format!("{}=", "a".repeat(42))), None);
        assert_eq!(token_hash(&"+".repeat(43)), None);
        assert!(token_hash(&"A".repeat(43)).is_some());
    }

    #[test]
    fn cookie_attributes_per_host() {
        let v = CookieValue("x".repeat(43));
        let t = set_cookie(CookieKind::Tenant, &v, CUSTOMER_MAX_LIFETIME);
        let t = t.ok().and_then(|h| h.to_str().ok().map(str::to_owned));
        assert_eq!(
            t.as_deref(),
            Some(
                "__Host-ptm_session=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; Path=/; \
                 Max-Age=604800; HttpOnly; Secure; SameSite=Lax"
            )
        );
        let c = clear_cookie(CookieKind::Platform);
        assert_eq!(
            c.to_str().ok(),
            Some("__Host-ptm_admin=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")
        );
    }

    #[test]
    fn read_cookie_cases() {
        let ok = "A".repeat(43);
        let mut h = HeaderMap::new();
        assert_eq!(read_cookie(&h, COOKIE_TENANT), CookieRead::Absent);
        h.insert(
            COOKIE,
            HeaderValue::from_str(&format!("a=b; {COOKIE_TENANT}={ok}"))
                .unwrap_or(HeaderValue::from_static("")),
        );
        assert!(matches!(
            read_cookie(&h, COOKIE_TENANT),
            CookieRead::Token(_)
        ));
        assert_eq!(read_cookie(&h, COOKIE_PLATFORM), CookieRead::Absent);
        h.append(
            COOKIE,
            HeaderValue::from_str(&format!("{COOKIE_TENANT}={ok}"))
                .unwrap_or(HeaderValue::from_static("")),
        );
        assert_eq!(read_cookie(&h, COOKIE_TENANT), CookieRead::Invalid);
        let mut h = HeaderMap::new();
        h.insert(COOKIE, HeaderValue::from_static("__Host-ptm_session=curto"));
        assert_eq!(read_cookie(&h, COOKIE_TENANT), CookieRead::Invalid);
    }

    #[test]
    fn lifetimes_match_the_db_check() {
        assert_eq!(SessionKind::Customer.max_lifetime().as_secs(), 168 * 3600);
        assert_eq!(SessionKind::Staff.max_lifetime().as_secs(), 12 * 3600);
        assert_eq!(SessionKind::Platform.max_lifetime().as_secs(), 8 * 3600);
        assert_eq!(SessionKind::Staff.idle().as_secs(), 30 * 60);
        assert_eq!(SessionKind::Platform.idle().as_secs(), 15 * 60);
    }
}
