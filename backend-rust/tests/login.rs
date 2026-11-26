//! Login de clientes (cartão 02/18), contra Postgres e Redis reais, pela API real (`http::api`) com
//! sessões, captcha falso (sem rede) e um contador à volta do Argon2 real.
//!
//! As pools da app fazem `SET ROLE ptmarket_app`. Leituras de `audit.*` e da função
//! `identity_customer_credentials` sem `query!` (o migrator não tem privilégios para o EXPLAIN):
//! SQL estático com casts.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use argon2::{Algorithm, Argon2, Params, Version, password_hash::PasswordHasher};
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderName, Method, Request, StatusCode, header},
};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    error::AppError,
    http::{api, audit_layer::AuditLayerState, client_ip::TrustedProxies},
    identity::{
        AccountKey, BreachChecker, CaptchaVerifier, Login, Password, PasswordCheck, Registration, Sessions,
        Subject, Verified,
        csrf::X_CSRF_TOKEN,
        password,
        session::{self, COOKIE_TENANT},
        account_hash,
        throttle::{self, Gate, Keys, Limits},
    },
    state::AppState,
    storage::NullStorage,
    tenancy::{HostResolver, TenantId, begin_tenant_tx},
};
use serde_json::{Value, json};
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tower::ServiceExt;
use utoipa::OpenApi;
use uuid::Uuid;

type TestResult = anyhow::Result<()>;
/// action, outcome, reason, actor_type, actor_id, target_type, target_id, changes.
type EvRow = (
    String,
    String,
    Option<String>,
    String,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
);

const CSRF_KEY: &str = "chave-csrf-de-teste-com-mais-de-32-bytes";
const INTERNAL_TOKEN: &str = "token-interno-de-teste-com-mais-de-32-bytes";
const LOGIN_URI: &str = "/api/v1/auth/login";
const REGISTER_URI: &str = "/api/v1/auth/register";
const SESSION_URI: &str = "/api/v1/auth/session";
const PW: &str = "uma-frase-longa-e-boa";
const WRONG: &str = "outra-frase-qualquer";
const CAPTCHA_OK: &str = "captcha-ok";

// ---------------------------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------------------------

/// Só aceita `CAPTCHA_OK` resolvido no host do tenant do pedido (`*.ptmarket.invalid`).
struct FakeCaptcha;

#[async_trait]
impl CaptchaVerifier for FakeCaptcha {
    async fn verify(&self, token: &str, _ip: Option<IpAddr>, expected_host: &str) -> bool {
        token == CAPTCHA_OK && expected_host.ends_with(".ptmarket.invalid")
    }
}

struct NoBreach;

#[async_trait]
impl BreachChecker for NoBreach {
    async fn is_breached(&self, _p: &Password) -> bool {
        false
    }
}

/// Argon2 real, com contador de execuções.
#[derive(Default)]
struct Counting(AtomicUsize);

#[async_trait]
impl PasswordCheck for Counting {
    async fn verify(&self, pw: &Password, phc: Option<&str>) -> Result<Verified, AppError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        password::verify(pw, phc).await
    }
}

// ---------------------------------------------------------------------------------------------
// Infra
// ---------------------------------------------------------------------------------------------

async fn app_pool(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(6)
        .after_connect(|c, _meta| {
            Box::pin(async move {
                sqlx::query!("SET ROLE ptmarket_app").execute(c).await?;
                Ok(())
            })
        })
        .connect_with(conn.clone())
        .await
}

async fn owner_pool(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(1)
        .connect_with(conn.clone())
        .await
}

fn redis() -> anyhow::Result<deadpool_redis::Pool> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    Ok(deadpool_redis::Config::from_url(url).create_pool(Some(Runtime::Tokio1))?)
}

/// BD em baixo: porta onde nada escuta.
fn dead_db() -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(500))
        .connect_lazy("postgres://ninguem:nada@127.0.0.1:1/db")?)
}

fn namespace() -> String {
    format!("test:login:{}:", Uuid::now_v7())
}

async fn cleanup(ns: &str) -> TestResult {
    let mut conn = redis()?.get().await?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{ns}*"))
        .query_async(&mut conn)
        .await?;
    if !keys.is_empty() {
        redis::cmd("DEL")
            .arg(keys)
            .query_async::<i64>(&mut conn)
            .await?;
    }
    Ok(())
}

struct Setup {
    /// Pool da app (handler); `hosts` = pool do `HostResolver` (sempre viva).
    db: PgPool,
    hosts: PgPool,
    audit_db: PgPool,
    limits: Limits,
    counter: Arc<Counting>,
}

impl Setup {
    fn new(app: &PgPool) -> Self {
        Self {
            db: app.clone(),
            hosts: app.clone(),
            audit_db: app.clone(),
            limits: Limits::default(),
            counter: Arc::new(Counting::default()),
        }
    }

    fn router(&self, ns: &str) -> anyhow::Result<Router> {
        let st = AppState {
            db_primary: self.db.clone(),
            db_replica: self.db.clone(),
            redis: redis()?,
            storage: Arc::new(NullStorage),
            hosts: Arc::new(HostResolver::new(
                self.hosts.clone(),
                None,
                Some(INTERNAL_TOKEN.to_owned().into()),
            )),
        };
        let registration =
            Registration::new(Arc::new(FakeCaptcha), Arc::new(NoBreach), account_key())
            .with_min_response_for_tests(Duration::ZERO);
        let login = Login::new(Arc::new(FakeCaptcha), account_key())
            .with_password_check_for_tests(self.counter.clone())
            .with_limits_for_tests(self.limits);
        let sessions = Sessions::for_tests(
            self.hosts.clone(),
            redis()?,
            CSRF_KEY.to_owned().into(),
            ns,
            None,
        )
        .with_internal_token(Some(INTERNAL_TOKEN.to_owned().into()))
        .with_registration(registration)
        .with_login(login);
        let audit = AuditLayerState::for_tests(
            self.audit_db.clone(),
            redis()?,
            TrustedProxies::none(),
            ns,
            Duration::from_secs(1),
        );
        Ok(api(st.clone(), audit, Some(sessions)).with_state(st))
    }

    fn argon2_runs(&self) -> usize {
        self.counter.0.load(Ordering::SeqCst)
    }
}

struct Tenant {
    id: Uuid,
    domain: String,
}

impl Tenant {
    fn tid(&self) -> TenantId {
        TenantId::for_tests(self.id)
    }
}

async fn seed_tenant(owner: &PgPool, slug: &str) -> sqlx::Result<Tenant> {
    let id = Uuid::now_v7();
    let domain = format!("{slug}.ptmarket.invalid");
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, country_code)
         VALUES ($1, $2, $3, $4, 'PT')",
        id,
        slug,
        domain,
        format!("Câmara {slug}")
    )
    .execute(owner)
    .await?;
    Ok(Tenant { id, domain })
}

struct Reply {
    status: StatusCode,
    body: String,
    request_id: Option<Uuid>,
    /// Cabeçalhos sem o `x-request-id` (único por pedido), ordenados.
    headers: Vec<(String, String)>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_default()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// `__Host-ptm_session=<token>` do `Set-Cookie`.
    fn session_cookie(&self) -> Option<String> {
        let sc = self.header("set-cookie")?;
        let pair = sc.split(';').next()?.trim();
        (pair.starts_with(&format!("{COOKIE_TENANT}=")) && pair.len() > COOKIE_TENANT.len() + 1)
            .then(|| pair.to_owned())
    }

    fn captcha_required(&self) -> bool {
        self.status == StatusCode::UNAUTHORIZED && self.json()["captcha_required"] == json!(true)
    }
}

async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(HeaderName, &str)],
    body: &str,
    peer: Option<IpAddr>,
) -> anyhow::Result<Reply> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body.to_owned()))?;
    for (k, v) in headers {
        req.headers_mut().append(k.clone(), v.parse()?);
    }
    if let Some(ip) = peer {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
    }
    let res = app.clone().oneshot(req).await?;
    let status = res.status();
    let request_id = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok());
    let mut hdrs: Vec<(String, String)> = res
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str() != "x-request-id")
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                v.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    hdrs.sort();
    let bytes = res.into_body().collect().await?.to_bytes();
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        request_id,
        headers: hdrs,
    })
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

async fn register(app: &Router, t: &Tenant, email: &str) -> TestResult {
    let body = json!({
        "email": email,
        "password": PW,
        "name": "Cliente",
        "consents": {"terms_version": "2026-11", "privacy_version": "2026-11"},
        "turnstile_token": CAPTCHA_OK,
        "website": "",
        "form_started_at": now_ms() - 5_000,
    });
    let origin = format!("https://{}", t.domain);
    let r = send(
        app,
        Method::POST,
        REGISTER_URI,
        &[
            (header::HOST, &t.domain),
            (header::CONTENT_TYPE, "application/json"),
            (header::ORIGIN, &origin),
        ],
        &body.to_string(),
        Some(ip("198.51.100.250")),
    )
    .await?;
    anyhow::ensure!(r.status == StatusCode::ACCEPTED, "registo: {}", r.body);
    Ok(())
}

/// Login sem sessão, a partir do próprio site (`Origin` do tenant).
async fn login(
    app: &Router,
    t: &Tenant,
    email: &str,
    pw: &str,
    token: Option<&str>,
    peer: &str,
) -> anyhow::Result<Reply> {
    login_with(app, t, email, pw, token, peer, None).await
}

/// Login com a sessão anterior do browser (`(cookie, csrf)`) e a `Origin` do tenant.
async fn login_with(
    app: &Router,
    t: &Tenant,
    email: &str,
    pw: &str,
    token: Option<&str>,
    peer: &str,
    session: Option<(&str, &str)>,
) -> anyhow::Result<Reply> {
    let origin = format!("https://{}", t.domain);
    login_from(app, t, email, pw, token, peer, session, Some(&origin)).await
}

/// Login com a `Origin` dada (`None` = sem `Origin`).
#[allow(clippy::too_many_arguments)]
async fn login_from(
    app: &Router,
    t: &Tenant,
    email: &str,
    pw: &str,
    token: Option<&str>,
    peer: &str,
    session: Option<(&str, &str)>,
    origin: Option<&str>,
) -> anyhow::Result<Reply> {
    let mut body = json!({"email": email, "password": pw});
    if let Some(tok) = token {
        body["turnstile_token"] = json!(tok);
    }
    let mut h = vec![
        (header::HOST, t.domain.as_str()),
        (header::CONTENT_TYPE, "application/json"),
    ];
    if let Some(o) = origin {
        h.push((header::ORIGIN, o));
    }
    if let Some((cookie, csrf)) = session {
        h.push((header::COOKIE, cookie));
        h.push((X_CSRF_TOKEN, csrf));
    }
    send(
        app,
        Method::POST,
        LOGIN_URI,
        &h,
        &body.to_string(),
        Some(ip(peer)),
    )
    .await
}

async fn session_status(app: &Router, host: &str, cookie: &str) -> anyhow::Result<Value> {
    let r = send(
        app,
        Method::GET,
        SESSION_URI,
        &[(header::HOST, host), (header::COOKIE, cookie)],
        "",
        Some(ip("198.51.100.251")),
    )
    .await?;
    Ok(r.json())
}

/// id + PHC pela única leitura por email.
async fn credentials(app: &PgPool, email: &str) -> anyhow::Result<(Uuid, Option<String>)> {
    let row: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT c.id::uuid, c.password_hash::text
         FROM public.identity_customer_credentials($1::text) AS c",
    )
    .bind(email)
    .fetch_optional(app)
    .await?;
    row.ok_or_else(|| anyhow::anyhow!("conta inexistente"))
}

fn customer_ctx(id: Uuid) -> AuditCtx {
    AuditCtx::for_tests(ActorType::Customer, Some(id), None, None)
}

/// Muda o PHC como o próprio cliente (`None` = conta só com passkey).
async fn set_phc(app: &PgPool, t: &Tenant, id: Uuid, phc: Option<&str>) -> TestResult {
    let ctx = customer_ctx(id);
    let mut tx = begin_tenant_tx(app, t.tid(), &ctx).await?;
    sqlx::query!(
        "UPDATE customers SET password_hash = $2 WHERE id = $1",
        id,
        phc
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Sessões do cliente: (id, revogada).
async fn sessions_of(app: &PgPool, t: &Tenant, id: Uuid) -> anyhow::Result<Vec<(Uuid, bool)>> {
    let ctx = customer_ctx(id);
    let mut tx = begin_tenant_tx(app, t.tid(), &ctx).await?;
    let rows = sqlx::query!(
        r#"SELECT id, revoked_at IS NOT NULL AS "revoked!" FROM sessions
           WHERE subject_type = 'customer' AND subject_id = $1 ORDER BY id"#,
        id
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(rows.into_iter().map(|r| (r.id, r.revoked)).collect())
}

/// Eventos da caixa negra do tenant `t` (filtro opcional por ação).
async fn events(app: &PgPool, t: &Tenant, action: Option<&str>) -> anyhow::Result<Vec<EvRow>> {
    let reader = AuditCtx::for_tests(ActorType::System, None, None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &reader).await?;
    let rows: Vec<EvRow> = sqlx::query_as(
        "SELECT action::text, outcome::text, reason::text, actor_type::text, actor_id::uuid,
                target_type::text, target_id::text, changes::text
         FROM audit.audit_events
         WHERE ($1::text IS NULL OR action = $1::text)
         ORDER BY chain_seq",
    )
    .bind(action)
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(rows)
}

const ACCOUNT_KEY: &str = "chave-de-conta-de-teste-com-mais-de-32-bytes";

fn account_key() -> AccountKey {
    AccountKey::new(ACCOUNT_KEY.to_owned().into())
}

fn hash_of(email: &str) -> String {
    account_hash(&account_key(), email)
}

/// PHC Argon2id com parâmetros mais fracos que os atuais (conta antiga).
fn weak_phc(pw: &str) -> anyhow::Result<String> {
    let params = Params::new(8_192, 1, 1, Some(32)).map_err(|e| anyhow::anyhow!("params: {e}"))?;
    let h = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_with_salt(pw.as_bytes(), b"sal-fixo-de-teste")
        .map_err(|e| anyhow::anyhow!("hash: {e}"))?;
    Ok(h.to_string())
}

// ---------------------------------------------------------------------------------------------
// Sucesso: cookie, rotação, rehash, email normalizado, host
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn login_rotates_session_rehashes_and_normalizes_email(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let b = seed_tenant(&owner, "camara-b").await?;
    let ns = namespace();
    let s = Setup::new(&pool);
    let app = s.router(&ns)?;
    register(&app, &a, " João@X.pt ").await?;
    let (id, _) = credentials(&pool, "joão@x.pt").await?;
    set_phc(&pool, &a, id, Some(&weak_phc(PW)?)).await?;

    // Sessão anterior deste browser (do mesmo cliente).
    let ctx = customer_ctx(id);
    let mut tx = begin_tenant_tx(&pool, a.tid(), &ctx).await?;
    let (old_id, old_value) =
        session::create(&mut tx, Subject::Customer(id), Some(a.tid()), &ctx).await?;
    tx.commit().await?;
    let old_cookie = format!("{COOKIE_TENANT}={}", old_value.expose());
    let csrf = session_status(&app, &a.domain, &old_cookie).await?["csrf_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("sem csrf"))?;

    // A forma NFD do mesmo email entra na mesma conta.
    let nfd = "joa\u{0303}o@x.pt";
    let r = login_with(
        &app,
        &a,
        nfd,
        PW,
        None,
        "203.0.113.1",
        Some((&old_cookie, &csrf)),
    )
    .await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let cookie = r
        .session_cookie()
        .ok_or_else(|| anyhow::anyhow!("sem Set-Cookie: {:?}", r.headers))?;
    let sc = r.header("set-cookie").unwrap_or_default();
    for want in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"] {
        assert!(sc.contains(want), "{sc}");
    }
    assert_eq!(
        session_status(&app, &a.domain, &cookie).await?["authenticated"],
        true
    );

    // A sessão anterior ficou revogada; há uma nova ativa.
    let rows = sessions_of(&pool, &a, id).await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.contains(&(old_id.as_uuid(), true)), "{rows:?}");
    let new_id = rows
        .iter()
        .find(|(_, revoked)| !revoked)
        .map(|(i, _)| *i)
        .ok_or_else(|| anyhow::anyhow!("sem sessão nova"))?;
    assert_eq!(
        session_status(&app, &a.domain, &old_cookie).await?["authenticated"],
        false
    );

    // PHC fraco regravado com os parâmetros atuais.
    let (_, phc) = credentials(&pool, "joão@x.pt").await?;
    assert!(
        phc.as_deref()
            .is_some_and(|p| p.starts_with("$argon2id$v=19$m=19456,t=2,p=1$")),
        "{phc:?}"
    );

    // Evento auth.login success com o ator e o id da sessão.
    let ev = events(&pool, &a, Some("auth.login")).await?;
    assert_eq!(ev.len(), 1, "{ev:?}");
    let (_, outcome, reason, actor_type, actor_id, target_type, target_id, _) = &ev[0];
    assert_eq!(outcome, "success");
    assert!(reason.is_none());
    assert_eq!(actor_type, "customer");
    assert_eq!(*actor_id, Some(id));
    assert_eq!(target_type.as_deref(), Some("session"));
    assert_eq!(target_id.as_deref(), Some(new_id.to_string().as_str()));

    // A forma original (espaços, maiúsculas) entra também.
    let r = login(&app, &a, " João@X.pt ", PW, None, "203.0.113.2").await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);

    // Login no Host A não dá sessão válida no Host B.
    assert_eq!(
        session_status(&app, &b.domain, &cookie).await?["authenticated"],
        false
    );
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// Falhas indistinguíveis
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn failures_are_byte_identical_and_always_run_argon2(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let ns = namespace();
    let s = Setup::new(&pool);
    let app = s.router(&ns)?;
    register(&app, &a, "pw@exemplo.pt").await?;
    register(&app, &a, "passkey@exemplo.pt").await?;
    let (pk, _) = credentials(&pool, "passkey@exemplo.pt").await?;
    set_phc(&pool, &a, pk, None).await?;

    let cases = [
        ("ninguem@exemplo.pt", PW),
        ("pw@exemplo.pt", WRONG),
        ("passkey@exemplo.pt", PW),
    ];
    let mut replies = Vec::new();
    for (i, (email, pw)) in cases.iter().enumerate() {
        let before = s.argon2_runs();
        let r = login(&app, &a, email, pw, None, &format!("203.0.113.{}", 10 + i)).await?;
        assert_eq!(s.argon2_runs(), before + 1, "Argon2 não correu: {email}");
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
        assert!(r.request_id.is_some());
        replies.push(r);
    }
    for r in &replies[1..] {
        assert_eq!(r.status, replies[0].status);
        assert_eq!(r.body, replies[0].body);
        assert_eq!(r.headers, replies[0].headers);
    }
    assert_eq!(replies[0].json()["error"]["code"], "unauthorized");
    assert!(replies[0].json().get("captcha_required").is_none());

    let ev = events(&pool, &a, Some("auth.login")).await?;
    assert_eq!(ev.len(), 3, "{ev:?}");
    for ((email, _), row) in cases.iter().zip(&ev) {
        let (_, outcome, reason, actor_type, actor_id, target_type, target_id, _) = row;
        assert_eq!(outcome, "denied");
        assert_eq!(reason.as_deref(), Some("bad_credentials"));
        assert_eq!(actor_type, "anonymous");
        assert!(actor_id.is_none());
        assert_eq!(target_type.as_deref(), Some("account_hash"));
        assert_eq!(target_id.as_deref(), Some(hash_of(email).as_str()));
    }
    // Nenhum evento do tenant leva o email nem a password.
    let all = format!("{:?}", events(&pool, &a, None).await?);
    for secret in ["ninguem@", "pw@exemplo", "passkey@", PW, WRONG] {
        assert!(!all.contains(secret), "{secret} na caixa negra");
    }
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// Captcha, espera exponencial e expiração
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn captcha_after_three_failures_backoff_and_expiry(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let ns = namespace();
    let mut s = Setup::new(&pool);
    s.limits = Limits {
        fail_ttl: Duration::from_secs(4),
        backoff_unit: Duration::from_secs(2),
        email_window: Duration::from_secs(4),
        ..Limits::default()
    };
    let app = s.router(&ns)?;
    register(&app, &a, "ana@exemplo.pt").await?;
    let me = "203.0.113.20";

    for _ in 0..3 {
        let r = login(&app, &a, "ana@exemplo.pt", WRONG, None, me).await?;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(!r.captcha_required(), "{}", r.body);
    }
    // 4.º pedido sem captcha → captcha_required (sem Argon2); com captcha errado também.
    let before = s.argon2_runs();
    let r = login(&app, &a, "ana@exemplo.pt", PW, None, me).await?;
    assert!(r.captcha_required(), "{} {}", r.status, r.body);
    let r = login(&app, &a, "ana@exemplo.pt", PW, Some("errado"), me).await?;
    assert!(r.captcha_required(), "{} {}", r.status, r.body);
    assert_eq!(s.argon2_runs(), before);
    let ev = events(&pool, &a, Some("auth.login")).await?;
    assert_eq!(
        ev.iter()
            .filter(|e| e.2.as_deref() == Some("captcha"))
            .count(),
        2
    );
    // Com captcha válido e password certa entra.
    let r = login(&app, &a, "ana@exemplo.pt", PW, Some(CAPTCHA_OK), me).await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);

    // 4.ª e 5.ª falhas (com captcha: o IP continua com 3) → a 6.ª tentativa leva 429.
    for _ in 0..2 {
        let r = login(&app, &a, "ana@exemplo.pt", WRONG, Some(CAPTCHA_OK), me).await?;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    }
    let n_events = events(&pool, &a, Some("auth.login")).await?.len();
    let r = login(&app, &a, "ana@exemplo.pt", PW, Some(CAPTCHA_OK), me).await?;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    let retry: u64 = r.header("retry-after").unwrap_or_default().parse()?;
    assert!((1..=2).contains(&retry), "{retry}");
    // 429 sem evento auth.login (só o middleware conta).
    assert_eq!(events(&pool, &a, Some("auth.login")).await?.len(), n_events);

    // Passado o TTL, tudo expirou: entra sem captcha (nunca bloqueio permanente).
    tokio::time::sleep(Duration::from_millis(4_500)).await;
    let r = login(&app, &a, "ana@exemplo.pt", PW, None, me).await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// Volume por IP e por email; sem DoS à conta alheia
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn ip_volume_is_429_and_email_volume_only_asks_captcha(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let ns = namespace();
    let s = Setup::new(&pool);
    let app = s.router(&ns)?;
    register(&app, &a, "bea@exemplo.pt").await?;

    // 21 tentativas do mesmo IP no mesmo minuto (3 falhas e 17 sem captcha) → a 21.ª é 429.
    let bot = "203.0.113.30";
    for i in 1..=20 {
        let email = format!("alvo{i}@exemplo.pt");
        let r = login(&app, &a, &email, WRONG, None, bot).await?;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{i}: {}", r.body);
    }
    let r = login(&app, &a, "alvo21@exemplo.pt", PW, Some(CAPTCHA_OK), bot).await?;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    assert!(r.header("retry-after").is_some());

    // 10 logins certos do mesmo email de IPs diferentes; o 11.º pede captcha (nunca 429).
    for i in 1..=10 {
        let r = login(
            &app,
            &a,
            "bea@exemplo.pt",
            PW,
            None,
            &format!("198.51.100.{i}"),
        )
        .await?;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{i}: {}", r.body);
    }
    let r = login(&app, &a, "bea@exemplo.pt", PW, None, "198.51.100.11").await?;
    assert!(r.captcha_required(), "{} {}", r.status, r.body);
    let r = login(
        &app,
        &a,
        "bea@exemplo.pt",
        PW,
        Some(CAPTCHA_OK),
        "198.51.100.12",
    )
    .await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn failures_from_another_ip_never_lock_the_owner_out(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let ns = namespace();
    let s = Setup::new(&pool);
    let app = s.router(&ns)?;
    register(&app, &a, "xavier@exemplo.pt").await?;

    let attacker = "203.0.113.40";
    for i in 0..5 {
        let token = (i >= 3).then_some(CAPTCHA_OK);
        let r = login(&app, &a, "xavier@exemplo.pt", WRONG, token, attacker).await?;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{i}: {}", r.body);
    }
    let r = login(
        &app,
        &a,
        "xavier@exemplo.pt",
        PW,
        Some(CAPTCHA_OK),
        attacker,
    )
    .await?;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);

    // O titular, de outro IP: captcha (nunca 429) e, com captcha, entra.
    let home = "2001:db8:aa::1";
    let r = login(&app, &a, "xavier@exemplo.pt", PW, None, home).await?;
    assert!(r.captcha_required(), "{} {}", r.status, r.body);
    let r = login(&app, &a, "xavier@exemplo.pt", PW, Some(CAPTCHA_OK), home).await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    assert!(r.session_cookie().is_some());
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn parallel_attempts_let_at_most_three_through_without_captcha(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let ns = namespace();
    let s = Setup::new(&pool);
    let app = s.router(&ns)?;
    register(&app, &a, "par@exemplo.pt").await?;

    // 10 em paralelo, IPs diferentes (só o contador da conta decide), password errada.
    let mut set = tokio::task::JoinSet::new();
    for i in 0..10 {
        let app = app.clone();
        let t = Tenant {
            id: a.id,
            domain: a.domain.clone(),
        };
        set.spawn(async move {
            let peer = format!("203.0.113.{}", 100 + i);
            login(&app, &t, "par@exemplo.pt", WRONG, None, &peer).await
        });
    }
    let mut passed = 0;
    while let Some(r) = set.join_next().await {
        let r = r??;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
        if !r.captcha_required() {
            passed += 1;
        }
    }
    assert!(passed <= 3, "{passed} passaram sem captcha");
    assert!(s.argon2_runs() <= 3, "{} Argon2", s.argon2_runs());
    // A seguir, sem captcha, continua a pedi-lo.
    let r = login(&app, &a, "par@exemplo.pt", PW, None, "203.0.113.200").await?;
    assert!(r.captcha_required(), "{} {}", r.status, r.body);
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn login_over_another_customers_session_logs_it_out(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let ns = namespace();
    let s = Setup::new(&pool);
    let app = s.router(&ns)?;
    register(&app, &a, "yara@exemplo.pt").await?;
    register(&app, &a, "xico@exemplo.pt").await?;
    let (y, _) = credentials(&pool, "yara@exemplo.pt").await?;
    let (x, _) = credentials(&pool, "xico@exemplo.pt").await?;

    // O browser tem a sessão da Yara; entra o Xico.
    let ctx = customer_ctx(y);
    let mut tx = begin_tenant_tx(&pool, a.tid(), &ctx).await?;
    let (y_sid, y_value) =
        session::create(&mut tx, Subject::Customer(y), Some(a.tid()), &ctx).await?;
    tx.commit().await?;
    let y_cookie = format!("{COOKIE_TENANT}={}", y_value.expose());
    let csrf = session_status(&app, &a.domain, &y_cookie).await?["csrf_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("sem csrf"))?;
    let r = login_with(
        &app,
        &a,
        "xico@exemplo.pt",
        PW,
        None,
        "203.0.113.70",
        Some((&y_cookie, &csrf)),
    )
    .await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);

    // A sessão da Yara ficou revogada, com auth.logout (ator Yara) e o motivo.
    assert_eq!(sessions_of(&pool, &a, y).await?, vec![(y_sid.as_uuid(), true)]);
    assert_eq!(sessions_of(&pool, &a, x).await?.len(), 1);
    assert_eq!(session_status(&app, &a.domain, &y_cookie).await?["authenticated"], false);
    let ev = events(&pool, &a, Some("auth.logout")).await?;
    assert_eq!(ev.len(), 1, "{ev:?}");
    let (_, outcome, reason, actor_type, actor_id, target_type, target_id, _) = &ev[0];
    assert_eq!(outcome, "success");
    assert_eq!(reason.as_deref(), Some("superseded_by_login"));
    assert_eq!(actor_type, "customer");
    assert_eq!(*actor_id, Some(y));
    assert_eq!(target_type.as_deref(), Some("session"));
    assert_eq!(target_id.as_deref(), Some(y_sid.as_uuid().to_string().as_str()));
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn anonymous_login_without_own_origin_is_403(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let ns = namespace();
    let s = Setup::new(&pool);
    let app = s.router(&ns)?;
    register(&app, &a, "olga@exemplo.pt").await?;
    let r = login_from(&app, &a, "olga@exemplo.pt", PW, None, "203.0.113.80", None, None).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    assert!(r.session_cookie().is_none());
    let rid = r.request_id.ok_or_else(|| anyhow::anyhow!("sem x-request-id"))?;
    let denied = events(&pool, &a, None)
        .await?
        .into_iter()
        .filter(|e| e.1 == "denied" && e.2.as_deref() == Some("csrf"))
        .count();
    assert!(denied >= 1, "sem evento denied ({rid})");
    for bad in ["https://outro-site.invalid", "null"] {
        let r = login_from(
            &app,
            &a,
            "olga@exemplo.pt",
            PW,
            None,
            "203.0.113.81",
            None,
            Some(bad),
        )
        .await?;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{bad}");
    }
    assert_eq!(s.argon2_runs(), 0);
    assert!(events(&pool, &a, Some("auth.login")).await?.is_empty());
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// Falha fechado
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn audit_db_down_is_503_and_no_session(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let ns = namespace();
    let s = Setup::new(&pool);
    register(&s.router(&ns)?, &a, "rui@exemplo.pt").await?;
    let (id, _) = credentials(&pool, "rui@exemplo.pt").await?;

    // A BD da app e da caixa negra em baixo (o Host continua a resolver).
    let mut down = Setup::new(&pool);
    down.db = dead_db()?;
    down.audit_db = dead_db()?;
    let r = login(
        &down.router(&ns)?,
        &a,
        "rui@exemplo.pt",
        PW,
        None,
        "203.0.113.50",
    )
    .await?;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.body);
    assert!(r.session_cookie().is_none());
    assert!(sessions_of(&pool, &a, id).await?.is_empty());
    assert!(events(&pool, &a, Some("auth.login")).await?.is_empty());
    cleanup(&ns).await
}

#[tokio::test]
async fn redis_down_asks_captcha_on_every_login() -> TestResult {
    let dead = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .create_pool(Some(Runtime::Tokio1))?;
    let l = Limits::default();
    let keys = Keys::new("test:login:dead:", &hash_of("ana@x.pt"), Some(ip("203.0.113.60")));
    let snap = throttle::begin(&dead, &keys, &l).await;
    assert!(snap.is_none());
    assert_eq!(throttle::decide(snap, &l), Gate::Proceed { captcha: true });
    // Nunca falha nem tranca: as escritas só ficam no log.
    throttle::failed(&dead, &keys, &l).await;
    throttle::succeeded(&dead, &keys).await;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Contrato
// ---------------------------------------------------------------------------------------------

#[test]
fn openapi_json_is_up_to_date() -> TestResult {
    let generated = ptmarket_api::http::openapi::ApiDoc::openapi().to_pretty_json()? + "\n";
    let committed = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json"))?;
    assert!(
        generated == committed,
        "openapi.json desatualizado: correr `cargo run --bin openapi`"
    );
    assert!(committed.contains("/api/v1/auth/login"));
    Ok(())
}
