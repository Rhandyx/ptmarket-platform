//! 2FA TOTP, códigos de recuperação, `RequireSuperAdmin` e o CLI `ptmarket-admin` (cartão 02/20),
//! contra Postgres e Redis reais, pela API real (`http::api`) com sessões e captcha falso.
//!
//! Contas e papéis de teste nascem pelo dono (`NO FORCE ROW LEVEL SECURITY` só dentro da transação
//! do seed). Leituras de `audit.*` sem `query!` (schema selado): eventos de tenant pela app; os da
//! plataforma (ator `admin`) pelos alertas `audit.superadmin_action`, lidos como `ptmarket_worker`.

use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderName, Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    http::{api, audit_layer::AuditLayerState, client_ip::TrustedProxies},
    identity::{
        AccountKey, CaptchaVerifier, Login, Password, Sessions, Totp,
        crypto::EncKey,
        password,
        session::{COOKIE_PLATFORM, COOKIE_TENANT},
        throttle::Limits,
        totp::{MFA_REVOKE_AFTER, base32_decode, code, mfa_limits, step_at},
    },
    state::AppState,
    storage::NullStorage,
    tenancy::{HostResolver, TenantId, begin_tenant_tx},
};
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tower::ServiceExt;
use uuid::Uuid;

type TestResult = anyhow::Result<()>;

const CSRF_KEY: &str = "chave-csrf-de-teste-com-mais-de-32-bytes";
const INTERNAL_TOKEN: &str = "token-interno-de-teste-com-mais-de-32-bytes";
const ACCOUNT_KEY: &str = "chave-de-conta-de-teste-com-mais-de-32-bytes";
const PLATFORM: &str = "admin.ptmarket.invalid";
const PW: &str = "uma-frase-longa-e-boa";
const ENROLL: &str = "/api/v1/staff/mfa/totp/enroll";
const CONFIRM: &str = "/api/v1/staff/mfa/totp/confirm";
const VERIFY: &str = "/api/v1/staff/mfa/verify";
const WHOAMI: &str = "/api/v1/superadmin/whoami";

fn enc_key() -> anyhow::Result<EncKey> {
    let b64 = STANDARD.encode([42u8; 32]);
    EncKey::from_base64(&SecretString::from(b64)).map_err(|e| anyhow::anyhow!("{e}"))
}

struct FakeCaptcha;

#[async_trait]
impl CaptchaVerifier for FakeCaptcha {
    async fn verify(&self, token: &str, _ip: Option<IpAddr>, _host: &str) -> bool {
        token == "captcha-ok"
    }
}

// ---------------------------------------------------------------------------------------------
// Infra
// ---------------------------------------------------------------------------------------------

async fn role_pool(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
    role: &'static str,
) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(10)
        .after_connect(move |c, _meta| {
            Box::pin(async move {
                match role {
                    "app" => sqlx::query!("SET ROLE ptmarket_app").execute(c).await?,
                    _ => sqlx::query!("SET ROLE ptmarket_worker").execute(c).await?,
                };
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

fn router(pool: &PgPool, ns: &str) -> anyhow::Result<Router> {
    router_with(pool, ns, None)
}

/// Com `limits`: travão do 2FA com outros limites (ex.: esperas de milissegundos).
fn router_with(pool: &PgPool, ns: &str, limits: Option<Limits>) -> anyhow::Result<Router> {
    let mut totp = Totp::new(enc_key()?)?;
    if let Some(l) = limits {
        totp = totp.with_limits_for_tests(l);
    }
    let st = AppState {
        db_primary: pool.clone(),
        db_replica: pool.clone(),
        redis: redis()?,
        storage: Arc::new(NullStorage),
        hosts: Arc::new(HostResolver::new(
            pool.clone(),
            Some(PLATFORM.to_owned()),
            Some(INTERNAL_TOKEN.to_owned().into()),
        )),
    };
    let key = AccountKey::new(ACCOUNT_KEY.to_owned().into());
    let sessions =
        Sessions::for_tests(pool.clone(), redis()?, CSRF_KEY.to_owned().into(), ns, None)
            .with_internal_token(Some(INTERNAL_TOKEN.to_owned().into()))
            .with_login(Login::new(Arc::new(FakeCaptcha), key))
            .with_totp(totp);
    let audit = AuditLayerState::for_tests(
        pool.clone(),
        redis()?,
        TrustedProxies::none(),
        ns,
        Duration::from_secs(1),
    );
    Ok(api(st.clone(), audit, Some(sessions)).with_state(st))
}

struct Reply {
    status: StatusCode,
    body: String,
    set_cookie: Option<String>,
    retry_after: Option<String>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_default()
    }

    fn cookie(&self) -> anyhow::Result<String> {
        self.set_cookie
            .as_deref()
            .and_then(|c| c.split(';').next())
            .map(|p| p.trim().to_owned())
            .ok_or_else(|| anyhow::anyhow!("sem Set-Cookie ({}): {}", self.status, self.body))
    }
}

async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(HeaderName, &str)],
    body: &str,
) -> anyhow::Result<Reply> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body.to_owned()))?;
    for (k, v) in headers {
        req.headers_mut().append(k.clone(), v.parse()?);
    }
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::from([203, 0, 113, 9]),
        40_000,
    )));
    let res = app.clone().oneshot(req).await?;
    let status = res.status();
    let hv = |h: header::HeaderName| {
        res.headers()
            .get(h)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let set_cookie = hv(header::SET_COOKIE);
    let retry_after = hv(header::RETRY_AFTER);
    let bytes = res.into_body().collect().await?.to_bytes();
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        set_cookie,
        retry_after,
    })
}

async fn login(app: &Router, host: &str, email: &str) -> anyhow::Result<String> {
    let origin = format!("https://{host}");
    let body = json!({"email": email, "password": PW});
    let r = send(
        app,
        Method::POST,
        "/api/v1/staff/auth/login",
        &[
            (header::HOST, host),
            (header::CONTENT_TYPE, "application/json"),
            (header::ORIGIN, &origin),
        ],
        &body.to_string(),
    )
    .await?;
    anyhow::ensure!(r.status == StatusCode::OK, "login {email}: {}", r.body);
    r.cookie()
}

async fn get(app: &Router, host: &str, uri: &str, cookie: &str) -> anyhow::Result<Reply> {
    send(
        app,
        Method::GET,
        uri,
        &[(header::HOST, host), (header::COOKIE, cookie)],
        "",
    )
    .await
}

/// POST com sessão: `Origin` do host e o token CSRF da sessão.
async fn post(
    app: &Router,
    host: &str,
    uri: &str,
    cookie: &str,
    body: &str,
) -> anyhow::Result<Reply> {
    let s = get(app, host, "/api/v1/auth/session", cookie).await?;
    let csrf = s.json()["csrf_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("sem csrf_token: {}", s.body))?;
    let origin = format!("https://{host}");
    send(
        app,
        Method::POST,
        uri,
        &[
            (header::HOST, host),
            (header::COOKIE, cookie),
            (header::ORIGIN, &origin),
            (header::CONTENT_TYPE, "application/json"),
            (HeaderName::from_static("x-csrf-token"), &csrf),
        ],
        body,
    )
    .await
}

fn code_body(c: &str) -> String {
    json!({ "code": c }).to_string()
}

fn now_step() -> u64 {
    step_at(SystemTime::now())
}

fn fmt6(n: u32) -> String {
    format!("{n:06}")
}

/// Um código que não confere em nenhum passo da janela atual.
fn wrong_code(secret: &[u8]) -> String {
    let s = now_step();
    let valid: Vec<u32> = (s - 1..=s + 2).map(|x| code(secret, x)).collect();
    let mut c = (code(secret, s) + 1) % 1_000_000;
    while valid.contains(&c) {
        c = (c + 1) % 1_000_000;
    }
    fmt6(c)
}

// ---------------------------------------------------------------------------------------------
// Seed e leituras
// ---------------------------------------------------------------------------------------------

struct Tenant {
    id: Uuid,
    domain: String,
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

async fn seed_user(
    owner: &PgPool,
    email: &str,
    roles: &[(&str, Option<Uuid>, Option<Uuid>)],
) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let phc = password::hash(&Password::parse(PW)?).await?;
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("ALTER TABLE user_roles NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "INSERT INTO users (id, email, password_hash, full_name, is_active)
         VALUES ($1, $2, $3, 'Pessoa de Teste', true)",
        id,
        email,
        phc
    )
    .execute(&mut *tx)
    .await?;
    for (role, tenant, store) in roles {
        sqlx::query!(
            "INSERT INTO user_roles (id, user_id, role, tenant_id, store_id)
             VALUES ($1, $2, $3, $4, $5)",
            Uuid::now_v7(),
            id,
            *role,
            *tenant,
            *store
        )
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query!("ALTER TABLE users FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("ALTER TABLE user_roles FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}

/// Códigos de recuperação "antigos" (pelo dono), para provar que o `confirm` os apaga.
async fn seed_old_codes(owner: &PgPool, user: Uuid, hashes: &[[u8; 32]]) -> TestResult {
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE user_recovery_codes NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    for h in hashes {
        sqlx::query!(
            "INSERT INTO user_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3)",
            Uuid::now_v7(),
            user,
            &h[..]
        )
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query!("ALTER TABLE user_recovery_codes FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// (totp_secret_enc, totp_enabled, hashes dos códigos de recuperação), lidos pelo dono.
async fn user_secrets(
    owner: &PgPool,
    user: Uuid,
) -> anyhow::Result<(Option<String>, bool, Vec<Vec<u8>>)> {
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("ALTER TABLE user_recovery_codes NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    let u = sqlx::query!(
        "SELECT totp_secret_enc, totp_enabled FROM users WHERE id = $1",
        user
    )
    .fetch_one(&mut *tx)
    .await?;
    let codes = sqlx::query_scalar!(
        "SELECT code_hash FROM user_recovery_codes WHERE user_id = $1",
        user
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok((u.totp_secret_enc, u.totp_enabled, codes))
}

/// Eventos do tenant como JSON (linha inteira, para procurar segredos).
async fn tenant_events(app: &PgPool, t: &Tenant) -> anyhow::Result<Vec<Value>> {
    let reader = AuditCtx::for_tests(ActorType::System, None, None, None);
    let mut tx = begin_tenant_tx(app, TenantId::for_tests(t.id), &reader).await?;
    let rows: Vec<(Value,)> =
        sqlx::query_as("SELECT to_jsonb(e) FROM audit.audit_events e ORDER BY chain_seq")
            .fetch_all(&mut *tx)
            .await?;
    tx.rollback().await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Payloads dos alertas `audit.superadmin_action` (ator `admin`), lidos como `ptmarket_worker`.
async fn admin_alerts(worker: &PgPool) -> anyhow::Result<Vec<Value>> {
    let rows: Vec<(Value,)> = sqlx::query_as(
        "SELECT payload FROM audit.audit_alerts
         WHERE event_type::text = 'audit.superadmin_action'::text ORDER BY created_at",
    )
    .fetch_all(worker)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

fn n_events(evs: &[Value], f: impl Fn(&Value) -> bool) -> usize {
    evs.iter().filter(|e| f(e)).count()
}

fn is(e: &Value, k: &str, v: &str) -> bool {
    e[k].as_str() == Some(v)
}

// ---------------------------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------------------------

/// `tenant_admin` sem 2FA: enroll → confirm (errado → 401 + denied; certo → 10 códigos, sessão
/// rodada e elevada, passa no `RequireTenantAdmin`); segredo cifrado com AAD; códigos antigos
/// apagados; código repetido recusado; código de recuperação uma só vez (também em paralelo);
/// `/superadmin/whoami` → 404; sem segredos nos eventos; travão → 429.
#[sqlx::test(migrations = "../migrations")]
async fn tenant_admin_totp_lifecycle(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let pool = role_pool(&opts, &conn, "app").await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let admin = seed_user(&owner, "camara@x.pt", &[("tenant_admin", Some(a.id), None)]).await?;
    let other = seed_user(&owner, "outra@x.pt", &[("tenant_admin", Some(a.id), None)]).await?;
    let ns = format!("test:totp:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;
    let h = a.domain.as_str();

    // Sem 2FA: as rotas normais recusam, as de 2FA não.
    let c0 = login(&app, h, "camara@x.pt").await?;
    assert_eq!(
        get(&app, h, "/api/v1/_test/tenant-admin", &c0)
            .await?
            .status,
        StatusCode::FORBIDDEN
    );
    let r = post(&app, h, ENROLL, &c0, "{}").await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let uri = r.json()["otpauth_uri"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        uri.starts_with("otpauth://totp/PT%20Market:camara%40x.pt?secret=")
            && uri.contains("&digits=6&period=30"),
        "{uri}"
    );
    let b32 = r.json()["secret_base32"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let secret = base32_decode(&b32).ok_or_else(|| anyhow::anyhow!("base32"))?;
    assert_eq!(secret.len(), 20);

    // Em repouso: cifrado, não é o segredo; AAD de outro utilizador falha.
    let (enc, enabled, _) = user_secrets(&owner, admin).await?;
    let enc = enc.unwrap_or_default();
    assert!(
        !enabled && enc.starts_with("v1:") && !enc.contains(&b32),
        "{enc}"
    );
    let key = enc_key()?;
    assert_eq!(key.decrypt(&enc, admin.as_bytes())?.as_slice(), &secret[..]);
    assert!(key.decrypt(&enc, other.as_bytes()).is_err());

    // Códigos antigos (de uma ativação anterior): o confirm apaga-os.
    let old = [[1u8; 32], [2u8; 32]];
    seed_old_codes(&owner, admin, &old).await?;

    // Errado → 401 + denied; o mesmo com corpo inválido/sem forma → 422 sem contar.
    let bad = wrong_code(&secret);
    let r = post(&app, h, CONFIRM, &c0, &code_body(&bad)).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    let r = post(&app, h, CONFIRM, &c0, r#"{"code":"1","extra":1}"#).await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Certo → 10 códigos, sessão nova elevada.
    let s0 = now_step();
    let good = fmt6(code(&secret, s0));
    let r = post(&app, h, CONFIRM, &c0, &code_body(&good)).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let codes: Vec<String> = serde_json::from_value(r.json()["recovery_codes"].clone())?;
    assert_eq!(codes.len(), 10);
    assert!(
        codes
            .iter()
            .all(|c| c.len() == 10 && !c.contains(['0', 'O', '1', 'I', 'L']))
    );
    let c1 = r.cookie()?;
    assert!(c1.starts_with(&format!("{COOKIE_TENANT}=")) && c1 != c0);
    // A sessão antiga foi revogada; a nova passa nos extractores normais.
    assert_eq!(
        get(&app, h, "/api/v1/staff/me", &c0).await?.status,
        StatusCode::UNAUTHORIZED
    );
    let r = get(&app, h, "/api/v1/_test/tenant-admin", &c1).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let (_, enabled, hashes) = user_secrets(&owner, admin).await?;
    assert!(enabled);
    assert_eq!(hashes.len(), 10);
    assert!(
        hashes
            .iter()
            .all(|h| h.as_slice() != old[0] && h.as_slice() != old[1])
    );
    // Ativo: novo enroll/confirm → 409.
    assert_eq!(
        post(&app, h, ENROLL, &c1, "{}").await?.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        post(&app, h, CONFIRM, &c1, &code_body(&good)).await?.status,
        StatusCode::CONFLICT
    );

    // tenant_admin com 2FA não abre a consola de plataforma.
    let r = get(&app, h, WHOAMI, &c1).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Verify: o código do confirm não volta a entrar; o do passo seguinte entra uma vez.
    let c2 = login(&app, h, "camara@x.pt").await?;
    let r = post(&app, h, VERIFY, &c2, &code_body(&good)).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "repetido: {}", r.body);
    let next = fmt6(code(&secret, s0 + 1));
    let r = post(&app, h, VERIFY, &c2, &code_body(&next)).await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let c3 = r.cookie()?;
    assert_eq!(
        get(&app, h, "/api/v1/_test/tenant-admin", &c3)
            .await?
            .status,
        StatusCode::OK
    );
    let c4 = login(&app, h, "camara@x.pt").await?;
    assert_eq!(
        post(&app, h, VERIFY, &c4, &code_body(&next)).await?.status,
        StatusCode::UNAUTHORIZED
    );

    // Código de recuperação: uma vez (aceita minúsculas e hífen).
    let rc = &codes[0];
    let typed = format!("{}-{}", &rc[..5], rc[5..].to_ascii_lowercase());
    let r = post(&app, h, VERIFY, &c4, &code_body(&typed)).await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let c5 = login(&app, h, "camara@x.pt").await?;
    assert_eq!(
        post(&app, h, VERIFY, &c5, &code_body(rc)).await?.status,
        StatusCode::UNAUTHORIZED
    );

    // Dois pedidos em paralelo (duas sessões) com o mesmo código: só um entra.
    let c6 = login(&app, h, "camara@x.pt").await?;
    let body = code_body(&codes[1]);
    let (x, y) = tokio::join!(
        post(&app, h, VERIFY, &c5, &body),
        post(&app, h, VERIFY, &c6, &body)
    );
    let mut st = [x?.status, y?.status];
    st.sort();
    assert_eq!(st, [StatusCode::NO_CONTENT, StatusCode::UNAUTHORIZED]);

    // Caixa negra: eventos certos, sem segredo, código nem códigos de recuperação.
    let evs = tenant_events(&pool, &a).await?;
    let mine = |e: &Value| e["actor_id"].as_str() == Some(admin.to_string().as_str());
    assert_eq!(
        n_events(&evs, |e| mine(e)
            && is(e, "action", "mfa.totp_enroll_started")),
        1
    );
    assert_eq!(
        n_events(&evs, |e| mine(e)
            && is(e, "action", "mfa.totp_enabled")
            && is(e, "outcome", "success")),
        1
    );
    assert_eq!(
        n_events(&evs, |e| mine(e)
            && is(e, "action", "mfa.totp_enabled")
            && is(e, "outcome", "denied")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        n_events(&evs, |e| mine(e)
            && is(e, "action", "mfa.verify")
            && is(e, "outcome", "success")),
        3
    );
    assert_eq!(
        n_events(&evs, |e| mine(e)
            && is(e, "action", "mfa.verify")
            && is(e, "outcome", "denied")),
        4
    );
    assert_eq!(
        n_events(&evs, |e| mine(e)
            && is(e, "reason", "superadmin_gate")
            && is(e, "actor_type", "municipal")),
        1
    );
    let all = serde_json::to_string(&evs)?;
    for s in [b32.as_str(), good.as_str(), next.as_str(), bad.as_str()]
        .into_iter()
        .chain(codes.iter().map(String::as_str))
    {
        assert!(!all.contains(s), "evento com segredo/código");
    }
    assert!(!all.contains(&STANDARD.encode(&secret)));

    // Travão: falhas seguidas → a partir da 5.ª há espera (429 + Retry-After); nunca permanente.
    let c7 = login(&app, h, "camara@x.pt").await?;
    let mut limited = None;
    for _ in 0..8 {
        let r = post(&app, h, VERIFY, &c7, &code_body(&wrong_code(&secret))).await?;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(r);
            break;
        }
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let limited = limited.ok_or_else(|| anyhow::anyhow!("sem 429"))?;
    assert!(
        limited
            .retry_after
            .is_some_and(|v| v.parse::<u64>().is_ok_and(|s| s >= 1))
    );

    // Consola: todos os caminhos `/api/v1/superadmin/*` do contrato e um inventado dão o MESMO
    // 404, sem sessão (plataforma e tenant) e com tenant_admin com 2FA; cada um com `denied`.
    let paths = superadmin_paths()?;
    let mut replies = Vec::new();
    for p in &paths {
        replies.push(get(&app, PLATFORM, p, "").await?);
        replies.push(get(&app, h, p, "").await?);
        replies.push(get(&app, h, p, &c3).await?);
    }
    let first = (replies[0].status, replies[0].body.clone());
    assert_eq!(first.0, StatusCode::NOT_FOUND, "{}", first.1);
    assert!(
        replies.iter().all(|r| (r.status, r.body.clone()) == first),
        "404 diferente"
    );
    let evs = tenant_events(&pool, &a).await?;
    assert_eq!(
        n_events(&evs, |e| mine(e)
            && is(e, "outcome", "denied")
            && is(e, "reason", "superadmin_gate")),
        1 + paths.len(),
        "{evs:?}"
    );

    // 10 falhas seguidas → a sessão pré-MFA é revogada (auth.logout / mfa_failures); um login novo
    // volta a poder tentar (nada é permanente). Esperas em ms para o teste.
    let ns2 = format!("test:totp:{}:", Uuid::now_v7());
    let fast = router_with(
        &pool,
        &ns2,
        Some(Limits {
            backoff_unit: Duration::from_millis(1),
            ..mfa_limits()
        }),
    )?;
    let o0 = login(&fast, h, "outra@x.pt").await?;
    let r = post(&fast, h, ENROLL, &o0, "{}").await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let osecret = base32_decode(r.json()["secret_base32"].as_str().unwrap_or_default())
        .ok_or_else(|| anyhow::anyhow!("base32"))?;
    let mut failures = 0;
    for _ in 0..60 {
        if failures == MFA_REVOKE_AFTER {
            break;
        }
        // Antes da 10.ª a sessão continua viva.
        assert_eq!(
            get(&fast, h, "/api/v1/staff/me", &o0).await?.status,
            StatusCode::OK
        );
        let r = post(&fast, h, CONFIRM, &o0, &code_body(&wrong_code(&osecret))).await?;
        match r.status {
            StatusCode::UNAUTHORIZED => failures += 1,
            StatusCode::TOO_MANY_REQUESTS => tokio::time::sleep(Duration::from_millis(60)).await,
            s => anyhow::bail!("inesperado {s}: {}", r.body),
        }
    }
    assert_eq!(failures, MFA_REVOKE_AFTER);
    assert_eq!(
        get(&fast, h, "/api/v1/staff/me", &o0).await?.status,
        StatusCode::UNAUTHORIZED,
        "sessão pré-MFA revogada"
    );
    let evs = tenant_events(&pool, &a).await?;
    let theirs = |e: &Value| e["actor_id"].as_str() == Some(other.to_string().as_str());
    assert_eq!(
        n_events(&evs, |e| theirs(e)
            && is(e, "action", "auth.logout")
            && is(e, "reason", "mfa_failures")),
        1,
        "{evs:?}"
    );
    // O login seguinte exige captcha, mesmo com a password certa.
    let origin = format!("https://{h}");
    let hdrs = [
        (header::HOST, h),
        (header::CONTENT_TYPE, "application/json"),
        (header::ORIGIN, origin.as_str()),
    ];
    let creds = json!({"email": "outra@x.pt", "password": PW});
    let r = send(
        &fast,
        Method::POST,
        "/api/v1/staff/auth/login",
        &hdrs,
        &creds.to_string(),
    )
    .await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert_eq!(r.json()["captcha_required"], json!(true), "{}", r.body);
    let creds = json!({"email": "outra@x.pt", "password": PW, "turnstile_token": "captcha-ok"});
    let r = send(
        &fast,
        Method::POST,
        "/api/v1/staff/auth/login",
        &hdrs,
        &creds.to_string(),
    )
    .await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let o1 = r.cookie()?;
    assert_eq!(
        get(&fast, h, "/api/v1/staff/me", &o1).await?.status,
        StatusCode::OK
    );
    cleanup(&ns2).await?;
    cleanup(&ns).await
}

/// Caminhos `/api/v1/superadmin/*` do `openapi.json` e um inventado.
fn superadmin_paths() -> anyhow::Result<Vec<String>> {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi.json"
    ))?)?;
    let mut paths: Vec<String> = doc["paths"]
        .as_object()
        .map(|m| {
            m.keys()
                .filter(|k| k.starts_with("/api/v1/superadmin/"))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    anyhow::ensure!(!paths.is_empty(), "openapi.json sem rotas superadmin");
    paths.push("/api/v1/superadmin/nao-existe/123".to_owned());
    Ok(paths)
}

/// Resultado de uma execução do CLI: sucesso, segredo base32 lido do enroll e toda a saída.
struct CliRun {
    ok: bool,
    secret_b32: Option<String>,
    /// Passo TOTP do código certo enviado no enroll.
    enroll_step: Option<u64>,
    out: String,
}

/// Corre `ptmarket-admin create-superadmin` com o stdin em pipe: a password duas vezes, depois lê o
/// segredo do enroll na saída e responde com o código TOTP certo (ou `bad_codes` errados antes).
fn run_cli(env: &[(&str, &str)], email: &str, bad_codes: usize) -> anyhow::Result<CliRun> {
    use std::io::{BufRead, BufReader, Read};
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ptmarket-admin"));
    cmd.args([
        "create-superadmin",
        "--email",
        email,
        "--name",
        "Raiz da Plataforma",
    ])
    .env_clear()
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdout"))?;
    stdin.write_all(format!("{PW}\n{PW}\n").as_bytes())?;
    stdin.flush()?;
    let mut reader = BufReader::new(stdout);
    let mut out = String::new();
    let mut secret_b32 = None;
    let mut enroll_step = None;
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        out.push_str(&line);
        if let Some(b32) = line.trim().strip_prefix("segredo: ") {
            let secret = base32_decode(b32).ok_or_else(|| anyhow::anyhow!("base32"))?;
            for _ in 0..bad_codes {
                stdin.write_all(format!("{}\n", wrong_code(&secret)).as_bytes())?;
            }
            let step = now_step();
            stdin.write_all(format!("{}\n", fmt6(code(&secret, step))).as_bytes())?;
            enroll_step = Some(step);
            stdin.flush()?;
            secret_b32 = Some(b32.to_owned());
            line.clear();
            break;
        }
        line.clear();
    }
    drop(stdin);
    reader.read_to_string(&mut out)?;
    let output = child.wait_with_output()?;
    out.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(CliRun {
        ok: output.status.success(),
        secret_b32,
        enroll_step,
        out,
    })
}

/// CLI (cartão 20c): cria o super_admin JÁ com TOTP (enroll no terminal) e 10 códigos; login na
/// plataforma + verify com o segredo do enroll → `/superadmin/whoami` 200; 2.ª vez → "email já
/// existe"; a app não escreve `user_roles`. Gate: sem TOTP, sem 2FA na sessão, caminho
/// desconhecido ou noutro host → 404 + `superadmin_gate`; 1 evento síncrono `admin` + 1 alerta.
#[sqlx::test(migrations = "../migrations")]
async fn superadmin_cli_and_gate(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let pool = role_pool(&opts, &conn, "app").await?;
    let worker = role_pool(&opts, &conn, "worker").await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    // super_admin sem TOTP (seed do dono): o gate recusa.
    let raw = seed_user(&owner, "semtotp@x.pt", &[("super_admin", None, None)]).await?;

    // Ligação do migrator a ESTA BD de teste; ambiente da API (APP_ENV=test, a mesma TOTP_ENC_KEY).
    let base = std::env::var("DATABASE_URL")?;
    let db = conn.get_database().unwrap_or("ptmarket");
    let admin_url = match base.rfind('/') {
        Some(i) => format!("{}/{db}", &base[..i]),
        None => anyhow::bail!("DATABASE_URL sem base de dados"),
    };
    let enc = STANDARD.encode([42u8; 32]);
    let ns = format!("test:totp:{}:", Uuid::now_v7());
    let env = [
        ("PTMARKET_TEST_REDIS_NS", ns.as_str()),
        ("APP_ENV", "test"),
        ("DATABASE_PRIMARY_URL", "postgres://u@127.0.0.1:1/x"),
        ("DATABASE_REPLICA_URL", "postgres://u@127.0.0.1:1/x"),
        ("REDIS_URL", "redis://127.0.0.1:6379"),
        ("TOTP_ENC_KEY", enc.as_str()),
        ("ADMIN_DATABASE_URL", admin_url.as_str()),
    ];

    // 1 código errado e depois o certo: criado com TOTP ativo; 10 códigos mostrados.
    let run = run_cli(&env, "Raiz@X.pt", 1)?;
    assert!(run.ok, "{}", run.out);
    assert!(
        run.out
            .contains("Código errado (2 tentativa(s) restante(s))"),
        "{}",
        run.out
    );
    let b32 = run
        .secret_b32
        .clone()
        .ok_or_else(|| anyhow::anyhow!("sem segredo"))?;
    let secret = base32_decode(&b32).ok_or_else(|| anyhow::anyhow!("base32"))?;
    let after = run
        .out
        .split("Códigos de recuperação")
        .nth(1)
        .unwrap_or_default();
    let codes: Vec<&str> = after
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| l.len() == 10)
        .collect();
    assert_eq!(codes.len(), 10, "{}", run.out);
    assert!(!run.out.contains(PW), "password na saída");
    assert!(run.out.contains("HIBP) está DESLIGADA"), "{}", run.out);
    assert_eq!(
        run.out.matches(b32.as_str()).count(),
        2,
        "segredo só no enroll (uri + base32)"
    );
    // 2.ª execução com o mesmo email (outra grafia) → falha; papel da API → recusado.
    let again = run_cli(&env, "raiz@x.pt", 0)?;
    assert!(
        !again.ok && again.out.contains("email já existe"),
        "{}",
        again.out
    );
    let mut app_env = env;
    app_env[6] = (
        "ADMIN_DATABASE_URL",
        "postgres://ptmarket_app@127.0.0.1:1/x",
    );
    assert!(!run_cli(&app_env, "outro@x.pt", 0)?.ok);
    let mut c = Command::new(env!("CARGO_BIN_EXE_ptmarket-admin"));
    c.args([
        "create-superadmin",
        "--email",
        "a@x.pt",
        "--name",
        "A",
        "--password",
        "x",
    ]);
    assert!(!c.output()?.status.success());

    // A API continua sem escrever em user_roles.
    let denied = sqlx::query!(
        "INSERT INTO user_roles (id, user_id, role) VALUES ($1, $2, 'super_admin')",
        Uuid::now_v7(),
        Uuid::now_v7()
    )
    .execute(&pool)
    .await;
    assert!(denied.is_err());

    let app = router(&pool, &ns)?;

    // super_admin sem TOTP ativo → 404 (ator admin na plataforma).
    let p0 = login(&app, PLATFORM, "semtotp@x.pt").await?;
    assert!(p0.starts_with(&format!("{COOKIE_PLATFORM}=")));
    let gated = get(&app, PLATFORM, WHOAMI, &p0).await?;
    assert_eq!(gated.status, StatusCode::NOT_FOUND);

    // Super_admin do CLI: TOTP ativo mas sessão sem 2FA → 404; verify → 200.
    let p2 = login(&app, PLATFORM, "raiz@x.pt").await?;
    assert_eq!(
        get(&app, PLATFORM, WHOAMI, &p2).await?.status,
        StatusCode::NOT_FOUND
    );
    let p3 = login(&app, PLATFORM, "raiz@x.pt").await?;
    // O código usado no enroll do CLI ficou marcado: no /verify é `replayed`.
    let s0 = run
        .enroll_step
        .ok_or_else(|| anyhow::anyhow!("sem passo do enroll"))?;
    let r = post(
        &app,
        PLATFORM,
        VERIFY,
        &p3,
        &code_body(&fmt6(code(&secret, s0))),
    )
    .await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    let r = post(
        &app,
        PLATFORM,
        VERIFY,
        &p3,
        &code_body(&fmt6(code(&secret, s0 + 1))),
    )
    .await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let p1 = r.cookie()?;
    let r = get(&app, PLATFORM, WHOAMI, &p1).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json()["full_name"], json!("Raiz da Plataforma"));
    let sa = r.json()["id"].as_str().unwrap_or_default().to_owned();
    // Um código de recuperação do CLI também serve (o hash com HMAC e o id bate certo).
    let p4 = login(&app, PLATFORM, "raiz@x.pt").await?;
    let r = post(&app, PLATFORM, VERIFY, &p4, &code_body(codes[0])).await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    // Caminho desconhecido com tudo certo: o mesmo 404 de uma recusa.
    let unknown = get(&app, PLATFORM, "/api/v1/superadmin/nao-existe", &p1).await?;
    assert_eq!((unknown.status, &unknown.body), (gated.status, &gated.body));

    // Noutro host (tenant) → 404 (o cookie da plataforma não vale lá).
    let r = get(&app, &a.domain, WHOAMI, &p1).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let evs = tenant_events(&pool, &a).await?;
    assert!(
        n_events(&evs, |e| is(e, "reason", "superadmin_gate")) >= 1,
        "{evs:?}"
    );

    // Alertas do ator admin (eventos síncronos da plataforma).
    let alerts = admin_alerts(&worker).await?;
    let whoami = |e: &Value| is(e, "target_id", WHOAMI) && is(e, "actor_id", &sa);
    assert_eq!(
        n_events(&alerts, |e| whoami(e)
            && is(e, "outcome", "success")
            && is(e, "actor_type", "admin")),
        1,
        "{alerts:?}"
    );
    assert_eq!(
        n_events(&alerts, |e| whoami(e)
            && is(e, "outcome", "denied")
            && is(e, "reason", "superadmin_gate")),
        1,
        "{alerts:?}"
    );
    assert_eq!(
        n_events(&alerts, |e| is(e, "actor_id", &raw.to_string())
            && is(e, "reason", "superadmin_gate")),
        1,
        "{alerts:?}"
    );
    assert_eq!(
        n_events(&alerts, |e| is(e, "actor_id", &sa)
            && is(e, "target_id", "/api/v1/superadmin/{*rest}")
            && is(e, "reason", "superadmin_gate")),
        1,
        "{alerts:?}"
    );
    assert_eq!(
        n_events(&alerts, |e| is(e, "actor_id", &sa)
            && is(e, "action", "mfa.verify")
            && is(e, "reason", "replayed")),
        1,
        "{alerts:?}"
    );
    let all = serde_json::to_string(&alerts)?;
    assert!(codes.iter().all(|c| !all.contains(c)));
    assert!(!all.contains(&b32));
    cleanup(&ns).await
}
