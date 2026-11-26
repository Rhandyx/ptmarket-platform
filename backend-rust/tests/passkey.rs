//! Passkeys de backoffice (cartão 02/21), contra Postgres e Redis reais, pela API real
//! (`http::api`) com sessões, e um autenticador de software (`SoftPasskey`, UV ligado).
//!
//! O `SoftPasskey` não guarda credenciais detetáveis: no login, o "browser" do teste põe o id da
//! sua credencial em `allowCredentials` e o `userHandle` na resposta (o que um autenticador real
//! com resident key faz sozinho). O servidor nunca envia a lista (descoberta).
//!
//! Contas e papéis nascem pelo dono (`NO FORCE ROW LEVEL SECURITY` só dentro da transação do seed).
//! Leituras de `audit.*` sem `query!` (schema selado).

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderName, Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    config::AppEnv,
    http::{api, audit_layer::AuditLayerState, client_ip::TrustedProxies},
    identity::{
        AccountKey, CaptchaVerifier, Login, Passkeys, Password, Sessions, Subject, password,
        session::{self, COOKIE_PLATFORM},
        throttle::Limits,
    },
    state::AppState,
    storage::NullStorage,
    tenancy::{HostResolver, TenantId, begin_tenant_tx, db::begin_platform_tx},
};
use serde_json::{Value, json};
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_authenticator_rs::{prelude::*, softpasskey::SoftPasskey};

type TestResult = anyhow::Result<()>;

const CSRF_KEY: &str = "chave-csrf-de-teste-com-mais-de-32-bytes";
const INTERNAL_TOKEN: &str = "token-interno-de-teste-com-mais-de-32-bytes";
const ACCOUNT_KEY: &str = "chave-de-conta-de-teste-com-mais-de-32-bytes";
const PLATFORM: &str = "admin.ptmarket.invalid";
const PW: &str = "uma-frase-longa-e-boa";
const REG_START: &str = "/api/v1/staff/passkeys/register/start";
const REG_FINISH: &str = "/api/v1/staff/passkeys/register/finish";
const LIST: &str = "/api/v1/staff/passkeys";
const AUTH_START: &str = "/api/v1/staff/auth/passkey/start";
const AUTH_FINISH: &str = "/api/v1/staff/auth/passkey/finish";
const ME: &str = "/api/v1/staff/me";
const WHOAMI: &str = "/api/v1/superadmin/whoami";

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

async fn app_pool(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(10)
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

async fn redis_keys(pattern: &str) -> anyhow::Result<Vec<String>> {
    let mut conn = redis()?.get().await?;
    Ok(redis::cmd("KEYS")
        .arg(pattern)
        .query_async(&mut conn)
        .await?)
}

async fn redis_del(keys: Vec<String>) -> TestResult {
    if keys.is_empty() {
        return Ok(());
    }
    let mut conn = redis()?.get().await?;
    redis::cmd("DEL")
        .arg(keys)
        .query_async::<i64>(&mut conn)
        .await?;
    Ok(())
}

async fn cleanup(ns: &str) -> TestResult {
    redis_del(redis_keys(&format!("{ns}*")).await?).await
}

fn router(pool: &PgPool, ns: &str) -> anyhow::Result<Router> {
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
            .with_login(Login::new(Arc::new(FakeCaptcha), key).with_limits_for_tests(lax()))
            .with_passkeys(Passkeys::new(AppEnv::Test).with_limits_for_tests(lax()));
    let audit = AuditLayerState::for_tests(
        pool.clone(),
        redis()?,
        TrustedProxies::none(),
        ns,
        Duration::from_secs(1),
    );
    Ok(api(st.clone(), audit, Some(sessions)).with_state(st))
}

/// Travão largo: os testes fazem muitas tentativas do mesmo IP (o travão é do cartão 19).
fn lax() -> Limits {
    Limits {
        ip_max: 1_000,
        backoff_from: 1_000,
        captcha_after: 1_000,
        email_max: 1_000,
        ..Limits::default()
    }
}

struct Reply {
    status: StatusCode,
    body: String,
    set_cookie: Option<String>,
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
        IpAddr::from([203, 0, 113, 21]),
        40_000,
    )));
    let res = app.clone().oneshot(req).await?;
    let status = res.status();
    let set_cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = res.into_body().collect().await?.to_bytes();
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        set_cookie,
    })
}

async fn password_login(app: &Router, host: &str, email: &str) -> anyhow::Result<String> {
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

/// Mutação com sessão: `Origin` do host e o token CSRF da sessão.
async fn mutate(
    app: &Router,
    method: Method,
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
        method,
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

/// POST anónimo com `Origin` do host.
async fn anon_post(app: &Router, host: &str, uri: &str, body: &str) -> anyhow::Result<Reply> {
    let origin = format!("https://{host}");
    send(
        app,
        Method::POST,
        uri,
        &[
            (header::HOST, host),
            (header::ORIGIN, &origin),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body,
    )
    .await
}

fn origin(host: &str) -> anyhow::Result<Url> {
    Ok(Url::parse(&format!("https://{host}"))?)
}

/// Opções + id da cerimónia de registo.
async fn reg_start(app: &Router, host: &str, cookie: &str) -> anyhow::Result<(String, Value)> {
    let r = mutate(app, Method::POST, host, REG_START, cookie, "").await?;
    anyhow::ensure!(r.status == StatusCode::OK, "register/start: {}", r.body);
    let v = r.json();
    let id = v["ceremony_id"].as_str().unwrap_or_default().to_owned();
    Ok((id, v["options"].clone()))
}

/// Registo completo com o autenticador `auth`: (resposta do finish, id da credencial).
async fn register(
    app: &Router,
    host: &str,
    cookie: &str,
    auth: &mut SoftPasskey,
    label: &str,
) -> anyhow::Result<(Reply, Vec<u8>)> {
    let (id, options) = reg_start(app, host, cookie).await?;
    let ccr: CreationChallengeResponse = serde_json::from_value(options)?;
    let cred = auth
        .do_registration(origin(host)?, ccr)
        .map_err(|e| anyhow::anyhow!("do_registration: {e:?}"))?;
    let raw = cred.raw_id.clone();
    let body = json!({"ceremony_id": id, "label": label, "credential": cred});
    let r = mutate(
        app,
        Method::POST,
        host,
        REG_FINISH,
        cookie,
        &body.to_string(),
    )
    .await?;
    Ok((r, raw))
}

async fn auth_start(app: &Router, host: &str) -> anyhow::Result<(String, Value)> {
    let r = anon_post(app, host, AUTH_START, "").await?;
    anyhow::ensure!(r.status == StatusCode::OK, "auth/start: {}", r.body);
    let v = r.json();
    let id = v["ceremony_id"].as_str().unwrap_or_default().to_owned();
    Ok((id, v["options"].clone()))
}

/// O "browser": escolhe a credencial `cred_id`, assina em `origin` e junta o `userHandle`.
fn sign(
    auth: &mut SoftPasskey,
    at: Url,
    mut options: Value,
    cred_id: &[u8],
    user: Uuid,
) -> anyhow::Result<Value> {
    options["publicKey"]["allowCredentials"] =
        json!([{"type": "public-key", "id": URL_SAFE_NO_PAD.encode(cred_id)}]);
    let rcr: RequestChallengeResponse = serde_json::from_value(options)?;
    let mut pkc = auth
        .do_authentication(at, rcr)
        .map_err(|e| anyhow::anyhow!("do_authentication: {e:?}"))?;
    pkc.response.user_handle = Some(user.as_bytes().to_vec());
    Ok(serde_json::to_value(&pkc)?)
}

async fn auth_finish(app: &Router, host: &str, id: &str, cred: &Value) -> anyhow::Result<Reply> {
    let body = json!({"ceremony_id": id, "credential": cred});
    anon_post(app, host, AUTH_FINISH, &body.to_string()).await
}

/// Login por passkey completo neste host (assina com a origin do próprio host).
async fn passkey_login(
    app: &Router,
    host: &str,
    auth: &mut SoftPasskey,
    cred_id: &[u8],
    user: Uuid,
) -> anyhow::Result<Reply> {
    let (id, options) = auth_start(app, host).await?;
    let cred = sign(auth, origin(host)?, options, cred_id, user)?;
    auth_finish(app, host, &id, &cred).await
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

async fn seed_store(app: &PgPool, t: &Tenant, slug: &str) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_tenant_tx(app, TenantId::for_tests(t.id), &ctx).await?;
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email)
         VALUES ($1, $2, $3, $3, $3, '500000000', 'PT50000000000000000000000', 'loja@test.invalid')",
        id,
        t.id,
        slug
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Conta de backoffice (com password e, se `totp`, TOTP ligado) e os papéis, pelo dono.
async fn seed_user(
    owner: &PgPool,
    email: &str,
    totp: bool,
    roles: &[(&str, Option<Uuid>, Option<Uuid>)],
) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let phc = password::hash(&Password::parse(PW)?).await?;
    let secret = totp.then_some("v1:teste:segredo-cifrado-de-teste");
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("ALTER TABLE user_roles NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "INSERT INTO users (id, email, password_hash, full_name, is_active, totp_secret_enc, totp_enabled)
         VALUES ($1, $2, $3, 'Pessoa de Teste', true, $4, $5)",
        id,
        email,
        phc,
        secret,
        totp
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

/// Conta só com passkey (password apagada), pelo dono.
async fn drop_password(owner: &PgPool, user: Uuid) -> TestResult {
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("UPDATE users SET password_hash = NULL WHERE id = $1", user)
        .execute(&mut *tx)
        .await?;
    sqlx::query!("ALTER TABLE users FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// (sign_count, last_used_at definido) da passkey, pelo dono; `set` grava o contador antes.
async fn counter(owner: &PgPool, id: Uuid, set: Option<i64>) -> anyhow::Result<(i64, bool)> {
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE user_passkeys NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    if let Some(n) = set {
        sqlx::query!(
            "UPDATE user_passkeys SET sign_count = $2 WHERE id = $1",
            id,
            n
        )
        .execute(&mut *tx)
        .await?;
    }
    let r = sqlx::query!(
        r#"SELECT sign_count, (last_used_at IS NOT NULL) AS "used!" FROM user_passkeys WHERE id = $1"#,
        id
    )
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query!("ALTER TABLE user_passkeys FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((r.sign_count, r.used))
}

/// Sessão de plataforma já elevada (o 2FA TOTP é do cartão 20; aqui só interessa a passkey).
async fn elevated_platform_session(app: &PgPool, user: Uuid) -> anyhow::Result<(String, Uuid)> {
    let ctx = AuditCtx::for_tests(ActorType::Admin, Some(user), None, None);
    let mut tx = begin_platform_tx(app, &ctx).await?;
    let (sid, value) = session::create(&mut tx, Subject::User(user), None, &ctx).await?;
    sqlx::query!(
        "UPDATE sessions SET mfa_verified_at = now() WHERE id = $1",
        sid.as_uuid()
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((
        format!("{COOKIE_PLATFORM}={}", value.expose()),
        sid.as_uuid(),
    ))
}

/// Envelhece a sessão `sid` em `by` (criação, expiração e 2FA), pelo dono.
async fn age_session(owner: &PgPool, sid: Uuid, by_secs: i32) -> TestResult {
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE sessions NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "UPDATE sessions
         SET created_at = created_at - make_interval(secs => $2),
             expires_at = expires_at - make_interval(secs => $2),
             mfa_verified_at = mfa_verified_at - make_interval(secs => $2)
         WHERE id = $1",
        sid,
        f64::from(by_secs)
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("ALTER TABLE sessions FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// `kind` dos `staff.security_notice` do outbox (lidos pelo dono).
async fn notices(owner: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE outbox_events NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    let kinds = sqlx::query_scalar!(
        r#"SELECT payload->>'kind' AS "kind!" FROM outbox_events
           WHERE event_type = 'staff.security_notice' ORDER BY id"#
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(kinds)
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

fn is(e: &Value, k: &str, v: &str) -> bool {
    e[k].as_str() == Some(v)
}

fn denied(evs: &[Value], action: &str, reason: &str) -> usize {
    evs.iter()
        .filter(|e| {
            is(e, "action", action) && is(e, "outcome", "denied") && is(e, "reason", reason)
        })
        .count()
}

// ---------------------------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------------------------

/// Lojista: registo sem sessão → 401; registo → lista → login por passkey (sessão elevada, evento
/// com o ator); challenge reutilizado, expirado, de outra cerimónia ou de outro host → 401 +
/// `denied`; origin de outro host → 401; passkey do host A no host B → 401; contador regressivo →
/// `cloned_authenticator`; anti-IDOR na lista e no DELETE; última credencial sem password → 409.
#[sqlx::test(migrations = "../migrations")]
async fn staff_passkey_lifecycle(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let ns = format!("t21a:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;
    let a = seed_tenant(&owner, "pk-a").await?;
    let b = seed_tenant(&owner, "pk-b").await?;
    let la = seed_store(&pool, &a, "loja-a").await?;
    let lb = seed_store(&pool, &b, "loja-b").await?;
    let u = seed_user(
        &owner,
        "u@x.pt",
        false,
        &[
            ("merchant_staff", Some(a.id), Some(la)),
            ("merchant_staff", Some(b.id), Some(lb)),
        ],
    )
    .await?;
    let v = seed_user(
        &owner,
        "v@x.pt",
        false,
        &[("merchant_staff", Some(a.id), Some(la))],
    )
    .await?;
    let (ha, hb) = (a.domain.as_str(), b.domain.as_str());

    // Registo sem sessão → 401.
    let r = anon_post(&app, ha, REG_START, "").await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);

    // Registo: opções (UV obrigatória, resident key preferida, nada a excluir) e finish → 201.
    let cu = password_login(&app, ha, "u@x.pt").await?;
    let (_, opts1) = reg_start(&app, ha, &cu).await?;
    let pk = &opts1["publicKey"];
    assert_eq!(pk["rp"]["id"], json!(ha));
    assert_eq!(
        pk["authenticatorSelection"]["userVerification"],
        json!("required")
    );
    assert_eq!(
        pk["authenticatorSelection"]["residentKey"],
        json!("preferred")
    );
    assert!(
        pk["excludeCredentials"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    let mut auth_u = SoftPasskey::new(true);
    let (r, cred_u) = register(&app, ha, &cu, &mut auth_u, "  Portátil  ").await?;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.json()["label"], json!("Portátil"));
    let id_u: Uuid = serde_json::from_value(r.json()["id"].clone())?;
    // Etiqueta inválida → 422 (a cerimónia não é consumida por isso).
    let bad = json!({"ceremony_id": "x", "label": "", "credential": {}});
    let r = mutate(&app, Method::POST, ha, REG_FINISH, &cu, &bad.to_string()).await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    // Uma segunda cerimónia já exclui a credencial registada.
    let (reg_id, opts2) = reg_start(&app, ha, &cu).await?;
    let excl = opts2["publicKey"]["excludeCredentials"].as_array().cloned();
    assert_eq!(excl.map(|x| x.len()), Some(1));

    let r = get(&app, ha, LIST, &cu).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let list = r.json();
    assert_eq!(list.as_array().map(Vec::len), Some(1));
    assert_eq!(list[0]["id"], json!(id_u));
    assert_eq!(list[0]["last_used_at"], Value::Null);
    assert!(list[0].get("credential").is_none());

    // Login por passkey no host A: opções sem lista de credenciais; 204 + sessão elevada.
    let (aid, aopts) = auth_start(&app, ha).await?;
    assert!(
        aopts["publicKey"]["allowCredentials"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    assert_eq!(aopts["publicKey"]["userVerification"], json!("required"));
    let signed = sign(&mut auth_u, origin(ha)?, aopts, &cred_u, u)?;
    let r = auth_finish(&app, ha, &aid, &signed).await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let ca = r.cookie()?;
    let me = get(&app, ha, ME, &ca).await?;
    assert_eq!(me.status, StatusCode::OK, "{}", me.body);
    assert_eq!(me.json()["id"], json!(u));
    assert_eq!(me.json()["mfa_verified"], json!(true));
    let (n, used) = counter(&owner, id_u, None).await?;
    assert!(n >= 1 && used, "contador {n}, usado {used}");
    let evs = tenant_events(&pool, &a).await?;
    let ok = evs.iter().filter(|e| {
        is(e, "action", "auth.passkey_login")
            && is(e, "outcome", "success")
            && e["actor_id"].as_str() == Some(u.to_string().as_str())
    });
    assert_eq!(ok.count(), 1);

    // Challenge reutilizado → 401 + denied.
    let r = auth_finish(&app, ha, &aid, &signed).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert!(r.set_cookie.is_none());
    // Cerimónia de outro tipo (registo) → 401.
    let r = auth_finish(&app, ha, &reg_id, &signed).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    // Expirada (TTL do Redis cumprido = chave desaparecida) → 401.
    let (eid, eopts) = auth_start(&app, ha).await?;
    let esigned = sign(&mut auth_u, origin(ha)?, eopts, &cred_u, u)?;
    redis_del(redis_keys(&format!("{ns}webauthn:auth:{eid}")).await?).await?;
    let r = auth_finish(&app, ha, &eid, &esigned).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    // Cerimónia iniciada no host A e concluída no host B → 401.
    let (xid, xopts) = auth_start(&app, ha).await?;
    let xsigned = sign(&mut auth_u, origin(ha)?, xopts, &cred_u, u)?;
    let r = auth_finish(&app, hb, &xid, &xsigned).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    let evs = tenant_events(&pool, &a).await?;
    assert_eq!(
        denied(&evs, "auth.passkey_login", "ceremony"),
        3,
        "{evs:#?}"
    );
    let evs_b = tenant_events(&pool, &b).await?;
    assert_eq!(denied(&evs_b, "auth.passkey_login", "ceremony"), 1);

    // `origin` de outro host no clientDataJSON → 401 (verificação).
    let (oid, oopts) = auth_start(&app, ha).await?;
    let evil = Url::parse(&format!("https://evil.{ha}"))?;
    let osigned = sign(&mut auth_u, evil, oopts, &cred_u, u)?;
    let r = auth_finish(&app, ha, &oid, &osigned).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    // `userHandle` de outro utilizador → 401 (verificação).
    let (hid, hopts) = auth_start(&app, ha).await?;
    let hsigned = sign(&mut auth_u, origin(ha)?, hopts, &cred_u, v)?;
    let r = auth_finish(&app, ha, &hid, &hsigned).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    let evs = tenant_events(&pool, &a).await?;
    assert_eq!(denied(&evs, "auth.passkey_login", "verification"), 2);

    // Passkey registada no host A não entra no host B (o utilizador tem papel nos dois).
    let r = passkey_login(&app, hb, &mut auth_u, &cred_u, u).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    let evs_b = tenant_events(&pool, &b).await?;
    assert_eq!(denied(&evs_b, "auth.passkey_login", "rp_mismatch"), 1);

    // Contador regressivo (ambos > 0) → recusa `cloned_authenticator`, sem sessão nem contador novo.
    counter(&owner, id_u, Some(1_000)).await?;
    let r = passkey_login(&app, ha, &mut auth_u, &cred_u, u).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert!(r.set_cookie.is_none());
    assert_eq!(counter(&owner, id_u, None).await?.0, 1_000);
    let evs = tenant_events(&pool, &a).await?;
    assert_eq!(
        denied(&evs, "auth.passkey_login", "cloned_authenticator"),
        1
    );
    counter(&owner, id_u, Some(0)).await?;

    // Anti-IDOR: V não vê nem apaga a passkey de U.
    let cv = password_login(&app, ha, "v@x.pt").await?;
    let r = get(&app, ha, LIST, &cv).await?;
    assert_eq!(r.json(), json!([]));
    let del_u = format!("{LIST}/{id_u}");
    let r = mutate(&app, Method::DELETE, ha, &del_u, &cv, "").await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    let evs = tenant_events(&pool, &a).await?;
    let idor = evs.iter().filter(|e| {
        is(e, "outcome", "denied")
            && is(e, "reason", "idor")
            && e["actor_id"].as_str() == Some(v.to_string().as_str())
    });
    assert_eq!(idor.count(), 1);
    assert_eq!(
        get(&app, ha, LIST, &cu)
            .await?
            .json()
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    // Última credencial de uma conta sem password → 409; com password → 204 + evento.
    let mut auth_v = SoftPasskey::new(true);
    let (r, _) = register(&app, ha, &cv, &mut auth_v, "Chave").await?;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let id_v = r.json()["id"].as_str().unwrap_or_default().to_owned();
    drop_password(&owner, v).await?;
    let r = mutate(&app, Method::DELETE, ha, &format!("{LIST}/{id_v}"), &cv, "").await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    let r = mutate(&app, Method::DELETE, ha, &del_u, &cu, "").await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    assert_eq!(get(&app, ha, LIST, &cu).await?.json(), json!([]));
    let evs = tenant_events(&pool, &a).await?;
    let n = |act: &str| {
        evs.iter()
            .filter(|e| is(e, "action", act) && is(e, "outcome", "success"))
            .count()
    };
    assert_eq!((n("passkey.registered"), n("passkey.removed")), (2, 1));
    let kinds = notices(&owner).await?;
    assert_eq!(kinds.len(), 4, "{kinds:?}");
    assert_eq!(kinds.last().map(String::as_str), Some("passkey_removed"));

    // Os eventos nunca levam a credencial (nem o id em base64url, nem a chave pública).
    let all = serde_json::to_string(&evs)?;
    assert!(!all.contains(&URL_SAFE_NO_PAD.encode(&cred_u)));
    assert!(!all.contains("challenge") && !all.contains("\"cred\""));
    cleanup(&ns).await
}

/// `super_admin` que entra por passkey na plataforma: sessão elevada, mas `RequireSuperAdmin` só
/// passa com TOTP ativo (regra do cartão 20).
#[sqlx::test(migrations = "../migrations")]
async fn superadmin_passkey_needs_totp(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let ns = format!("t21b:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;
    let with_totp = seed_user(&owner, "s1@x.pt", true, &[("super_admin", None, None)]).await?;
    let no_totp = seed_user(&owner, "s2@x.pt", false, &[("super_admin", None, None)]).await?;
    for (user, whoami) in [
        (with_totp, StatusCode::OK),
        (no_totp, StatusCode::NOT_FOUND),
    ] {
        // Sessão com login/2FA há 11 min → 403 `reauth_required` (janela de 10 min).
        let (old, old_sid) = elevated_platform_session(&pool, user).await?;
        age_session(&owner, old_sid, 11 * 60).await?;
        let r = mutate(&app, Method::POST, PLATFORM, REG_START, &old, "").await?;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
        let (c, _) = elevated_platform_session(&pool, user).await?;
        let mut auth = SoftPasskey::new(true);
        let (r, cred) = register(&app, PLATFORM, &c, &mut auth, "Admin").await?;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        let r = passkey_login(&app, PLATFORM, &mut auth, &cred, user).await?;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
        let cookie = r.cookie()?;
        assert!(cookie.starts_with(COOKIE_PLATFORM));
        let me = get(&app, PLATFORM, ME, &cookie).await?;
        assert_eq!(me.json()["mfa_verified"], json!(true), "{}", me.body);
        let w = get(&app, PLATFORM, WHOAMI, &cookie).await?;
        assert_eq!(w.status, whoami, "{}", w.body);
    }
    cleanup(&ns).await
}
