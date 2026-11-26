//! Login de staff e extractores de RBAC (cartão 02/19), contra Postgres e Redis reais, pela API
//! real (`http::api`) com sessões, captcha falso e as rotas de prova `/api/v1/_test/*`
//! (feature `test-support`).
//!
//! Contas e papéis nascem pelo dono (a app não escreve `users`/`user_roles`): `NO FORCE ROW LEVEL
//! SECURITY` só dentro da transação do seed. Leituras de `audit.*` sem `query!` (schema selado).

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
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    http::{api, audit_layer::AuditLayerState, client_ip::TrustedProxies},
    identity::{
        AccountKey, BreachChecker, CaptchaVerifier, Login, Password, Registration, Sessions,
        password,
        session::{COOKIE_PLATFORM, COOKIE_TENANT},
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
use uuid::Uuid;

type TestResult = anyhow::Result<()>;
/// action, outcome, reason, actor_type, actor_id.
type EvRow = (String, String, Option<String>, String, Option<Uuid>);

const CSRF_KEY: &str = "chave-csrf-de-teste-com-mais-de-32-bytes";
const INTERNAL_TOKEN: &str = "token-interno-de-teste-com-mais-de-32-bytes";
const ACCOUNT_KEY: &str = "chave-de-conta-de-teste-com-mais-de-32-bytes";
const PLATFORM: &str = "admin.ptmarket.invalid";
const STAFF_LOGIN: &str = "/api/v1/staff/auth/login";
const STAFF_ME: &str = "/api/v1/staff/me";
const PW: &str = "uma-frase-longa-e-boa";
const CAPTCHA_OK: &str = "captcha-ok";

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
    let key = || AccountKey::new(ACCOUNT_KEY.to_owned().into());
    let registration = Registration::new(Arc::new(FakeCaptcha), Arc::new(NoBreach), key())
        .with_min_response_for_tests(Duration::ZERO);
    let sessions =
        Sessions::for_tests(pool.clone(), redis()?, CSRF_KEY.to_owned().into(), ns, None)
            .with_internal_token(Some(INTERNAL_TOKEN.to_owned().into()))
            .with_registration(registration)
            .with_login(Login::new(Arc::new(FakeCaptcha), key()));
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
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_default()
    }

    /// `nome=token` do `Set-Cookie`.
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
        IpAddr::from([203, 0, 113, 7]),
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

async fn staff_login(app: &Router, host: &str, email: &str, pw: &str) -> anyhow::Result<Reply> {
    let origin = format!("https://{host}");
    let body = json!({"email": email, "password": pw});
    send(
        app,
        Method::POST,
        STAFF_LOGIN,
        &[
            (header::HOST, host),
            (header::CONTENT_TYPE, "application/json"),
            (header::ORIGIN, &origin),
        ],
        &body.to_string(),
    )
    .await
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

// ---------------------------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------------------------

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

async fn seed_store(app: &PgPool, t: &Tenant, slug: &str) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &ctx).await?;
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

/// Conta de backoffice com os papéis `(role, tenant, store)`, criada pelo dono.
async fn seed_user(
    owner: &PgPool,
    email: &str,
    active: bool,
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
         VALUES ($1, $2, $3, 'Pessoa de Teste', $4)",
        id,
        email,
        phc,
        active
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

/// id da conta pelo email (lookup do login).
async fn owner_id(app: &PgPool, _t: &Tenant, email: &str) -> anyhow::Result<Uuid> {
    let row: Option<(Uuid,)> =
        sqlx::query_as("SELECT u.id::uuid FROM public.identity_user_credentials($1::text) AS u")
            .bind(email)
            .fetch_optional(app)
            .await?;
    row.map(|r| r.0).ok_or_else(|| anyhow::anyhow!("sem conta"))
}

/// Marca o 2FA nas sessões ativas do utilizador (como o cartão 20 fará), com o próprio como ator.
async fn elevate(app: &PgPool, t: &Tenant, user: Uuid) -> TestResult {
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(user), None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &ctx).await?;
    let r = sqlx::query!(
        "UPDATE sessions SET mfa_verified_at = now()
         WHERE subject_type = 'user' AND subject_id = $1 AND revoked_at IS NULL",
        user
    )
    .execute(&mut *tx)
    .await?;
    anyhow::ensure!(r.rows_affected() >= 1, "nenhuma sessão elevada");
    tx.commit().await?;
    Ok(())
}

/// Liga o TOTP da conta (pelo dono; a app não o liga sem o cartão 20).
async fn enable_totp(owner: &PgPool, user: Uuid) -> TestResult {
    let mut tx = owner.begin().await?;
    sqlx::query!("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "UPDATE users SET totp_secret_enc = 'segredo-cifrado', totp_enabled = true WHERE id = $1",
        user
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("ALTER TABLE users FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Eventos da caixa negra do tenant `t`.
async fn events(app: &PgPool, t: &Tenant) -> anyhow::Result<Vec<EvRow>> {
    let reader = AuditCtx::for_tests(ActorType::System, None, None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &reader).await?;
    let rows: Vec<EvRow> = sqlx::query_as(
        "SELECT action::text, outcome::text, reason::text, actor_type::text, actor_id::uuid
         FROM audit.audit_events ORDER BY chain_seq",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(rows)
}

fn count(evs: &[EvRow], f: impl Fn(&EvRow) -> bool) -> usize {
    evs.iter().filter(|e| f(e)).count()
}

// ---------------------------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------------------------

/// Merchant: L1 sim; L2 (mesmo tenant) e L3 (outro tenant) → 404 + `idor` com o ator;
/// `merchant_staff` no `RequireStoreOwner` → 403; `/staff/me`; `last_login_at` → `users.update`;
/// host sem papel → o 401 de uma password errada.
#[sqlx::test(migrations = "../migrations")]
async fn merchant_scope_idor_owner_and_me(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let b = seed_tenant(&owner, "camara-b").await?;
    let l1 = seed_store(&pool, &a, "loja-1").await?;
    let l2 = seed_store(&pool, &a, "loja-2").await?;
    let l3 = seed_store(&pool, &b, "loja-3").await?;
    let staff = seed_user(
        &owner,
        "staff@x.pt",
        true,
        &[("merchant_staff", Some(a.id), Some(l1))],
    )
    .await?;
    seed_user(
        &owner,
        "dona@x.pt",
        true,
        &[("merchant_owner", Some(a.id), Some(l1))],
    )
    .await?;
    let ns = format!("test:rbac:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;

    let r = staff_login(&app, &a.domain, "Staff@X.pt", PW).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json(), json!({"mfa_required": false}));
    let cookie = r.cookie()?;
    assert!(cookie.starts_with(&format!("{COOKIE_TENANT}=")), "{cookie}");

    assert_eq!(
        get(
            &app,
            &a.domain,
            &format!("/api/v1/_test/stores/{l1}"),
            &cookie
        )
        .await?
        .status,
        StatusCode::OK
    );
    assert_eq!(
        get(
            &app,
            &a.domain,
            &format!("/api/v1/_test/stores/{l2}"),
            &cookie
        )
        .await?
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(
            &app,
            &a.domain,
            &format!("/api/v1/_test/stores/{l3}"),
            &cookie
        )
        .await?
        .status,
        StatusCode::NOT_FOUND
    );
    let owner_only = get(
        &app,
        &a.domain,
        &format!("/api/v1/_test/stores/{l1}/owner"),
        &cookie,
    )
    .await?;
    assert_eq!(owner_only.status, StatusCode::FORBIDDEN);

    // RequireStoreOwner exige SEMPRE 2FA (dinheiro/IBAN); `{store_id}` que não é UUID → 404 idor.
    let dona_id = owner_id(&pool, &a, "dona@x.pt").await?;
    let dona = staff_login(&app, &a.domain, "dona@x.pt", PW)
        .await?
        .cookie()?;
    let owner_uri = format!("/api/v1/_test/stores/{l1}/owner");
    assert_eq!(
        get(&app, &a.domain, &owner_uri, &dona).await?.status,
        StatusCode::FORBIDDEN
    );
    elevate(&pool, &a, dona_id).await?;
    assert_eq!(
        get(&app, &a.domain, &owner_uri, &dona).await?.status,
        StatusCode::OK
    );
    let bad = get(&app, &a.domain, "/api/v1/_test/stores/nao-e-uuid", &dona).await?;
    assert_eq!(bad.status, StatusCode::NOT_FOUND);
    let evs = events(&pool, &a).await?;
    let d = |e: &EvRow| e.4 == Some(dona_id) && e.1 == "denied";
    assert_eq!(
        count(&evs, |e| d(e) && e.2.as_deref() == Some("mfa_required")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| d(e) && e.2.as_deref() == Some("idor")),
        1,
        "{evs:?}"
    );

    // /staff/me: síncrono, sem hashes nem segredos.
    let me = get(&app, &a.domain, STAFF_ME, &cookie).await?;
    assert_eq!(me.status, StatusCode::OK, "{}", me.body);
    assert_eq!(
        me.json(),
        json!({
            "id": staff,
            "full_name": "Pessoa de Teste",
            "roles": [{"role": "merchant_staff", "tenant_id": a.id, "store_id": l1}],
            "mfa_verified": false
        })
    );
    assert!(!me.body.contains("argon2") && !me.body.contains("hash") && !me.body.contains("totp"));

    let evs = events(&pool, &a).await?;
    let mine = |e: &EvRow| e.4 == Some(staff) && e.3 == "merchant";
    assert_eq!(
        count(&evs, |e| mine(e)
            && e.1 == "denied"
            && e.2.as_deref() == Some("idor")),
        2,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e) && e.2.as_deref() == Some("rbac")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e) && e.0 == "users.update"),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e)
            && e.0 == "auth.staff_login"
            && e.1 == "success"),
        1,
        "{evs:?}"
    );
    // GET /staff/me é ReadSync: já está na caixa negra quando a resposta sai.
    assert!(
        count(&evs, |e| mine(e) && e.1 == "success" && e.0 == "http.get") >= 1,
        "{evs:?}"
    );

    // Host onde não tem papel: o mesmo 401 de uma password errada + `no_role_here`.
    let no_role = staff_login(&app, &b.domain, "staff@x.pt", PW).await?;
    let wrong = staff_login(&app, &b.domain, "staff@x.pt", "outra-frase-qualquer").await?;
    assert_eq!(no_role.status, StatusCode::UNAUTHORIZED);
    assert_eq!((no_role.status, &no_role.body), (wrong.status, &wrong.body));
    assert!(no_role.set_cookie.is_none());
    let evs = events(&pool, &b).await?;
    assert_eq!(
        count(&evs, |e| e.0 == "auth.staff_login"
            && e.2.as_deref() == Some("no_role_here")),
        1,
        "{evs:?}"
    );
    cleanup(&ns).await
}

/// `tenant_admin` sem 2FA → 403 `mfa_required`; `super_admin` num host de tenant não é Admin e na
/// plataforma recebe `__Host-ptm_admin` Strict; inativo não entra; cliente em rota de staff → 401;
/// sem `Origin` → 403; 2FA exigido no ramo Merchant (TOTP; tenant_admin dono de loja).
#[sqlx::test(migrations = "../migrations")]
async fn tenant_admin_super_admin_inactive_and_customer(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let l1 = seed_store(&pool, &a, "loja-1").await?;
    let admin = seed_user(
        &owner,
        "camara@x.pt",
        true,
        &[("tenant_admin", Some(a.id), None)],
    )
    .await?;
    let totp = seed_user(
        &owner,
        "totp@x.pt",
        true,
        &[("merchant_staff", Some(a.id), Some(l1))],
    )
    .await?;
    enable_totp(&owner, totp).await?;
    seed_user(
        &owner,
        "misto@x.pt",
        true,
        &[
            ("tenant_admin", Some(a.id), None),
            ("merchant_owner", Some(a.id), Some(l1)),
        ],
    )
    .await?;
    let sup = seed_user(
        &owner,
        "super@x.pt",
        true,
        &[
            ("super_admin", None, None),
            ("merchant_owner", Some(a.id), Some(l1)),
        ],
    )
    .await?;
    seed_user(
        &owner,
        "inativo@x.pt",
        false,
        &[("merchant_staff", Some(a.id), Some(l1))],
    )
    .await?;
    let ns = format!("test:rbac:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;

    // tenant_admin: entra, mas sem 2FA não passa no RequireTenantAdmin.
    let r = staff_login(&app, &a.domain, "camara@x.pt", PW).await?;
    assert_eq!(r.json(), json!({"mfa_required": true}), "{}", r.body);
    let c = r.cookie()?;
    let r = get(&app, &a.domain, "/api/v1/_test/tenant-admin", &c).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // 2FA obrigatório no servidor também no ramo Merchant: lojista com TOTP e tenant_admin que é
    // dono de uma loja, ambos sem 2FA → 403.
    let store_uri = format!("/api/v1/_test/stores/{l1}");
    for email in ["totp@x.pt", "misto@x.pt"] {
        let r = staff_login(&app, &a.domain, email, PW).await?;
        assert_eq!(
            r.json(),
            json!({"mfa_required": true}),
            "{email}: {}",
            r.body
        );
        let g = get(&app, &a.domain, &store_uri, &r.cookie()?).await?;
        assert_eq!(g.status, StatusCode::FORBIDDEN, "{email}");
    }

    // super_admin no host do tenant: ator Merchant (papel de loja), nunca Admin.
    let r = staff_login(&app, &a.domain, "super@x.pt", PW).await?;
    assert_eq!(r.json(), json!({"mfa_required": true}), "{}", r.body);
    let evs = events(&pool, &a).await?;
    assert_eq!(
        count(&evs, |e| e.4 == Some(admin)
            && e.3 == "municipal"
            && e.2.as_deref() == Some("mfa_required")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| e.4 == Some(sup)
            && e.0 == "auth.staff_login"
            && e.3 == "merchant"),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| e.4 == Some(sup) && e.3 == "admin"),
        0,
        "{evs:?}"
    );

    // Plataforma: cookie próprio, SameSite=Strict; /staff/me só com o papel global.
    let r = staff_login(&app, PLATFORM, "super@x.pt", PW).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let sc = r.set_cookie.clone().unwrap_or_default();
    assert!(
        sc.starts_with(&format!("{COOKIE_PLATFORM}=")) && sc.contains("SameSite=Strict"),
        "{sc}"
    );
    let me = get(&app, PLATFORM, STAFF_ME, &r.cookie()?).await?;
    assert_eq!(
        me.json()["roles"],
        json!([{"role": "super_admin", "tenant_id": null, "store_id": null}]),
        "{}",
        me.body
    );
    // Na plataforma só entra super_admin.
    assert_eq!(
        staff_login(&app, PLATFORM, "camara@x.pt", PW).await?.status,
        StatusCode::UNAUTHORIZED
    );

    // Inativo: o 401 genérico.
    let r = staff_login(&app, &a.domain, "inativo@x.pt", PW).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.set_cookie.is_none());

    // Cliente: sessão `customer` numa rota de staff → 401.
    let origin = format!("https://{}", a.domain);
    let hdrs = [
        (header::HOST, a.domain.as_str()),
        (header::CONTENT_TYPE, "application/json"),
        (header::ORIGIN, origin.as_str()),
    ];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let reg = json!({
        "email": "cliente@x.pt", "password": PW, "name": "Cliente",
        "consents": {"terms_version": "2026-11", "privacy_version": "2026-11"},
        "turnstile_token": CAPTCHA_OK, "website": "", "form_started_at": now_ms - 5_000,
    });
    let r = send(
        &app,
        Method::POST,
        "/api/v1/auth/register",
        &hdrs,
        &reg.to_string(),
    )
    .await?;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
    let login = json!({"email": "cliente@x.pt", "password": PW});
    let r = send(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        &hdrs,
        &login.to_string(),
    )
    .await?;
    let customer = r.cookie()?;
    assert_eq!(
        get(&app, &a.domain, STAFF_ME, &customer).await?.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(
            &app,
            &a.domain,
            &format!("/api/v1/_test/stores/{l1}"),
            &customer
        )
        .await?
        .status,
        StatusCode::UNAUTHORIZED
    );

    // Login de staff sem Origin → 403.
    let r = send(
        &app,
        Method::POST,
        STAFF_LOGIN,
        &[
            (header::HOST, a.domain.as_str()),
            (header::CONTENT_TYPE, "application/json"),
        ],
        &json!({"email": "camara@x.pt", "password": PW}).to_string(),
    )
    .await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    cleanup(&ns).await
}
