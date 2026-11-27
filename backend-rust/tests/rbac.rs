//! Login de staff e extractores de RBAC (cartões 02/19 e 03/13: painel único), contra Postgres e
//! Redis reais, pela API real (`http::api`) com sessões, captcha falso e as rotas de prova
//! `/api/v1/_test/*` (feature `test-support`).
//!
//! Contas e papéis nascem pelo dono (a app não escreve `users`/`user_roles`): `NO FORCE ROW LEVEL
//! SECURITY` só dentro da transação do seed. As lojas nascem num tenant `national_portal` (um por país,
//! 0035), pela app com o âmbito da própria loja (`begin_store_tx`). Os
//! eventos da plataforma (`tenant_id` NULL) leem-se pela porta do super_admin (`common`).

mod common;

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
    identity::rbac::StoreScope,
    identity::{
        AccountKey, BreachChecker, CaptchaVerifier, Login, Password, Registration, Sessions,
        password,
        session::{COOKIE_PLATFORM, COOKIE_TENANT},
    },
    state::AppState,
    storage::NullStorage,
    tenancy::{
        HostResolver, TenantId, begin_tenant_tx,
        db::{begin_platform_tx, begin_store_tx},
    },
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

async fn owner_pool(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(1)
        .connect_with(conn.clone())
        .await
}

use common::{PlatformReader, app_login_pool, count, is};

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

/// Tenant `national_portal` (onde nascem as lojas) ou `municipal` (só um Host de canal), em PT.
async fn seed_tenant(owner: &PgPool, slug: &str, tenant_type: &str) -> sqlx::Result<Tenant> {
    seed_tenant_in(owner, slug, tenant_type, "PT").await
}

/// Como `seed_tenant`, no país `country` (um só `national_portal` por país, 0035).
async fn seed_tenant_in(
    owner: &PgPool,
    slug: &str,
    tenant_type: &str,
    country: &str,
) -> sqlx::Result<Tenant> {
    let id = Uuid::now_v7();
    let domain = format!("{slug}.ptmarket.invalid");
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, country_code, tenant_type)
         VALUES ($1, $2, $3, $4, $5, $6)",
        id,
        slug,
        domain,
        format!("Canal {slug}"),
        country,
        tenant_type
    )
    .execute(owner)
    .await?;
    Ok(Tenant { id, domain })
}

/// Loja pela app, com o âmbito da própria loja (`app.store_id` = o id novo, gerado em Rust: 0035).
async fn seed_store(app: &PgPool, t: &Tenant, slug: &str) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_store_tx(app, &StoreScope::for_tests(t.tid(), id), &ctx).await?;
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

/// Entidade patrocinadora (associação: sem área própria), pelo dono.
async fn seed_entity(owner: &PgPool, slug: &str) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO sponsor_entities (id, kind, name, slug) VALUES ($1, 'association', $2, $2)",
        id,
        slug
    )
    .execute(owner)
    .await?;
    Ok(id)
}

/// Câmara (`municipality`, concelho `9301`) ou Junta (`parish`, freguesia `930101`) de PT, pelo
/// dono. As áreas DICOFRE de teste nascem antes (`seed_test_areas`).
async fn seed_area_entity(
    owner: &PgPool,
    kind: &str,
    slug: &str,
    area: &str,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code)
         VALUES ($1, $2, 'PT', $3, $3, $4)",
        id,
        kind,
        slug,
        area
    )
    .execute(owner)
    .await?;
    Ok(id)
}

/// Distrito `93`, concelho `9301` e freguesia `930101` de teste (DICOFRE), pelo dono.
async fn seed_test_areas(owner: &PgPool) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
            ('93', 'district', NULL, 'Distrito Teste', 'T'),
            ('9301', 'municipality', '93', 'Concelho A', 'T'),
            ('930101', 'parish', '9301', 'Freguesia B', 'T')"
    )
    .execute(owner)
    .await?;
    Ok(())
}

/// Papel: (role, tenant, loja, entidade).
type Grant<'a> = (&'a str, Option<Uuid>, Option<Uuid>, Option<Uuid>);

fn merchant<'a>(role: &'a str, t: &Tenant, store: Uuid) -> Grant<'a> {
    (role, Some(t.id), Some(store), None)
}

/// Conta de backoffice com os papéis, criada pelo dono.
async fn seed_user(
    owner: &PgPool,
    email: &str,
    active: bool,
    roles: &[Grant<'_>],
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
    for (role, tenant, store, entity) in roles {
        sqlx::query!(
            "INSERT INTO user_roles (id, user_id, role, tenant_id, store_id, sponsor_entity_id)
             VALUES ($1, $2, $3, $4, $5, $6)",
            Uuid::now_v7(),
            id,
            *role,
            *tenant,
            *store,
            *entity
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

/// Marca o 2FA nas sessões ativas do utilizador (sessões de plataforma), com o próprio como ator.
async fn elevate(app: &PgPool, user: Uuid) -> TestResult {
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(user), None, None);
    let mut tx = begin_platform_tx(app, &ctx).await?;
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

/// Eventos do tenant `t` (recusas num Host de canal), como JSON.
async fn tenant_events(app: &PgPool, t: &Tenant) -> anyhow::Result<Vec<Value>> {
    // 0038: a auditoria é fail-closed por loja; ler como admin sem impersonação.
    let reader = AuditCtx::for_tests(ActorType::Admin, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &reader).await?;
    let rows: Vec<(Value,)> =
        sqlx::query_as("SELECT to_jsonb(e) FROM audit.audit_events e ORDER BY chain_seq")
            .fetch_all(&mut *tx)
            .await?;
    tx.rollback().await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Login com a password certa e com uma errada no mesmo host: (certa, errada). Router próprio
/// (travão do Redis limpo), para as falhas por IP de outras contas não pedirem já captcha.
async fn right_and_wrong(pool: &PgPool, host: &str, email: &str) -> anyhow::Result<(Reply, Reply)> {
    let ns = format!("test:rbac:{}:", Uuid::now_v7());
    let app = router(pool, &ns)?;
    let right = staff_login(&app, host, email, PW).await?;
    let wrong = staff_login(&app, host, email, "outra-frase-qualquer").await?;
    cleanup(&ns).await?;
    Ok((right, wrong))
}

/// A recusa com a password certa é igual à da password errada (401, mesmo corpo, sem cookie).
fn same_as_wrong_password(right: &Reply, wrong: &Reply, who: &str) {
    assert_eq!(
        right.status,
        StatusCode::UNAUTHORIZED,
        "{who}: {}",
        right.body
    );
    assert_eq!(
        (right.status, &right.body),
        (wrong.status, &wrong.body),
        "{who}"
    );
    assert!(right.set_cookie.is_none(), "{who}");
}

fn uid(e: &Value) -> Option<Uuid> {
    e["actor_id"].as_str().and_then(|s| Uuid::parse_str(s).ok())
}

// ---------------------------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------------------------

/// Merchant no host de plataforma: L1 sim (tenant do papel); L2 do MESMO tenant nacional e um UUID
/// inexistente → 404 + `idor`; `merchant_staff` no `RequireStoreOwner` → 403; dono sem 2FA → 403;
/// `/staff/me` com o âmbito; `last_login_at` → `users.update`; whoami → 404 + `superadmin_gate`;
/// Host de canal: login = o 401 da password errada + `no_role_here`, cookie de staff → 401.
#[sqlx::test(migrations = "../migrations")]
async fn merchant_scope_idor_owner_and_me(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_login_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let reader = PlatformReader::new(&owner, &pool).await?;
    let n = seed_tenant(&owner, "nacional", "national_portal").await?;
    let c = seed_tenant(&owner, "camara-a", "municipal").await?;
    let l1 = seed_store(&pool, &n, "loja-1").await?;
    let l2 = seed_store(&pool, &n, "loja-2").await?;
    let staff = seed_user(
        &owner,
        "staff@x.pt",
        true,
        &[merchant("merchant_staff", &n, l1)],
    )
    .await?;
    let dona_id = seed_user(
        &owner,
        "dona@x.pt",
        true,
        &[merchant("merchant_owner", &n, l1)],
    )
    .await?;
    let ns = format!("test:rbac:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;

    let r = staff_login(&app, PLATFORM, "Staff@X.pt", PW).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json(), json!({"mfa_required": false}));
    let sc = r.set_cookie.clone().unwrap_or_default();
    assert!(
        sc.starts_with(&format!("{COOKIE_PLATFORM}=")) && sc.contains("SameSite=Strict"),
        "{sc}"
    );
    let cookie = r.cookie()?;

    let store = |l: Uuid| format!("/api/v1/_test/stores/{l}");
    let r = get(&app, PLATFORM, &store(l1), &cookie).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json()["tenant_id"], json!(n.id), "tenant do papel");
    for other in [l2, Uuid::now_v7()] {
        let r = get(&app, PLATFORM, &store(other), &cookie).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    }
    let owner_only = get(&app, PLATFORM, &format!("{}/owner", store(l1)), &cookie).await?;
    assert_eq!(owner_only.status, StatusCode::FORBIDDEN);

    // RequireStoreOwner exige SEMPRE 2FA (dinheiro/IBAN); `{store_id}` que não é UUID → 404 idor.
    let dona = staff_login(&app, PLATFORM, "dona@x.pt", PW)
        .await?
        .cookie()?;
    let owner_uri = format!("{}/owner", store(l1));
    assert_eq!(
        get(&app, PLATFORM, &owner_uri, &dona).await?.status,
        StatusCode::FORBIDDEN
    );
    elevate(&pool, dona_id).await?;
    let r = get(&app, PLATFORM, &owner_uri, &dona).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json()["tenant_id"], json!(n.id));
    let bad = get(&app, PLATFORM, "/api/v1/_test/stores/nao-e-uuid", &dona).await?;
    assert_eq!(bad.status, StatusCode::NOT_FOUND);
    let evs = reader.events(&pool, Some(dona_id)).await?;
    let d = |e: &Value| is(e, "outcome", "denied");
    assert_eq!(
        count(&evs, |e| d(e) && is(e, "reason", "mfa_required")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| d(e) && is(e, "reason", "idor")),
        1,
        "{evs:?}"
    );

    // /staff/me: síncrono, sem hashes nem segredos, com o âmbito do papel.
    let me = get(&app, PLATFORM, STAFF_ME, &cookie).await?;
    assert_eq!(me.status, StatusCode::OK, "{}", me.body);
    assert_eq!(
        me.json(),
        json!({
            "id": staff,
            "full_name": "Pessoa de Teste",
            "roles": [{"role": "merchant_staff", "tenant_id": n.id, "store_id": l1,
                       "sponsor_entity_id": null}],
            "mfa_verified": false
        })
    );
    assert!(!me.body.contains("argon2") && !me.body.contains("hash") && !me.body.contains("totp"));

    // Merchant na consola → 404 + `superadmin_gate`.
    let w = get(&app, PLATFORM, "/api/v1/superadmin/whoami", &cookie).await?;
    assert_eq!(w.status, StatusCode::NOT_FOUND);

    let evs = reader.events(&pool, Some(staff)).await?;
    let mine = |e: &Value| uid(e) == Some(staff) && is(e, "actor_type", "merchant");
    assert_eq!(
        count(&evs, |e| mine(e) && d(e) && is(e, "reason", "idor")),
        2,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e) && is(e, "reason", "rbac")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e)
            && d(e)
            && is(e, "reason", "superadmin_gate")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e) && is(e, "action", "users.update")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e)
            && is(e, "action", "auth.staff_login")
            && is(e, "outcome", "success")),
        1,
        "{evs:?}"
    );
    assert!(
        count(&evs, |e| mine(e)
            && is(e, "outcome", "success")
            && is(e, "action", "http.get"))
            >= 1,
        "{evs:?}"
    );

    // Host de canal: o mesmo 401 de uma password errada + `no_role_here` (no tenant do canal).
    let (right, wrong) = right_and_wrong(&pool, &c.domain, "staff@x.pt").await?;
    same_as_wrong_password(&right, &wrong, "merchant");
    let evs = tenant_events(&pool, &c).await?;
    assert_eq!(
        count(&evs, |e| is(e, "action", "auth.staff_login")
            && is(e, "reason", "no_role_here")),
        1,
        "{evs:?}"
    );
    // O cookie de staff (com qualquer nome) não vale num Host de canal → 401.
    let token = cookie.split_once('=').map(|x| x.1).unwrap_or_default();
    for name in [COOKIE_PLATFORM, COOKIE_TENANT] {
        let r = get(&app, &c.domain, STAFF_ME, &format!("{name}={token}")).await?;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{name}: {}", r.body);
    }
    // E continua a valer na plataforma.
    assert_eq!(
        get(&app, PLATFORM, STAFF_ME, &cookie).await?.status,
        StatusCode::OK
    );
    cleanup(&ns).await
}

/// `tenant_admin`, `sponsor_admin` e `super_admin` no painel único: 2FA obrigatório (403 antes),
/// `tenant_admin` só pelo `{tenant_id}` da rota e nunca em lojas (404); `super_admin` e
/// `sponsor_admin` recusados num Host de canal como uma password errada; sem papéis não entra;
/// inativo não entra; cliente em rota de staff → 401; sem `Origin` → 403.
#[sqlx::test(migrations = "../migrations")]
async fn admins_sponsor_super_admin_inactive_and_customer(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_login_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let reader = PlatformReader::new(&owner, &pool).await?;
    let n = seed_tenant(&owner, "nacional", "national_portal").await?;
    let a = seed_tenant(&owner, "camara-a", "municipal").await?;
    let b = seed_tenant(&owner, "camara-b", "municipal").await?;
    let l1 = seed_store(&pool, &n, "loja-1").await?;
    let entity = seed_entity(&owner, "associacao-x").await?;
    let admin = seed_user(
        &owner,
        "camara@x.pt",
        true,
        &[("tenant_admin", Some(a.id), None, None)],
    )
    .await?;
    let totp = seed_user(
        &owner,
        "totp@x.pt",
        true,
        &[merchant("merchant_staff", &n, l1)],
    )
    .await?;
    enable_totp(&owner, totp).await?;
    seed_user(
        &owner,
        "misto@x.pt",
        true,
        &[
            ("tenant_admin", Some(a.id), None, None),
            merchant("merchant_owner", &n, l1),
        ],
    )
    .await?;
    let sponsor = seed_user(
        &owner,
        "patrocinio@x.pt",
        true,
        &[("sponsor_admin", None, None, Some(entity))],
    )
    .await?;
    let sup = seed_user(
        &owner,
        "super@x.pt",
        true,
        &[
            ("super_admin", None, None, None),
            merchant("merchant_owner", &n, l1),
        ],
    )
    .await?;
    seed_user(&owner, "sempapel@x.pt", true, &[]).await?;
    seed_user(
        &owner,
        "inativo@x.pt",
        false,
        &[merchant("merchant_staff", &n, l1)],
    )
    .await?;
    let ns = format!("test:rbac:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;
    let store_uri = format!("/api/v1/_test/stores/{l1}");
    let tenant_uri = |t: Uuid| format!("/api/v1/_test/tenants/{t}/admin");

    // tenant_admin: entra na plataforma, mas sem 2FA não passa no RequireTenantAdmin.
    let r = staff_login(&app, PLATFORM, "camara@x.pt", PW).await?;
    assert_eq!(r.json(), json!({"mfa_required": true}), "{}", r.body);
    let c = r.cookie()?;
    let r = get(&app, PLATFORM, &tenant_uri(a.id), &c).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    elevate(&pool, admin).await?;
    let r = get(&app, PLATFORM, &tenant_uri(a.id), &c).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json()["tenant_id"], json!(a.id));
    // Outro tenant (pela rota) → 404 idor; rota de loja → 404 idor (tenant_admin não vê lojas).
    let r = get(&app, PLATFORM, &tenant_uri(b.id), &c).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = get(&app, PLATFORM, &store_uri, &c).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = get(&app, PLATFORM, &format!("{store_uri}/owner"), &c).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let evs = reader.events(&pool, Some(admin)).await?;
    let mine = |e: &Value| uid(e) == Some(admin) && is(e, "actor_type", "municipal");
    assert_eq!(
        count(&evs, |e| mine(e) && is(e, "reason", "mfa_required")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e) && is(e, "reason", "idor")),
        3,
        "{evs:?}"
    );

    // 2FA obrigatório no servidor também no ramo Merchant: lojista com TOTP e tenant_admin que é
    // dono de uma loja, ambos sem 2FA → 403.
    for email in ["totp@x.pt", "misto@x.pt"] {
        let r = staff_login(&app, PLATFORM, email, PW).await?;
        assert_eq!(
            r.json(),
            json!({"mfa_required": true}),
            "{email}: {}",
            r.body
        );
        let g = get(&app, PLATFORM, &store_uri, &r.cookie()?).await?;
        assert_eq!(g.status, StatusCode::FORBIDDEN, "{email}");
    }

    // sponsor_admin: canal → 401 da password errada; plataforma → `mfa_required`, /staff/me com a
    // entidade, rotas pós-MFA → 403; ator Municipal.
    let (right, wrong) = right_and_wrong(&pool, &a.domain, "patrocinio@x.pt").await?;
    same_as_wrong_password(&right, &wrong, "sponsor_admin");
    let r = staff_login(&app, PLATFORM, "patrocinio@x.pt", PW).await?;
    assert_eq!(r.json(), json!({"mfa_required": true}), "{}", r.body);
    let cs = r.cookie()?;
    let me = get(&app, PLATFORM, STAFF_ME, &cs).await?;
    assert_eq!(me.status, StatusCode::OK, "{}", me.body);
    assert_eq!(
        me.json()["roles"],
        json!([{"role": "sponsor_admin", "tenant_id": null, "store_id": null,
                "sponsor_entity_id": entity}])
    );
    for uri in [store_uri.clone(), tenant_uri(a.id)] {
        let r = get(&app, PLATFORM, &uri, &cs).await?;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{uri}");
    }
    let evs = reader.events(&pool, Some(sponsor)).await?;
    assert_eq!(
        count(&evs, |e| is(e, "actor_type", "municipal")
            && is(e, "reason", "mfa_required")),
        2,
        "{evs:?}"
    );
    assert_eq!(count(&evs, |e| is(e, "actor_type", "admin")), 0, "{evs:?}");

    // super_admin: canal → 401 da password errada; plataforma → cookie Strict, todos os papéis.
    let (right, wrong) = right_and_wrong(&pool, &a.domain, "super@x.pt").await?;
    same_as_wrong_password(&right, &wrong, "super_admin");
    let r = staff_login(&app, PLATFORM, "super@x.pt", PW).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json(), json!({"mfa_required": true}), "{}", r.body);
    let sc = r.set_cookie.clone().unwrap_or_default();
    assert!(
        sc.starts_with(&format!("{COOKIE_PLATFORM}=")) && sc.contains("SameSite=Strict"),
        "{sc}"
    );
    let me = get(&app, PLATFORM, STAFF_ME, &r.cookie()?).await?;
    assert_eq!(
        me.json()["roles"],
        json!([
            {"role": "merchant_owner", "tenant_id": n.id, "store_id": l1, "sponsor_entity_id": null},
            {"role": "super_admin", "tenant_id": null, "store_id": null, "sponsor_entity_id": null}
        ]),
        "{}",
        me.body
    );
    let evs = reader.events(&pool, Some(sup)).await?;
    assert_eq!(
        count(&evs, |e| is(e, "action", "auth.staff_login")
            && is(e, "outcome", "success")
            && is(e, "actor_type", "admin")),
        1,
        "{evs:?}"
    );
    // As 3 recusas num canal ficaram no tenant do canal, com `no_role_here`.
    let evs = tenant_events(&pool, &a).await?;
    assert_eq!(
        count(&evs, |e| is(e, "action", "auth.staff_login")
            && is(e, "reason", "no_role_here")),
        2,
        "{evs:?}"
    );

    // Sem papéis: o 401 genérico, também na plataforma.
    let (right, wrong) = right_and_wrong(&pool, PLATFORM, "sempapel@x.pt").await?;
    same_as_wrong_password(&right, &wrong, "sem papéis");

    // Inativo: o 401 genérico.
    let r = staff_login(&app, PLATFORM, "inativo@x.pt", PW).await?;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.set_cookie.is_none());

    // Cliente: sessão `customer` (num canal) numa rota de staff → 401.
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
        get(&app, &a.domain, &store_uri, &customer).await?.status,
        StatusCode::UNAUTHORIZED
    );

    // Login de staff sem Origin → 403.
    let r = send(
        &app,
        Method::POST,
        STAFF_LOGIN,
        &[
            (header::HOST, PLATFORM),
            (header::CONTENT_TYPE, "application/json"),
        ],
        &json!({"email": "camara@x.pt", "password": PW}).to_string(),
    )
    .await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    cleanup(&ns).await
}

/// Inatividade (TTL da chave no Redis) e duração absoluta (`expires_at`) da sessão de staff.
async fn session_ttls(
    app: &Router,
    pool: &PgPool,
    ns: &str,
    email: &str,
) -> anyhow::Result<(i64, i64)> {
    let c = staff_login(app, PLATFORM, email, PW).await?.cookie()?;
    assert_eq!(
        get(app, PLATFORM, STAFF_ME, &c).await?.status,
        StatusCode::OK
    );
    let mut conn = redis()?.get().await?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{ns}sess:idle:*"))
        .query_async(&mut conn)
        .await?;
    anyhow::ensure!(keys.len() == 1, "{keys:?}");
    let idle_ms: i64 = redis::cmd("PTTL")
        .arg(&keys[0])
        .query_async(&mut conn)
        .await?;
    let sid = keys[0].rsplit(':').next().unwrap_or_default();
    let sid = Uuid::parse_str(sid)?;
    let user: Uuid =
        serde_json::from_value(get(app, PLATFORM, STAFF_ME, &c).await?.json()["id"].clone())?;
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(user), None, None);
    let mut tx = begin_platform_tx(pool, &ctx).await?;
    let (secs,): (f64,) = sqlx::query_as(
        "SELECT extract(epoch FROM expires_at - created_at)::float8 FROM sessions WHERE id = $1",
    )
    .bind(sid)
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok((idle_ms, secs as i64))
}

/// Duração pelo papel: merchant → inatividade de staff (30 min); super_admin → de plataforma
/// (15 min). A absoluta fica nas 8 h que o CHECK da 0019 permite a uma sessão sem tenant.
#[sqlx::test(migrations = "../migrations")]
async fn session_lifetime_follows_the_role(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_login_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let n = seed_tenant(&owner, "nacional", "national_portal").await?;
    let l1 = seed_store(&pool, &n, "loja-1").await?;
    seed_user(
        &owner,
        "dona@x.pt",
        true,
        &[merchant("merchant_owner", &n, l1)],
    )
    .await?;
    seed_user(
        &owner,
        "super@x.pt",
        true,
        &[("super_admin", None, None, None)],
    )
    .await?;
    for (email, idle_min) in [("dona@x.pt", 30), ("super@x.pt", 15)] {
        let ns = format!("test:rbac:{}:", Uuid::now_v7());
        let app = router(&pool, &ns)?;
        let (idle_ms, abs_secs) = session_ttls(&app, &pool, &ns, email).await?;
        let max = idle_min * 60_000;
        assert!(
            idle_ms > max - 60_000 && idle_ms <= max,
            "{email}: {idle_ms} ms"
        );
        assert_eq!(abs_secs, 8 * 3600, "{email}");
        cleanup(&ns).await?;
    }
    Ok(())
}

/// Âmbito de loja e de entidade pelo lado do extractor (cartão 03/14): o merchant de L1 lê e
/// escreve L1 (dentro de `begin_store_tx`); L2 do mesmo país (mesmo tenant), uma loja ES e um UUID
/// inexistente → 404 + `idor`. O `sponsor_admin` da Câmara A → 200 em A e 404 + `idor` na Junta B
/// e num UUID inexistente; sem 2FA → 403 `mfa_required`; um merchant numa rota de entidade → 403
/// `rbac`.
#[sqlx::test(migrations = "../migrations")]
async fn store_and_sponsor_scope_from_the_extractor(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_login_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let reader = PlatformReader::new(&owner, &pool).await?;
    let pt = seed_tenant_in(&owner, "nacional-pt", "national_portal", "PT").await?;
    let es = seed_tenant_in(&owner, "nacional-es", "national_portal", "ES").await?;
    let l1 = seed_store(&pool, &pt, "loja-1").await?;
    let l2 = seed_store(&pool, &pt, "loja-2").await?;
    let les = seed_store(&pool, &es, "tienda").await?;
    seed_test_areas(&owner).await?;
    let camara_a = seed_area_entity(&owner, "municipality", "camara-a", "9301").await?;
    let junta_b = seed_area_entity(&owner, "parish", "junta-b", "930101").await?;
    let dona = seed_user(
        &owner,
        "dona@x.pt",
        true,
        &[merchant("merchant_owner", &pt, l1)],
    )
    .await?;
    let sponsor = seed_user(
        &owner,
        "camara@x.pt",
        true,
        &[("sponsor_admin", None, None, Some(camara_a))],
    )
    .await?;
    let ns = format!("test:rbac:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;
    let store = |l: Uuid| format!("/api/v1/_test/stores/{l}");
    let entity = |e: &str| format!("/api/v1/_test/sponsors/{e}");
    let d = |e: &Value| is(e, "outcome", "denied");

    // Merchant de L1: lê e escreve L1; L2 (mesmo tenant), ES e inexistente → 404.
    let c = staff_login(&app, PLATFORM, "dona@x.pt", PW)
        .await?
        .cookie()?;
    let r = get(&app, PLATFORM, &store(l1), &c).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json()["name"], json!("loja-1"));
    assert_eq!(r.json()["tenant_id"], json!(pt.id));
    let body = json!({"name": "Loja Um"}).to_string();
    let r = mutate(
        &app,
        Method::PUT,
        PLATFORM,
        &format!("{}/name", store(l1)),
        &c,
        &body,
    )
    .await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = get(&app, PLATFORM, &store(l1), &c).await?;
    assert_eq!(r.json()["name"], json!("Loja Um"));
    for other in [l2, les, Uuid::now_v7()] {
        let r = get(&app, PLATFORM, &store(other), &c).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{other}: {}", r.body);
    }
    let r = mutate(
        &app,
        Method::PUT,
        PLATFORM,
        &format!("{}/name", store(l2)),
        &c,
        &body,
    )
    .await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    // Merchant numa rota de entidade → 403 `rbac`.
    let r = get(&app, PLATFORM, &entity(&camara_a.to_string()), &c).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    let evs = reader.events(&pool, Some(dona)).await?;
    assert_eq!(
        count(&evs, |e| d(e) && is(e, "reason", "idor")),
        4,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| d(e) && is(e, "reason", "rbac")),
        1,
        "{evs:?}"
    );

    // sponsor_admin da Câmara A: sem 2FA → 403; com 2FA → 200 em A, 404 na Junta B e inexistente.
    let r = staff_login(&app, PLATFORM, "camara@x.pt", PW).await?;
    assert_eq!(r.json(), json!({"mfa_required": true}), "{}", r.body);
    let cs = r.cookie()?;
    let r = get(&app, PLATFORM, &entity(&camara_a.to_string()), &cs).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    elevate(&pool, sponsor).await?;
    let r = get(&app, PLATFORM, &entity(&camara_a.to_string()), &cs).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json(), json!({"entity_id": camara_a, "user_id": sponsor}));
    for other in [
        junta_b.to_string(),
        Uuid::now_v7().to_string(),
        "nao-e-uuid".to_owned(),
    ] {
        let r = get(&app, PLATFORM, &entity(&other), &cs).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{other}: {}", r.body);
    }
    // E nenhuma loja (o papel de entidade não dá âmbito de loja).
    let r = get(&app, PLATFORM, &store(l1), &cs).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    let evs = reader.events(&pool, Some(sponsor)).await?;
    let mine = |e: &Value| uid(e) == Some(sponsor) && is(e, "actor_type", "municipal");
    assert_eq!(
        count(&evs, |e| mine(e) && d(e) && is(e, "reason", "mfa_required")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| mine(e) && d(e) && is(e, "reason", "idor")),
        4,
        "{evs:?}"
    );
    cleanup(&ns).await
}
