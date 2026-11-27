//! Patrocínios: API do lojista (cartão 03/19), contra Postgres e Redis reais, pela API real
//! (`http::api`) com sessões no `PLATFORM_ADMIN_HOST`.
//!
//! Mundo: canal nacional PT; concelho 9301 (Câmara) com as freguesias 930101 (Junta) e 930102
//! (Junta K, não cobre 930101); uma associação inativa no concelho. Lojas pela app com o âmbito da
//! própria loja; morada física (`storefront_dicofre`), contas, papéis e ativações pelo dono.

mod common;

use std::{
    net::{IpAddr, SocketAddr},
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
use common::{PlatformReader, app_login_pool, count, is};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    http::{api, audit_layer::AuditLayerState, client_ip::TrustedProxies},
    identity::{
        AccountKey, BreachChecker, CaptchaVerifier, Login, Password, Registration, Sessions,
        password, rbac::StoreScope,
    },
    money::{Cents, CommissionRule},
    payments::commission::effective_commission_bps,
    state::AppState,
    storage::NullStorage,
    tenancy::{
        HostResolver, TenantId,
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
const PW: &str = "uma-frase-longa-e-boa";
const ACTION: &str = "sponsorship.requested";

struct FakeCaptcha;

#[async_trait]
impl CaptchaVerifier for FakeCaptcha {
    async fn verify(&self, _token: &str, _ip: Option<IpAddr>, _expected_host: &str) -> bool {
        false
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

async fn get(app: &Router, uri: &str, cookie: &str) -> anyhow::Result<Reply> {
    send(
        app,
        Method::GET,
        uri,
        &[(header::HOST, PLATFORM), (header::COOKIE, cookie)],
        "",
    )
    .await
}

/// POST com sessão: `Origin` do host e o token CSRF da sessão.
async fn post(app: &Router, uri: &str, cookie: &str, body: &str) -> anyhow::Result<Reply> {
    let s = get(app, "/api/v1/auth/session", cookie).await?;
    let csrf = s.json()["csrf_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("sem csrf_token: {}", s.body))?;
    let origin = format!("https://{PLATFORM}");
    send(
        app,
        Method::POST,
        uri,
        &[
            (header::HOST, PLATFORM),
            (header::COOKIE, cookie),
            (header::ORIGIN, &origin),
            (header::CONTENT_TYPE, "application/json"),
            (HeaderName::from_static("x-csrf-token"), &csrf),
        ],
        body,
    )
    .await
}

/// Pedido do lojista com o corpo `{"sponsor_entity_id": entity}`.
async fn ask(app: &Router, cookie: &str, store: Uuid, entity: Uuid) -> anyhow::Result<Reply> {
    let body = json!({ "sponsor_entity_id": entity }).to_string();
    post(app, &sponsorships(store), cookie, &body).await
}

async fn login(app: &Router, email: &str) -> anyhow::Result<String> {
    let origin = format!("https://{PLATFORM}");
    let body = json!({"email": email, "password": PW});
    send(
        app,
        Method::POST,
        STAFF_LOGIN,
        &[
            (header::HOST, PLATFORM),
            (header::CONTENT_TYPE, "application/json"),
            (header::ORIGIN, &origin),
        ],
        &body.to_string(),
    )
    .await?
    .cookie()
}

fn sponsorships(store: Uuid) -> String {
    format!("/api/v1/stores/{store}/sponsorships")
}

fn eligible(store: Uuid) -> String {
    format!("/api/v1/stores/{store}/sponsors/eligible")
}

// ---------------------------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------------------------

struct World {
    owner: PgPool,
    app: PgPool,
    tenant: TenantId,
    camara: Uuid,
    junta: Uuid,
    junta_k: Uuid,
    inactive: Uuid,
}

async fn entity(
    owner: &PgPool,
    kind: &str,
    name: &str,
    area: Option<&str>,
    active: bool,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code, is_active, logo_key)
         VALUES ($1, $2, 'PT', $3, $4, $5, $6, $7)",
        id,
        kind,
        name,
        format!("e-{id}"),
        area,
        active,
        format!("logos/{id}.svg")
    )
    .execute(owner)
    .await?;
    Ok(id)
}

/// Associação ativa que cobre o concelho 9301.
async fn association(owner: &PgPool, name: &str, active: bool) -> sqlx::Result<Uuid> {
    let id = entity(owner, "association", name, None, active).await?;
    sqlx::query!(
        "INSERT INTO sponsor_entity_areas (sponsor_entity_id, area_code) VALUES ($1, '9301')",
        id
    )
    .execute(owner)
    .await?;
    Ok(id)
}

async fn world(opts: &PgPoolOptions, conn: &PgConnectOptions) -> anyhow::Result<World> {
    let owner = owner_pool(opts, conn).await?;
    let app = app_login_pool(opts, conn).await?;
    let tenant = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code)
         VALUES ($1, 'nacional', 'nacional.ptmarket.invalid', 'Nacional', 'national_portal', 'PT')",
        tenant
    )
    .execute(&owner)
    .await?;
    sqlx::query!(
        "INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
            ('93', 'district', NULL, 'Distrito Teste', 'T'),
            ('9301', 'municipality', '93', 'Concelho A', 'T'),
            ('930101', 'parish', '9301', 'Freguesia J', 'T'),
            ('930102', 'parish', '9301', 'Freguesia K', 'T')"
    )
    .execute(&owner)
    .await?;
    // Nomes contra a ordem dos selos: o tipo manda.
    let camara = entity(&owner, "municipality", "Zzz Câmara", Some("9301"), true).await?;
    let junta = entity(&owner, "parish", "Mmm Junta", Some("930101"), true).await?;
    let junta_k = entity(&owner, "parish", "Aaa Junta K", Some("930102"), true).await?;
    let inactive = association(&owner, "Aaa Inativa", false).await?;
    Ok(World {
        owner,
        app,
        tenant: TenantId::for_tests(tenant),
        camara,
        junta,
        junta_k,
        inactive,
    })
}

/// Loja pela app com o âmbito da própria loja e a morada física `dicofre`, pelo dono.
async fn seed_store(w: &World, slug: &str, dicofre: Option<&str>) -> anyhow::Result<Uuid> {
    let scope = StoreScope::for_tests(w.tenant, Uuid::now_v7());
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_store_tx(&w.app, &scope, &ctx).await?;
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email)
         VALUES ($1, $2, $3, $3, $3, '500000000', 'PT50000000000000000000000', 'loja@test.invalid')",
        scope.store_id(),
        w.tenant.as_uuid(),
        slug
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut tx = w.owner.begin().await?;
    sqlx::query("ALTER TABLE stores NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "UPDATE stores SET storefront_dicofre = $2 WHERE id = $1",
        scope.store_id(),
        dicofre
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("ALTER TABLE stores FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(scope.store_id())
}

/// Conta de backoffice com um papel de loja, criada pelo dono.
async fn seed_user(w: &World, email: &str, role: &str, store: Uuid) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let phc = password::hash(&Password::parse(PW)?).await?;
    let mut tx = w.owner.begin().await?;
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
    sqlx::query!(
        "INSERT INTO user_roles (id, user_id, role, tenant_id, store_id)
         VALUES ($1, $2, $3, $4, $5)",
        Uuid::now_v7(),
        id,
        role,
        w.tenant.as_uuid(),
        store
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("ALTER TABLE users FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("ALTER TABLE user_roles FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}

/// Marca o 2FA nas sessões ativas do utilizador, com o próprio como ator.
async fn elevate(w: &World, user: Uuid) -> TestResult {
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(user), None, None);
    let mut tx = begin_platform_tx(&w.app, &ctx).await?;
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

/// Linhas de `store_sponsorships` da loja (pelo dono: vê tudo).
async fn rows(w: &World, store: Uuid) -> anyhow::Result<Vec<(Uuid, String, String, Option<Uuid>)>> {
    let r = sqlx::query!(
        "SELECT sponsor_entity_id, status, initiated_by, decided_by FROM store_sponsorships
         WHERE store_id = $1 ORDER BY created_at",
        store
    )
    .fetch_all(&w.owner)
    .await?;
    Ok(r.into_iter()
        .map(|r| (r.sponsor_entity_id, r.status, r.initiated_by, r.decided_by))
        .collect())
}

/// Regra da comissão efetiva da loja agora (âmbito da loja, como a app).
async fn rule_now(w: &World, store: Uuid) -> anyhow::Result<CommissionRule> {
    let scope = StoreScope::for_tests(w.tenant, store);
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_store_tx(&w.app, &scope, &ctx).await?;
    let snap = effective_commission_bps(
        &mut tx,
        store,
        SystemTime::now(),
        Cents::new(0)?,
        Cents::new(10_000)?,
    )
    .await?;
    tx.rollback().await?;
    Ok(snap.quote.rule)
}

fn already(list: &Value, id: Uuid) -> Option<String> {
    list.as_array()?
        .iter()
        .find(|e| e["id"] == json!(id))
        .and_then(|e| e["already"].as_str())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------------------------

/// O dono pede → 201 `pending` + evento; repetir → 409; não elegível (4 casos) → 422 igual e nada
/// gravado; co-patrocínio Câmara + Junta; lista e `eligible`; corpo com campos a mais → 400; só
/// `pending` → regra Plan; anti-IDOR (L2 do mesmo canal), `merchant_staff` e 2FA; loja sem morada.
#[sqlx::test(migrations = "../migrations")]
async fn owner_requests_and_lists_sponsorships(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let reader = PlatformReader::new(&w.owner, &w.app).await?;
    let l1 = seed_store(&w, "loja-1", Some("930101")).await?;
    let l2 = seed_store(&w, "loja-2", Some("930101")).await?;
    let l3 = seed_store(&w, "loja-3", None).await?;
    let dona = seed_user(&w, "dona@x.pt", "merchant_owner", l1).await?;
    let staff = seed_user(&w, "staff@x.pt", "merchant_staff", l1).await?;
    let dona3 = seed_user(&w, "dona3@x.pt", "merchant_owner", l3).await?;
    let ns = format!("test:sponsorships:{}:", Uuid::now_v7());
    let app = router(&w.app, &ns)?;
    let d = |e: &Value| is(e, "outcome", "denied");

    // Sem 2FA → 403 mfa_required (antes do recurso) e nada gravado.
    let c = login(&app, "dona@x.pt").await?;
    let r = ask(&app, &c, l1, w.camara).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    elevate(&w, dona).await?;

    // Pedido → 201 pending; a linha nasce pending, initiated_by store, sem decided_by.
    let r = ask(&app, &c, l1, w.camara).await?;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.json()["status"], json!("pending"));
    let first = r.json()["id"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_default();
    assert_eq!(
        rows(&w, l1).await?,
        vec![(w.camara, "pending".to_owned(), "store".to_owned(), None)]
    );

    // Repetir → 409 already_requested.
    let r = ask(&app, &c, l1, w.camara).await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    assert_eq!(r.json()["error"]["code"], json!("already_requested"));

    // Não cobre a freguesia, inativa, inexistente → 422 not_eligible, a mesma resposta; nada gravado.
    let mut bodies = Vec::new();
    for e in [w.junta_k, w.inactive, Uuid::now_v7()] {
        let r = ask(&app, &c, l1, e).await?;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
        assert_eq!(r.json()["error"]["code"], json!("not_eligible"));
        bodies.push(r.body);
    }
    assert!(bodies.windows(2).all(|p| p[0] == p[1]), "{bodies:?}");
    assert_eq!(rows(&w, l1).await?.len(), 1);

    // Corpo com estado, datas ou bps (ou sem corpo JSON) → 400; nada gravado.
    for body in [
        json!({"sponsor_entity_id": w.junta, "status": "active"}),
        json!({"sponsor_entity_id": w.junta, "valid_from": "2026-01-01T00:00:00Z"}),
        json!({"sponsor_entity_id": w.junta, "commission_override_bps": 0}),
        json!({}),
    ] {
        let r = post(&app, &sponsorships(l1), &c, &body.to_string()).await?;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{body}: {}", r.body);
    }
    assert_eq!(rows(&w, l1).await?.len(), 1);

    // Co-patrocínio: Junta também → dois pending independentes.
    let r = ask(&app, &c, l1, w.junta).await?;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let second = r.json()["id"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_default();
    let list = get(&app, &sponsorships(l1), &c).await?;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    let items = list.json();
    let ids: Vec<&str> = items
        .as_array()
        .map(|a| a.iter().filter_map(|i| i["id"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(
        ids,
        vec![second.as_str(), first.as_str()],
        "mais recente primeiro"
    );
    for i in items.as_array().into_iter().flatten() {
        assert_eq!(i["status"], json!("pending"));
        assert_eq!(i["commission_override_bps"], json!(0));
        assert!(i["valid_from"].is_null() && i["decided_at"].is_null());
        assert!(i["created_at"].as_str().is_some_and(|s| s.ends_with('Z')));
        assert!(i.get("requested_by").is_none() && i.get("decided_by").is_none());
    }
    assert_eq!(items[0]["sponsor"]["id"], json!(w.junta));
    assert_eq!(items[0]["sponsor"]["kind"], json!("parish"));
    assert!(!list.body.contains("dona@x.pt") && !list.body.contains("Pessoa de Teste"));

    let el = get(&app, &eligible(l1), &c).await?;
    assert_eq!(el.status, StatusCode::OK, "{}", el.body);
    let order: Vec<Value> = el
        .json()
        .as_array()
        .map(|a| a.iter().map(|e| e["id"].clone()).collect())
        .unwrap_or_default();
    assert_eq!(
        order,
        vec![json!(w.camara), json!(w.junta)],
        "ordem dos selos, só ativas"
    );
    assert_eq!(already(&el.json(), w.camara).as_deref(), Some("pending"));
    assert_eq!(already(&el.json(), w.junta).as_deref(), Some("pending"));

    // Só pending → a loja continua na regra Plan.
    assert_eq!(rule_now(&w, l1).await?, CommissionRule::Plan);

    // Anti-IDOR no mesmo canal: L2 → 404 em POST e GET; nada gravado em L2.
    for r in [
        ask(&app, &c, l2, w.camara).await?,
        get(&app, &sponsorships(l2), &c).await?,
        get(&app, &eligible(l2), &c).await?,
    ] {
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    }
    assert!(rows(&w, l2).await?.is_empty());

    // merchant_staff: POST → 403 rbac; lê a lista.
    let cs = login(&app, "staff@x.pt").await?;
    let r = ask(&app, &cs, l1, w.camara).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    let r = get(&app, &sponsorships(l1), &cs).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // Loja sem morada física → 422 store_address_missing; eligible vazio.
    let c3 = login(&app, "dona3@x.pt").await?;
    elevate(&w, dona3).await?;
    let r = ask(&app, &c3, l3, w.camara).await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    assert_eq!(r.json()["error"]["code"], json!("store_address_missing"));
    let r = get(&app, &eligible(l3), &c3).await?;
    assert_eq!(r.json(), json!([]), "{}", r.body);
    assert!(rows(&w, l3).await?.is_empty());

    // Caixa negra.
    let evs = reader.events(&w.app, Some(dona)).await?;
    let req = |e: &Value| is(e, "action", ACTION);
    assert_eq!(
        count(&evs, |e| req(e) && is(e, "outcome", "success")),
        2,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| req(e)
            && is(e, "outcome", "success")
            && (is(e, "target_id", &first) || is(e, "target_id", &second))),
        2,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| req(e)
            && d(e)
            && is(e, "reason", "already_requested")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| req(e) && d(e) && is(e, "reason", "not_eligible")),
        3,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| d(e) && is(e, "reason", "mfa_required")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| d(e) && is(e, "reason", "idor")),
        3,
        "{evs:?}"
    );
    let evs = reader.events(&w.app, Some(staff)).await?;
    assert_eq!(
        count(&evs, |e| d(e) && is(e, "reason", "rbac")),
        1,
        "{evs:?}"
    );
    let evs = reader.events(&w.app, Some(dona3)).await?;
    assert_eq!(
        count(&evs, |e| req(e)
            && d(e)
            && is(e, "reason", "store_address_missing")),
        1,
        "{evs:?}"
    );
    cleanup(&ns).await
}

/// Patrocínio `active` vigente → novo pedido 409 e `eligible` marca `active` (regra Sponsored);
/// 10 pending → o 11.º dá 409 `too_many_pending`.
#[sqlx::test(migrations = "../migrations")]
async fn active_pair_and_pending_limit(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let w = world(&opts, &conn).await?;
    let l1 = seed_store(&w, "loja-1", Some("930101")).await?;
    let dona = seed_user(&w, "dona@x.pt", "merchant_owner", l1).await?;
    let ns = format!("test:sponsorships:{}:", Uuid::now_v7());
    let app = router(&w.app, &ns)?;
    let c = login(&app, "dona@x.pt").await?;
    elevate(&w, dona).await?;

    let r = ask(&app, &c, l1, w.camara).await?;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    // A entidade aprova (aqui pelo dono): ativo desde ontem, sem fim.
    sqlx::query!(
        "UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
         WHERE store_id = $1 AND sponsor_entity_id = $2",
        l1,
        w.camara
    )
    .execute(&w.owner)
    .await?;
    let r = ask(&app, &c, l1, w.camara).await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    assert_eq!(r.json()["error"]["code"], json!("already_requested"));
    let el = get(&app, &eligible(l1), &c).await?;
    assert_eq!(already(&el.json(), w.camara).as_deref(), Some("active"));
    assert_eq!(already(&el.json(), w.junta).as_deref(), Some("none"));
    assert_eq!(rule_now(&w, l1).await?, CommissionRule::Sponsored);

    // Limite de pending: Junta + 9 associações = 10; a 11.ª → 409.
    let mut targets = vec![w.junta];
    for i in 0..10 {
        targets.push(association(&w.owner, &format!("Assoc {i:02}"), true).await?);
    }
    for e in &targets[..10] {
        let r = ask(&app, &c, l1, *e).await?;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    }
    let r = ask(&app, &c, l1, targets[10]).await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    assert_eq!(r.json()["error"]["code"], json!("too_many_pending"));
    assert_eq!(rows(&w, l1).await?.len(), 11, "1 active + 10 pending");
    cleanup(&ns).await
}
