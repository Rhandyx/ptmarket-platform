//! Patrocínios: API do `sponsor_admin` (cartão 03/20), contra Postgres e Redis reais, pela API real
//! (`http::api`) com sessões no `PLATFORM_ADMIN_HOST`.
//!
//! Mundo: canal nacional PT; concelho 9301 (Câmara) com as freguesias 930101 (Junta) e 930102 (não
//! coberta pela Junta). Lojas pela app com o âmbito da própria loja; morada física, estado, contas,
//! papéis, pedidos `pending` e ativações pelo dono (a API do lojista tem o seu teste).

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
        password,
        rbac::{SponsorScope, StoreScope},
    },
    money::{Cents, CommissionRule},
    payments::commission::effective_commission_bps,
    state::AppState,
    storage::NullStorage,
    tenancy::{
        HostResolver, TenantId,
        db::{begin_platform_tx, begin_sponsor_tx, begin_store_tx},
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

fn list(entity: Uuid) -> String {
    format!("/api/v1/sponsors/{entity}/sponsorships")
}

fn act(entity: Uuid, id: Uuid, action: &str) -> String {
    format!("/api/v1/sponsors/{entity}/sponsorships/{id}/{action}")
}

fn reason(r: &str) -> String {
    json!({ "reason": r }).to_string()
}

// ---------------------------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------------------------

struct World {
    owner: PgPool,
    app: PgPool,
    worker: PgPool,
    tenant: TenantId,
    camara: Uuid,
    junta: Uuid,
}

async fn worker_pool(opts: &PgPoolOptions, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(1)
        .after_connect(|c, _meta| {
            Box::pin(async move {
                sqlx::query!("SET ROLE ptmarket_worker").execute(c).await?;
                Ok(())
            })
        })
        .connect_with(conn.clone())
        .await
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
        "INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code, is_active)
         VALUES ($1, $2, 'PT', $3, $4, $5, $6)",
        id,
        kind,
        name,
        format!("e-{id}"),
        area,
        active
    )
    .execute(owner)
    .await?;
    Ok(id)
}

async fn world(opts: &PgPoolOptions, conn: &PgConnectOptions) -> anyhow::Result<World> {
    let owner = owner_pool(opts, conn).await?;
    let app = app_login_pool(opts, conn).await?;
    let worker = worker_pool(opts, conn).await?;
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
    let camara = entity(&owner, "municipality", "Câmara A", Some("9301"), true).await?;
    let junta = entity(&owner, "parish", "Junta J", Some("930101"), true).await?;
    Ok(World {
        owner,
        app,
        worker,
        tenant: TenantId::for_tests(tenant),
        camara,
        junta,
    })
}

/// Loja pela app com o âmbito da própria loja; morada física `dicofre` e `is_active` pelo dono.
async fn seed_store(w: &World, slug: &str, dicofre: &str, active: bool) -> anyhow::Result<Uuid> {
    let scope = StoreScope::for_tests(w.tenant, Uuid::now_v7());
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_store_tx(&w.app, &scope, &ctx).await?;
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, phone)
         VALUES ($1, $2, $3, $3, $4, '500000000', 'PT50000000000000000000000',
                 'loja@test.invalid', '+351910000000')",
        scope.store_id(),
        w.tenant.as_uuid(),
        slug,
        format!("{slug} Lda")
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut tx = w.owner.begin().await?;
    sqlx::query("ALTER TABLE stores NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "UPDATE stores SET storefront_dicofre = $2, is_active = $3 WHERE id = $1",
        scope.store_id(),
        dicofre,
        active
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("ALTER TABLE stores FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(scope.store_id())
}

type RoleSeed<'a> = (&'a str, Option<Uuid>, Option<Uuid>, Option<Uuid>);

/// Conta de backoffice com papéis `(role, tenant, store, entity)`, criada pelo dono.
async fn seed_user(w: &World, email: &str, roles: &[RoleSeed<'_>]) -> anyhow::Result<Uuid> {
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

/// Login de staff + 2FA marcado: o cookie.
async fn session(app: &Router, w: &World, email: &str, user: Uuid) -> anyhow::Result<String> {
    let c = login(app, email).await?;
    elevate(w, user).await?;
    Ok(c)
}

/// Pedido `pending` da loja (pelo dono: a API do lojista tem o seu teste).
async fn pending(w: &World, store: Uuid, entity: Uuid) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO store_sponsorships
             (id, tenant_id, store_id, sponsor_entity_id, initiated_by)
         VALUES ($1, $2, $3, $4, 'store')",
        id,
        w.tenant.as_uuid(),
        store,
        entity
    )
    .execute(&w.owner)
    .await?;
    Ok(id)
}

/// Estado, `decided_by`, motivo e se `valid_to` está definido (pelo dono: vê tudo).
async fn row(w: &World, id: Uuid) -> anyhow::Result<(String, Option<Uuid>, Option<String>, bool)> {
    let r = sqlx::query!(
        r#"SELECT status, decided_by, decision_reason, valid_to IS NOT NULL AS "has_end!"
           FROM store_sponsorships WHERE id = $1"#,
        id
    )
    .fetch_one(&w.owner)
    .await?;
    Ok((r.status, r.decided_by, r.decision_reason, r.has_end))
}

/// Regra e bps aplicados da comissão efetiva da loja agora (âmbito da loja, como a app).
async fn rule_now(w: &World, store: Uuid) -> anyhow::Result<(CommissionRule, i32)> {
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
    Ok((snap.quote.rule, snap.quote.applied_commission_bps.get()))
}

/// Instante `now() + offset` (intervalo SQL) em RFC 3339 UTC, pelo relógio da BD.
async fn at(w: &World, offset: &str) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar!(
        r#"SELECT to_char((now() + $1::text::interval) AT TIME ZONE 'UTC',
                          'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "t!""#,
        offset
    )
    .fetch_one(&w.owner)
    .await?)
}

/// Alertas críticos `sponsorship_revoked` (lidos como `ptmarket_worker`).
async fn revoked_alerts(w: &World) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*)::int8 FROM audit.audit_alerts WHERE kind::text = 'sponsorship_revoked'",
    )
    .fetch_one(&w.worker)
    .await?)
}

fn items(page: &Value) -> Vec<Value> {
    page["items"].as_array().cloned().unwrap_or_default()
}

fn ids_of(page: &Value) -> Vec<String> {
    items(page)
        .iter()
        .filter_map(|i| i["id"].as_str().map(str::to_owned))
        .collect()
}

/// Nenhum corpo de resposta da API da entidade leva dados sensíveis da loja.
fn assert_no_leak(bodies: &[String]) {
    for b in bodies {
        let low = b.to_lowercase();
        for bad in [
            "iban",
            "email",
            "phone",
            "commission",
            "pt5000",
            "loja@test",
            "+351",
        ] {
            assert!(!low.contains(bad), "{bad} em {b}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------------------------

/// Câmara e Junta decidem os pedidos da mesma loja: lista (campos públicos, uma vez por entidade,
/// páginas, filtro), aprovar → Sponsored a 0 bps, co-patrocínio, anti-IDOR (filtro + RLS), revogar
/// → evento crítico e plano só quando ambos cessam; 409 (sobreposto, transição), 422 (não elegível,
/// loja inativa), 400 (corpo), 403 (sem 2FA, merchant, tenant_admin); nada sensível no JSON.
#[sqlx::test(migrations = "../migrations")]
async fn sponsor_admin_decides_sponsorships(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let reader = PlatformReader::new(&w.owner, &w.app).await?;
    let l1 = seed_store(&w, "loja-1", "930101", true).await?;
    let l2 = seed_store(&w, "loja-2", "930101", true).await?;
    let l3 = seed_store(&w, "loja-3", "930102", true).await?;
    let off = seed_store(&w, "loja-off", "930101", false).await?;
    let cam = seed_user(
        &w,
        "camara@x.pt",
        &[("sponsor_admin", None, None, Some(w.camara))],
    )
    .await?;
    let jun = seed_user(
        &w,
        "junta@x.pt",
        &[("sponsor_admin", None, None, Some(w.junta))],
    )
    .await?;
    let t = Some(w.tenant.as_uuid());
    let dona = seed_user(&w, "dona@x.pt", &[("merchant_owner", t, Some(l1), None)]).await?;
    let tadm = seed_user(&w, "tadmin@x.pt", &[("tenant_admin", t, None, None)]).await?;
    let p_cam_l1 = pending(&w, l1, w.camara).await?;
    let p_jun_l1 = pending(&w, l1, w.junta).await?;
    let p_cam_l2 = pending(&w, l2, w.camara).await?;
    let p_cam_off = pending(&w, off, w.camara).await?;
    let p_jun_l3 = pending(&w, l3, w.junta).await?;
    let ns = format!("test:sponsor-admin:{}:", Uuid::now_v7());
    let app = router(&w.app, &ns)?;
    let mut bodies = Vec::new();

    // Sem 2FA → 403 (antes do recurso).
    let cc = login(&app, "camara@x.pt").await?;
    let r = get(&app, &list(w.camara), &cc).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    let r = post(&app, &act(w.camara, p_cam_l1, "approve"), &cc, "{}").await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    assert_eq!(row(&w, p_cam_l1).await?.0, "pending");
    elevate(&w, cam).await?;

    // Lista da Câmara: mais recentes primeiro; a loja inativa fica de fora; só campos públicos.
    let r = get(&app, &list(w.camara), &cc).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    bodies.push(r.body.clone());
    let page = r.json();
    assert_eq!(
        ids_of(&page),
        vec![p_cam_l2.to_string(), p_cam_l1.to_string()],
        "{}",
        r.body
    );
    assert!(page["next_cursor"].is_null());
    let first = &items(&page)[1];
    assert_eq!(first["status"], json!("pending"));
    assert!(first["valid_from"].is_null() && first["decided_at"].is_null());
    assert!(
        first["requested_at"]
            .as_str()
            .is_some_and(|s| s.ends_with('Z'))
    );
    let mut keys: Vec<&str> = first["store"]
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "id",
            "legal_name",
            "name",
            "nif",
            "slug",
            "storefront_dicofre"
        ]
    );
    assert_eq!(first["store"]["id"], json!(l1));
    assert_eq!(first["store"]["legal_name"], json!("loja-1 Lda"));
    assert_eq!(first["store"]["storefront_dicofre"], json!("930101"));
    let mut item_keys: Vec<&str> = first
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    item_keys.sort_unstable();
    assert_eq!(
        item_keys,
        [
            "decided_at",
            "id",
            "requested_at",
            "status",
            "store",
            "valid_from",
            "valid_to"
        ]
    );

    // Páginas (limit=1 + cursor) e filtros inválidos → 400.
    let r = get(&app, &format!("{}?limit=1", list(w.camara)), &cc).await?;
    assert_eq!(ids_of(&r.json()), vec![p_cam_l2.to_string()], "{}", r.body);
    let cursor = r.json()["next_cursor"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_default();
    let r = get(
        &app,
        &format!("{}?limit=1&cursor={cursor}", list(w.camara)),
        &cc,
    )
    .await?;
    assert_eq!(ids_of(&r.json()), vec![p_cam_l1.to_string()], "{}", r.body);
    for q in ["limit=0", "limit=101", "status=x", "cursor=abc", "outro=1"] {
        let r = get(&app, &format!("{}?{q}", list(w.camara)), &cc).await?;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{q}: {}", r.body);
    }

    // Corpo inválido → 400 e nada muda (bps, estado, datas no passado, fim ≤ início, lixo).
    let past = at(&w, "-1 hour").await?;
    let soon = at(&w, "1 day").await?;
    let later = at(&w, "2 days").await?;
    for body in [
        json!({"commission_override_bps": 0}),
        json!({"status": "active"}),
        json!({"valid_from": past}),
        json!({"valid_from": later, "valid_to": soon}),
        json!({"valid_from": soon, "valid_to": soon}),
        json!({"valid_from": "2026-02-30T00:00:00Z"}),
        json!({"valid_to": "amanhã"}),
    ] {
        let r = post(
            &app,
            &act(w.camara, p_cam_l1, "approve"),
            &cc,
            &body.to_string(),
        )
        .await?;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{body}: {}", r.body);
        bodies.push(r.body);
    }
    assert_eq!(row(&w, p_cam_l1).await?.0, "pending");

    // Aprovar (sem corpo de datas) → active, sem fim; decided_by = a sessão; regra Sponsored a 0.
    assert_eq!(rule_now(&w, l1).await?.0, CommissionRule::Plan);
    let r = post(&app, &act(w.camara, p_cam_l1, "approve"), &cc, "{}").await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    bodies.push(r.body.clone());
    assert_eq!(r.json()["id"], json!(p_cam_l1));
    assert_eq!(r.json()["status"], json!("active"));
    assert!(
        r.json()["valid_from"]
            .as_str()
            .is_some_and(|s| s.ends_with('Z'))
    );
    assert!(r.json()["valid_to"].is_null());
    assert_eq!(
        row(&w, p_cam_l1).await?,
        ("active".to_owned(), Some(cam), None, false)
    );
    assert_eq!(rule_now(&w, l1).await?, (CommissionRule::Sponsored, 0));
    // Aprovar outra vez → 409 (transição).
    let r = post(&app, &act(w.camara, p_cam_l1, "approve"), &cc, "{}").await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    assert_eq!(r.json()["error"]["code"], json!("invalid_transition"));

    // Co-patrocínio: a Junta vê L1 uma vez e aprova a sua.
    let cj = session(&app, &w, "junta@x.pt", jun).await?;
    let r = get(&app, &list(w.junta), &cj).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    bodies.push(r.body.clone());
    assert_eq!(
        ids_of(&r.json()),
        vec![p_jun_l3.to_string(), p_jun_l1.to_string()]
    );
    let r = post(&app, &act(w.junta, p_jun_l1, "approve"), &cj, "{}").await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = get(&app, &format!("{}?status=active", list(w.camara)), &cc).await?;
    assert_eq!(ids_of(&r.json()), vec![p_cam_l1.to_string()], "{}", r.body);
    let l1_count = items(&r.json())
        .iter()
        .filter(|i| i["store"]["id"] == json!(l1))
        .count();
    assert_eq!(l1_count, 1);

    // Anti-IDOR: a Câmara não vê nem altera o patrocínio da Junta (filtro → 404 + idor) …
    for (a, body) in [
        ("approve", "{}".to_owned()),
        ("reject", reason("não é meu")),
        ("revoke", reason("não é meu")),
    ] {
        let r = post(&app, &act(w.camara, p_jun_l1, a), &cc, &body).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{a}: {}", r.body);
        bodies.push(r.body);
    }
    for path in [
        act(w.camara, Uuid::now_v7(), "revoke"),
        format!("{}/nao-e-uuid/revoke", list(w.camara)),
    ] {
        let r = post(&app, &path, &cc, &reason("x")).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}: {}", r.body);
    }
    // … nem pela rota da Junta (extractor) …
    let r = get(&app, &list(w.junta), &cc).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    let r = post(&app, &act(w.junta, p_jun_l1, "revoke"), &cc, &reason("x")).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    assert_eq!(row(&w, p_jun_l1).await?.0, "active");
    // … e a RLS sozinha (sem o filtro) também esconde e protege a linha da Junta.
    let ctx = AuditCtx::for_tests(ActorType::Municipal, Some(cam), None, None);
    let mut tx =
        begin_sponsor_tx(&w.app, w.tenant, &SponsorScope::for_tests(w.camara), &ctx).await?;
    let seen = sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM store_sponsorships WHERE id = $1"#,
        p_jun_l1
    )
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(seen, 0);
    let upd = sqlx::query!(
        "UPDATE store_sponsorships SET decision_reason = 'x' WHERE id = $1",
        p_jun_l1
    )
    .execute(&mut *tx)
    .await?;
    assert_eq!(upd.rows_affected(), 0);
    tx.rollback().await?;

    // Revogar a da Câmara → revoked com fim; L1 continua patrocinada pela Junta (0 bps).
    for bad in [
        reason(""),
        reason("   "),
        reason(&"x".repeat(501)),
        json!({"reason": "x", "status": "active"}).to_string(),
    ] {
        let r = post(&app, &act(w.camara, p_cam_l1, "revoke"), &cc, &bad).await?;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", r.body);
    }
    let r = post(
        &app,
        &act(w.camara, p_cam_l1, "revoke"),
        &cc,
        &reason("fim do protocolo"),
    )
    .await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    bodies.push(r.body.clone());
    assert_eq!(r.json()["status"], json!("revoked"));
    assert!(
        r.json()["valid_to"]
            .as_str()
            .is_some_and(|s| s.ends_with('Z'))
    );
    assert_eq!(
        row(&w, p_cam_l1).await?,
        (
            "revoked".to_owned(),
            Some(cam),
            Some("fim do protocolo".to_owned()),
            true
        )
    );
    assert_eq!(rule_now(&w, l1).await?, (CommissionRule::Sponsored, 0));
    // Revogar outra vez → 409; revogar um pending → 409.
    let r = post(
        &app,
        &act(w.camara, p_cam_l1, "revoke"),
        &cc,
        &reason("de novo"),
    )
    .await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    let r = post(
        &app,
        &act(w.camara, p_cam_l2, "revoke"),
        &cc,
        &reason("cedo"),
    )
    .await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    // A Junta revoga a sua → a loja volta ao plano de imediato.
    let r = post(&app, &act(w.junta, p_jun_l1, "revoke"), &cj, &reason("fim")).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(rule_now(&w, l1).await?.0, CommissionRule::Plan);
    assert_eq!(
        revoked_alerts(&w).await?,
        2,
        "um evento crítico por revogação"
    );

    // L2: aprovar com fim explícito; um segundo período sobreposto → 409; rejeitar; aprovar o
    // rejeitado → 409.
    let r = post(
        &app,
        &act(w.camara, p_cam_l2, "approve"),
        &cc,
        &json!({"valid_to": later}).to_string(),
    )
    .await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(
        r.json()["valid_to"]
            .as_str()
            .is_some_and(|s| s.ends_with('Z'))
    );
    let again = pending(&w, l2, w.camara).await?;
    let r = post(&app, &act(w.camara, again, "approve"), &cc, "{}").await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    assert_eq!(r.json()["error"]["code"], json!("overlapping_period"));
    assert_eq!(row(&w, again).await?.0, "pending");
    let r = post(
        &app,
        &act(w.camara, again, "reject"),
        &cc,
        &reason("duplicado"),
    )
    .await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    bodies.push(r.body.clone());
    assert_eq!(r.json()["status"], json!("rejected"));
    assert_eq!(
        row(&w, again).await?,
        (
            "rejected".to_owned(),
            Some(cam),
            Some("duplicado".to_owned()),
            false
        )
    );
    let r = post(&app, &act(w.camara, again, "approve"), &cc, "{}").await?;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    assert_eq!(r.json()["error"]["code"], json!("invalid_transition"));

    // Não elegível: a Junta não cobre a freguesia de L3; loja inativa → 422; nada muda.
    let r = post(&app, &act(w.junta, p_jun_l3, "approve"), &cj, "{}").await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    assert_eq!(r.json()["error"]["code"], json!("not_eligible"));
    let r = post(&app, &act(w.camara, p_cam_off, "approve"), &cc, "{}").await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    bodies.push(r.body.clone());
    assert_eq!(row(&w, p_jun_l3).await?.0, "pending");
    assert_eq!(row(&w, p_cam_off).await?.0, "pending");

    // Merchant e tenant_admin (com 2FA) não entram nas rotas da entidade (403 `rbac` do extractor).
    for (email, user) in [("dona@x.pt", dona), ("tadmin@x.pt", tadm)] {
        let c = session(&app, &w, email, user).await?;
        let r = get(&app, &list(w.camara), &c).await?;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{email}: {}", r.body);
        let r = post(&app, &act(w.camara, p_cam_l2, "revoke"), &c, &reason("x")).await?;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{email}: {}", r.body);
    }
    assert_eq!(row(&w, p_cam_l2).await?.0, "active");

    assert_no_leak(&bodies);

    // Caixa negra (Câmara).
    let evs = reader.events(&w.app, Some(cam)).await?;
    let ok = |e: &Value, a: &str, id: Uuid| {
        is(e, "action", a) && is(e, "outcome", "success") && is(e, "target_id", &id.to_string())
    };
    assert_eq!(
        count(&evs, |e| ok(e, "sponsorship.approved", p_cam_l1)),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| ok(e, "sponsorship.approved", p_cam_l2)),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| ok(e, "sponsorship.revoked", p_cam_l1)),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| ok(e, "sponsorship.rejected", again)),
        1,
        "{evs:?}"
    );
    let d = |e: &Value, r: &str| is(e, "outcome", "denied") && is(e, "reason", r);
    assert_eq!(count(&evs, |e| d(e, "idor")), 7, "{evs:?}");
    assert_eq!(count(&evs, |e| d(e, "mfa_required")), 2, "{evs:?}");
    assert_eq!(
        count(&evs, |e| is(e, "action", "sponsorship.approved")
            && d(e, "overlapping_period")),
        1,
        "{evs:?}"
    );
    assert_eq!(
        count(&evs, |e| is(e, "action", "sponsorship.approved")
            && d(e, "not_eligible")),
        1,
        "{evs:?}"
    );
    // A lista é leitura de admin: gravada SÍNCRONA (já está na BD sem o consumidor do Stream).
    // 9 = 4 leituras 200 + 5 filtros inválidos (400).
    assert_eq!(
        count(&evs, |e| is(e, "action", "http.get")
            && is(e, "outcome", "success")
            && is(
                e,
                "target_id",
                "/api/v1/sponsors/{entity_id}/sponsorships"
            )),
        9,
        "{evs:?}"
    );
    let evs = reader.events(&w.app, Some(dona)).await?;
    assert!(count(&evs, |e| d(e, "rbac")) >= 2, "{evs:?}");
    cleanup(&ns).await
}

/// Entidade desativada (`is_active = false`): o seu `sponsor_admin` recebe 404 + `idor` em listar,
/// aprovar, rejeitar e revogar, e nada muda.
#[sqlx::test(migrations = "../migrations")]
async fn deactivated_entity_is_not_found(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let reader = PlatformReader::new(&w.owner, &w.app).await?;
    let l1 = seed_store(&w, "loja-1", "930101", true).await?;
    let l2 = seed_store(&w, "loja-2", "930101", true).await?;
    let p1 = pending(&w, l1, w.junta).await?;
    let p2 = pending(&w, l2, w.junta).await?;
    sqlx::query!(
        "UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
         WHERE id = $1",
        p2
    )
    .execute(&w.owner)
    .await?;
    let jun = seed_user(
        &w,
        "junta@x.pt",
        &[("sponsor_admin", None, None, Some(w.junta))],
    )
    .await?;
    let ns = format!("test:sponsor-admin:{}:", Uuid::now_v7());
    let app = router(&w.app, &ns)?;
    let cj = session(&app, &w, "junta@x.pt", jun).await?;
    let r = get(&app, &list(w.junta), &cj).await?;
    assert_eq!(r.status, StatusCode::OK, "ativa: {}", r.body);

    sqlx::query!(
        "UPDATE sponsor_entities SET is_active = false WHERE id = $1",
        w.junta
    )
    .execute(&w.owner)
    .await?;
    let r = get(&app, &list(w.junta), &cj).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    for (id, a, body) in [
        (p1, "approve", "{}".to_owned()),
        (p1, "reject", reason("x")),
        (p2, "revoke", reason("x")),
    ] {
        let r = post(&app, &act(w.junta, id, a), &cj, &body).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{a}: {}", r.body);
    }
    assert_eq!(row(&w, p1).await?.0, "pending");
    assert_eq!(row(&w, p2).await?.0, "active");
    let evs = reader.events(&w.app, Some(jun)).await?;
    assert_eq!(
        count(&evs, |e| is(e, "outcome", "denied")
            && is(e, "reason", "idor")),
        4,
        "{evs:?}"
    );
    assert_eq!(revoked_alerts(&w).await?, 0);
    cleanup(&ns).await
}
