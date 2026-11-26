//! Timeline da caixa negra no Super-Admin (cartão 02/23), contra Postgres e Redis reais, pela API
//! real (`http::api`) com sessões e captcha falso.
//!
//! A porta da BD (`identity_admin_read_events`, 0026) exige `session_user = ptmarket_app`: a pool da
//! API LIGA como `ptmarket_app` (password de dev `PTM_APP_PASSWORD`, por omissão `dev_app`); a pool
//! com `SET ROLE` (session_user = migrator) prova o 42501 → 404. Infra de teste copiada de
//! `tests/totp.rs` (cada ficheiro de `tests/` é um crate; não há módulo comum).

use std::{
    collections::HashSet,
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
use base64::{Engine, engine::general_purpose::STANDARD};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{self, ActorType, AuditCtx, AuditEvent, Outcome},
    http::{api, audit_layer::AuditLayerState, client_ip::TrustedProxies},
    identity::{
        AccountKey, CaptchaVerifier, Login, Password, Sessions, Totp,
        crypto::EncKey,
        password,
        totp::{base32_decode, code, step_at},
    },
    state::AppState,
    storage::NullStorage,
    tenancy::{HostResolver, TenantId, begin_tenant_tx, db::begin_platform_tx},
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
const EVENTS: &str = "/api/v1/superadmin/audit/events";

// ---------------------------------------------------------------------------------------------
// Infra (de `tests/totp.rs`)
// ---------------------------------------------------------------------------------------------

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

/// Ligação REAL como `ptmarket_app` (session_user = ptmarket_app) a esta BD de teste. A password de
/// dev (`dev_app`) só vale em `127.0.0.1`/`localhost`; noutro host `PTM_APP_PASSWORD` é obrigatória.
async fn app_login_pool(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
) -> anyhow::Result<PgPool> {
    let local = matches!(conn.get_host(), "127.0.0.1" | "localhost");
    let pw = match std::env::var("PTM_APP_PASSWORD") {
        Ok(pw) => pw,
        Err(_) if local => "dev_app".to_owned(),
        Err(_) => anyhow::bail!(
            "PTM_APP_PASSWORD em falta: o DATABASE_URL aponta para {} (não local) e os testes \
             da timeline têm de ligar como ptmarket_app",
            conn.get_host()
        ),
    };
    Ok(opts
        .clone()
        .max_connections(6)
        .connect_with(conn.clone().username("ptmarket_app").password(&pw))
        .await?)
}

/// Ligação do migrator com `SET ROLE ptmarket_app` (session_user continua a ser o migrator).
async fn set_role_pool(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(3)
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
    let key = AccountKey::new(ACCOUNT_KEY.to_owned().into());
    let sessions =
        Sessions::for_tests(pool.clone(), redis()?, CSRF_KEY.to_owned().into(), ns, None)
            .with_internal_token(Some(INTERNAL_TOKEN.to_owned().into()))
            .with_login(Login::new(Arc::new(FakeCaptcha), key))
            .with_totp(Totp::new(enc_key()?)?);
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

    fn events(&self) -> Vec<Value> {
        self.json()["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
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
    let mut headers = vec![(header::HOST, host)];
    if !cookie.is_empty() {
        headers.push((header::COOKIE, cookie));
    }
    send(app, Method::GET, uri, &headers, "").await
}

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

struct Tenant {
    id: Uuid,
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
    Ok(Tenant { id })
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

// ---------------------------------------------------------------------------------------------
// Próprios deste cartão
// ---------------------------------------------------------------------------------------------

/// `now() + delta` em RFC 3339 UTC (pela BD: o mesmo relógio de `created_at`).
async fn at(owner: &PgPool, delta_hours: i32) -> anyhow::Result<String> {
    let s = sqlx::query_scalar!(
        r#"SELECT to_char((now() + make_interval(hours => $1)) AT TIME ZONE 'UTC',
                          'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "s!""#,
        delta_hours
    )
    .fetch_one(owner)
    .await?;
    Ok(s)
}

struct Seeded {
    tenant: Uuid,
    store: Uuid,
    actor: Uuid,
    action: &'static str,
    target_type: Option<&'static str>,
    target_id: Option<String>,
    changes: Option<Value>,
}

/// Evento semântico de um ator de loja no tenant (pela app, como um handler).
async fn seed_event(app: &PgPool, s: Seeded) -> TestResult {
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(s.actor), None, None);
    let mut tx = begin_tenant_tx(app, TenantId::for_tests(s.tenant), &ctx).await?;
    audit::record(
        &mut tx,
        AuditEvent {
            action: s.action,
            target_type: s.target_type,
            target_id: s.target_id,
            outcome: Outcome::Success,
            reason: None,
            changes: s.changes,
            store_id: Some(s.store),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Timeline com a janela `[from, to)` e os parâmetros extra (`k=v&...`).
async fn timeline(
    app: &Router,
    cookie: &str,
    from: &str,
    to: &str,
    extra: &str,
) -> anyhow::Result<Reply> {
    let mut uri = format!("{EVENTS}?from={from}&to={to}");
    if !extra.is_empty() {
        uri.push('&');
        uri.push_str(extra);
    }
    get(app, PLATFORM, &uri, cookie).await
}

/// 200 e os eventos.
async fn ok_events(
    app: &Router,
    cookie: &str,
    from: &str,
    to: &str,
    extra: &str,
) -> anyhow::Result<Vec<Value>> {
    let r = timeline(app, cookie, from, to, extra).await?;
    anyhow::ensure!(
        r.status == StatusCode::OK,
        "{extra}: {} {}",
        r.status,
        r.body
    );
    Ok(r.events())
}

fn all_eq(evs: &[Value], k: &str, v: &str) -> bool {
    evs.iter().all(|e| e[k].as_str() == Some(v))
}

// ---------------------------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------------------------

/// Filtros (tenant, loja, utilizador, encomenda), cursor estável em 3 páginas, 1 evento por leitura
/// (gravado pela BD), recusas: não super_admin / sem 2FA → 404 + `superadmin_gate`; 42501 da porta
/// → 404 + denied; 22023 (janela, limite) e query inválida → 400 (as da BD com denied).
#[sqlx::test(migrations = "../migrations")]
async fn timeline_filters_cursor_and_denials(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_login_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let b = seed_tenant(&owner, "camara-b").await?;
    let sa = seed_user(&owner, "raiz@x.pt", &[("super_admin", None, None)]).await?;
    let raw = seed_user(&owner, "semtotp@x.pt", &[("super_admin", None, None)]).await?;
    let tadmin = seed_user(&owner, "camara@x.pt", &[("tenant_admin", Some(a.id), None)]).await?;
    let ns = format!("test:timeline:{}:", Uuid::now_v7());
    let app = router(&pool, &ns)?;

    // super_admin: TOTP ativado pela API → sessão de plataforma elevada.
    let c0 = login(&app, PLATFORM, "raiz@x.pt").await?;
    let r = post(&app, PLATFORM, "/api/v1/staff/mfa/totp/enroll", &c0, "{}").await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let b32 = r.json()["secret_base32"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let secret = base32_decode(&b32).ok_or_else(|| anyhow::anyhow!("base32"))?;
    let good = format!("{:06}", code(&secret, step_at(SystemTime::now())));
    let r = post(
        &app,
        PLATFORM,
        "/api/v1/staff/mfa/totp/confirm",
        &c0,
        &json!({ "code": good }).to_string(),
    )
    .await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let c = r.cookie()?;

    // Dados: 2 tenants, 3 lojas, 2 utilizadores, 1 encomenda (criada, paga, faturada).
    let (s1, s2, s3) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let (u1, u2) = (Uuid::now_v7(), Uuid::now_v7());
    let order = Uuid::now_v7();
    let upd = |tenant, store, actor| Seeded {
        tenant,
        store,
        actor,
        action: "catalog.product.update",
        target_type: Some("product"),
        target_id: Some(Uuid::now_v7().to_string()),
        changes: None,
    };
    for s in [
        upd(a.id, s1, u1),
        upd(a.id, s1, u1),
        upd(a.id, s1, u1),
        upd(a.id, s2, u2),
        upd(a.id, s2, u2),
        Seeded {
            action: "order.created",
            target_type: Some("order"),
            target_id: Some(order.to_string()),
            ..upd(a.id, s1, u1)
        },
        Seeded {
            action: "payment.captured",
            target_type: Some("payment"),
            changes: Some(json!({ "order_id": order, "amount_cents": 1234 })),
            ..upd(a.id, s1, u1)
        },
        Seeded {
            action: "invoice.issued",
            target_type: Some("invoice"),
            changes: Some(json!({ "order_id": order })),
            ..upd(a.id, s1, u2)
        },
        upd(b.id, s3, u1),
        upd(b.id, s3, u1),
        upd(b.id, s3, u2),
    ] {
        seed_event(&pool, s).await?;
    }
    let from = at(&owner, -1).await?;
    let to = at(&owner, 1).await?;
    let mut reads = 0usize;
    let mut ok = |extra: String| {
        reads += 1;
        extra
    };

    // Filtros.
    let ta = ok_events(&app, &c, &from, &to, &ok(format!("tenant_id={}", a.id))).await?;
    // + 2 do trigger da BD no seed (tenants.insert, user_roles.insert do tenant_admin).
    assert_eq!(ta.len(), 10, "{ta:?}");
    assert!(all_eq(&ta, "tenant_id", &a.id.to_string()));
    assert!(ta.iter().all(|e| e["chain_ok"] == json!(true)), "{ta:?}");
    assert!(
        ta.windows(2)
            .all(|w| w[0]["created_at"].as_str() >= w[1]["created_at"].as_str()),
        "mais recentes primeiro"
    );
    let tb = ok_events(&app, &c, &from, &to, &ok(format!("tenant_id={}", b.id))).await?;
    assert_eq!(tb.len(), 4); // + tenants.insert
    assert!(all_eq(&tb, "tenant_id", &b.id.to_string()));
    let st1 = ok_events(&app, &c, &from, &to, &ok(format!("store_id={s1}"))).await?;
    assert_eq!(st1.len(), 6);
    assert!(all_eq(&st1, "store_id", &s1.to_string()));
    let st2 = ok_events(&app, &c, &from, &to, &ok(format!("store_id={s2}"))).await?;
    assert_eq!(st2.len(), 2);
    let a1 = ok_events(&app, &c, &from, &to, &ok(format!("actor_id={u1}"))).await?;
    assert_eq!(a1.len(), 7);
    assert!(all_eq(&a1, "actor_id", &u1.to_string()));
    let a2 = ok_events(
        &app,
        &c,
        &from,
        &to,
        &ok(format!("tenant_id={}&actor_id={u2}", a.id)),
    )
    .await?;
    assert_eq!(a2.len(), 3);
    let o = ok_events(&app, &c, &from, &to, &ok(format!("order_id={order}"))).await?;
    let actions: HashSet<&str> = o.iter().filter_map(|e| e["action"].as_str()).collect();
    assert_eq!(
        actions,
        HashSet::from(["order.created", "payment.captured", "invoice.issued"])
    );
    assert_eq!(o.len(), 3);
    let pay = o
        .iter()
        .find(|e| e["action"] == "payment.captured")
        .cloned()
        .unwrap_or_default();
    assert_eq!(pay["changes"]["order_id"], json!(order));
    assert_eq!(pay["actor_type"], "merchant");
    assert!(pay["chain_seq"].as_i64().is_some());

    // Cursor: 3 páginas de 4 sobre os 10 do tenant A, sem repetidos nem buracos.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for page in 0..3 {
        let extra = match &cursor {
            None => format!("tenant_id={}&limit=4", a.id),
            Some(cur) => format!("tenant_id={}&limit=4&cursor={cur}", a.id),
        };
        let r = timeline(&app, &c, &from, &to, &ok(extra)).await?;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let evs = r.events();
        assert_eq!(evs.len(), if page < 2 { 4 } else { 2 });
        seen.extend(
            evs.iter()
                .filter_map(|e| e["id"].as_str().map(str::to_owned)),
        );
        cursor = r.json()["next_cursor"].as_str().map(str::to_owned);
        assert_eq!(cursor.is_some(), page < 2, "página {page}: {}", r.body);
    }
    let expected: Vec<String> = ta
        .iter()
        .filter_map(|e| e["id"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        seen, expected,
        "páginas = a lista completa, pela mesma ordem"
    );

    // Recusas da BD (22023) → 400; da forma (app) → 400 sem ir à BD.
    let long = at(&owner, -24 * 40).await?;
    let day = at(&owner, -25).await?;
    for (f, extra) in [
        (from.as_str(), format!("tenant_id={}&limit=101", a.id)),
        (long.as_str(), format!("tenant_id={}", a.id)),
        (day.as_str(), String::new()),
        (from.as_str(), "action_prefix=Nope%25".to_owned()),
        (from.as_str(), "extra=1".to_owned()),
        (from.as_str(), "cursor=abc".to_owned()),
        (from.as_str(), "tenant_id=nao-uuid".to_owned()),
        // Fuso acima de ±15:59: a app recusa (o Postgres daria 22009); nunca 503.
        ("2026-11-26T10:00:00%2B16:00", format!("tenant_id={}", a.id)),
    ] {
        let r = timeline(&app, &c, f, &to, &extra).await?;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{extra}: {}", r.body);
        assert!(r.json()["events"].is_null(), "nenhum dado");
    }
    let r = get(&app, PLATFORM, &format!("{EVENTS}?from=ontem&to={to}"), &c).await?;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Não super_admin / sem 2FA / anónimo → 404 uniforme (gate).
    let p_raw = login(&app, PLATFORM, "semtotp@x.pt").await?;
    let p_sa = login(&app, PLATFORM, "raiz@x.pt").await?; // TOTP ativo, sessão sem 2FA
    // Painel único (cartão 03/13): o tenant_admin também só entra na plataforma.
    let t_admin = login(&app, PLATFORM, "camara@x.pt").await?;
    let q = format!("tenant_id={}", a.id);
    for cookie in [&p_raw, &p_sa, ""] {
        let r = timeline(&app, cookie, &from, &to, &q).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    }
    let uri = format!("{EVENTS}?from={from}&to={to}&{q}");
    let r = get(&app, PLATFORM, &uri, &t_admin).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // 42501 da porta (ligação com SET ROLE: session_user ≠ ptmarket_app) → 404 + denied.
    let setrole = set_role_pool(&opts, &conn).await?;
    let app_sr = router(&setrole, &ns)?;
    let r = timeline(&app_sr, &c, &from, &to, &q).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    assert!(r.json()["events"].is_null());

    // Cada leitura com sucesso deixou 1 evento (BD) com os filtros; as recusas da BD, `denied`.
    let mine = ok_events(
        &app,
        &c,
        &from,
        &to,
        &format!("actor_id={sa}&action_prefix=admin.audit_timeline.read&limit=100"),
    )
    .await?;
    let success: Vec<&Value> = mine.iter().filter(|e| e["outcome"] == "success").collect();
    assert_eq!(success.len(), reads, "1 evento por leitura");
    assert!(all_eq(&mine, "actor_type", "admin"));
    assert!(success.iter().any(|e| {
        e["changes"]["tenant_id"] == json!(a.id) && e["changes"]["limit"] == json!(4)
    }));
    let denied: Vec<&Value> = mine.iter().filter(|e| e["outcome"] == "denied").collect();
    let reasons: Vec<&str> = denied.iter().filter_map(|e| e["reason"].as_str()).collect();
    assert_eq!(
        reasons
            .iter()
            .filter(|r| **r == "invalid_parameter")
            .count(),
        9, // 4 da BD (22023) + 5 da forma (extra, cursor, uuid, fuso, `from=ontem`)
        "{reasons:?}"
    );
    assert_eq!(
        reasons
            .iter()
            .filter(|r| **r == "db_access_refused")
            .count(),
        1,
        "{reasons:?}"
    );
    assert!(
        denied
            .iter()
            .any(|e| e["changes"]["limit"] == json!(101) && e["changes"]["cursor"] == json!(false))
    );

    // As recusas do gate ficaram na caixa negra (`superadmin_gate`, pelo middleware).
    for who in [raw, sa, tadmin] {
        let evs = ok_events(
            &app,
            &c,
            &from,
            &to,
            &format!("actor_id={who}&outcome=denied"),
        )
        .await?;
        assert!(
            evs.iter().any(|e| e["reason"] == "superadmin_gate"),
            "{who}: {evs:?}"
        );
    }
    cleanup(&ns).await
}

/// `app.session_id` vai para todas as transações de um contexto com sessão (tenant e plataforma) e
/// fica vazio sem sessão e depois do COMMIT.
#[sqlx::test(migrations = "../migrations")]
async fn session_id_guc_in_every_tx(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let pool = app_login_pool(&opts, &conn).await?;
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-s").await?;
    let sid = Uuid::now_v7();
    let base = AuditCtx::for_tests(ActorType::Admin, Some(Uuid::now_v7()), None, None);
    let with = base.clone().with_session_for_tests(sid);
    assert_eq!(with.session_id(), Some(sid));

    let mut tx = begin_platform_tx(&pool, &with).await?;
    let v = sqlx::query_scalar!(r#"SELECT current_setting('app.session_id', true) AS "v!""#)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(v, sid.to_string());
    tx.commit().await?;

    let mut tx = begin_tenant_tx(&pool, TenantId::for_tests(t.id), &with).await?;
    let v = sqlx::query_scalar!(r#"SELECT current_setting('app.session_id', true) AS "v!""#)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(v, sid.to_string());
    tx.rollback().await?;

    let mut tx = begin_platform_tx(&pool, &base).await?;
    let v = sqlx::query_scalar!(r#"SELECT current_setting('app.session_id', true) AS "v!""#)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(v, "");
    tx.rollback().await?;

    // Fora de transação (a ligação volta à pool): nada fica.
    let v = sqlx::query_scalar!(
        r#"SELECT COALESCE(current_setting('app.session_id', true), '') AS "v!""#
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(v, "");
    Ok(())
}
