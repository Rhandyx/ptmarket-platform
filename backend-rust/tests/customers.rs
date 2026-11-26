//! Clientes (cartão 02/17): registo sem enumeração de emails e perfil `/me`, contra Postgres e
//! Redis reais, pela API real (`http::api`) com sessões e captcha/HIBP falsos (sem rede).
//!
//! As pools da app fazem `SET ROLE ptmarket_app`; o outbox lê-se como `ptmarket_worker` e a
//! contagem de contas como `ptmarket_identity` (as únicas leituras que esses papéis têm). Leituras
//! de `audit.*` e da função `identity_customer_credentials` sem `query!` (o migrator não tem
//! privilégios para o EXPLAIN): SQL estático com casts.

use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{HeaderName, Method, Request, StatusCode, header},
};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    http::{api, audit_layer::AuditLayerState, client_ip::TrustedProxies},
    identity::{
        BreachChecker, CaptchaVerifier, Password, Registration, Sessions, Subject,
        csrf::X_CSRF_TOKEN,
        password,
        session::{self, COOKIE_TENANT},
    },
    state::AppState,
    storage::NullStorage,
    tenancy::{HostResolver, TenantId, begin_tenant_tx},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
const REGISTER_URI: &str = "/api/v1/auth/register";
const ME_URI: &str = "/api/v1/me";
const SESSION_URI: &str = "/api/v1/auth/session";
const PW: &str = "uma-frase-longa-e-boa";
const CAPTCHA_OK: &str = "captcha-ok";
const CAPTCHA_OTHER_SITE: &str = "captcha-de-outro-site";

// ---------------------------------------------------------------------------------------------
// Fakes (sem rede)
// ---------------------------------------------------------------------------------------------

/// Só aceita o token `CAPTCHA_OK`, resolvido no host do tenant do pedido (os tenants dos testes
/// são `*.ptmarket.invalid`; `CAPTCHA_OTHER_SITE` simula um token resolvido noutro site).
struct FakeCaptcha;

#[async_trait]
impl CaptchaVerifier for FakeCaptcha {
    async fn verify(&self, token: &str, _ip: Option<IpAddr>, expected_host: &str) -> bool {
        let solved_on = if token == CAPTCHA_OTHER_SITE {
            "outro-site.invalid"
        } else {
            expected_host
        };
        (token == CAPTCHA_OK || token == CAPTCHA_OTHER_SITE)
            && expected_host.ends_with(".ptmarket.invalid")
            && solved_on == expected_host
    }
}

/// Considera (ou não) todas as passwords vazadas.
struct StaticBreach(bool);

#[async_trait]
impl BreachChecker for StaticBreach {
    async fn is_breached(&self, _p: &Password) -> bool {
        self.0
    }
}

// ---------------------------------------------------------------------------------------------
// Infra
// ---------------------------------------------------------------------------------------------

async fn role_pool(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
    role: &'static str,
    max: u32,
) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(max)
        .after_connect(move |c, _meta| {
            Box::pin(async move {
                match role {
                    "app" => sqlx::query!("SET ROLE ptmarket_app").execute(c).await?,
                    "worker" => sqlx::query!("SET ROLE ptmarket_worker").execute(c).await?,
                    _ => {
                        sqlx::query!("SET ROLE ptmarket_identity")
                            .execute(c)
                            .await?
                    }
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

struct Db {
    app: PgPool,
    worker: PgPool,
    identity: PgPool,
    owner: PgPool,
}

async fn db(opts: &PgPoolOptions, conn: &PgConnectOptions) -> anyhow::Result<Db> {
    Ok(Db {
        app: role_pool(opts, conn, "app", 6).await?,
        worker: role_pool(opts, conn, "worker", 1).await?,
        identity: role_pool(opts, conn, "identity", 1).await?,
        owner: owner_pool(opts, conn).await?,
    })
}

fn redis() -> anyhow::Result<deadpool_redis::Pool> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    Ok(deadpool_redis::Config::from_url(url).create_pool(Some(Runtime::Tokio1))?)
}

/// BD de auditoria em baixo: porta onde nada escuta.
fn dead_db() -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(500))
        .connect_lazy("postgres://ninguem:nada@127.0.0.1:1/db")?)
}

fn namespace() -> String {
    format!("test:cust:{}:", Uuid::now_v7())
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

fn state(app: &PgPool) -> anyhow::Result<AppState> {
    Ok(AppState {
        db_primary: app.clone(),
        db_replica: app.clone(),
        redis: redis()?,
        storage: Arc::new(NullStorage),
        hosts: Arc::new(HostResolver::new(
            app.clone(),
            None,
            Some(INTERNAL_TOKEN.to_owned().into()),
        )),
    })
}

/// A API real com sessões de teste; `breached` = o HIBP falso diz que toda a password vazou;
/// `audit_db` = BD da caixa negra (`None` = a mesma da app).
fn app_router(
    app: &PgPool,
    ns: &str,
    breached: bool,
    audit_db: Option<PgPool>,
) -> anyhow::Result<Router> {
    app_router_with(app, ns, breached, audit_db, Duration::ZERO)
}

/// Como `app_router`, com o tempo mínimo de resposta do registo (`Duration::ZERO` nos testes
/// funcionais; o de produção é 1 s).
fn app_router_with(
    app: &PgPool,
    ns: &str,
    breached: bool,
    audit_db: Option<PgPool>,
    min_response: Duration,
) -> anyhow::Result<Router> {
    let st = state(app)?;
    let registration = Registration::new(Arc::new(FakeCaptcha), Arc::new(StaticBreach(breached)))
        .with_min_response_for_tests(min_response);
    let sessions = Sessions::for_tests(app.clone(), redis()?, CSRF_KEY.to_owned().into(), ns, None)
        .with_internal_token(Some(INTERNAL_TOKEN.to_owned().into()))
        .with_registration(registration);
    let audit = AuditLayerState::for_tests(
        audit_db.unwrap_or_else(|| app.clone()),
        redis()?,
        TrustedProxies::none(),
        ns,
        Duration::from_secs(1),
    );
    Ok(api(st.clone(), audit, Some(sessions)).with_state(st))
}

struct Tenant {
    id: Uuid,
    domain: String,
}

impl Tenant {
    fn tid(&self) -> TenantId {
        TenantId::for_tests(self.id)
    }

    fn origin(&self) -> String {
        format!("https://{}", self.domain)
    }
}

async fn seed_tenant(owner: &PgPool, slug: &str, country: &str) -> sqlx::Result<Tenant> {
    let id = Uuid::now_v7();
    let domain = format!("{slug}.ptmarket.invalid");
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, country_code)
         VALUES ($1, $2, $3, $4, $5)",
        id,
        slug,
        domain,
        format!("Câmara {slug}"),
        country
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

    fn rid(&self) -> anyhow::Result<Uuid> {
        self.request_id
            .ok_or_else(|| anyhow::anyhow!("sem x-request-id"))
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

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

/// Corpo de registo válido (sem `marketing`: tem de ficar `false`).
fn register_body(email: &str, name: &str) -> Value {
    json!({
        "email": email,
        "password": PW,
        "name": name,
        "consents": {"terms_version": "2026-11", "privacy_version": "2026-11"},
        "turnstile_token": CAPTCHA_OK,
        "website": "",
        "form_started_at": now_ms() - 5_000,
    })
}

async fn register(app: &Router, t: &Tenant, body: &Value) -> anyhow::Result<Reply> {
    send(
        app,
        Method::POST,
        REGISTER_URI,
        &[
            (header::HOST, &t.domain),
            (header::CONTENT_TYPE, "application/json"),
        ],
        &body.to_string(),
    )
    .await
}

/// Total de contas (como `ptmarket_identity`: só vê id/email/hash).
async fn customer_count(d: &Db) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM customers"#)
            .fetch_one(&d.identity)
            .await?,
    )
}

/// id + hash pela única leitura por email (`identity_customer_credentials`, como no login).
async fn credentials(app: &PgPool, email: &str) -> anyhow::Result<Option<(Uuid, Option<String>)>> {
    Ok(sqlx::query_as(
        "SELECT c.id::uuid, c.password_hash::text
         FROM public.identity_customer_credentials($1::text) AS c",
    )
    .bind(email)
    .fetch_optional(app)
    .await?)
}

/// Eventos de outbox `customer.duplicate_registration`: (tenant_id, payload).
async fn duplicate_events(d: &Db) -> anyhow::Result<Vec<(Option<Uuid>, Value)>> {
    let rows = sqlx::query!(
        "SELECT tenant_id, payload FROM outbox_events
         WHERE event_type = 'customer.duplicate_registration' ORDER BY id"
    )
    .fetch_all(&d.worker)
    .await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.payload)).collect())
}

/// Eventos da caixa negra do tenant `t` (com filtro por pedido ou por ação).
async fn events(
    app: &PgPool,
    t: &Tenant,
    rid: Option<Uuid>,
    action: Option<&str>,
) -> anyhow::Result<Vec<EvRow>> {
    let reader = AuditCtx::for_tests(ActorType::System, None, None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &reader).await?;
    let rows: Vec<EvRow> = sqlx::query_as(
        "SELECT action::text, outcome::text, reason::text, actor_type::text, actor_id::uuid,
                target_type::text, target_id::text, changes::text
         FROM audit.audit_events
         WHERE ($1::uuid IS NULL OR request_id = $1::uuid)
           AND ($2::text IS NULL OR action = $2::text)
         ORDER BY chain_seq",
    )
    .bind(rid)
    .bind(action)
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(rows)
}

/// "Login": verifica a password contra o hash da conta e cria a sessão no host de `t`.
async fn login(app: &PgPool, t: &Tenant, email: &str) -> anyhow::Result<(Uuid, String)> {
    let (id, phc) = credentials(app, email)
        .await?
        .ok_or_else(|| anyhow::anyhow!("conta inexistente"))?;
    let v = password::verify(&Password::parse(PW)?, phc.as_deref()).await?;
    anyhow::ensure!(v.ok, "password não confere");
    let ctx = AuditCtx::for_tests(ActorType::Customer, Some(id), None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &ctx).await?;
    let (_, value) = session::create(&mut tx, Subject::Customer(id), Some(t.tid()), &ctx).await?;
    tx.commit().await?;
    Ok((id, format!("{COOKIE_TENANT}={}", value.expose())))
}

async fn get_me(
    app: &Router,
    t: &Tenant,
    cookie: Option<&str>,
    uri: &str,
) -> anyhow::Result<Reply> {
    let mut h = vec![(header::HOST, t.domain.as_str())];
    if let Some(c) = cookie {
        h.push((header::COOKIE, c));
    }
    send(app, Method::GET, uri, &h, "").await
}

async fn csrf_token(app: &Router, t: &Tenant, cookie: &str) -> anyhow::Result<String> {
    let r = send(
        app,
        Method::GET,
        SESSION_URI,
        &[(header::HOST, &t.domain), (header::COOKIE, cookie)],
        "",
    )
    .await?;
    r.json()["csrf_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("sem csrf_token: {}", r.body))
}

async fn patch_me(
    app: &Router,
    t: &Tenant,
    cookie: &str,
    csrf: Option<&str>,
    body: &Value,
) -> anyhow::Result<Reply> {
    let origin = t.origin();
    let mut h = vec![
        (header::HOST, t.domain.as_str()),
        (header::COOKIE, cookie),
        (header::ORIGIN, origin.as_str()),
        (header::CONTENT_TYPE, "application/json"),
    ];
    if let Some(tok) = csrf {
        h.push((X_CSRF_TOKEN, tok));
    }
    send(app, Method::PATCH, ME_URI, &h, &body.to_string()).await
}

fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Registo: 202 sempre igual, sem enumeração; conta global
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn register_creates_account_and_duplicates_are_indistinguishable(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let d = db(&opts, &conn).await?;
    let a = seed_tenant(&d.owner, "camara-a", "PT").await?;
    let b = seed_tenant(&d.owner, "camara-b", "PT").await?;
    let ns = namespace();
    let app = app_router(&d.app, &ns, false, None)?;
    let email = "jo\u{e3}o.silva@exemplo.pt";

    let first = register(
        &app,
        &a,
        &register_body("Jo\u{e3}o.Silva@Exemplo.pt", "João"),
    )
    .await?;
    assert_eq!(first.status, StatusCode::ACCEPTED, "{}", first.body);
    assert_eq!(first.body, r#"{"status":"ok"}"#);
    assert!(
        first.headers.iter().all(|(k, _)| k != "set-cookie"),
        "não inicia sessão"
    );
    assert_eq!(customer_count(&d).await?, 1);

    // Linha: email normalizado, hash Argon2id.
    let (id, phc) = credentials(&d.app, email)
        .await?
        .ok_or_else(|| anyhow::anyhow!("conta não criada"))?;
    assert!(
        phc.as_deref()
            .is_some_and(|h| h.starts_with("$argon2id$v=19$")),
        "{phc:?}"
    );
    // Eventos: customers.insert (L1, anónimo, PII mascarada) + customer.registered (id, nunca email).
    let evs = events(&d.app, &a, Some(first.rid()?), None).await?;
    let insert = evs.iter().find(|e| e.0 == "customers.insert");
    assert!(
        insert.is_some_and(|e| e.3 == "anonymous" && e.4.is_none()),
        "{evs:?}"
    );
    assert!(insert.is_some_and(|e| e.7.as_deref().is_some_and(|c| !c.contains("exemplo.pt"))));
    let reg = evs.iter().find(|e| e.0 == "customer.registered");
    assert!(
        reg.is_some_and(|e| e.6.as_deref() == Some(id.to_string().as_str())),
        "{evs:?}"
    );
    assert!(
        evs.iter().all(|e| !format!("{e:?}").contains("exemplo.pt")),
        "{evs:?}"
    );

    // O mesmo email (espaços, maiúsculas, NFD): 202 byte a byte igual, 1 linha, 1 evento por vez.
    let variants = [
        "  JO\u{c3}O.SILVA@EXEMPLO.PT \t".to_owned(),
        "joa\u{303}o.silva@exemplo.pt".to_owned(),
        email.to_owned(),
    ];
    for (i, v) in variants.iter().enumerate() {
        let r = register(&app, &a, &register_body(v, "Outro")).await?;
        assert_eq!(r.status, first.status, "{v:?}: {}", r.body);
        assert_eq!(r.body, first.body, "{v:?}");
        assert_eq!(r.headers, first.headers, "{v:?}");
        assert_eq!(customer_count(&d).await?, 1, "{v:?}");
        let dups = duplicate_events(&d).await?;
        assert_eq!(dups.len(), i + 1, "{v:?}");
        let (tenant, payload) = &dups[i];
        assert_eq!(*tenant, Some(a.id));
        assert_eq!(*payload, json!({ "customer_id": id }));
        let evs = events(&d.app, &a, Some(r.rid()?), None).await?;
        assert!(
            evs.iter().any(|e| e.0 == "customer.register_duplicate"
                && e.5.as_deref() == Some("account_hash")
                && e.6.as_deref() == Some(sha256_hex(email).as_str())),
            "{evs:?}"
        );
        assert!(
            evs.iter().all(|e| !format!("{e:?}").contains("exemplo.pt")),
            "{evs:?}"
        );
        assert!(evs.iter().all(|e| e.0 != "customers.insert"), "{evs:?}");
    }

    // Conta global: autentica-se em dois tenants e vê o mesmo perfil.
    for t in [&a, &b] {
        let (cid, cookie) = login(&d.app, t, email).await?;
        assert_eq!(cid, id);
        let r = get_me(&app, t, Some(&cookie), ME_URI).await?;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let p = r.json();
        assert_eq!(p["id"], id.to_string());
        assert_eq!(p["email"], email);
        assert_eq!(p["name"], "João");
        let c = &p["consents"];
        assert_eq!(c["terms"]["version"], "2026-11");
        assert_eq!(c["privacy"]["version"], "2026-11");
        assert_eq!(c["marketing"]["granted"], false);
        for k in ["terms", "privacy", "marketing"] {
            assert!(c[k]["at"].as_str().is_some_and(|s| s.ends_with('Z')), "{c}");
        }
    }
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn invalid_registrations_are_422_without_rows(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let d = db(&opts, &conn).await?;
    let a = seed_tenant(&d.owner, "camara-a", "PT").await?;
    let ns = namespace();
    let app = app_router(&d.app, &ns, false, None)?;
    let ok = register_body("x@exemplo.pt", "X");

    let mut no_terms = ok.clone();
    no_terms["consents"] = json!({"privacy_version": "2026-11"});
    let mut unknown = ok.clone();
    unknown["is_admin"] = json!(true);
    let mut unknown_consent = ok.clone();
    unknown_consent["consents"]["outro"] = json!(true);
    let mut short_pw = ok.clone();
    short_pw["password"] = json!("curta");
    let mut bad_email = ok.clone();
    bad_email["email"] = json!("sem-arroba");
    for (what, body) in [
        ("sem terms_version", no_terms),
        ("campo desconhecido", unknown),
        ("consentimento desconhecido", unknown_consent),
        ("password curta", short_pw),
        ("email inválido", bad_email),
    ] {
        let r = register(&app, &a, &body).await?;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{what}: {}",
            r.body
        );
        assert_eq!(r.json()["error"]["code"], "validation", "{what}");
    }

    // Bots: honeypot, depressa demais, captcha falso → 422 genérico + recusa "bot".
    let mut honeypot = ok.clone();
    honeypot["website"] = json!("https://spam.invalid");
    let mut fast = ok.clone();
    fast["form_started_at"] = json!(now_ms() - 500);
    let mut captcha = ok.clone();
    captcha["turnstile_token"] = json!("token-falso");
    let mut other_site = ok.clone();
    other_site["turnstile_token"] = json!(CAPTCHA_OTHER_SITE);
    for (what, body) in [
        ("honeypot", honeypot),
        ("rápido", fast),
        ("captcha", captcha),
        ("captcha de outro site", other_site),
    ] {
        // Prefixo Redis próprio: a 1.ª recusa anónima da janela é gravada de forma síncrona.
        let ns_bot = namespace();
        let bot_app = app_router(&d.app, &ns_bot, false, None)?;
        let r = register(&bot_app, &a, &body).await?;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{what}: {}",
            r.body
        );
        assert_eq!(r.json()["error"]["fields"], json!([]), "{what}: genérico");
        let evs = events(&d.app, &a, Some(r.rid()?), None).await?;
        assert_eq!(evs.len(), 1, "{what}: {evs:?}");
        assert!(
            evs[0].1 == "denied" && evs[0].2.as_deref() == Some("bot"),
            "{what}: {evs:?}"
        );
        cleanup(&ns_bot).await?;
    }

    // Password vazada → 422 no campo password.
    let leaky = app_router(&d.app, &ns, true, None)?;
    let r = register(&leaky, &a, &ok).await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    assert_eq!(r.json()["error"]["fields"][0]["field"], "password");

    assert_eq!(customer_count(&d).await?, 0);
    assert!(duplicate_events(&d).await?.is_empty());

    // O mesmo corpo, com tudo certo, passa (o 422 acima não foi por acaso).
    let r = register(&app, &a, &ok).await?;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{}", r.body);
    assert_eq!(customer_count(&d).await?, 1);
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn every_register_outcome_takes_the_minimum_time(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let d = db(&opts, &conn).await?;
    let a = seed_tenant(&d.owner, "camara-a", "PT").await?;
    let ns = namespace();
    let min = Duration::from_millis(400);
    let app = app_router_with(&d.app, &ns, false, None, min)?;
    let ok = register_body("t@exemplo.pt", "T");
    let mut honeypot = ok.clone();
    honeypot["website"] = json!("x");
    let mut bad_email = ok.clone();
    bad_email["email"] = json!("t@@exemplo.pt");
    for (what, body, status) in [
        ("nova", ok.clone(), StatusCode::ACCEPTED),
        ("repetida", ok, StatusCode::ACCEPTED),
        ("bot", honeypot, StatusCode::UNPROCESSABLE_ENTITY),
        ("validação", bad_email, StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let t = std::time::Instant::now();
        let r = register(&app, &a, &body).await?;
        let took = t.elapsed();
        assert_eq!(r.status, status, "{what}: {}", r.body);
        assert!(took >= min, "{what}: {took:?}");
    }
    assert_eq!(customer_count(&d).await?, 1);
    assert_eq!(duplicate_events(&d).await?.len(), 1);
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// /me: só o próprio; 401 auditado; leitura síncrona
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn me_returns_only_the_session_owner(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let d = db(&opts, &conn).await?;
    let a = seed_tenant(&d.owner, "camara-a", "PT").await?;
    let ns = namespace();
    let app = app_router(&d.app, &ns, false, None)?;
    for (e, n) in [("x@exemplo.pt", "Xavier"), ("y@exemplo.pt", "Yara")] {
        assert_eq!(
            register(&app, &a, &register_body(e, n)).await?.status,
            StatusCode::ACCEPTED
        );
    }
    let (x, cx) = login(&d.app, &a, "x@exemplo.pt").await?;
    let (y, cy) = login(&d.app, &a, "y@exemplo.pt").await?;

    // Trocar cookies troca o perfil; um id no pedido não muda nada.
    for (cookie, id, name, other) in [(&cx, x, "Xavier", y), (&cy, y, "Yara", x)] {
        for uri in [ME_URI.to_owned(), format!("{ME_URI}?id={other}")] {
            let r = get_me(&app, &a, Some(cookie), &uri).await?;
            assert_eq!(r.status, StatusCode::OK, "{}", r.body);
            assert_eq!(r.json()["id"], id.to_string(), "{uri}");
            assert_eq!(r.json()["name"], name, "{uri}");
            assert!(!r.body.contains(&other.to_string()), "{uri}");
            assert!(
                r.headers
                    .contains(&("cache-control".into(), "no-store".into()))
            );
        }
        // Leitura de dados pessoais: evento síncrono do próprio.
        let r = get_me(&app, &a, Some(cookie), ME_URI).await?;
        let evs = events(&d.app, &a, Some(r.rid()?), None).await?;
        assert!(
            evs.iter()
                .any(|e| e.0 == "http.get" && e.3 == "customer" && e.4 == Some(id)),
            "{evs:?}"
        );
    }
    // PATCH com um id alheio no corpo: campo desconhecido → 422; Y fica igual.
    let tok = csrf_token(&app, &a, &cx).await?;
    let r = patch_me(
        &app,
        &a,
        &cx,
        Some(&tok),
        &json!({"id": y, "name": "Roubado"}),
    )
    .await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    assert_eq!(
        get_me(&app, &a, Some(&cy), ME_URI).await?.json()["name"],
        "Yara"
    );

    // Sem sessão: 401 + evento denied (router com prefixo Redis próprio: o 1.º 401 anónimo de cada
    // janela é síncrono, os seguintes só contam para o resumo).
    for method in [Method::GET, Method::PATCH] {
        let ns_anon = namespace();
        let anon = app_router(&d.app, &ns_anon, false, None)?;
        let r = send(
            &anon,
            method.clone(),
            ME_URI,
            &[
                (header::HOST, &a.domain),
                (header::CONTENT_TYPE, "application/json"),
            ],
            "{}",
        )
        .await?;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{method}: {}", r.body);
        let evs = events(&d.app, &a, Some(r.rid()?), None).await?;
        assert!(
            evs.iter()
                .any(|e| e.1 == "denied" && e.2.as_deref() == Some("unauthorized")),
            "{method}: {evs:?}"
        );
        cleanup(&ns_anon).await?;
    }
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn me_is_503_when_the_audit_db_is_down(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let d = db(&opts, &conn).await?;
    let a = seed_tenant(&d.owner, "camara-a", "PT").await?;
    let ns = namespace();
    let app = app_router(&d.app, &ns, false, None)?;
    assert_eq!(
        register(&app, &a, &register_body("x@exemplo.pt", "Xavier"))
            .await?
            .status,
        StatusCode::ACCEPTED
    );
    let (_, cookie) = login(&d.app, &a, "x@exemplo.pt").await?;
    let down = app_router(&d.app, &ns, false, Some(dead_db()?))?;
    let r = get_me(&down, &a, Some(&cookie), ME_URI).await?;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.body);
    assert!(!r.body.contains("Xavier") && !r.body.contains("x@exemplo.pt"));
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// PATCH /me: CSRF, NIF por país, caixa negra sem PII
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn patch_me_requires_csrf_validates_nif_and_audits_without_pii(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let d = db(&opts, &conn).await?;
    let pt = seed_tenant(&d.owner, "camara-pt", "PT").await?;
    let es = seed_tenant(&d.owner, "ayuntamiento-es", "ES").await?;
    let ns = namespace();
    let app = app_router(&d.app, &ns, false, None)?;
    assert_eq!(
        register(&app, &pt, &register_body("x@exemplo.pt", "Xavier"))
            .await?
            .status,
        StatusCode::ACCEPTED
    );
    let (x, cookie) = login(&d.app, &pt, "x@exemplo.pt").await?;
    let tok = csrf_token(&app, &pt, &cookie).await?;

    // Sem CSRF → 403 e nada muda.
    let r = patch_me(&app, &pt, &cookie, None, &json!({"name": "Sem CSRF"})).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    // NIF PT com dígito de controlo errado → 422.
    for bad in ["123456788", "12345678Z", "1234567890"] {
        let r = patch_me(&app, &pt, &cookie, Some(&tok), &json!({"nif": bad})).await?;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{bad}: {}",
            r.body
        );
        assert_eq!(r.json()["error"]["fields"][0]["field"], "nif");
    }
    let r = patch_me(
        &app,
        &pt,
        &cookie,
        Some(&tok),
        &json!({"phone": "9".repeat(51)}),
    )
    .await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    let me = get_me(&app, &pt, Some(&cookie), ME_URI).await?.json();
    assert_eq!(me["name"], "Xavier");
    assert!(me["nif"].is_null() && me["phone"].is_null());

    // PATCH válido: perfil novo; customers.update com ator customer e PII mascarada.
    let change = json!({
        "name": "Xavier Novo",
        "phone": "+351 912 345 678",
        "nif": "123456789",
        "marketing": true
    });
    let r = patch_me(&app, &pt, &cookie, Some(&tok), &change).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let p = r.json();
    assert_eq!(p["id"], x.to_string());
    assert_eq!(p["name"], "Xavier Novo");
    assert_eq!(p["phone"], "+351 912 345 678");
    assert_eq!(p["nif"], "123456789");
    assert_eq!(p["consents"]["marketing"]["granted"], true);
    assert_eq!(p["consents"]["terms"]["version"], "2026-11", "o resto fica");
    let evs = events(&d.app, &pt, Some(r.rid()?), Some("customers.update")).await?;
    assert_eq!(evs.len(), 1, "{evs:?}");
    let ev = &evs[0];
    assert_eq!((ev.3.as_str(), ev.4), ("customer", Some(x)));
    let changes = ev.7.clone().unwrap_or_default();
    assert!(changes.contains("[pii]"), "{changes}");
    for secret in ["Xavier", "912 345", "123456789"] {
        assert!(!changes.contains(secret), "{secret} em claro: {changes}");
    }

    // "" apaga telefone e NIF; o resto não muda.
    let r = patch_me(
        &app,
        &pt,
        &cookie,
        Some(&tok),
        &json!({"phone": "", "nif": ""}),
    )
    .await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.json()["phone"].is_null() && r.json()["nif"].is_null());
    assert_eq!(r.json()["name"], "Xavier Novo");

    // Tenant ES: 9 alfanuméricos aceites sem dígito de controlo; outro formato → 422.
    let (_, ces) = login(&d.app, &es, "x@exemplo.pt").await?;
    let tes = csrf_token(&app, &es, &ces).await?;
    let r = patch_me(&app, &es, &ces, Some(&tes), &json!({"nif": "x1234567l"})).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json()["nif"], "X1234567L");
    let r = patch_me(&app, &es, &ces, Some(&tes), &json!({"nif": "X-123456"})).await?;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    cleanup(&ns).await
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
    for path in ["/api/v1/auth/register", "/api/v1/me"] {
        assert!(committed.contains(path), "{path}");
    }
    Ok(())
}
