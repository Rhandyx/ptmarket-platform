//! Sessões, CSRF e logout (cartão 02/16) contra Postgres e Redis reais.
//!
//! As pools da app fazem `SET ROLE ptmarket_app`. Os tenants semeiam-se como dono; os clientes
//! pela app (registo anónimo); as sessões com `session::create` numa transação com o próprio
//! cliente como ator. Cada teste usa um prefixo Redis próprio e apaga-o no fim. Leituras de
//! `audit.*` sem `query!` (o migrator não tem SELECT na caixa negra): SQL estático.

use std::{sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    body::Body,
    extract::State,
    http::{HeaderName, Method, Request, StatusCode, header},
    routing::post,
};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    error::AppError,
    http::{
        api,
        audit_layer::{AuditLayerState, audited},
        client_ip::TrustedProxies,
        with_host_resolution,
    },
    identity::{
        CookieKind, CookieValue, SessionId, Sessions, Subject,
        http::with_sessions,
        session::{self, SessionKind},
    },
    state::AppState,
    storage::NullStorage,
    tenancy::{HostResolver, ResolvedHost, TenantId, begin_tenant_tx, db::begin_platform_tx},
};
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tower::ServiceExt;
use uuid::Uuid;

type TestResult = anyhow::Result<()>;
/// action, outcome, reason, actor_type, actor_id de `audit.audit_events`.
type EvRow = (String, String, Option<String>, String, Option<Uuid>);

const ADMIN_HOST: &str = "admin.ptmarket.invalid";
const CSRF_KEY: &str = "chave-csrf-de-teste-com-mais-de-32-bytes";
const INTERNAL_TOKEN: &str = "token-interno-de-teste-com-mais-de-32-bytes";
const SESSION_URI: &str = "/api/v1/auth/session";
const LOGOUT_URI: &str = "/api/v1/auth/logout";

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

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned())
}

fn redis() -> anyhow::Result<deadpool_redis::Pool> {
    Ok(deadpool_redis::Config::from_url(redis_url()).create_pool(Some(Runtime::Tokio1))?)
}

fn dead_redis() -> anyhow::Result<deadpool_redis::Pool> {
    Ok(deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .create_pool(Some(Runtime::Tokio1))?)
}

fn state(app: &PgPool) -> anyhow::Result<AppState> {
    Ok(AppState {
        db_primary: app.clone(),
        db_replica: app.clone(),
        redis: redis()?,
        storage: Arc::new(NullStorage),
        hosts: Arc::new(HostResolver::new(
            app.clone(),
            Some(ADMIN_HOST.to_owned()),
            Some(INTERNAL_TOKEN.to_owned().into()),
        )),
    })
}

fn namespace() -> String {
    format!("test:sess:{}:", Uuid::now_v7())
}

/// Apaga as chaves Redis do teste (dev; `KEYS` só aqui).
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

fn sessions(app: &PgPool, ns: &str, idle: Option<Duration>) -> anyhow::Result<Sessions> {
    Ok(
        Sessions::for_tests(app.clone(), redis()?, CSRF_KEY.to_owned().into(), ns, idle)
            .with_internal_token(Some(INTERNAL_TOKEN.to_owned().into())),
    )
}

fn audit_layer(app: &PgPool, ns: &str) -> anyhow::Result<AuditLayerState> {
    Ok(AuditLayerState::for_tests(
        app.clone(),
        redis()?,
        TrustedProxies::none(),
        ns,
        Duration::from_secs(1),
    ))
}

/// A API real (`http::api`) com sessões de teste.
fn app_router(app: &PgPool, ns: &str, sessions: Sessions) -> anyhow::Result<Router> {
    let st = state(app)?;
    Ok(api(st.clone(), audit_layer(app, ns)?, Some(sessions)).with_state(st))
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

async fn seed_tenant(owner: &PgPool, slug: &str) -> sqlx::Result<Tenant> {
    seed_tenant_at(owner, slug, &format!("{slug}.ptmarket.invalid")).await
}

async fn seed_tenant_at(owner: &PgPool, slug: &str, domain: &str) -> sqlx::Result<Tenant> {
    let id = Uuid::now_v7();
    let domain = domain.to_owned();
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name) VALUES ($1, $2, $3, $4)",
        id,
        slug,
        domain,
        format!("Câmara {slug}")
    )
    .execute(owner)
    .await?;
    Ok(Tenant { id, domain })
}

/// Cliente registado (como no registo: ator anónimo).
async fn seed_customer(app: &PgPool) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let ctx = AuditCtx::for_tests(ActorType::Anonymous, None, None, None);
    let mut tx = begin_platform_tx(app, &ctx).await?;
    sqlx::query!(
        "INSERT INTO customers (id, email) VALUES ($1, $2)",
        id,
        format!("{id}@test.invalid")
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

fn customer_ctx(id: Uuid) -> AuditCtx {
    AuditCtx::for_tests(ActorType::Customer, Some(id), None, None)
}

/// Sessão do cliente nascida no host do tenant `t`.
async fn login(app: &PgPool, t: &Tenant, customer: Uuid) -> anyhow::Result<(SessionId, String)> {
    let ctx = customer_ctx(customer);
    let mut tx = begin_tenant_tx(app, t.tid(), &ctx).await?;
    let (id, v) =
        session::create(&mut tx, Subject::Customer(customer), Some(t.tid()), &ctx).await?;
    tx.commit().await?;
    Ok((id, v.expose().to_owned()))
}

fn tenant_cookie(token: &str) -> String {
    format!("{}={token}", session::COOKIE_TENANT)
}

struct Reply {
    status: StatusCode,
    body: String,
    request_id: Option<Uuid>,
    set_cookies: Vec<String>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_default()
    }

    fn authenticated(&self) -> bool {
        self.json()["authenticated"] == serde_json::Value::Bool(true)
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
    let set_cookies = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect();
    let bytes = res.into_body().collect().await?.to_bytes();
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        request_id,
        set_cookies,
    })
}

async fn whoami(app: &Router, host: &str, cookie: &str) -> anyhow::Result<Reply> {
    send(
        app,
        Method::GET,
        SESSION_URI,
        &[(header::HOST, host), (header::COOKIE, cookie)],
        "",
    )
    .await
}

fn clears_tenant_cookie(r: &Reply) -> bool {
    r.set_cookies
        .iter()
        .any(|c| c.starts_with("__Host-ptm_session=;") && c.contains("Max-Age=0"))
}

/// Eventos da caixa negra de um pedido (no tenant `t`).
async fn events(app: &PgPool, t: &Tenant, rid: Uuid) -> anyhow::Result<Vec<EvRow>> {
    // 0038: a auditoria é fail-closed por loja; ler como admin sem impersonação.
    let reader = AuditCtx::for_tests(ActorType::Admin, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &reader).await?;
    let rows: Vec<EvRow> = sqlx::query_as(
        "SELECT action, outcome::text, reason, actor_type, actor_id
         FROM audit.audit_events WHERE request_id = $1 ORDER BY chain_seq",
    )
    .bind(rid)
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------------------------
// Sessão válida só no seu host; expirada, revogada, inativa e rodada → anónimo
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn session_is_valid_only_on_its_host(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let b = seed_tenant(&owner, "camara-b").await?;
    let pool = app_pool(&opts, &conn).await?;
    let ns = namespace();
    let app = app_router(&pool, &ns, sessions(&pool, &ns, None)?)?;
    let customer = seed_customer(&pool).await?;
    let (_, token) = login(&pool, &a, customer).await?;
    let cookie = tenant_cookie(&token);

    let r = whoami(&app, &a.domain, &cookie).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.authenticated(), "{}", r.body);
    assert_eq!(r.json()["actor_type"], "customer");
    assert_eq!(r.json()["csrf_token"].as_str().map(str::len), Some(43));
    assert!(r.set_cookies.is_empty());

    // Host B (outro tenant) e host de plataforma: anónimo e cookie limpo; nunca 4xx.
    let r = whoami(&app, &b.domain, &cookie).await?;
    assert_eq!(r.status, StatusCode::OK);
    assert!(!r.authenticated(), "{}", r.body);
    assert!(r.json()["csrf_token"].is_null() && r.json()["actor_type"].is_null());
    assert!(clears_tenant_cookie(&r), "{:?}", r.set_cookies);
    let admin_cookie = format!("{}={token}", session::COOKIE_PLATFORM);
    let r = whoami(&app, ADMIN_HOST, &admin_cookie).await?;
    assert!(!r.authenticated(), "{}", r.body);

    // Cookie com formato inválido ou repetido: anónimo e limpo.
    for bad in [
        tenant_cookie("curto"),
        tenant_cookie(&"A".repeat(43)),
        format!("{cookie}; {cookie}"),
    ] {
        let r = whoami(&app, &a.domain, &bad).await?;
        assert_eq!(r.status, StatusCode::OK, "{bad}");
        assert!(!r.authenticated(), "{bad}");
        assert!(clears_tenant_cookie(&r), "{bad}");
    }
    // Continua válida no host A.
    assert!(whoami(&app, &a.domain, &cookie).await?.authenticated());
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn expired_revoked_and_rotated_sessions_are_anonymous(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let pool = app_pool(&opts, &conn).await?;
    let ns = namespace();
    let app = app_router(&pool, &ns, sessions(&pool, &ns, None)?)?;
    let customer = seed_customer(&pool).await?;
    let ctx = customer_ctx(customer);

    // Expirada (duração absoluta de 1 s).
    let mut tx = begin_tenant_tx(&pool, a.tid(), &ctx).await?;
    let (_, short) = session::create_for_tests(
        &mut tx,
        Subject::Customer(customer),
        Some(a.tid()),
        &ctx,
        Duration::from_secs(1),
    )
    .await?;
    tx.commit().await?;
    let cookie = tenant_cookie(short.expose());
    assert!(whoami(&app, &a.domain, &cookie).await?.authenticated());
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let r = whoami(&app, &a.domain, &cookie).await?;
    assert!(!r.authenticated() && clears_tenant_cookie(&r), "{}", r.body);

    // Revogada.
    let (id, token) = login(&pool, &a, customer).await?;
    let cookie = tenant_cookie(&token);
    assert!(whoami(&app, &a.domain, &cookie).await?.authenticated());
    let mut tx = begin_tenant_tx(&pool, a.tid(), &ctx).await?;
    assert!(session::revoke(&mut tx, id).await?);
    tx.commit().await?;
    let r = whoami(&app, &a.domain, &cookie).await?;
    assert!(!r.authenticated() && clears_tenant_cookie(&r), "{}", r.body);
    // Revogada é imutável: revogar outra vez não altera nada.
    let mut tx = begin_tenant_tx(&pool, a.tid(), &ctx).await?;
    assert!(!session::revoke(&mut tx, id).await?);
    tx.commit().await?;

    // Rotação: o token antigo deixa de valer; o novo vale.
    let (old_id, old_token) = login(&pool, &a, customer).await?;
    let mut tx = begin_tenant_tx(&pool, a.tid(), &ctx).await?;
    let (new_id, new_token) = session::rotate(
        &mut tx,
        Some(old_id),
        Subject::Customer(customer),
        Some(a.tid()),
        &ctx,
    )
    .await?;
    tx.commit().await?;
    assert_ne!(old_id, new_id);
    assert!(
        !whoami(&app, &a.domain, &tenant_cookie(&old_token))
            .await?
            .authenticated()
    );
    assert!(
        whoami(&app, &a.domain, &tenant_cookie(new_token.expose()))
            .await?
            .authenticated()
    );

    // revoke_all: todas as do sujeito.
    let (_, t2) = login(&pool, &a, customer).await?;
    let mut tx = begin_tenant_tx(&pool, a.tid(), &ctx).await?;
    assert!(session::revoke_all(&mut tx, Subject::Customer(customer)).await? >= 2);
    tx.commit().await?;
    for t in [new_token.expose(), t2.as_str()] {
        assert!(
            !whoami(&app, &a.domain, &tenant_cookie(t))
                .await?
                .authenticated()
        );
    }

    // Só para o próprio sujeito: outro ator não cria sessão alheia.
    let other = AuditCtx::for_tests(ActorType::Customer, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_tenant_tx(&pool, a.tid(), &other).await?;
    let res = session::create(&mut tx, Subject::Customer(customer), Some(a.tid()), &other).await;
    assert!(res.is_err());
    tx.rollback().await?;
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn inactive_session_is_anonymous_and_activity_renews_it(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let pool = app_pool(&opts, &conn).await?;
    let ns = namespace();
    let idle = Duration::from_millis(1500);
    let app = app_router(&pool, &ns, sessions(&pool, &ns, Some(idle))?)?;
    let customer = seed_customer(&pool).await?;
    let (id, token) = login(&pool, &a, customer).await?;
    let cookie = tenant_cookie(&token);

    // Cada pedido renova o TTL: passa bem além de `idle` desde a criação.
    for _ in 0..3 {
        assert!(whoami(&app, &a.domain, &cookie).await?.authenticated());
        tokio::time::sleep(Duration::from_millis(900)).await;
    }
    let mut conn = redis()?.get().await?;
    let key = format!("{ns}sess:idle:{}", id.as_uuid());
    let ttl: i64 = redis::cmd("PTTL").arg(&key).query_async(&mut conn).await?;
    assert!(ttl > 0 && ttl <= 1500, "{ttl}");

    // TTL esgotado → anónimo e cookie limpo.
    tokio::time::sleep(Duration::from_millis(1800)).await;
    let r = whoami(&app, &a.domain, &cookie).await?;
    assert!(!r.authenticated() && clears_tenant_cookie(&r), "{}", r.body);
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn redis_down_with_cookie_is_503(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let pool = app_pool(&opts, &conn).await?;
    let ns = namespace();
    let down = Sessions::for_tests(
        pool.clone(),
        dead_redis()?,
        CSRF_KEY.to_owned().into(),
        &ns,
        None,
    );
    let app = app_router(&pool, &ns, down)?;
    let customer = seed_customer(&pool).await?;
    let (_, token) = login(&pool, &a, customer).await?;
    let r = whoami(&app, &a.domain, &tenant_cookie(&token)).await?;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.body);
    // Sem cookie não precisa do Redis das sessões.
    let r = send(
        &app,
        Method::GET,
        SESSION_URI,
        &[(header::HOST, &a.domain)],
        "",
    )
    .await?;
    assert_eq!(r.status, StatusCode::OK);
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// Set-Cookie e hash na BD
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn set_cookie_is_host_prefixed_and_db_keeps_only_the_hash(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let pool = app_pool(&opts, &conn).await?;
    let ns = namespace();
    let customer = seed_customer(&pool).await?;
    let st = state(&pool)?;

    // Probe de "login": cria a sessão do cliente no host do pedido e devolve o Set-Cookie.
    let probe = Router::new().route(
        "/login-probe",
        post(
            move |State(s): State<AppState>, Extension(host): Extension<ResolvedHost>| async move {
                let ctx = customer_ctx(customer);
                let subject = Subject::Customer(customer);
                let (kind, id, value): (CookieKind, SessionId, CookieValue) = match host {
                    ResolvedHost::Tenant(t) => {
                        let mut tx = begin_tenant_tx(&s.db_primary, t.id(), &ctx).await?;
                        let (id, v) = session::create(&mut tx, subject, Some(t.id()), &ctx).await?;
                        tx.commit().await?;
                        (CookieKind::Tenant, id, v)
                    }
                    ResolvedHost::Platform => {
                        let mut tx = begin_platform_tx(&s.db_primary, &ctx).await?;
                        let (id, v) = session::create(&mut tx, subject, None, &ctx).await?;
                        tx.commit().await?;
                        (CookieKind::Platform, id, v)
                    }
                    _ => return Err(AppError::NotFound),
                };
                let sc = session::set_cookie(kind, &value, SessionKind::Customer.max_lifetime())?;
                Ok::<_, AppError>(([(header::SET_COOKIE, sc)], id.as_uuid().to_string()))
            },
        ),
    );
    let app = with_host_resolution(
        with_sessions(
            audited(probe, audit_layer(&pool, &ns)?),
            sessions(&pool, &ns, None)?,
        ),
        st.clone(),
    )
    .with_state(st);

    for (host, name, same_site) in [
        (a.domain.as_str(), "__Host-ptm_session", "SameSite=Lax"),
        (ADMIN_HOST, "__Host-ptm_admin", "SameSite=Strict"),
    ] {
        let r = send(
            &app,
            Method::POST,
            "/login-probe",
            &[(header::HOST, host)],
            "",
        )
        .await?;
        assert_eq!(r.status, StatusCode::OK, "{host}: {}", r.body);
        assert_eq!(r.set_cookies.len(), 1, "{host}");
        let sc = &r.set_cookies[0];
        let (pair, attrs) = sc.split_once(';').unwrap_or_default();
        let (cname, token) = pair.split_once('=').unwrap_or_default();
        assert_eq!(cname, name);
        assert_eq!(token.len(), 43);
        let attrs: Vec<&str> = attrs.split(';').map(str::trim).collect();
        for want in ["Path=/", "HttpOnly", "Secure", same_site, "Max-Age=604800"] {
            assert!(attrs.contains(&want), "{host}: falta {want} em {sc}");
        }
        assert!(!sc.to_ascii_lowercase().contains("domain"), "{sc}");

        // Na BD: só o sha256 do token; o token não aparece em lado nenhum da linha.
        let id = Uuid::parse_str(&r.body)?;
        let ctx = customer_ctx(customer);
        let mut tx = begin_platform_tx(&pool, &ctx).await?;
        let row = sqlx::query!(
            r#"SELECT token_hash, row_to_json(s)::text AS "row!" FROM sessions s WHERE id = $1"#,
            id
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.rollback().await?;
        assert_eq!(row.token_hash, Sha256::digest(token.as_bytes()).to_vec());
        assert!(!row.row.contains(token), "{host}");
    }
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------------------------

async fn csrf_token(app: &Router, t: &Tenant, cookie: &str) -> anyhow::Result<String> {
    let r = whoami(app, &t.domain, cookie).await?;
    r.json()["csrf_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("sem csrf_token: {}", r.body))
}

#[sqlx::test(migrations = "../migrations")]
async fn mutation_without_valid_csrf_or_origin_is_403_with_denied_event(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let pool = app_pool(&opts, &conn).await?;
    let ns = namespace();
    let app = app_router(&pool, &ns, sessions(&pool, &ns, None)?)?;
    let customer = seed_customer(&pool).await?;
    let (_, token) = login(&pool, &a, customer).await?;
    let cookie = tenant_cookie(&token);
    let mine = csrf_token(&app, &a, &cookie).await?;
    let (_, other_token) = login(&pool, &a, seed_customer(&pool).await?).await?;
    let theirs = csrf_token(&app, &a, &tenant_cookie(&other_token)).await?;
    assert_ne!(mine, theirs);

    let origin = a.origin();
    let http_origin = format!("http://{}", a.domain);
    let x_csrf = HeaderName::from_static("x-csrf-token");
    let host = (header::HOST, a.domain.as_str());
    let ck = (header::COOKIE, cookie.as_str());
    let cases: Vec<(&str, Vec<(HeaderName, &str)>)> = vec![
        (
            "sem token",
            vec![host.clone(), ck.clone(), (header::ORIGIN, &origin)],
        ),
        (
            "token de outra sessão",
            vec![
                host.clone(),
                ck.clone(),
                (header::ORIGIN, &origin),
                (x_csrf.clone(), &theirs),
            ],
        ),
        (
            "Origin de outro host",
            vec![
                host.clone(),
                ck.clone(),
                (header::ORIGIN, "https://evil.invalid"),
                (x_csrf.clone(), &mine),
            ],
        ),
        (
            "sem Origin",
            vec![host.clone(), ck.clone(), (x_csrf.clone(), &mine)],
        ),
        (
            "http em produção",
            vec![
                host.clone(),
                ck.clone(),
                (header::ORIGIN, &http_origin),
                (x_csrf.clone(), &mine),
            ],
        ),
    ];
    for (name, headers) in cases {
        let r = send(&app, Method::POST, LOGOUT_URI, &headers, "").await?;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{name}: {}", r.body);
        let rows = events(&pool, &a, r.rid()?).await?;
        assert_eq!(
            rows,
            vec![(
                "http.post".to_owned(),
                "denied".to_owned(),
                Some("csrf".to_owned()),
                "customer".to_owned(),
                Some(customer)
            )],
            "{name}"
        );
    }
    // Nada foi revogado.
    assert!(whoami(&app, &a.domain, &cookie).await?.authenticated());

    // Formulário com `_csrf` certo (e Origin certa): passa.
    let form = format!("_csrf={mine}");
    let r = send(
        &app,
        Method::POST,
        LOGOUT_URI,
        &[
            host.clone(),
            ck.clone(),
            (header::ORIGIN, &origin),
            (header::CONTENT_TYPE, "application/x-www-form-urlencoded"),
        ],
        &form,
    )
    .await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    cleanup(&ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn ssr_without_origin_needs_csrf_and_http_only_on_localhost(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let dev = seed_tenant_at(&owner, "camara-dev", "camara-dev.localhost").await?;
    let pool = app_pool(&opts, &conn).await?;
    let ns = namespace();
    let app = app_router(&pool, &ns, sessions(&pool, &ns, None)?)?;
    let customer = seed_customer(&pool).await?;
    let x_csrf = HeaderName::from_static("x-csrf-token");
    let xfh = HeaderName::from_static("x-forwarded-host");
    let xit = HeaderName::from_static("x-internal-token");

    // SSR do Next (token interno válido, host efetivo = X-Forwarded-Host), sem Origin.
    let (_, token) = login(&pool, &a, customer).await?;
    let cookie = tenant_cookie(&token);
    let csrf = csrf_token(&app, &a, &cookie).await?;
    let ssr = vec![
        (header::HOST, "api.interno"),
        (xfh.clone(), a.domain.as_str()),
        (xit.clone(), INTERNAL_TOKEN),
        (header::COOKIE, cookie.as_str()),
    ];
    let r = send(&app, Method::POST, LOGOUT_URI, &ssr, "").await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "SSR sem CSRF: {}", r.body);
    let rows = events(&pool, &a, r.rid()?).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2.as_deref(), Some("csrf"));
    // SSR com Origin de outro host: 403 na mesma.
    let mut bad = ssr.clone();
    bad.push((header::ORIGIN, "https://evil.invalid"));
    bad.push((x_csrf.clone(), csrf.as_str()));
    let r = send(&app, Method::POST, LOGOUT_URI, &bad, "").await?;
    assert_eq!(
        r.status,
        StatusCode::FORBIDDEN,
        "SSR Origin alheia: {}",
        r.body
    );
    // Sem o token interno, o mesmo pedido sem Origin é recusado (não é SSR).
    let browser = vec![
        (header::HOST, a.domain.as_str()),
        (header::COOKIE, cookie.as_str()),
        (x_csrf.clone(), csrf.as_str()),
    ];
    let r = send(&app, Method::POST, LOGOUT_URI, &browser, "").await?;
    assert_eq!(
        r.status,
        StatusCode::FORBIDDEN,
        "browser sem Origin: {}",
        r.body
    );
    let mut good = ssr.clone();
    good.push((x_csrf.clone(), csrf.as_str()));
    let r = send(&app, Method::POST, LOGOUT_URI, &good, "").await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "SSR com CSRF: {}", r.body);
    assert!(!whoami(&app, &a.domain, &cookie).await?.authenticated());

    // Dev: http aceite em *.localhost (com porta do Next).
    let (_, token) = login(&pool, &dev, customer).await?;
    let cookie = tenant_cookie(&token);
    let csrf = csrf_token(&app, &dev, &cookie).await?;
    let r = send(
        &app,
        Method::POST,
        LOGOUT_URI,
        &[
            (header::HOST, dev.domain.as_str()),
            (header::COOKIE, cookie.as_str()),
            (header::ORIGIN, "http://camara-dev.localhost:3000"),
            (x_csrf.clone(), csrf.as_str()),
        ],
        "",
    )
    .await?;
    assert_eq!(
        r.status,
        StatusCode::NO_CONTENT,
        "http em localhost: {}",
        r.body
    );
    cleanup(&ns).await
}

// ---------------------------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn logout_revokes_clears_cookie_and_records_events(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let pool = app_pool(&opts, &conn).await?;
    let ns = namespace();
    let app = app_router(&pool, &ns, sessions(&pool, &ns, None)?)?;
    let customer = seed_customer(&pool).await?;
    let (id, token) = login(&pool, &a, customer).await?;
    let cookie = tenant_cookie(&token);
    let csrf = csrf_token(&app, &a, &cookie).await?;
    let origin = a.origin();

    let r = send(
        &app,
        Method::POST,
        LOGOUT_URI,
        &[
            (header::HOST, &a.domain),
            (header::COOKIE, &cookie),
            (header::ORIGIN, &origin),
            (HeaderName::from_static("x-csrf-token"), &csrf),
        ],
        "",
    )
    .await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    assert!(clears_tenant_cookie(&r), "{:?}", r.set_cookies);

    // revoked_at preenchido.
    let ctx = customer_ctx(customer);
    let mut tx = begin_tenant_tx(&pool, a.tid(), &ctx).await?;
    let revoked = sqlx::query_scalar!(
        r#"SELECT revoked_at IS NOT NULL AS "revoked!" FROM sessions WHERE id = $1"#,
        id.as_uuid()
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;
    assert!(revoked);

    // sessions.update (L1) e auth.logout, ambos com o ator; nada mais neste pedido.
    let rows = events(&pool, &a, r.rid()?).await?;
    let want = |action: &str| {
        (
            action.to_owned(),
            "success".to_owned(),
            None,
            "customer".to_owned(),
            Some(customer),
        )
    };
    assert_eq!(rows, vec![want("sessions.update"), want("auth.logout")]);

    // Chave de inatividade apagada.
    let mut conn = redis()?.get().await?;
    let exists: i64 = redis::cmd("EXISTS")
        .arg(format!("{ns}sess:idle:{}", id.as_uuid()))
        .query_async(&mut conn)
        .await?;
    assert_eq!(exists, 0);

    // 2.º pedido com o mesmo cookie: anónimo.
    let r = whoami(&app, &a.domain, &cookie).await?;
    assert!(!r.authenticated() && clears_tenant_cookie(&r), "{}", r.body);
    // Logout sem sessão: 204 (idempotente), sem eventos de sessão.
    let r = send(
        &app,
        Method::POST,
        LOGOUT_URI,
        &[(header::HOST, &a.domain)],
        "",
    )
    .await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    cleanup(&ns).await
}
