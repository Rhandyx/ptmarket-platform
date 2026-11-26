//! Middleware da caixa negra (cartão 02/07) contra Postgres e Redis reais: uma linha da tabela de
//! decisão por teste, falha fechado e ausência de interruptor.
//!
//! O ator, o tenant e o peer TCP entram nas extensões do pedido (o papel das layers de
//! autenticação/tenant, que ficam por fora do middleware); a classe entra por uma layer
//! `Extension` posta no router. Cada teste usa um prefixo Redis próprio e apaga-o no fim.
//! Leituras de `audit.*` sem `query!` (o migrator não tem SELECT na caixa negra): SQL estático.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Extension, Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    routing::{get, options, post},
};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{Actor, ActorType, AuditClass, AuditCtx, AuditEvent, Denied, Outcome, record},
    error::AppError,
    http::{
        audit_layer::{AuditLayerState, audited},
        client_ip::TrustedProxies,
        with_edge_layers, with_edge_layers_for_tests,
    },
    tenancy::{TenantId, begin_tenant_tx},
};
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tower::ServiceExt;
use tower_http::request_id::RequestId;
use uuid::Uuid;

type TestResult = anyhow::Result<()>;
/// actor_type, actor_id, action, target_type, target_id, outcome, reason, changes, ip, ua_hash
type EvRow = (
    String,
    Option<Uuid>,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<serde_json::Value>,
    Option<String>,
    Option<String>,
);

const WINDOW: Duration = Duration::from_millis(1500);
/// Por omissão o pedido chega por um proxy de confiança (como em produção, pela Cloudflare), que
/// envia `CF-Connecting-IP: CLIENT` e o `x-request-id` do teste.
const PROXY_NETS: [&str; 1] = ["10.0.0.0/8"];
const PEER: &str = "10.0.0.5:5555";
const CLIENT: &str = "198.51.100.9";
const UA: &str = "Mozilla/5.0 (teste)";

// ---------------------------------------------------------------------------------------------
// Infra
// ---------------------------------------------------------------------------------------------

async fn app_pool(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
    max: u32,
) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(max)
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

async fn seed_tenant(owner: &PgPool, slug: &str) -> sqlx::Result<TenantId> {
    let id = Uuid::now_v7();
    let domain = format!("{slug}.test.invalid");
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name) VALUES ($1, $2, $3, $4)",
        id,
        slug,
        domain,
        slug
    )
    .execute(owner)
    .await?;
    Ok(TenantId::for_tests(id))
}

fn redis_pool(url: &str) -> anyhow::Result<deadpool_redis::Pool> {
    Ok(deadpool_redis::Config::from_url(url).create_pool(Some(Runtime::Tokio1))?)
}

fn live_redis() -> anyhow::Result<deadpool_redis::Pool> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis_pool(&url)
}

/// Redis em baixo: porta onde nada escuta.
fn dead_redis() -> anyhow::Result<deadpool_redis::Pool> {
    redis_pool("redis://127.0.0.1:1")
}

/// BD de auditoria em baixo: porta onde nada escuta.
fn dead_db() -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(500))
        .connect_lazy("postgres://ninguem:nada@127.0.0.1:1/db")?)
}

fn namespace() -> String {
    format!("test:{}:", Uuid::now_v7())
}

/// Middleware de teste: o proxy de teste (`10.0.0.0/8`) é de confiança.
fn layer(db: PgPool, redis: deadpool_redis::Pool, ns: &str) -> AuditLayerState {
    layer_with_window(db, redis, ns, WINDOW)
}

fn layer_with_window(
    db: PgPool,
    redis: deadpool_redis::Pool,
    ns: &str,
    window: Duration,
) -> AuditLayerState {
    let trusted = TrustedProxies::new(PROXY_NETS.iter().filter_map(|n| n.parse().ok()).collect());
    AuditLayerState::for_tests(db, redis, trusted, ns, window)
}

async fn cleanup(redis: &deadpool_redis::Pool, ns: &str) -> TestResult {
    let mut conn = redis.get().await?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{ns}*"))
        .query_async(&mut conn)
        .await?;
    if !keys.is_empty() {
        let _: i64 = redis::cmd("DEL").arg(keys).query_async(&mut conn).await?;
    }
    Ok(())
}

/// Eventos do Stream do teste (campo `event`, JSON).
async fn stream(redis: &deadpool_redis::Pool, ns: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut conn = redis.get().await?;
    let entries: Vec<(String, Vec<String>)> = redis::cmd("XRANGE")
        .arg(format!("{ns}audit:stream"))
        .arg("-")
        .arg("+")
        .query_async(&mut conn)
        .await?;
    let mut out = Vec::new();
    for (_, fields) in entries {
        assert_eq!(fields.len(), 2, "entrada com campos a mais: {fields:?}");
        assert_eq!(fields[0], "event");
        out.push(serde_json::from_str(&fields[1])?);
    }
    Ok(out)
}

fn stream_for(events: &[serde_json::Value], rid: Uuid) -> Vec<serde_json::Value> {
    events
        .iter()
        .filter(|e| e["request_id"] == rid.to_string())
        .cloned()
        .collect()
}

/// Espera (até `max`) que o Stream do teste tenha pelo menos `n` entradas.
async fn wait_stream(
    redis: &deadpool_redis::Pool,
    ns: &str,
    n: usize,
    max: Duration,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let start = std::time::Instant::now();
    loop {
        let evs = stream(redis, ns).await?;
        if evs.len() >= n || start.elapsed() > max {
            return Ok(evs);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Quantos eventos há com estes request_id (lidos como app, dentro do tenant).
async fn count_events(app: &PgPool, tenant: TenantId, rids: &[Uuid]) -> anyhow::Result<i64> {
    let reader = AuditCtx::for_tests(ActorType::System, None, None, None);
    let mut tx = begin_tenant_tx(app, tenant, &reader).await?;
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit.audit_events WHERE request_id = ANY($1)")
            .bind(rids)
            .fetch_one(&mut *tx)
            .await?;
    tx.rollback().await?;
    Ok(n)
}

/// Eventos gravados com este request_id (lidos como app, dentro do tenant).
async fn events(app: &PgPool, tenant: TenantId, rid: Uuid) -> anyhow::Result<Vec<EvRow>> {
    let reader = AuditCtx::for_tests(ActorType::System, None, None, None);
    let mut tx = begin_tenant_tx(app, tenant, &reader).await?;
    let rows: Vec<EvRow> = sqlx::query_as(
        "SELECT actor_type::text, actor_id, action::text, target_type::text, target_id,
                outcome::text, reason, changes, host(ip), encode(user_agent_hash, 'hex')
         FROM audit.audit_events WHERE request_id = $1 ORDER BY chain_seq",
    )
    .bind(rid)
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(rows)
}

/// (request_id, ip) dos eventos deste ator (quando o request_id não é conhecido).
async fn events_by_actor(
    app: &PgPool,
    tenant: TenantId,
    actor: Actor,
) -> anyhow::Result<Vec<(Option<Uuid>, Option<String>)>> {
    let reader = AuditCtx::for_tests(ActorType::System, None, None, None);
    let mut tx = begin_tenant_tx(app, tenant, &reader).await?;
    let rows = sqlx::query_as(
        "SELECT request_id, host(ip) FROM audit.audit_events WHERE actor_id = $1 ORDER BY chain_seq",
    )
    .bind(actor.actor_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(rows)
}

fn merchant() -> Actor {
    Actor {
        actor_type: ActorType::Merchant,
        actor_id: Some(Uuid::now_v7()),
        impersonator_id: None,
    }
}

// ---------------------------------------------------------------------------------------------
// Router de teste
// ---------------------------------------------------------------------------------------------

fn settings_event() -> AuditEvent {
    AuditEvent {
        action: "store.settings_changed",
        target_type: Some("store"),
        target_id: None,
        outcome: Outcome::Success,
        reason: None,
        changes: None,
        store_id: None,
    }
}

fn test_router(st: AuditLayerState, db: PgPool) -> Router {
    // Grava com `audit::record` e faz rollback (erro de negócio): o evento não fica.
    let db_rb = db.clone();
    let rolled_back = post(move |ctx: AuditCtx, Extension(t): Extension<TenantId>| {
        let db = db_rb.clone();
        async move {
            let mut tx = begin_tenant_tx(&db, t, &ctx).await?;
            record(&mut tx, settings_event()).await?;
            tx.rollback().await?;
            Err::<StatusCode, _>(AppError::Conflict)
        }
    });
    let recorded = post(move |ctx: AuditCtx, Extension(t): Extension<TenantId>| {
        let db = db.clone();
        async move {
            let mut tx = begin_tenant_tx(&db, t, &ctx).await?;
            record(&mut tx, settings_event()).await?;
            tx.commit().await?;
            Ok::<_, AppError>(StatusCode::CREATED)
        }
    });
    // Sem `AuditClass`: tem de valer `ReadSync`.
    // 17 parâmetros: só os 16 primeiros entram no evento.
    let many: String = (b'a'..=b'q')
        .map(|c| format!("/{{{}}}", char::from(c)))
        .collect();
    let default_class = Router::new()
        .route(
            "/items/{id}",
            get(|| async { "secret-body-xyz" }).delete(|| async { StatusCode::NO_CONTENT }),
        )
        .route(&format!("/p{many}"), get(|| async { "many" }))
        .route(
            "/slow",
            get(|| async {
                tracing::info!("slow-start");
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            }),
        )
        .route(
            "/rid",
            get(
                |Extension(rid): Extension<RequestId>, headers: HeaderMap| async move {
                    let ext = rid.header_value().to_str().unwrap_or_default().to_owned();
                    let hdr = headers
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    tracing::info!("handler-log");
                    format!("{ext}|{hdr}")
                },
            ),
        )
        .route(
            "/unauth",
            get(|| async { Err::<(), _>(AppError::Unauthorized) }),
        )
        .route(
            "/forbidden",
            get(|| async { Err::<(), _>(AppError::Forbidden) }),
        )
        .route(
            "/stores/{id}",
            get(|| async { (Extension(Denied("idor")), AppError::NotFound) }),
        )
        .route("/limited", get(|| async { StatusCode::TOO_MANY_REQUESTS }))
        .route(
            "/plain",
            post(|| async { (StatusCode::CREATED, "created-body") }),
        )
        .route(
            "/boom",
            post(|| async { AppError::Internal(anyhow::anyhow!("rebentou")) }),
        )
        .route("/recorded", recorded)
        .route("/rolled-back", rolled_back)
        .route("/opts", options(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/opts-denied",
            options(|| async { Err::<(), _>(AppError::Forbidden) }),
        );
    let read_async = Router::new()
        .route("/async/items/{id}", get(|| async { "async-body" }))
        .route(
            "/async/forbidden",
            get(|| async { Err::<(), _>(AppError::Forbidden) }),
        );
    audited(default_class, st.clone())
        .merge(audited(read_async, st).layer(Extension(AuditClass::ReadAsync)))
}

struct Call<'a> {
    method: &'a str,
    uri: &'a str,
    actor: Option<Actor>,
    tenant: Option<TenantId>,
    peer: &'a str,
    /// Valor de `CF-Connecting-IP` ("" = sem cabeçalho).
    client: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body: &'a str,
    /// Envia `x-request-id: <client_rid>` (como um cliente que o escolhe).
    send_client_rid: bool,
}

impl<'a> Call<'a> {
    fn new(method: &'a str, uri: &'a str, actor: Option<Actor>, tenant: TenantId) -> Self {
        Self {
            method,
            uri,
            actor,
            tenant: Some(tenant),
            peer: PEER,
            client: CLIENT,
            headers: vec![("user-agent", UA)],
            body: "",
            send_client_rid: true,
        }
    }
}

struct Reply {
    status: StatusCode,
    body: String,
    /// `request_id` do servidor (o `x-request-id` da resposta).
    rid: Uuid,
    /// O `x-request-id` que o cliente enviou.
    client_rid: Uuid,
}

async fn send(app: &Router, c: Call<'_>) -> anyhow::Result<Reply> {
    let client_rid = Uuid::now_v7();
    let mut b = Request::builder().method(c.method).uri(c.uri);
    if c.send_client_rid {
        b = b.header("x-request-id", client_rid.to_string());
    }
    if !c.client.is_empty() {
        b = b.header("cf-connecting-ip", c.client);
    }
    for (k, v) in &c.headers {
        b = b.header(*k, *v);
    }
    let mut req = b.body(Body::from(c.body.to_owned()))?;
    let peer: SocketAddr = c.peer.parse()?;
    req.extensions_mut().insert(ConnectInfo(peer));
    if let Some(a) = c.actor {
        req.extensions_mut().insert(a);
    }
    if let Some(t) = c.tenant {
        req.extensions_mut().insert(t);
    }
    let res = app.clone().oneshot(req).await?;
    let status = res.status();
    let server_rid = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_default();
    let bytes = res.into_body().collect().await?.to_bytes();
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        rid: server_rid,
        client_rid,
    })
}

fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// 1. 401/403/Denied → síncrono 'denied'
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn decision_1_denials_are_sync_and_idor_keeps_actor(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = test_router(layer(db.clone(), redis.clone(), &ns), db.clone());
    let who = merchant();

    for (uri, status, reason) in [
        ("/unauth", StatusCode::UNAUTHORIZED, "unauthorized"),
        ("/forbidden", StatusCode::FORBIDDEN, "forbidden"),
        // ReadAsync não muda nada: a recusa é sempre síncrona.
        ("/async/forbidden", StatusCode::FORBIDDEN, "forbidden"),
    ] {
        let r = send(&app, Call::new("GET", uri, Some(who), t)).await?;
        assert_eq!(r.status, status, "{uri}");
        let rows = events(&db, t, r.rid).await?;
        assert_eq!(rows.len(), 1, "{uri}: {rows:?}");
        let (actor_type, actor_id, action, _, target_id, outcome, why, ..) = &rows[0];
        assert_eq!(
            (actor_type.as_str(), *actor_id, action.as_str()),
            ("merchant", who.actor_id, "http.get")
        );
        assert_eq!((outcome.as_str(), why.as_deref()), ("denied", Some(reason)));
        assert_eq!(target_id.as_deref(), Some(uri));
    }

    // IDOR: 404 com `Denied` → recusa com o ator, a rota-modelo e os parâmetros.
    let r = send(&app, Call::new("GET", "/stores/42", Some(who), t)).await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (_, actor_id, _, target_type, target_id, outcome, why, changes, ip, ua) = &rows[0];
    assert_eq!(*actor_id, who.actor_id);
    assert_eq!((outcome.as_str(), why.as_deref()), ("denied", Some("idor")));
    assert_eq!(target_type.as_deref(), Some("route"));
    assert_eq!(target_id.as_deref(), Some("/stores/{id}"));
    let changes = changes.clone().unwrap_or_default();
    assert_eq!(changes["status"], 404);
    assert_eq!(changes["path_params"]["id"], "42");
    assert_eq!(ip.as_deref(), Some("198.51.100.9"));
    assert_eq!(ua.as_deref(), Some(sha256_hex(UA).as_str()));

    // Recusa anónima também fica (actor 'anonymous').
    let r = send(&app, Call::new("GET", "/unauth", None, t)).await?;
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].0.as_str(), rows[0].5.as_str()),
        ("anonymous", "denied")
    );

    assert!(
        stream(&redis, &ns).await?.is_empty(),
        "recusas não vão para o Stream"
    );
    cleanup(&redis, &ns).await
}

// ---------------------------------------------------------------------------------------------
// 2. 429 → 1.º por janela síncrono; os seguintes contam; 1 resumo no Stream no fim da janela
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn decision_2_rate_limit_first_sync_then_one_summary(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = test_router(layer(db.clone(), redis.clone(), &ns), db.clone());
    let who = merchant();

    let mut rids = Vec::new();
    for _ in 0..3 {
        let r = send(&app, Call::new("GET", "/limited", Some(who), t)).await?;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
        rids.push(r.rid);
    }
    let first = events(&db, t, rids[0]).await?;
    assert_eq!(first.len(), 1, "o 1.º 429 é síncrono");
    assert_eq!(
        (first[0].5.as_str(), first[0].6.as_deref()),
        ("denied", Some("rate_limit"))
    );
    assert_eq!(first[0].1, who.actor_id);
    for rid in &rids[1..] {
        assert!(
            events(&db, t, *rid).await?.is_empty(),
            "o 2.º e o 3.º só contam"
        );
    }

    // Outro sujeito (anónimo, outro IP) tem a sua própria janela.
    let mut anon = Call::new("GET", "/limited", None, t);
    anon.client = "198.51.100.77";
    let r = send(&app, anon).await?;
    assert_eq!(events(&db, t, r.rid).await?.len(), 1);

    // Nada no Stream antes de a janela fechar; depois, exatamente 1 resumo com a contagem.
    assert!(stream(&redis, &ns).await?.is_empty());
    let mut summary = Vec::new();
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        summary = stream(&redis, &ns).await?;
        if !summary.is_empty() {
            break;
        }
    }
    assert_eq!(summary.len(), 1, "um resumo por janela: {summary:?}");
    let s = &summary[0];
    assert_eq!(s["action"], "security.rate_limit_summary");
    assert_eq!(
        (s["outcome"].as_str(), s["reason"].as_str()),
        (Some("denied"), Some("rate_limit"))
    );
    assert_eq!(s["changes"]["count"], 2);
    assert_eq!(
        s["actor_id"],
        who.actor_id.map(|a| a.to_string()).unwrap_or_default()
    );
    assert_eq!(s["tenant_id"], t.as_uuid().to_string());
    assert_eq!(s["target_id"], "/limited");

    // Janela nova: volta a haver uma escrita síncrona.
    let r = send(&app, Call::new("GET", "/limited", Some(who), t)).await?;
    assert_eq!(events(&db, t, r.rid).await?.len(), 1);

    // Redis indisponível → 503 (falha fechado), sem o corpo original.
    let down = test_router(layer(db.clone(), dead_redis()?, &ns), db.clone());
    let r = send(&down, Call::new("GET", "/limited", Some(merchant()), t)).await?;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    cleanup(&redis, &ns).await
}

// ---------------------------------------------------------------------------------------------
// 3. Mutações: síncronas (também anónimas); `audit::record` não duplica; 5xx = 'error'
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn decision_3_mutations_sync_without_duplicates(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = test_router(layer(db.clone(), redis.clone(), &ns), db.clone());

    let r = send(&app, Call::new("POST", "/plain", None, t)).await?;
    assert_eq!(
        (r.status, r.body.as_str()),
        (StatusCode::CREATED, "created-body")
    );
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].0.as_str(), rows[0].2.as_str(), rows[0].5.as_str()),
        ("anonymous", "http.post", "success")
    );
    assert_eq!(rows[0].7.clone().unwrap_or_default()["status"], 201);

    // O handler grava com `audit::record`: o middleware não acrescenta outro.
    let who = merchant();
    let r = send(&app, Call::new("POST", "/recorded", Some(who), t)).await?;
    assert_eq!(r.status, StatusCode::CREATED);
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1, "duplicado: {rows:?}");
    assert_eq!(rows[0].2, "store.settings_changed");
    assert_eq!(rows[0].1, who.actor_id);

    // `audit::record` + rollback + 409: a marca não passou o COMMIT, o middleware grava.
    let r = send(&app, Call::new("POST", "/rolled-back", Some(who), t)).await?;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1, "evento perdido no rollback: {rows:?}");
    assert_eq!(
        (rows[0].2.as_str(), rows[0].5.as_str()),
        ("http.post", "success")
    );
    assert_eq!(rows[0].7.clone().unwrap_or_default()["status"], 409);

    let r = send(&app, Call::new("POST", "/boom", Some(who), t)).await?;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].5, "error");

    assert!(
        stream(&redis, &ns).await?.is_empty(),
        "mutações nunca vão para o Stream"
    );
    cleanup(&redis, &ns).await
}

// ---------------------------------------------------------------------------------------------
// 4–6. Leituras: ReadSync síncrona; ReadAsync no Stream; anónima com sucesso → nada
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn decision_4_5_6_reads(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = test_router(layer(db.clone(), redis.clone(), &ns), db.clone());
    let who = merchant();

    // 4. ReadSync (aqui por omissão): síncrono, nada no Stream.
    let r = send(&app, Call::new("GET", "/items/7", Some(who), t)).await?;
    assert_eq!(
        (r.status, r.body.as_str()),
        (StatusCode::OK, "secret-body-xyz")
    );
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].2.as_str(), rows[0].5.as_str()),
        ("http.get", "success")
    );
    assert!(stream_for(&stream(&redis, &ns).await?, r.rid).is_empty());

    // 5. ReadAsync: XADD com o contrato exato; nada na BD.
    let r = send(&app, Call::new("GET", "/async/items/9", Some(who), t)).await?;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, "async-body"));
    assert!(
        events(&db, t, r.rid).await?.is_empty(),
        "ReadAsync não grava síncrono"
    );
    let evs = stream_for(&stream(&redis, &ns).await?, r.rid);
    assert_eq!(evs.len(), 1);
    let e = &evs[0];
    let mut keys: Vec<&str> = e
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    let mut expected = vec![
        "id",
        "tenant_id",
        "store_id",
        "actor_type",
        "actor_id",
        "actor_label",
        "impersonator_id",
        "action",
        "target_type",
        "target_id",
        "outcome",
        "reason",
        "changes",
        "request_id",
        "ip",
        "user_agent_hash",
        "occurred_at",
    ];
    expected.sort_unstable();
    assert_eq!(keys, expected);
    assert!(
        Uuid::parse_str(e["id"].as_str().unwrap_or_default())
            .is_ok_and(|u| u.get_version_num() == 7)
    );
    assert_eq!(e["tenant_id"], t.as_uuid().to_string());
    assert!(
        e["store_id"].is_null() && e["actor_label"].is_null() && e["impersonator_id"].is_null()
    );
    assert_eq!(e["actor_type"], "merchant");
    assert_eq!(
        e["actor_id"],
        who.actor_id.map(|a| a.to_string()).unwrap_or_default()
    );
    assert_eq!(e["action"], "http.get");
    assert_eq!(
        (e["target_type"].as_str(), e["target_id"].as_str()),
        (Some("route"), Some("/async/items/{id}"))
    );
    assert_eq!(e["outcome"], "success");
    assert!(e["reason"].is_null());
    assert_eq!(e["changes"]["status"], 200);
    assert_eq!(e["changes"]["path_params"]["id"], "9");
    assert_eq!(e["ip"], "198.51.100.9");
    assert_eq!(e["user_agent_hash"], sha256_hex(UA));
    let at = e["occurred_at"].as_str().unwrap_or_default();
    assert!(
        at.len() == 27 && at.ends_with('Z') && at.as_bytes()[10] == b'T',
        "{at}"
    );

    // 6. Leitura anónima com sucesso: nada (nem BD nem Stream), em qualquer classe.
    for uri in ["/items/1", "/async/items/1"] {
        let r = send(&app, Call::new("GET", uri, None, t)).await?;
        assert_eq!(r.status, StatusCode::OK);
        assert!(events(&db, t, r.rid).await?.is_empty(), "{uri}");
        assert!(
            stream_for(&stream(&redis, &ns).await?, r.rid).is_empty(),
            "{uri}"
        );
    }
    // HEAD é GET; OPTIONS também é leitura (anónimo → nada; recusa → síncrono).
    let r = send(&app, Call::new("HEAD", "/items/1", Some(who), t)).await?;
    assert_eq!(r.status, StatusCode::OK);
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].2, "http.head");
    let r = send(&app, Call::new("HEAD", "/items/1", None, t)).await?;
    assert!(events(&db, t, r.rid).await?.is_empty());
    let r = send(&app, Call::new("OPTIONS", "/opts", None, t)).await?;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(
        events(&db, t, r.rid).await?.is_empty(),
        "OPTIONS anónimo não é mutação"
    );
    let r = send(&app, Call::new("OPTIONS", "/opts-denied", None, t)).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].2.as_str(), rows[0].5.as_str()),
        ("http.options", "denied")
    );
    let r = send(&app, Call::new("OPTIONS", "/opts", Some(who), t)).await?;
    assert_eq!(
        events(&db, t, r.rid).await?.len(),
        1,
        "OPTIONS autenticado = leitura ReadSync"
    );

    // `ActorType::Anonymous` explícito conta como anónimo.
    let anon = Actor {
        actor_type: ActorType::Anonymous,
        actor_id: None,
        impersonator_id: None,
    };
    let r = send(&app, Call::new("GET", "/items/1", Some(anon), t)).await?;
    assert!(events(&db, t, r.rid).await?.is_empty());
    cleanup(&redis, &ns).await
}

// ---------------------------------------------------------------------------------------------
// Falha fechado
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn fail_closed_audit_db_down_is_503_without_body(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 2).await?;
    let redis = live_redis()?;
    let ns = namespace();
    // Só a BD de auditoria do middleware está em baixo.
    let app = test_router(layer(dead_db()?, redis.clone(), &ns), db);
    let who = merchant();

    for (method, uri, leak) in [
        ("GET", "/items/1", "secret-body-xyz"),
        ("POST", "/plain", "created-body"),
        ("GET", "/unauth", "unauthorized"),
    ] {
        let r = send(&app, Call::new(method, uri, Some(who), t)).await?;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{method} {uri}");
        assert!(
            !r.body.contains(leak),
            "{method} {uri}: corpo original saiu: {}",
            r.body
        );
        assert!(r.body.contains("service_unavailable"), "{}", r.body);
    }
    // Anónimo a escrever também falha fechado.
    let r = send(&app, Call::new("POST", "/plain", None, t)).await?;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    cleanup(&redis, &ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn fail_closed_redis_down_read_async_is_recorded_sync(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 2).await?;
    let ns = namespace();
    let app = test_router(layer(db.clone(), dead_redis()?, &ns), db.clone());
    let who = merchant();

    let r = send(&app, Call::new("GET", "/async/items/5", Some(who), t)).await?;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, "async-body"));
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1, "XADD falhou: tinha de gravar síncrono");
    assert_eq!(
        (rows[0].2.as_str(), rows[0].4.as_deref()),
        ("http.get", Some("/async/items/{id}"))
    );

    // Redis e BD em baixo: 503.
    let both = test_router(layer(dead_db()?, dead_redis()?, &ns), db);
    let r = send(&both, Call::new("GET", "/async/items/5", Some(who), t)).await?;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!r.body.contains("async-body"));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Sem interruptor; IP; o evento nunca leva cookies, corpo nem valores de query
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn no_kill_switch(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    // Sem feature que desligue: só existe `test-support` (construtores de teste).
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))?;
    let features: Vec<&str> = manifest
        .split("[features]")
        .nth(1)
        .and_then(|s| s.split("\n[").next())
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(
        features,
        vec!["test-support = []"],
        "feature nova: {features:?}"
    );
    // Sem variável de ambiente: o middleware não lê o ambiente.
    for src in [
        include_str!("../src/http/audit_layer.rs"),
        include_str!("../src/http/client_ip.rs"),
    ] {
        assert!(!src.contains("env::var") && !src.contains("std::env"));
    }

    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = test_router(layer(db.clone(), redis.clone(), &ns), db.clone());
    let who = merchant();

    // Router sem `AuditClass`: GET autenticado é ReadSync (BD, não Stream).
    let r = send(&app, Call::new("GET", "/items/3", Some(who), t)).await?;
    assert_eq!(events(&db, t, r.rid).await?.len(), 1);
    assert!(stream_for(&stream(&redis, &ns).await?, r.rid).is_empty());

    // Cliente direto (peer não confiável): CF-Connecting-IP ignorado.
    let direct = merchant();
    let mut c = Call::new("GET", "/items/3", Some(direct), t);
    c.peer = "198.51.100.20:5555";
    c.client = "203.0.113.50";
    let r = send(&app, c).await?;
    let rows = events_by_actor(&db, t, direct).await?;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1.as_deref(), Some("198.51.100.20"));
    assert_eq!(rows[0].0, Some(r.rid));

    // Proxy de confiança: o IP aceite.
    let mut c = Call::new("GET", "/items/3", Some(who), t);
    c.peer = "10.1.2.3:443";
    c.client = "203.0.113.50";
    let r = send(&app, c).await?;
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].8.as_deref(), Some("203.0.113.50"));

    // Nem cookies, nem corpo, nem valores de query (BD e Stream).
    let secrets = [
        "cookie-secret-123",
        "body-secret-456",
        "query-secret-789",
        "tok-secret",
    ];
    let with_secrets = |method: &'static str, uri: &'static str| {
        let mut c = Call::new(method, uri, Some(who), t);
        c.headers.push(("cookie", "session=cookie-secret-123"));
        c.headers.push(("authorization", "Bearer tok-secret"));
        c.body = "{\"note\":\"body-secret-456\"}";
        c
    };
    let r = send(
        &app,
        with_secrets("POST", "/plain?email=query-secret-789&page=2"),
    )
    .await?;
    let rows = events(&db, t, r.rid).await?;
    assert_eq!(rows.len(), 1);
    let changes = rows[0].7.clone().unwrap_or_default();
    // Par de 2 com chave sensível ("email", x) → x mascarado pelo redator comum (vetores 03e): mascarar a mais é aceite.
    assert_eq!(changes["query_keys"], serde_json::json!(["email", "[pii]"]));
    let text = format!("{rows:?}");
    for s in secrets {
        assert!(!text.contains(s), "{s} no evento: {text}");
    }
    let r = send(
        &app,
        with_secrets("GET", "/async/items/1?email=query-secret-789"),
    )
    .await?;
    let evs = stream_for(&stream(&redis, &ns).await?, r.rid);
    assert_eq!(evs.len(), 1);
    assert_eq!(
        evs[0]["changes"]["query_keys"],
        serde_json::json!(["email"])
    );
    let text = evs[0].to_string();
    for s in secrets {
        assert!(!text.contains(s), "{s} no Stream: {text}");
    }
    cleanup(&redis, &ns).await
}

// ---------------------------------------------------------------------------------------------
// 07b: endurecimento (NUL, flood anónimo, request_id do servidor, /64, abort do cliente)
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn nul_in_path_params_is_recorded_with_replacement(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = test_router(layer(db.clone(), redis.clone(), &ns), db.clone());
    let who = merchant();

    // GET autenticado (ReadSync) e DELETE anónimo: gravados, sem 503, com U+FFFD.
    for (method, actor, status) in [
        ("GET", Some(who), StatusCode::OK),
        ("DELETE", None, StatusCode::NO_CONTENT),
    ] {
        let r = send(&app, Call::new(method, "/items/%00abc", actor, t)).await?;
        assert_eq!(r.status, status, "{method}");
        let rows = events(&db, t, r.rid).await?;
        assert_eq!(rows.len(), 1, "{method}: {rows:?}");
        let changes = rows[0].7.clone().unwrap_or_default();
        assert_eq!(changes["path_params"]["id"], "\u{FFFD}abc", "{method}");
    }

    // ReadAsync: o Stream também leva U+FFFD (a fila morta não enche).
    let r = send(&app, Call::new("GET", "/async/items/%00x", Some(who), t)).await?;
    assert_eq!(r.status, StatusCode::OK);
    let evs = stream_for(&stream(&redis, &ns).await?, r.rid);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0]["changes"]["path_params"]["id"], "\u{FFFD}x");
    assert!(!evs[0].to_string().contains("\\u0000"));

    // Valores longos cortados a 256 caracteres; no máximo 16 parâmetros.
    let long = "é".repeat(300);
    let uri = format!("/items/{long}");
    let r = send(&app, Call::new("GET", &uri, Some(who), t)).await?;
    let rows = events(&db, t, r.rid).await?;
    let id = rows[0].7.clone().unwrap_or_default()["path_params"]["id"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .count();
    assert_eq!(id, 256);
    let many: String = (1..=17).map(|i| format!("/v{i}")).collect();
    let uri = format!("/p{many}");
    let r = send(&app, Call::new("GET", &uri, Some(who), t)).await?;
    assert_eq!(r.status, StatusCode::OK);
    let rows = events(&db, t, r.rid).await?;
    let params = rows[0].7.clone().unwrap_or_default()["path_params"].clone();
    assert_eq!(params.as_object().map(|m| m.len()), Some(16), "{params}");
    cleanup(&redis, &ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn anonymous_flood_is_counted_but_authenticated_denials_always_sync(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let window = Duration::from_secs(3);
    let app = test_router(
        layer_with_window(db.clone(), redis.clone(), &ns, window),
        db.clone(),
    );

    // 50 × 401 anónimos do mesmo IP: 1 síncrono, 49 contados.
    let mut rids = Vec::new();
    for _ in 0..50 {
        let r = send(&app, Call::new("GET", "/unauth", None, t)).await?;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        rids.push(r.rid);
    }
    assert_eq!(events(&db, t, rids[0]).await?.len(), 1, "o 1.º é síncrono");
    assert_eq!(count_events(&db, t, &rids).await?, 1);

    // Mutações anónimas do mesmo IP: classe própria (a janela de auth_fail não as cala).
    let mut posts = Vec::new();
    for _ in 0..3 {
        let r = send(&app, Call::new("POST", "/plain", None, t)).await?;
        assert_eq!(r.status, StatusCode::CREATED);
        posts.push(r.rid);
    }
    assert_eq!(events(&db, t, posts[0]).await?.len(), 1);
    assert_eq!(count_events(&db, t, &posts).await?, 1);

    // 403 autenticado: sempre 1 evento cada.
    let who = merchant();
    let mut denied = Vec::new();
    for _ in 0..5 {
        let r = send(&app, Call::new("GET", "/forbidden", Some(who), t)).await?;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        denied.push(r.rid);
    }
    assert_eq!(count_events(&db, t, &denied).await?, 5);

    // No fim da janela: 1 resumo por classe com a contagem.
    let evs = wait_stream(&redis, &ns, 2, window * 3).await?;
    assert_eq!(evs.len(), 2, "{evs:?}");
    let by = |a: &str| evs.iter().find(|e| e["action"] == a).cloned();
    let auth = by("security.auth_fail_summary").unwrap_or_default();
    assert_eq!(auth["changes"]["count"], 49, "{auth}");
    assert_eq!(
        (auth["outcome"].as_str(), auth["reason"].as_str()),
        (Some("denied"), Some("auth_fail"))
    );
    assert_eq!(
        (auth["actor_type"].as_str(), auth["ip"].as_str()),
        (Some("anonymous"), Some(CLIENT))
    );
    assert!(auth["tenant_id"].is_null(), "resumo de plataforma");
    let anon = by("security.anon_mutation_summary").unwrap_or_default();
    assert_eq!(anon["changes"]["count"], 2, "{anon}");
    assert_eq!(anon["outcome"], "success");
    cleanup(&redis, &ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn ipv6_same_64_shares_the_window(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = test_router(
        layer_with_window(db.clone(), redis.clone(), &ns, Duration::from_secs(10)),
        db.clone(),
    );
    for (ip, expected) in [
        ("2001:db8:1:2::1", 1),
        ("2001:db8:1:2:ffff::abcd", 0),
        ("2001:db8:1:3::1", 1),
    ] {
        let mut c = Call::new("GET", "/limited", None, t);
        c.client = ip;
        let r = send(&app, c).await?;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(events(&db, t, r.rid).await?.len(), expected, "{ip}");
    }
    cleanup(&redis, &ns).await
}

/// Escritor de logs para o teste (memória partilhada).
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut g) = self.0.lock() {
            g.extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        self.0
            .lock()
            .map(|g| String::from_utf8_lossy(&g).into_owned())
            .unwrap_or_default()
    }
}

#[sqlx::test(migrations = "../migrations")]
async fn request_id_is_always_server_generated(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 4).await?;
    let redis = live_redis()?;
    let ns = namespace();
    // As layers de entrada de `http::router_with` por fora da caixa negra.
    let app = with_edge_layers(test_router(
        layer(db.clone(), redis.clone(), &ns),
        db.clone(),
    ));
    let (logs, _guard) = capture_logs();
    let who = merchant();

    // Proxy de confiança e cliente direto: nenhum escolhe o request_id.
    for peer in [PEER, "198.51.100.20:5555"] {
        let mut c = Call::new("GET", "/rid", Some(who), t);
        c.peer = peer;
        let r = send(&app, c).await?;
        assert_eq!(r.status, StatusCode::OK);
        assert_ne!(r.rid, r.client_rid, "{peer}");
        assert_eq!(r.rid.get_version_num(), 7);
        assert!(events(&db, t, r.client_rid).await?.is_empty(), "{peer}");
        let rows = events(&db, t, r.rid).await?;
        assert_eq!(rows.len(), 1, "{peer}");
        let changes = rows[0].7.clone().unwrap_or_default();
        assert_eq!(changes["client_request_id"], r.client_rid.to_string());
        // O handler (extensão `RequestId` e cabeçalho) e a resposta veem o id do evento.
        assert_eq!(r.body, format!("{0}|{0}", r.rid), "{peer}");
        // Os logs do pedido levam o id do evento, nunca o do cliente.
        let text = logs.text();
        let line = text
            .lines()
            .find(|l| l.contains("handler-log") && l.contains(&r.rid.to_string()));
        assert!(line.is_some(), "{text}");
        assert!(!text.contains(&r.client_rid.to_string()), "{text}");
    }

    // Sem cabeçalho do cliente, ou com um que não é UUID: sem `client_request_id`.
    for client_header in [None, Some("nope")] {
        let mut c = Call::new("POST", "/plain", Some(who), t);
        c.send_client_rid = false;
        if let Some(h) = client_header {
            c.headers.push(("x-request-id", h));
        }
        let r = send(&app, c).await?;
        assert_eq!(r.rid.get_version_num(), 7, "{client_header:?}");
        let rows = events(&db, t, r.rid).await?;
        assert_eq!(rows.len(), 1, "{client_header:?}");
        let changes = rows[0].7.clone().unwrap_or_default();
        assert!(changes.get("client_request_id").is_none(), "{changes}");
    }
    cleanup(&redis, &ns).await
}

/// Logs do teste em memória (subscriber só desta thread; o runtime do teste é de uma thread).
fn capture_logs() -> (LogBuf, tracing::subscriber::DefaultGuard) {
    let logs = LogBuf::default();
    let writer = logs.clone();
    let guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish(),
    );
    (logs, guard)
}

#[sqlx::test(migrations = "../migrations")]
async fn timeout_408_carries_the_logged_request_id(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 2).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = with_edge_layers_for_tests(
        test_router(layer(db.clone(), redis.clone(), &ns), db.clone()),
        Duration::from_millis(300),
    );
    let (logs, _guard) = capture_logs();

    let r = send(&app, Call::new("GET", "/slow", Some(merchant()), t)).await?;
    assert_eq!(r.status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(r.rid.get_version_num(), 7, "o 408 sai sem o id do servidor");
    assert_ne!(r.rid, r.client_rid);
    let text = logs.text();
    let line = text.lines().find(|l| l.contains("slow-start"));
    assert!(
        line.is_some_and(|l| l.contains(&r.rid.to_string())),
        "o log não leva o id do 408: {text}"
    );
    assert!(!text.contains(&r.client_rid.to_string()), "{text}");
    cleanup(&redis, &ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn client_abort_mid_mutation_still_records(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let t = seed_tenant(&owner, "camara-a").await?;
    let db = app_pool(&opts, &conn, 2).await?;
    // A pool da caixa negra tem 1 ligação, que o teste segura: a gravação fica à espera.
    let audit_db = app_pool(&opts, &conn, 1).await?;
    let redis = live_redis()?;
    let ns = namespace();
    let app = test_router(layer(audit_db.clone(), redis.clone(), &ns), db.clone());
    let who = merchant();

    let held = audit_db.acquire().await?;
    let aborted = tokio::time::timeout(
        Duration::from_millis(300),
        send(&app, Call::new("POST", "/plain", Some(who), t)),
    )
    .await;
    assert!(
        aborted.is_err(),
        "o pedido devia estar à espera da gravação"
    );
    drop(held);

    let mut rows = Vec::new();
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        rows = events_by_actor(&db, t, who).await?;
        if !rows.is_empty() {
            break;
        }
    }
    assert_eq!(rows.len(), 1, "o abort do cliente cancelou a gravação");
    cleanup(&redis, &ns).await
}
