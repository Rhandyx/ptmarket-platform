//! Tenant pelo `Host` (cartão 02/11) contra Postgres real: `GET /api/v1/tenant`, normalização,
//! 404 genérico, anti-IDOR (`X-Forwarded-Host` sem token, `tenant_id` forjado), rotas de
//! plataforma, a transação só de leitura do portal nacional (view `portal_stores`) e o travão a
//! hosts desconhecidos por IP (Redis; falha aberta).
//!
//! As pools da app fazem `SET ROLE ptmarket_app` (o dono não prova nada). Os tenants semeiam-se
//! como dono (tabela global); as lojas pela app dentro de `begin_tenant_tx`. Leituras de `audit.*`
//! sem `query!` (o migrator não tem SELECT na caixa negra): SQL estático.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{
    Extension, Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderName, Request, StatusCode, header::HOST},
    response::IntoResponse,
    routing::get,
};
use deadpool_redis::{Runtime, redis};
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{Actor, ActorType, AuditClass, AuditCtx},
    error::AppError,
    http::{
        audit_layer::{AuditLayerState, audited},
        client_ip::TrustedProxies,
        router, with_host_resolution,
    },
    state::AppState,
    storage::NullStorage,
    tenancy::{
        HostResolver, PlatformHost, ResolvedHost, ResolvedTenant, TenantId, begin_portal_read_tx,
        begin_tenant_tx,
        portal::{DENIED_NOT_PORTAL, PORTAL_FORBIDDEN_COLUMNS},
        resolver::{MAX_UNKNOWN_HOSTS, MAX_UNKNOWN_HOSTS_48, POSITIVE_TTL},
    },
};
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tower::ServiceExt;
use uuid::Uuid;

type TestResult = anyhow::Result<()>;
/// tenant_id, outcome, reason, actor_id de `audit.audit_events`.
type EvRow = (Option<Uuid>, String, Option<String>, Option<Uuid>);

const ADMIN_HOST: &str = "admin.ptmarket.invalid";
const TOKEN: &str = "token-interno-de-teste-com-mais-de-32-bytes";
const IBAN: &str = "PT50000201231234567890154";
const SECRET_ENC: &str = "enc:segredo-faturacao";
const SPLIT_KEY: &str = "split-key-segredo";
const STRIPE: &str = "acct_segredo";
/// SQLSTATE `read_only_sql_transaction`.
const READ_ONLY: &str = "25006";
/// SQLSTATE `undefined_column`.
const UNDEFINED_COLUMN: &str = "42703";
/// (coluna, SELECT em `stores` de outro tenant, SELECT na view). SQL estático: a view não tem a
/// coluna, por isso não pode ser `query!` (falharia a compilar).
const FORBIDDEN_PROBES: [(&str, &str, &str); 6] = [
    (
        "iban",
        "SELECT iban::text FROM stores WHERE tenant_id = $1",
        "SELECT iban::text FROM portal_stores",
    ),
    (
        "invoicing_credentials_enc",
        "SELECT invoicing_credentials_enc::text FROM stores WHERE tenant_id = $1",
        "SELECT invoicing_credentials_enc::text FROM portal_stores",
    ),
    (
        "eupago_split_key",
        "SELECT eupago_split_key::text FROM stores WHERE tenant_id = $1",
        "SELECT eupago_split_key::text FROM portal_stores",
    ),
    (
        "stripe_account_id",
        "SELECT stripe_account_id::text FROM stores WHERE tenant_id = $1",
        "SELECT stripe_account_id::text FROM portal_stores",
    ),
    (
        "custom_commission_bps",
        "SELECT custom_commission_bps::text FROM stores WHERE tenant_id = $1",
        "SELECT custom_commission_bps::text FROM portal_stores",
    ),
    (
        "kyc_verified",
        "SELECT kyc_verified::text FROM stores WHERE tenant_id = $1",
        "SELECT kyc_verified::text FROM portal_stores",
    ),
];

// ---------------------------------------------------------------------------------------------
// Infra
// ---------------------------------------------------------------------------------------------

async fn app_pool(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(4)
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

fn state(app: &PgPool) -> anyhow::Result<AppState> {
    Ok(AppState {
        db_primary: app.clone(),
        db_replica: app.clone(),
        redis: redis()?,
        storage: Arc::new(NullStorage),
        hosts: Arc::new(HostResolver::new(
            app.clone(),
            Some(ADMIN_HOST.to_owned()),
            Some(TOKEN.to_owned().into()),
        )),
    })
}

struct Tenant {
    id: Uuid,
    domain: String,
}

impl Tenant {
    fn tid(&self) -> TenantId {
        TenantId::for_tests(self.id)
    }
}

async fn seed_tenant(
    owner: &PgPool,
    slug: &str,
    tenant_type: &str,
    country: &str,
    active: bool,
) -> sqlx::Result<Tenant> {
    let id = Uuid::now_v7();
    let domain = format!("{slug}.ptmarket.invalid");
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code, is_active,
                              default_commission_bps)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1234)",
        id,
        slug,
        domain,
        format!("Câmara {slug}"),
        tenant_type,
        country,
        active
    )
    .execute(owner)
    .await?;
    Ok(Tenant { id, domain })
}

/// Loja com todas as colunas sensíveis preenchidas.
async fn seed_store(app: &PgPool, t: &Tenant, slug: &str, publish: bool) -> anyhow::Result<()> {
    let ctx = AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_tenant_tx(app, t.tid(), &ctx).await?;
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email,
                             invoicing_credentials_enc, eupago_split_key, stripe_account_id,
                             publish_to_national_portal, custom_commission_bps, kyc_verified)
         VALUES ($1, $2, $3, $4, $5, '500000000', $6, 'loja@test.invalid', $7, $8, $9, $10,
                 777, true)",
        Uuid::now_v7(),
        t.id,
        slug,
        slug,
        slug,
        IBAN,
        SECRET_ENC,
        SPLIT_KEY,
        STRIPE,
        publish
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

struct Reply {
    status: StatusCode,
    body: String,
    request_id: Option<Uuid>,
    retry_after: Option<u64>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_default()
    }
}

async fn send(app: &Router, uri: &str, headers: &[(HeaderName, &str)]) -> anyhow::Result<Reply> {
    send_from(app, uri, headers, None).await
}

/// Com `peer`, o pedido leva `ConnectInfo` (como o binário): é o IP do cliente do travão.
async fn send_from(
    app: &Router,
    uri: &str,
    headers: &[(HeaderName, &str)],
    peer: Option<&str>,
) -> anyhow::Result<Reply> {
    let mut req = Request::get(uri).body(Body::empty())?;
    for (k, v) in headers {
        req.headers_mut().append(k.clone(), v.parse()?);
    }
    if let Some(p) = peer {
        let ip: IpAddr = p.parse()?;
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
    }
    let res = app.clone().oneshot(req).await?;
    let status = res.status();
    let retry_after = res
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let request_id = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok());
    let bytes = res.into_body().collect().await?.to_bytes();
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        request_id,
        retry_after,
    })
}

async fn tenant_get(app: &Router, headers: &[(HeaderName, &str)]) -> anyhow::Result<Reply> {
    send(app, "/api/v1/tenant", headers).await
}

async fn not_found_body() -> anyhow::Result<String> {
    let bytes = AppError::NotFound
        .into_response()
        .into_body()
        .collect()
        .await?
        .to_bytes();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn h(name: &'static str) -> HeaderName {
    HeaderName::from_static(name)
}

// ---------------------------------------------------------------------------------------------
// Host → tenant
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../migrations")]
async fn host_resolves_its_tenant_and_normalizes(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a", "municipal", "PT", true).await?;
    seed_tenant(&owner, "camara-b", "municipal", "PT", true).await?;
    let app = router(state(&app_pool(&opts, &conn).await?)?);

    let r = tenant_get(&app, &[(HOST, &a.domain)]).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let v = r.json();
    assert_eq!(v["slug"], "camara-a");
    assert_eq!(v["name"], "Câmara camara-a");
    assert_eq!(v["tenant_type"], "municipal");
    assert_eq!(v["country_code"], "PT");
    assert_eq!(v["currency"], "EUR");
    assert_eq!(v["template_layout"], "bairro");
    assert!(v["theme_config"].is_object() && v["legal_config"].is_object());
    let mut keys: Vec<&str> = v
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "country_code",
            "currency",
            "legal_config",
            "name",
            "slug",
            "template_layout",
            "tenant_type",
            "theme_config"
        ]
    );
    assert!(!r.body.contains(&a.id.to_string()) && !r.body.contains("1234"));

    let upper = a.domain.to_uppercase();
    let port = format!("{}:8443", a.domain);
    let dot = format!("{}.", a.domain);
    let all = format!("{}.:443", a.domain.to_uppercase());
    for host in [&upper, &port, &dot, &all] {
        let n = tenant_get(&app, &[(HOST, host)]).await?;
        assert_eq!(
            (n.status, n.body.as_str()),
            (r.status, r.body.as_str()),
            "{host}"
        );
    }
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn unknown_inactive_ip_and_duplicate_hosts_get_the_same_404(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a", "municipal", "PT", true).await?;
    let b = seed_tenant(&owner, "camara-b", "municipal", "PT", true).await?;
    let off = seed_tenant(&owner, "camara-off", "municipal", "PT", false).await?;
    let app = router(state(&app_pool(&opts, &conn).await?)?);
    let expected = not_found_body().await?;

    let cases: Vec<(&str, Vec<(HeaderName, &str)>)> = vec![
        ("desconhecido", vec![(HOST, "nada.ptmarket.invalid")]),
        ("inativo", vec![(HOST, &off.domain)]),
        ("ipv4", vec![(HOST, "127.0.0.1")]),
        ("ipv4:porta", vec![(HOST, "127.0.0.1:8080")]),
        ("ipv6", vec![(HOST, "[::1]:8080")]),
        (
            "duplicado igual",
            vec![(HOST, &a.domain), (HOST, &a.domain)],
        ),
        ("duplicado A+B", vec![(HOST, &a.domain), (HOST, &b.domain)]),
        ("vazio", vec![(HOST, "")]),
        ("sem Host", vec![]),
        ("plataforma", vec![(HOST, ADMIN_HOST)]),
    ];
    for (name, headers) in cases {
        let r = tenant_get(&app, &headers).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{name}");
        assert_eq!(r.body, expected, "{name}");
    }
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn forwarded_host_needs_token_and_forged_tenant_id_has_no_effect(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a", "municipal", "PT", true).await?;
    let b = seed_tenant(&owner, "camara-b", "municipal", "PT", true).await?;
    let app = router(state(&app_pool(&opts, &conn).await?)?);
    let slug = |r: &Reply| r.json()["slug"].as_str().unwrap_or_default().to_owned();
    let xfh = h("x-forwarded-host");
    let tok = h("x-internal-token");

    // Sem token, com token errado, com um prefixo do token: ignora o X-Forwarded-Host.
    let wrong = "x".repeat(TOKEN.len());
    let prefix = &TOKEN[..TOKEN.len() - 1];
    for extra in [None, Some(wrong.as_str()), Some(prefix)] {
        let mut hs = vec![(HOST, a.domain.as_str()), (xfh.clone(), b.domain.as_str())];
        if let Some(t) = extra {
            hs.push((tok.clone(), t));
        }
        let r = tenant_get(&app, &hs).await?;
        assert_eq!((r.status, slug(&r)), (StatusCode::OK, "camara-a".into()));
    }

    // Token certo (SSR do Next): vale o X-Forwarded-Host.
    let r = tenant_get(
        &app,
        &[
            (HOST, "api.interno"),
            (xfh.clone(), &b.domain),
            (tok.clone(), TOKEN),
        ],
    )
    .await?;
    assert_eq!((r.status, slug(&r)), (StatusCode::OK, "camara-b".into()));

    // `tenant_id` forjado em cabeçalhos, query e cookie: sem efeito.
    let bid = b.id.to_string();
    let cookie = format!("tenant_id={bid}");
    let uri = format!("/api/v1/tenant?tenant_id={bid}&tenant={}", b.domain);
    let r = send(
        &app,
        &uri,
        &[
            (HOST, &a.domain),
            (h("tenant_id"), &bid),
            (h("x-tenant-id"), &bid),
            (h("x-tenant"), &b.domain),
            (h("forwarded"), &format!("host={}", b.domain)),
            (h("x-original-host"), &b.domain),
            (h("cookie"), &cookie),
        ],
    )
    .await?;
    assert_eq!((r.status, slug(&r)), (StatusCode::OK, "camara-a".into()));
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn platform_routes_refuse_tenant_hosts(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a", "municipal", "PT", true).await?;
    let pool = app_pool(&opts, &conn).await?;
    let st = state(&pool)?;
    let audit = AuditLayerState::for_tests(
        pool.clone(),
        redis()?,
        TrustedProxies::none(),
        &format!("test:{}:", Uuid::now_v7()),
        Duration::from_secs(1),
    );
    let probe = Router::new().route("/platform-probe", get(|_: PlatformHost| async { "ok" }));
    let app = with_host_resolution(audited(probe, audit), st.clone()).with_state(st);

    let r = send(
        &app,
        "/platform-probe",
        &[(HOST, "Admin.PTMarket.invalid:443")],
    )
    .await?;
    assert_eq!((r.status, r.body.as_str()), (StatusCode::OK, "ok"));
    let expected = not_found_body().await?;
    for host in [a.domain.as_str(), "nada.ptmarket.invalid"] {
        let r = send(&app, "/platform-probe", &[(HOST, host)]).await?;
        assert_eq!(
            (r.status, &r.body),
            (StatusCode::NOT_FOUND, &expected),
            "{host}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Portal nacional
// ---------------------------------------------------------------------------------------------

async fn resolve(app: &PgPool, t: &Tenant) -> anyhow::Result<ResolvedTenant> {
    let st = state(app)?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(HOST, t.domain.parse()?);
    match st.hosts.resolve(&headers, &"/".parse()?, None).await {
        Ok(ResolvedHost::Tenant(r)) => Ok(r),
        other => anyhow::bail!("host não resolvido: {other:?}"),
    }
}

#[sqlx::test(migrations = "../migrations")]
async fn portal_reads_published_stores_of_all_tenants_without_secrets_and_is_read_only(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a", "municipal", "PT", true).await?;
    let b = seed_tenant(&owner, "camara-b", "municipal", "PT", true).await?;
    let es = seed_tenant(&owner, "ayto-es", "municipal", "ES", true).await?;
    let p = seed_tenant(&owner, "portal", "national_portal", "PT", true).await?;
    let app = app_pool(&opts, &conn).await?;
    seed_store(&app, &a, "a-publicada", true).await?;
    seed_store(&app, &a, "a-privada", false).await?;
    seed_store(&app, &b, "b-publicada", true).await?;
    seed_store(&app, &es, "es-publicada", true).await?;

    let portal = resolve(&app, &p).await?;
    let ctx = AuditCtx::for_tests(ActorType::Anonymous, None, None, None);
    let mut tx = begin_portal_read_tx(&app, &portal, &ctx).await?;
    assert_eq!(tx.tenant(), p.tid());
    let stores = tx.published_stores(100).await?;
    let mut seen: Vec<(Uuid, &str)> = stores
        .iter()
        .map(|s| (s.tenant_id, s.slug.as_str()))
        .collect();
    seen.sort_unstable();
    let mut want = vec![(a.id, "a-publicada"), (b.id, "b-publicada")];
    want.sort_unstable();
    assert_eq!(seen, want);

    // Nenhuma coluna sensível sai do tipo do portal (nem o nome, nem o valor).
    let json = serde_json::to_string(&stores)?;
    for secret in [IBAN, SECRET_ENC, SPLIT_KEY, STRIPE, "777"] {
        assert!(!json.contains(secret), "{secret}");
    }
    for col in PORTAL_FORBIDDEN_COLUMNS {
        assert!(!json.contains(col), "{col}");
    }

    // Pela ligação de testes, em modo portal: as lojas de outro tenant não se leem em `stores`
    // (0 linhas) e a view não tem nenhuma das 6 colunas (42703).
    assert_eq!(FORBIDDEN_PROBES.len(), PORTAL_FORBIDDEN_COLUMNS.len());
    for (col, in_stores, in_view) in FORBIDDEN_PROBES {
        assert!(PORTAL_FORBIDDEN_COLUMNS.contains(&col), "{col}");
        assert!(in_stores.contains(col) && in_view.contains(col), "{col}");
        let rows = sqlx::query(in_stores)
            .bind(a.id)
            .fetch_all(tx.conn_for_tests())
            .await?;
        assert!(rows.is_empty(), "{col}: stores de outro tenant visível");
        sqlx::query("SAVEPOINT probe")
            .execute(tx.conn_for_tests())
            .await?;
        let err = sqlx::query(in_view)
            .fetch_all(tx.conn_for_tests())
            .await
            .err();
        let code = err
            .as_ref()
            .and_then(|e| e.as_database_error())
            .and_then(|e| e.code())
            .map(|c| c.into_owned());
        assert_eq!(code.as_deref(), Some(UNDEFINED_COLUMN), "{col}: {err:?}");
        sqlx::query("ROLLBACK TO SAVEPOINT probe")
            .execute(tx.conn_for_tests())
            .await?;
    }

    // READ ONLY: um UPDATE (mesmo de uma loja visível) falha.
    let err = sqlx::query!("UPDATE stores SET name = 'x' WHERE tenant_id = $1", a.id)
        .execute(tx.conn_for_tests())
        .await
        .err();
    let code = err
        .as_ref()
        .and_then(|e| e.as_database_error())
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    assert_eq!(code.as_deref(), Some(READ_ONLY), "{err:?}");
    tx.finish().await?;

    // Fora do modo portal, o mesmo tenant não vê lojas de outros.
    let mut t = begin_tenant_tx(&app, p.tid(), &ctx).await?;
    let n = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM stores"#)
        .fetch_one(&mut *t)
        .await?;
    assert_eq!(n, 0);
    t.rollback().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn portal_refuses_municipal_tenant_with_denied_event(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a", "municipal", "PT", true).await?;
    let p = seed_tenant(&owner, "portal", "national_portal", "PT", true).await?;
    let pool = app_pool(&opts, &conn).await?;

    // Direto: tenant municipal → Forbidden, sem abrir transação.
    let municipal = resolve(&pool, &a).await?;
    let ctx = AuditCtx::for_tests(ActorType::Anonymous, None, None, None);
    let res = begin_portal_read_tx(&pool, &municipal, &ctx).await;
    assert!(matches!(res, Err(AppError::Forbidden)), "{res:?}");

    // Pelo HTTP: 403 com a marca `Denied` → evento `denied` no tenant resolvido pelo Host.
    let st = state(&pool)?;
    let audit = AuditLayerState::for_tests(
        pool.clone(),
        redis()?,
        TrustedProxies::none(),
        &format!("test:{}:", Uuid::now_v7()),
        Duration::from_secs(1),
    );
    let probe = Router::new().route(
        "/portal-probe",
        get(
            |State(s): State<AppState>, ctx: AuditCtx, t: ResolvedTenant| async move {
                match begin_portal_read_tx(&s.db_replica, &t, &ctx).await {
                    Ok(tx) => {
                        tx.finish().await?;
                        Ok::<_, AppError>(StatusCode::OK.into_response())
                    }
                    Err(e) => Ok((Extension(DENIED_NOT_PORTAL), e).into_response()),
                }
            },
        ),
    );
    let actor = Actor {
        actor_type: ActorType::Customer,
        actor_id: Some(Uuid::now_v7()),
        impersonator_id: None,
    };
    let app = with_host_resolution(
        audited(probe, audit)
            .layer(Extension(AuditClass::ReadSync))
            .layer(Extension(actor)),
        st.clone(),
    )
    .with_state(st);

    let r = send(&app, "/portal-probe", &[(HOST, &a.domain)]).await?;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    let rid = r
        .request_id
        .ok_or_else(|| anyhow::anyhow!("sem x-request-id"))?;
    let reader = AuditCtx::for_tests(ActorType::System, None, None, None);
    let mut tx = begin_tenant_tx(&pool, a.tid(), &reader).await?;
    let rows: Vec<EvRow> = sqlx::query_as(
        "SELECT tenant_id, outcome::text, reason, actor_id
         FROM audit.audit_events WHERE request_id = $1 ORDER BY chain_seq",
    )
    .bind(rid)
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    assert_eq!(
        rows,
        vec![(
            Some(a.id),
            "denied".to_owned(),
            Some("not_national_portal".to_owned()),
            actor.actor_id
        )]
    );

    // O portal abre (e o pedido não é recusado).
    let r = send(&app, "/portal-probe", &[(HOST, &p.domain)]).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Travão a hosts desconhecidos (por IP; Redis com falha aberta)
// ---------------------------------------------------------------------------------------------

fn namespace() -> String {
    format!("test:{}:", Uuid::now_v7())
}

/// Redis em baixo: porta onde nada escuta.
fn dead_redis() -> anyhow::Result<deadpool_redis::Pool> {
    Ok(deadpool_redis::Config::from_url("redis://127.0.0.1:1")
        .create_pool(Some(Runtime::Tokio1))?)
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

/// Estado com o travão ligado (chaves Redis com prefixo `ns`) e `GET /api/v1/tenant` pela caixa
/// negra (também com o prefixo: nada sai para o Stream real).
fn limited_app(
    pool: &PgPool,
    redis: deadpool_redis::Pool,
    ns: &str,
) -> (Router, Arc<HostResolver>) {
    let hosts = Arc::new(
        HostResolver::new(
            pool.clone(),
            Some(ADMIN_HOST.to_owned()),
            Some(TOKEN.to_owned().into()),
        )
        .with_miss_limit_for_tests(redis.clone(), TrustedProxies::none(), ns),
    );
    let st = AppState {
        db_primary: pool.clone(),
        db_replica: pool.clone(),
        redis: redis.clone(),
        storage: Arc::new(NullStorage),
        hosts: hosts.clone(),
    };
    let audit = AuditLayerState::for_tests(
        pool.clone(),
        redis,
        TrustedProxies::none(),
        ns,
        Duration::from_secs(60),
    );
    let routes = Router::new().route(
        "/api/v1/tenant",
        get(ptmarket_api::tenancy::http::tenant_info),
    );
    let app = with_host_resolution(
        audited(routes, audit).layer(Extension(AuditClass::ReadAsync)),
        st.clone(),
    )
    .with_state(st);
    (ptmarket_api::http::with_edge_layers(app), hosts)
}

async fn from(app: &Router, host: &str, ip: &str) -> anyhow::Result<Reply> {
    send_from(app, "/api/v1/tenant", &[(HOST, host)], Some(ip)).await
}

#[sqlx::test(migrations = "../migrations")]
async fn unknown_host_flood_is_limited_per_ip_without_queries(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a", "municipal", "PT", true).await?;
    let b = seed_tenant(&owner, "camara-b", "municipal", "PT", true).await?;
    let pool = app_pool(&opts, &conn).await?;
    let redis = redis()?;
    let ns = namespace();
    let (app, hosts) = limited_app(&pool, redis.clone(), &ns);
    let expected_404 = not_found_body().await?;
    let ip = "198.51.100.7";
    let limit = usize::try_from(MAX_UNKNOWN_HOSTS)?;

    // Tenant válido em cache antes do flood (e nunca gasta o limite).
    for _ in 0..3 {
        assert_eq!(from(&app, &a.domain, ip).await?.status, StatusCode::OK);
    }

    // 30 hosts desconhecidos diferentes: 404 genérico, uma consulta cada.
    let before = hosts.db_lookups();
    for i in 0..limit {
        let r = from(&app, &format!("flood-{i}.ptmarket.invalid"), ip).await?;
        assert_eq!(
            (r.status, &r.body),
            (StatusCode::NOT_FOUND, &expected_404),
            "{i}"
        );
    }
    assert_eq!(hosts.db_lookups() - before, u64::try_from(limit)?);

    // O 31.º: 429 com Retry-After, corpo genérico, sem consulta.
    let before = hosts.db_lookups();
    let r = from(&app, "flood-x.ptmarket.invalid", ip).await?;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    let retry = r.retry_after.unwrap_or_default();
    assert!((1..=60).contains(&retry), "Retry-After {retry:?}");
    assert_eq!(r.json()["error"]["code"], "too_many_requests");
    assert!(!r.body.contains("flood-x") && !r.body.contains(ip));
    assert_eq!(hosts.db_lookups(), before, "o 31.º não pode fazer query");
    // Um tenant válido fora da cache também espera (não há consulta para o distinguir).
    let r = from(&app, &b.domain, ip).await?;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(hosts.db_lookups(), before);
    // Por dentro da caixa negra: o 1.º 429 da janela é síncrono (evento de plataforma, que a app
    // não lê) e o 2.º fica a contar para o resumo `rate_limit` (uma chave por IP + rota).
    let mut c = redis.get().await?;
    let pending: i64 = redis::cmd("ZCARD")
        .arg(format!("{ns}audit:rl:pending"))
        .query_async(&mut c)
        .await?;
    assert_eq!(pending, 1, "429 fora da regra de resumo da caixa negra");
    drop(c);

    // Um host válido em cache continua a responder ao IP limitado (sem tocar no Redis).
    let r = from(&app, &a.domain, ip).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // Entrada expirada (CGNAT/borda partilhada): o IP limitado recebe a stale, sem consulta.
    hosts.age_cache_for_tests(POSITIVE_TTL);
    let before = hosts.db_lookups();
    let r = from(&app, &a.domain, ip).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.json()["slug"], "camara-a");
    assert_eq!(hosts.db_lookups(), before);

    // Outro IP não é afetado.
    let r = from(&app, "flood-x.ptmarket.invalid", "198.51.100.8").await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = from(&app, &b.domain, "198.51.100.8").await?;
    assert_eq!(r.status, StatusCode::OK);

    // IPv6: dois endereços do mesmo /64 partilham o contador; outro /64 não.
    let (v6a, v6b) = ("2001:db8:5:6::1", "2001:db8:5:6:ffff:ffff:ffff:ffff");
    for i in 0..limit {
        let peer = if i % 2 == 0 { v6a } else { v6b };
        let r = from(&app, &format!("v6-{i}.ptmarket.invalid"), peer).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{i}");
    }
    for peer in [v6a, v6b, "2001:db8:5:6:1:2:3:4"] {
        let r = from(&app, "v6-x.ptmarket.invalid", peer).await?;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{peer}");
    }
    let r = from(&app, "v6-x.ptmarket.invalid", "2001:db8:5:7::1").await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // A chave Redis é por IP normalizado, com TTL (janela).
    let mut c = redis.get().await?;
    let ttl: i64 = redis::cmd("TTL")
        .arg(format!("{ns}host:miss:ip:{ip}"))
        .query_async(&mut c)
        .await?;
    assert!((1..=60).contains(&ttl), "TTL {ttl}");
    let n: i64 = redis::cmd("GET")
        .arg(format!("{ns}host:miss:ip6:2001:db8:5:6::/64"))
        .query_async(&mut c)
        .await?;
    assert_eq!(n, MAX_UNKNOWN_HOSTS);
    drop(c);
    cleanup(&redis, &ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn redis_down_refuses_uncached_hosts_but_serves_cache(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a", "municipal", "PT", true).await?;
    let b = seed_tenant(&owner, "camara-b", "municipal", "PT", true).await?;
    let pool = app_pool(&opts, &conn).await?;
    let (app, hosts) = limited_app(&pool, dead_redis()?, &namespace());
    let ip = "198.51.100.9";

    // A entra em cache por um pedido sem `ConnectInfo` (sem IP não há contador).
    let r = send(&app, "/api/v1/tenant", &[(HOST, &a.domain)]).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // Em cache (também stale): servido. Fora da cache: 503 (decisão do owner), sem consulta.
    let before = hosts.db_lookups();
    assert_eq!(from(&app, &a.domain, ip).await?.status, StatusCode::OK);
    hosts.age_cache_for_tests(POSITIVE_TTL);
    assert_eq!(from(&app, &a.domain, ip).await?.status, StatusCode::OK);
    for host in [b.domain.as_str(), "down.ptmarket.invalid"] {
        let r = from(&app, host, ip).await?;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{host}");
        assert_eq!(r.json()["error"]["code"], "service_unavailable");
        assert!(!r.body.contains(host));
    }
    assert_eq!(hosts.db_lookups(), before);
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn parallel_burst_never_passes_the_limit(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let redis = redis()?;
    let ns = namespace();
    let (_, hosts) = limited_app(&pool, redis.clone(), &ns);
    let peer: Option<IpAddr> = Some("198.51.100.10".parse()?);
    let uri: axum::http::Uri = "/api/v1/tenant".parse()?;

    let mut set = tokio::task::JoinSet::new();
    for i in 0..(3 * MAX_UNKNOWN_HOSTS) {
        let hosts = hosts.clone();
        let uri = uri.clone();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(HOST, format!("burst-{i}.ptmarket.invalid").parse()?);
        set.spawn(async move { hosts.resolve(&headers, &uri, peer).await });
    }
    let mut unknown = 0_u64;
    while let Some(res) = set.join_next().await {
        if res? == Ok(ResolvedHost::Unknown) {
            unknown += 1;
        }
    }
    let max = u64::try_from(MAX_UNKNOWN_HOSTS)?;
    assert!(hosts.db_lookups() <= max, "{} consultas", hosts.db_lookups());
    assert_eq!(unknown, hosts.db_lookups());

    // Depois da rajada, nunca mais de `MAX_UNKNOWN_HOSTS` no contador.
    let mut c = redis.get().await?;
    let n: Option<i64> = redis::cmd("GET")
        .arg(format!("{ns}host:miss:ip:198.51.100.10"))
        .query_async(&mut c)
        .await?;
    assert!(n.unwrap_or_default() <= MAX_UNKNOWN_HOSTS, "{n:?}");
    drop(c);
    cleanup(&redis, &ns).await
}

#[sqlx::test(migrations = "../migrations")]
async fn ipv6_slash_48_has_a_wider_second_limit(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let pool = app_pool(&opts, &conn).await?;
    let redis = redis()?;
    let ns = namespace();
    let (app, hosts) = limited_app(&pool, redis.clone(), &ns);
    let per64 = usize::try_from(MAX_UNKNOWN_HOSTS)?;
    let nets = usize::try_from(MAX_UNKNOWN_HOSTS_48 / MAX_UNKNOWN_HOSTS)?;

    // Rodar /64 dentro do mesmo /48: cada /64 fica no seu limite, o /48 esgota ao fim de 10×.
    for n in 0..nets {
        let peer = format!("2001:db8:9:{n:x}::1");
        for i in 0..per64 {
            let r = from(&app, &format!("r48-{n}-{i}.ptmarket.invalid"), &peer).await?;
            assert_eq!(r.status, StatusCode::NOT_FOUND, "{peer} {i}");
        }
    }
    let before = hosts.db_lookups();
    let r = from(&app, "r48-x.ptmarket.invalid", "2001:db8:9:ff::1").await?;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "/64 novo no /48 esgotado");
    assert_eq!(hosts.db_lookups(), before);
    let r = from(&app, "r48-x.ptmarket.invalid", "2001:db8:a::1").await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "outro /48");
    cleanup(&redis, &ns).await
}
