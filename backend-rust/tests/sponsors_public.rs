//! Geografia e entidades elegíveis (cartão 03/17) contra o Postgres real, pela API pública
//! (`/api/v1/geo/*`, `/api/v1/sponsors/eligible`) e pela API interna (`covers`).
//!
//! `sqlx::test` cria uma BD nova por teste: o DICOFRE e as entidades semeiam-se como dono.
//! Mundo: distrito 03; concelhos 0302 e 0303; freguesias 0302FA (alfanumérica), 030201, 030202
//! (extinta) e 0303FB. Câmara 0302, Junta 0302FA, Associação A (só 0302FA), Associação B (concelho
//! 0302), Junta inativa de 030201 e Câmara ES de 0302.

use axum::{
    body::Body,
    http::{Request, StatusCode, header::HOST},
};
use deadpool_redis::Runtime;
use http_body_util::BodyExt;
use ptmarket_api::{
    http::router, sponsors::eligibility::covers, state::AppState, storage::NullStorage,
    tenancy::HostResolver,
};
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

type TestResult = anyhow::Result<()>;

const ADMIN_HOST: &str = "admin.ptmarket.invalid";
const TOKEN: &str = "token-interno-de-teste-com-mais-de-32-bytes";

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

fn state(app: &PgPool) -> anyhow::Result<AppState> {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let redis = deadpool_redis::Config::from_url(url).create_pool(Some(Runtime::Tokio1))?;
    Ok(AppState {
        db_primary: app.clone(),
        db_replica: app.clone(),
        redis,
        storage: Arc::new(NullStorage),
        hosts: Arc::new(HostResolver::new(
            app.clone(),
            Some(ADMIN_HOST.to_owned()),
            Some(TOKEN.to_owned().into()),
        )),
    })
}

struct Entities {
    camara: Uuid,
    junta: Uuid,
    assoc_a: Uuid,
    assoc_b: Uuid,
}

async fn entity(
    owner: &PgPool,
    kind: &str,
    country: &str,
    name: &str,
    slug: &str,
    area: Option<&str>,
    active: bool,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code, is_active, logo_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        id,
        kind,
        country,
        name,
        slug,
        area,
        active,
        format!("logos/{slug}.svg")
    )
    .execute(owner)
    .await?;
    Ok(id)
}

async fn area(owner: &PgPool, entity: Uuid, code: &str) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO sponsor_entity_areas (sponsor_entity_id, area_code) VALUES ($1, $2)",
        entity,
        code
    )
    .execute(owner)
    .await?;
    Ok(())
}

async fn world(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
) -> anyhow::Result<(Router, PgPool, Entities)> {
    let owner = opts
        .clone()
        .max_connections(1)
        .connect_with(conn.clone())
        .await?;
    sqlx::query!(
        "INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version, valid_to) VALUES
            ('03', 'district', NULL, 'Distrito Três', 'T', NULL),
            ('0302', 'municipality', '03', 'Concelho Dois', 'T', NULL),
            ('0303', 'municipality', '03', 'Concelho Três', 'T', NULL),
            ('0302FA', 'parish', '0302', 'União Zeta', 'T', NULL),
            ('030201', 'parish', '0302', 'Alfa', 'T', NULL),
            ('030202', 'parish', '0302', 'Extinta', 'T', now()),
            ('0303FB', 'parish', '0303', 'Beta', 'T', NULL)"
    )
    .execute(&owner)
    .await?;
    // Nomes contra a ordem dos selos: o tipo manda, depois o nome.
    let camara = entity(
        &owner,
        "municipality",
        "PT",
        "Zzz Câmara",
        "camara",
        Some("0302"),
        true,
    )
    .await?;
    let junta = entity(
        &owner,
        "parish",
        "PT",
        "Mmm Junta",
        "junta",
        Some("0302FA"),
        true,
    )
    .await?;
    let assoc_a = entity(
        &owner,
        "association",
        "PT",
        "Aaa Associação A",
        "assoc-a",
        None,
        true,
    )
    .await?;
    area(&owner, assoc_a, "0302FA").await?;
    let assoc_b = entity(
        &owner,
        "association",
        "PT",
        "Bbb Associação B",
        "assoc-b",
        None,
        true,
    )
    .await?;
    area(&owner, assoc_b, "0302").await?;
    entity(
        &owner,
        "parish",
        "PT",
        "Junta Inativa",
        "junta-off",
        Some("030201"),
        false,
    )
    .await?;
    entity(
        &owner,
        "municipality",
        "ES",
        "Câmara ES",
        "camara-es",
        Some("0302"),
        true,
    )
    .await?;
    let app = app_pool(opts, conn).await?;
    let router = router(state(&app)?);
    Ok((
        router,
        app,
        Entities {
            camara,
            junta,
            assoc_a,
            assoc_b,
        },
    ))
}

use axum::Router;

struct Reply {
    status: StatusCode,
    cache: Option<String>,
    body: serde_json::Value,
    raw: String,
}

async fn get(app: &Router, host: &str, uri: &str) -> anyhow::Result<Reply> {
    let req = Request::get(uri).header(HOST, host).body(Body::empty())?;
    let res = app.clone().oneshot(req).await?;
    let status = res.status();
    let cache = res
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let raw = String::from_utf8_lossy(&res.into_body().collect().await?.to_bytes()).into_owned();
    Ok(Reply {
        status,
        cache,
        body: serde_json::from_str(&raw).unwrap_or_default(),
        raw,
    })
}

async fn tenant_host(owner: &PgPool) -> anyhow::Result<String> {
    let id = Uuid::now_v7();
    let domain = "nacional.ptmarket.invalid";
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code)
         VALUES ($1, 'nacional', $2, 'Nacional', 'national_portal', 'PT')",
        id,
        domain
    )
    .execute(owner)
    .await?;
    Ok(domain.to_owned())
}

fn kinds(r: &Reply) -> Vec<String> {
    r.body
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e["slug"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[sqlx::test(migrations = "../migrations")]
async fn eligibility_lists_town_hall_parish_and_associations_in_fixed_order(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let (app, db, e) = world(&opts, &conn).await?;
    let host = {
        let owner = opts
            .clone()
            .max_connections(1)
            .connect_with(conn.clone())
            .await?;
        tenant_host(&owner).await?
    };

    // Câmara + Junta + Associação A + Associação B (concelho), pela ordem fixa dos selos.
    let r = get(&app, &host, "/api/v1/sponsors/eligible?dicofre=0302FA").await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(kinds(&r), ["camara", "junta", "assoc-a", "assoc-b"]);
    assert_eq!(r.cache.as_deref(), Some("public, max-age=300"));
    // Só os campos públicos: sem canal nem contactos.
    let first = r.body[0]
        .as_object()
        .map(|o| o.keys().cloned().collect::<std::collections::BTreeSet<_>>());
    let expect: std::collections::BTreeSet<String> = ["id", "kind", "name", "slug", "logo_key"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(first, Some(expect));
    assert!(!r.raw.contains("channel"));

    // Freguesia vizinha: Câmara + Associação B (concelho); a Junta inativa e a Câmara ES ficam de fora.
    let r = get(&app, &host, "/api/v1/sponsors/eligible?dicofre=030201").await?;
    assert_eq!(kinds(&r), ["camara", "assoc-b"]);
    // Outro concelho: ninguém.
    let r = get(&app, &host, "/api/v1/sponsors/eligible?dicofre=0303FB").await?;
    assert_eq!(r.status, StatusCode::OK);
    assert!(kinds(&r).is_empty());

    // API interna: aceita códigos fora de vigor.
    let mut c = db.acquire().await?;
    assert!(covers(&mut c, e.camara, "030202").await?);
    assert!(covers(&mut c, e.junta, "0302FA").await?);
    assert!(!covers(&mut c, e.junta, "030201").await?);
    assert!(covers(&mut c, e.assoc_a, "0302FA").await?);
    assert!(!covers(&mut c, e.assoc_a, "030201").await?);
    assert!(covers(&mut c, e.assoc_b, "030201").await?);
    assert!(!covers(&mut c, e.camara, "0303FB").await?);
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn validation_and_vigor(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let (app, _db, _e) = world(&opts, &conn).await?;
    // Host de plataforma também serve.
    let h = ADMIN_HOST;
    for bad in [
        "dicofre=1106",
        "dicofre=0302fa",
        "dicofre=03A2FA",
        "dicofre=0302FAX",
        "dicofre=",
        "dicofre=0302FA&x=1",
        "x=1",
        "",
    ] {
        let r = get(&app, h, &format!("/api/v1/sponsors/eligible?{bad}")).await?;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", r.raw);
    }
    for bad in [
        "/api/v1/geo/municipalities?district=0",
        "/api/v1/geo/municipalities?district=A3",
        "/api/v1/geo/municipalities?district=03&y=1",
        "/api/v1/geo/municipalities",
        "/api/v1/geo/parishes?municipality=03",
        "/api/v1/geo/parishes?municipality=03A2",
        "/api/v1/geo/parishes?municipality=0302&y=1",
        "/api/v1/geo/districts?y=1",
    ] {
        let r = get(&app, h, bad).await?;
        let want = if bad.ends_with("districts?y=1") {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(r.status, want, "{bad}");
    }
    // Extinta: 404 na elegibilidade; inexistente: 404.
    for code in ["030202", "9999ZZ"] {
        let r = get(
            &app,
            h,
            &format!("/api/v1/sponsors/eligible?dicofre={code}"),
        )
        .await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{code}");
    }
    // Listas: em vigor, por nome; a extinta não sai.
    let r = get(&app, h, "/api/v1/geo/districts").await?;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body,
        serde_json::json!([{"code": "03", "name": "Distrito Três"}])
    );
    assert_eq!(r.cache.as_deref(), Some("public, max-age=300"));
    let r = get(&app, h, "/api/v1/geo/municipalities?district=03").await?;
    assert_eq!(r.body[0]["code"], "0302");
    assert_eq!(r.body[1]["code"], "0303");
    let r = get(&app, h, "/api/v1/geo/parishes?municipality=0302").await?;
    let codes: Vec<_> = r
        .body
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| e["code"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(codes, ["030201", "0302FA"]);
    // Host desconhecido: 404.
    let r = get(&app, "desconhecido.invalid", "/api/v1/geo/districts").await?;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    Ok(())
}
