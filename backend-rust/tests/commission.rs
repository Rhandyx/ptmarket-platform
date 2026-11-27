//! Comissão efetiva com os dados da BD (cartão 03/18): `payments::commission::effective_commission_bps`
//! contra o Postgres real, com a pool da app (`SET ROLE ptmarket_app`) e o âmbito da loja
//! (`StoreScope::for_tests` + `begin_store_tx`), e a pré-visualização pública do registo
//! (`GET /api/v1/signup/commission-preview`).
//!
//! Mundo: canal nacional PT; concelho 9301 (Câmara) com as freguesias 930101 (Junta + Associação) e
//! 930102 (sem Junta); concelho 9302 sem entidades; 930199 extinta. Lojas e pedidos de patrocínio
//! pela app; ativação, overrides, condições da loja, comissão base e escalões pelo dono (migrator).

use std::time::{Duration, SystemTime};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::HOST},
};
use deadpool_redis::Runtime;
use http_body_util::BodyExt;
use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    error::AppError,
    http::router,
    identity::rbac::StoreScope,
    money::{Cents, CommissionRule, monthly_fee_due},
    payments::commission::{CommissionSnapshot, effective_commission_bps, plan_tiers},
    state::AppState,
    storage::NullStorage,
    tenancy::{HostResolver, TenantId, db::begin_store_tx},
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
const DAY: Duration = Duration::from_secs(86_400);
/// Um dia em segundos (vigências pelo dono).
const D: i64 = 86_400;

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

fn merchant() -> AuditCtx {
    AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None)
}

fn cents(v: i64) -> anyhow::Result<Cents> {
    Ok(Cents::new(v)?)
}

struct World {
    owner: PgPool,
    app: PgPool,
    tenant: TenantId,
    camara: Uuid,
    junta: Uuid,
    assoc: Uuid,
    assoc2: Uuid,
}

async fn entity(
    owner: &PgPool,
    kind: &str,
    name: &str,
    slug: &str,
    area: Option<&str>,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code, is_active, logo_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        id,
        kind,
        "PT",
        name,
        slug,
        area,
        true,
        format!("logos/{slug}.svg")
    )
    .execute(owner)
    .await?;
    Ok(id)
}

async fn world(opts: &PgPoolOptions, conn: &PgConnectOptions) -> anyhow::Result<World> {
    let owner = owner_pool(opts, conn).await?;
    let tenant = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code)
         VALUES ($1, 'nacional', 'nacional.ptmarket.invalid', 'Nacional', 'national_portal', 'PT')",
        tenant
    )
    .execute(&owner)
    .await?;
    sqlx::query!(
        "INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version, valid_to) VALUES
            ('93', 'district', NULL, 'Distrito Teste', 'T', NULL),
            ('9301', 'municipality', '93', 'Concelho A', 'T', NULL),
            ('9302', 'municipality', '93', 'Concelho B', 'T', NULL),
            ('930101', 'parish', '9301', 'Freguesia J', 'T', NULL),
            ('930102', 'parish', '9301', 'Freguesia K', 'T', NULL),
            ('930199', 'parish', '9301', 'Extinta', 'T', now()),
            ('930201', 'parish', '9302', 'Freguesia B', 'T', NULL)"
    )
    .execute(&owner)
    .await?;
    // Nomes contra a ordem dos selos: o tipo manda.
    let camara = entity(&owner, "municipality", "Zzz Câmara", "camara", Some("9301")).await?;
    let junta = entity(&owner, "parish", "Mmm Junta", "junta", Some("930101")).await?;
    let assoc = entity(&owner, "association", "Aaa Associação", "assoc", None).await?;
    let assoc2 = entity(&owner, "association", "Bbb Associação", "assoc2", None).await?;
    for (e, code) in [(assoc, "930102"), (assoc2, "930102")] {
        sqlx::query!(
            "INSERT INTO sponsor_entity_areas (sponsor_entity_id, area_code) VALUES ($1, $2)",
            e,
            code
        )
        .execute(&owner)
        .await?;
    }
    let app = app_pool(opts, conn).await?;
    Ok(World {
        owner,
        app,
        tenant: TenantId::for_tests(tenant),
        camara,
        junta,
        assoc,
        assoc2,
    })
}

/// Loja pela app com o âmbito da própria loja.
async fn seed_store(w: &World, slug: &str) -> anyhow::Result<StoreScope> {
    let scope = StoreScope::for_tests(w.tenant, Uuid::now_v7());
    let mut tx = begin_store_tx(&w.app, &scope, &merchant()).await?;
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
    Ok(scope)
}

/// Condições comerciais da loja, pelo dono (a app não escreve `custom_commission_bps`).
async fn set_terms(
    w: &World,
    store: Uuid,
    custom: Option<i32>,
    plan: &str,
    dicofre: Option<&str>,
) -> anyhow::Result<()> {
    let mut tx = w.owner.begin().await?;
    sqlx::query("ALTER TABLE stores NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    let r = sqlx::query!(
        "UPDATE stores SET custom_commission_bps = $2, billing_plan_code = $3, storefront_dicofre = $4
         WHERE id = $1",
        store,
        custom,
        plan,
        dicofre
    )
    .execute(&mut *tx)
    .await?;
    assert_eq!(r.rows_affected(), 1);
    sqlx::query("ALTER TABLE stores FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Pedido da loja (pending) com o override fixado pelo dono: o id.
async fn request(
    w: &World,
    scope: &StoreScope,
    entity: Uuid,
    override_bps: i32,
) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let mut tx = begin_store_tx(&w.app, scope, &merchant()).await?;
    sqlx::query!(
        "INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id)
         VALUES ($1, $2, $3, $4)",
        id,
        w.tenant.as_uuid(),
        scope.store_id(),
        entity
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    sqlx::query!(
        "UPDATE store_sponsorships SET commission_override_bps = $2 WHERE id = $1",
        id,
        override_bps
    )
    .execute(&w.owner)
    .await?;
    Ok(id)
}

/// Ativa com a vigência `[now + from_s, now + to_s)` (`None` = sem fim), pelo dono.
async fn activate(w: &World, id: Uuid, from_s: i64, to_s: Option<i64>) -> anyhow::Result<()> {
    let r = sqlx::query!(
        "UPDATE store_sponsorships SET status = 'active',
                valid_from = now() + $2::int8 * interval '1 second',
                valid_to = now() + $3::int8 * interval '1 second'
         WHERE id = $1",
        id,
        from_s,
        to_s
    )
    .execute(&w.owner)
    .await?;
    assert_eq!(r.rows_affected(), 1);
    Ok(())
}

async fn quote(
    w: &World,
    scope: &StoreScope,
    store: Uuid,
    at: SystemTime,
    before: i64,
    subtotal: i64,
) -> anyhow::Result<Result<CommissionSnapshot, AppError>> {
    let mut tx = begin_store_tx(&w.app, scope, &merchant()).await?;
    let r = effective_commission_bps(&mut tx, store, at, cents(before)?, cents(subtotal)?).await;
    tx.rollback().await?;
    Ok(r)
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort_unstable();
    v
}

/// Patrocínio ativo → Sponsored, fee 0, desconto 8 %; co-patrocínio Câmara + Junta → um só desconto
/// (MIN dos overrides) e os 2 ids ordenados; sem mensalidade mesmo no plano por escalões.
#[sqlx::test(migrations = "../migrations")]
async fn sponsored_and_co_sponsored(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let w = world(&opts, &conn).await?;
    let l1 = seed_store(&w, "loja-1").await?;
    let s1 = l1.store_id();
    set_terms(&w, s1, None, "tiered_subscription", Some("930101")).await?;
    let c = request(&w, &l1, w.camara, 0).await?;
    activate(&w, c, -D, None).await?;

    let now = SystemTime::now();
    let snap = quote(&w, &l1, s1, now, 1_234_500, 10_000).await??;
    assert_eq!(snap.quote.rule, CommissionRule::Sponsored);
    assert_eq!(snap.quote.base_commission_bps.get(), 800);
    assert_eq!(snap.quote.applied_commission_bps.get(), 0);
    assert_eq!(snap.quote.platform_fee, Cents::ZERO);
    assert_eq!(snap.quote.sponsored_discount.get(), 800);
    assert_eq!(snap.active_sponsor_ids, [w.camara]);
    assert_eq!(snap.billing_plan_code, "tiered_subscription");
    assert_eq!(snap.store_monthly_gmv_before.get(), 1_234_500);
    assert_eq!(snap.store_dicofre.as_deref(), Some("930101"));

    // Mensalidade a cobrar com patrocínio ativo: 0 (os escalões vêm da BD).
    let mut c = w.app.acquire().await?;
    let tiers = plan_tiers(&mut c, &snap.billing_plan_code).await?;
    drop(c);
    let due = monthly_fee_due(
        &tiers,
        cents(1_234_500)?,
        !snap.active_sponsor_ids.is_empty(),
    )?;
    assert_eq!(due, Cents::ZERO);

    // Co-patrocínio: Junta com override maior; o MIN manda e o desconto não duplica.
    let j = request(&w, &l1, w.junta, 300).await?;
    activate(&w, j, -D, Some(30 * D)).await?;
    let snap = quote(&w, &l1, s1, SystemTime::now(), 0, 10_000).await??;
    assert_eq!(snap.quote.rule, CommissionRule::Sponsored);
    assert_eq!(snap.quote.applied_commission_bps.get(), 0);
    assert_eq!(snap.quote.platform_fee, Cents::ZERO);
    assert_eq!(snap.quote.sponsored_discount.get(), 800);
    assert_eq!(snap.active_sponsor_ids, sorted(vec![w.camara, w.junta]));
    Ok(())
}

/// Só `active` dentro da vigência conta (a vigência manda, não o job de expiração); `at` no passado
/// dentro da vigência antiga conta; nada ativo → plano com os escalões da BD.
#[sqlx::test(migrations = "../migrations")]
async fn only_active_within_validity_counts(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let l = seed_store(&w, "loja-v").await?;
    let s = l.store_id();
    let d = D;
    // Câmara: active mas vencido (o job ainda não passou a expired).
    let c = request(&w, &l, w.camara, 0).await?;
    activate(&w, c, -10 * d, Some(-5 * d)).await?;
    // Junta: active que só começa daqui a 5 dias.
    let j = request(&w, &l, w.junta, 0).await?;
    activate(&w, j, 5 * d, None).await?;
    // Associação: pending.
    request(&w, &l, w.assoc, 0).await?;
    // Associação 2: revogada (vigorou desde há 30 dias até agora).
    let r = request(&w, &l, w.assoc2, 0).await?;
    activate(&w, r, -30 * d, None).await?;
    sqlx::query!(
        "UPDATE store_sponsorships SET status = 'revoked' WHERE id = $1",
        r
    )
    .execute(&w.owner)
    .await?;

    let now = SystemTime::now();
    // Nada ativo agora → plano commission_payg da BD: 8 % até 20.000 €.
    let snap = quote(&w, &l, s, now, 0, 10_000).await??;
    assert_eq!(snap.quote.rule, CommissionRule::Plan);
    assert!(snap.active_sponsor_ids.is_empty());
    assert_eq!(snap.billing_plan_code, "commission_payg");
    assert_eq!(snap.quote.applied_commission_bps.get(), 800);
    assert_eq!(snap.quote.platform_fee.get(), 800);
    assert_eq!(snap.quote.sponsored_discount, Cents::ZERO);
    // Venda que atravessa os 20.000 €: 10 € a 8 % + 10 € a 6 %.
    let snap = quote(&w, &l, s, now, 1_999_000, 2_000).await??;
    assert_eq!(snap.quote.platform_fee.get(), 80 + 60);

    // Há 7 dias: só a Câmara vigorava como active (a revogada não conta, a pending nunca).
    let snap = quote(&w, &l, s, now - 7 * DAY, 0, 10_000).await??;
    assert_eq!(snap.quote.rule, CommissionRule::Sponsored);
    assert_eq!(snap.active_sponsor_ids, [w.camara]);
    // Daqui a 6 dias: só a Junta.
    let snap = quote(&w, &l, s, now + 6 * DAY, 0, 10_000).await??;
    assert_eq!(snap.quote.rule, CommissionRule::Sponsored);
    assert_eq!(snap.active_sponsor_ids, [w.junta]);
    // Limites da vigência [from, to): logo a seguir ao fim da Câmara já não conta.
    let snap = quote(
        &w,
        &l,
        s,
        now - 5 * DAY + Duration::from_secs(60),
        0,
        10_000,
    )
    .await??;
    assert_eq!(snap.quote.rule, CommissionRule::Plan);
    Ok(())
}

/// A comissão base e os escalões vêm da BD (sem recompilar); exceção negociada; plano sem escalões
/// ou escalões inválidos → erro; âmbito de L1 a pedir L2 → erro (nunca 0 %).
#[sqlx::test(migrations = "../migrations")]
async fn db_driven_and_fail_closed(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let w = world(&opts, &conn).await?;
    let l1 = seed_store(&w, "loja-1").await?;
    let l2 = seed_store(&w, "loja-2").await?;
    let (s1, s2) = (l1.store_id(), l2.store_id());
    let now = SystemTime::now();

    // Muda a base e o 1.º escalão do commission_payg como migrator.
    sqlx::query!("UPDATE platform_settings SET base_commission_bps = 1000")
        .execute(&w.owner)
        .await?;
    sqlx::query!(
        "UPDATE billing_plan_tiers SET marginal_commission_bps = 500
         WHERE plan_code = 'commission_payg' AND gmv_from_cents = 0"
    )
    .execute(&w.owner)
    .await?;
    let snap = quote(&w, &l1, s1, now, 0, 10_000).await??;
    assert_eq!(snap.quote.rule, CommissionRule::Plan);
    assert_eq!(snap.quote.base_commission_bps.get(), 1000);
    assert_eq!(snap.quote.applied_commission_bps.get(), 500);
    assert_eq!(snap.quote.platform_fee.get(), 500);

    // Exceção negociada: manda sobre o plano e é a referência.
    set_terms(&w, s1, Some(450), "commission_payg", None).await?;
    let snap = quote(&w, &l1, s1, now, 0, 10_000).await??;
    assert_eq!(snap.quote.rule, CommissionRule::Custom);
    assert_eq!(snap.quote.applied_commission_bps.get(), 450);
    assert_eq!(snap.quote.base_commission_bps.get(), 450);
    assert_eq!(snap.quote.platform_fee.get(), 450);

    // L2 patrocinada; o âmbito de L1 a pedir L2 → NotFound (nunca 0 %).
    let c = request(&w, &l2, w.camara, 0).await?;
    activate(&w, c, -D, None).await?;
    let r = quote(&w, &l1, s2, now, 0, 10_000).await?;
    assert!(matches!(r, Err(AppError::NotFound)), "{r:?}");
    // Loja inexistente: o mesmo.
    let r = quote(&w, &l1, Uuid::now_v7(), now, 0, 10_000).await?;
    assert!(matches!(r, Err(AppError::NotFound)), "{r:?}");

    // Escalões inválidos (buraco) e plano sem escalões → Internal, mesmo com patrocínio ativo.
    sqlx::query("ALTER TABLE billing_plan_tiers DISABLE TRIGGER billing_plan_tiers_contiguous")
        .execute(&w.owner)
        .await?;
    sqlx::query!(
        "UPDATE billing_plan_tiers SET gmv_to_cents = 1500000
         WHERE plan_code = 'commission_payg' AND gmv_from_cents = 0"
    )
    .execute(&w.owner)
    .await?;
    let r = quote(&w, &l2, s2, now, 0, 10_000).await?;
    assert!(matches!(r, Err(AppError::Internal(_))), "{r:?}");
    sqlx::query!("DELETE FROM billing_plan_tiers WHERE plan_code = 'tiered_subscription'")
        .execute(&w.owner)
        .await?;
    set_terms(&w, s2, None, "tiered_subscription", None).await?;
    let r = quote(&w, &l2, s2, now, 0, 10_000).await?;
    assert!(matches!(r, Err(AppError::Internal(_))), "{r:?}");
    Ok(())
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

struct Reply {
    status: StatusCode,
    cache: Option<String>,
    body: serde_json::Value,
    raw: String,
}

async fn get(app: &Router, uri: &str) -> anyhow::Result<Reply> {
    let req = Request::get(uri)
        .header(HOST, ADMIN_HOST)
        .body(Body::empty())?;
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

const PREVIEW: &str = "/api/v1/signup/commission-preview";

/// Sem `dicofre` → `sponsored: null` e os planos da BD; freguesia com Câmara + Junta → 2 sponsors
/// pela ordem fixa; sem entidades → null; `dicofre` inválido → 400.
#[sqlx::test(migrations = "../migrations")]
async fn signup_preview(opts: PgPoolOptions, conn: PgConnectOptions) -> TestResult {
    let w = world(&opts, &conn).await?;
    let app = router(state(&w.app)?);

    let r = get(&app, PREVIEW).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.cache.as_deref(), Some("public, max-age=60"));
    assert_eq!(r.body["reference_bps"], 800);
    assert!(r.body["sponsored"].is_null(), "{}", r.raw);
    let plans = r.body["plans"].as_array().cloned().unwrap_or_default();
    assert_eq!(plans.len(), 2, "{}", r.raw);
    assert_eq!(plans[0]["plan_code"], "commission_payg");
    assert_eq!(plans[0]["is_default"], true);
    assert_eq!(
        plans[0]["tiers"],
        serde_json::json!([
            {"gmv_from_cents": 0, "gmv_to_cents": 2_000_000, "monthly_fee_cents": 0, "marginal_commission_bps": 800},
            {"gmv_from_cents": 2_000_000, "gmv_to_cents": null, "monthly_fee_cents": 0, "marginal_commission_bps": 600}
        ])
    );
    assert_eq!(plans[1]["plan_code"], "tiered_subscription");
    assert_eq!(plans[1]["is_default"], false);
    assert_eq!(plans[1]["tiers"].as_array().map(Vec::len), Some(7));
    assert_eq!(
        plans[1]["tiers"][6]["gmv_to_cents"],
        serde_json::Value::Null
    );
    assert!(!r.raw.contains('.'), "só inteiros: {}", r.raw);

    // Câmara + Junta, pela ordem fixa dos selos (apesar dos nomes).
    let r = get(&app, &format!("{PREVIEW}?dicofre=930101")).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.body["sponsored"]["applied_bps"], 0);
    let ids: Vec<_> = r.body["sponsored"]["sponsors"]
        .as_array()
        .map(|a| a.iter().map(|e| e["id"].clone()).collect())
        .unwrap_or_default();
    assert_eq!(
        ids,
        [
            serde_json::json!(w.camara.to_string()),
            serde_json::json!(w.junta.to_string())
        ]
    );
    assert_eq!(r.body["sponsored"]["sponsors"][0]["slug"], "camara");
    assert_eq!(r.body["sponsored"]["sponsors"][1]["kind"], "parish");
    assert_eq!(r.body["plans"].as_array().map(Vec::len), Some(2));

    // Concelho sem entidades → null.
    let r = get(&app, &format!("{PREVIEW}?dicofre=930201")).await?;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert!(r.body["sponsored"].is_null(), "{}", r.raw);

    // A base vem da BD.
    sqlx::query!("UPDATE platform_settings SET base_commission_bps = 750")
        .execute(&w.owner)
        .await?;
    let r = get(&app, PREVIEW).await?;
    assert_eq!(r.body["reference_bps"], 750);

    for bad in [
        "dicofre=",
        "dicofre=9301",
        "dicofre=930101X",
        "dicofre=93010a",
        "dicofre=930199",
        "dicofre=999999",
        "dicofre=930101&x=1",
        "x=1",
    ] {
        let r = get(&app, &format!("{PREVIEW}?{bad}")).await?;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", r.raw);
    }
    Ok(())
}
