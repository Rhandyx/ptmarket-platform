//! Leitura por canal (cartão 03/16; spec 14 §1.1) contra o Postgres real: `PortalReadTx` no canal
//! nacional e nos canais white-label das Câmaras, selos pela ordem fixa, co-patrocínio sem
//! duplicados e patrocínios vencidos/revogados fora do white-label sem correr job nenhum.
//!
//! A pool da app faz `SET ROLE ptmarket_app` (o dono não prova nada). Tenants, DICOFRE e entidades
//! semeiam-se como dono (migrator); lojas e pedidos de patrocínio pela app com o âmbito da loja
//! (`begin_store_tx`) e as decisões com o âmbito da entidade (`begin_sponsor_tx`), cartão 03/14.
//!
//! Mundo (todas as lojas no nacional PT, o único tipo de tenant que pode ter lojas):
//! - `s1` Câmara A (canal CA) + Junta J (sem domínio) · `s2` Câmara B (canal CB) · `s3` sem
//!   patrocínio, sem o antigo opt-in, `pickup_only` · `s4` Câmara A `active` com `valid_to` no
//!   passado · `s5` Câmara A revogado · `s6` Associação + Junta J + Junta K (sem domínio).
//! - `es` no nacional ES.

use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    error::AppError,
    identity::rbac::{SponsorScope, StoreScope},
    tenancy::{
        CountryCode, PortalReadTx, PortalStore, ResolvedTenant, ShippingScope, SponsorKind,
        TenantId, TenantType, begin_portal_read_tx,
        db::{begin_sponsor_tx, begin_store_tx},
    },
};
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

type TestResult = anyhow::Result<()>;

const IBAN: &str = "PT50000201231234567890154";

async fn app_pool(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(2)
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

fn actor() -> AuditCtx {
    AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None)
}

async fn seed_tenant(
    owner: &PgPool,
    slug: &str,
    tenant_type: TenantType,
    country: CountryCode,
) -> sqlx::Result<ResolvedTenant> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code)
         VALUES ($1, $2, $3, $4, $5, $6)",
        id,
        slug,
        format!("{slug}.ptmarket.invalid"),
        slug,
        tenant_type.as_str(),
        country.as_str()
    )
    .execute(owner)
    .await?;
    Ok(ResolvedTenant::for_tests(
        TenantId::for_tests(id),
        tenant_type,
        country,
    ))
}

async fn seed_entity(
    owner: &PgPool,
    kind: &str,
    name: &str,
    slug: &str,
    area: Option<&str>,
    channel: Option<&ResolvedTenant>,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code,
                                       channel_tenant_id, logo_key)
         VALUES ($1, $2, 'PT', $3, $4, $5, $6, $7)",
        id,
        kind,
        name,
        slug,
        area,
        channel.map(|c| c.id().as_uuid()),
        format!("logos/{slug}.svg")
    )
    .execute(owner)
    .await?;
    Ok(id)
}

/// Loja na app (com IBAN, para provar que não sai).
async fn seed_store(
    app: &PgPool,
    t: &ResolvedTenant,
    name: &str,
    slug: &str,
    publish: bool,
    scope: &str,
    dicofre: Option<&str>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    // Âmbito da própria loja (`app.store_id` = o id novo, gerado em Rust: 0035).
    let mut tx = begin_store_tx(app, &StoreScope::for_tests(t.id(), id), &actor()).await?;
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email,
                             publish_to_national_portal, shipping_scope, storefront_dicofre)
         VALUES ($1, $2, $3, $4, $3, '500000000', $5, 'loja@test.invalid', $6, $7, $8)",
        id,
        t.id().as_uuid(),
        name,
        slug,
        IBAN,
        publish,
        scope,
        dicofre
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Como termina o patrocínio criado por `sponsor`.
#[derive(Clone, Copy)]
enum Fate {
    /// `active` desde ontem, sem fim.
    Active,
    /// `active` com a vigência já acabada (o job de expiração ainda não passou).
    ActiveButPast,
    /// `active` e depois `revoked`.
    Revoked,
}

/// Patrocínio pela app: a loja pede (nasce `pending`, com o âmbito da loja) e a entidade decide
/// por UPDATE (trigger da 0031), com o âmbito da entidade no canal nacional da loja (0035).
async fn sponsor(
    app: &PgPool,
    t: &ResolvedTenant,
    store: Uuid,
    entity: Uuid,
    fate: Fate,
) -> anyhow::Result<()> {
    let id = Uuid::now_v7();
    let mut tx = begin_store_tx(app, &StoreScope::for_tests(t.id(), store), &actor()).await?;
    sqlx::query!(
        "INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id)
         VALUES ($1, $2, $3, $4)",
        id,
        t.id().as_uuid(),
        store,
        entity
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let decider = AuditCtx::for_tests(ActorType::Municipal, Some(Uuid::now_v7()), None, None);
    let mut tx = begin_sponsor_tx(app, t.id(), &SponsorScope::for_tests(entity), &decider).await?;
    match fate {
        Fate::Active | Fate::Revoked => {
            sqlx::query!(
                "UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
                 WHERE id = $1",
                id
            )
            .execute(&mut *tx)
            .await?;
        }
        Fate::ActiveButPast => {
            sqlx::query!(
                "UPDATE store_sponsorships SET status = 'active',
                        valid_from = now() - interval '10 days', valid_to = now() - interval '1 day'
                 WHERE id = $1",
                id
            )
            .execute(&mut *tx)
            .await?;
        }
    }
    if matches!(fate, Fate::Revoked) {
        sqlx::query!(
            "UPDATE store_sponsorships SET status = 'revoked' WHERE id = $1",
            id
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

struct World {
    app: PgPool,
    np: ResolvedTenant,
    ca: ResolvedTenant,
    cb: ResolvedTenant,
    camara_a: Uuid,
    camara_b: Uuid,
    junta_j: Uuid,
    junta_k: Uuid,
    assoc: Uuid,
    s: [Uuid; 6],
}

async fn world(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> anyhow::Result<World> {
    let owner = owner_pool(opts, conn).await?;
    sqlx::query!(
        "INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
            ('93', 'district', NULL, 'Distrito Teste', 'T'),
            ('9301', 'municipality', '93', 'Concelho A', 'T'),
            ('9302', 'municipality', '93', 'Concelho B', 'T'),
            ('930101', 'parish', '9301', 'Freguesia J', 'T'),
            ('930102', 'parish', '9301', 'Freguesia K', 'T')"
    )
    .execute(&owner)
    .await?;
    let np = seed_tenant(
        &owner,
        "nacional-pt",
        TenantType::NationalPortal,
        CountryCode::Pt,
    )
    .await?;
    let ne = seed_tenant(
        &owner,
        "nacional-es",
        TenantType::NationalPortal,
        CountryCode::Es,
    )
    .await?;
    let ca = seed_tenant(&owner, "canal-a", TenantType::Municipal, CountryCode::Pt).await?;
    let cb = seed_tenant(&owner, "canal-b", TenantType::Municipal, CountryCode::Pt).await?;
    // Nomes contra a ordem alfabética: os selos ordenam-se pelo tipo e só depois pelo nome.
    let camara_a = seed_entity(
        &owner,
        "municipality",
        "Zzz Câmara A",
        "camara-a",
        Some("9301"),
        Some(&ca),
    )
    .await?;
    let camara_b = seed_entity(
        &owner,
        "municipality",
        "Zzz Câmara B",
        "camara-b",
        Some("9302"),
        Some(&cb),
    )
    .await?;
    let junta_j = seed_entity(
        &owner,
        "parish",
        "Mmm Junta J",
        "junta-j",
        Some("930101"),
        None,
    )
    .await?;
    let junta_k = seed_entity(
        &owner,
        "parish",
        "Mmn Junta K",
        "junta-k",
        Some("930102"),
        None,
    )
    .await?;
    let assoc = seed_entity(&owner, "association", "Aaa Associação", "assoc", None, None).await?;

    let app = app_pool(opts, conn).await?;
    let s1 = seed_store(&app, &np, "Loja 1", "s1", true, "national", Some("930101")).await?;
    let s2 = seed_store(&app, &np, "Loja 2", "s2", true, "local_only", None).await?;
    let s3 = seed_store(&app, &np, "Loja 3", "s3", false, "pickup_only", None).await?;
    let s4 = seed_store(&app, &np, "Loja 4", "s4", true, "national", None).await?;
    let s5 = seed_store(&app, &np, "Loja 5", "s5", true, "national", None).await?;
    let s6 = seed_store(&app, &np, "Loja 6", "s6", true, "national", None).await?;
    seed_store(&app, &ne, "Tienda", "es", true, "national", None).await?;
    sponsor(&app, &np, s1, camara_a, Fate::Active).await?;
    sponsor(&app, &np, s1, junta_j, Fate::Active).await?;
    sponsor(&app, &np, s2, camara_b, Fate::Active).await?;
    sponsor(&app, &np, s4, camara_a, Fate::ActiveButPast).await?;
    sponsor(&app, &np, s5, camara_a, Fate::Revoked).await?;
    sponsor(&app, &np, s6, assoc, Fate::Active).await?;
    sponsor(&app, &np, s6, junta_k, Fate::Active).await?;
    sponsor(&app, &np, s6, junta_j, Fate::Active).await?;
    Ok(World {
        app,
        np,
        ca,
        cb,
        camara_a,
        camara_b,
        junta_j,
        junta_k,
        assoc,
        s: [s1, s2, s3, s4, s5, s6],
    })
}

async fn open(w: &World, channel: &ResolvedTenant) -> anyhow::Result<PortalReadTx> {
    let ctx = AuditCtx::for_tests(ActorType::Anonymous, None, None, None);
    Ok(begin_portal_read_tx(&w.app, channel, &ctx).await?)
}

fn ids(stores: &[PortalStore]) -> Vec<Uuid> {
    stores.iter().map(|s| s.id).collect()
}

fn badges(store: &PortalStore) -> Vec<Uuid> {
    store.badges.iter().map(|b| b.sponsor_entity_id).collect()
}

fn find(stores: &[PortalStore], id: Uuid) -> anyhow::Result<&PortalStore> {
    stores
        .iter()
        .find(|s| s.id == id)
        .ok_or_else(|| anyhow::anyhow!("loja {id} em falta"))
}

#[sqlx::test(migrations = "../migrations")]
async fn white_label_channels_are_isolated_and_national_shows_all_active_stores(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let [s1, s2, s3, s4, s5, s6] = w.s;

    // Canal da Câmara A: só a loja patrocinada pela Câmara A (vigente).
    let mut tx = open(&w, &w.ca).await?;
    assert_eq!(ids(&tx.published_stores(100).await?), vec![s1]);
    assert_eq!(
        tx.store_by_slug("s1").await?.map(|s| s.id),
        Some(s1),
        "loja visível no canal"
    );
    for slug in ["s2", "s3", "s4", "s5", "s6", "es", "nada"] {
        assert_eq!(tx.store_by_slug(slug).await?, None, "{slug}");
    }
    assert!(tx.stores_by_ids(&[s2, s3, s4, s5, s6]).await?.is_empty());
    assert_eq!(ids(&tx.stores_by_ids(&[s2, s1]).await?), vec![s1]);
    assert!(tx.stores_by_entity("camara-b", 100).await?.is_empty());
    tx.finish().await?;

    // Canal da Câmara B: só a sua; a da Câmara A não existe aqui.
    let mut tx = open(&w, &w.cb).await?;
    let stores = tx.published_stores(100).await?;
    assert_eq!(ids(&stores), vec![s2]);
    assert_eq!(badges(&stores[0]), vec![w.camara_b]);
    assert_eq!(stores[0].shipping_scope, ShippingScope::LocalOnly);
    assert_eq!(tx.store_by_slug("s1").await?, None);
    assert!(tx.stores_by_ids(&[s1]).await?.is_empty());
    tx.finish().await?;

    // Nacional: todas as ativas do país (sem opt-out; pickup_only não esconde), nenhuma de ES.
    let mut tx = open(&w, &w.np).await?;
    let stores = tx.published_stores(100).await?;
    assert_eq!(ids(&stores), vec![s1, s2, s3, s4, s5, s6]);
    assert!(stores.iter().all(|s| s.tenant_id == w.np.id().as_uuid()));
    let s3_row = find(&stores, s3)?;
    assert_eq!(s3_row.shipping_scope, ShippingScope::PickupOnly);
    assert!(s3_row.badges.is_empty());
    let s1_row = find(&stores, s1)?;
    assert_eq!(s1_row.storefront_dicofre.as_deref(), Some("930101"));
    assert_eq!(s1_row.nif, "500000000");
    assert_eq!(tx.store_by_slug("es").await?, None);
    // Limites: 1..=100.
    assert_eq!(tx.published_stores(0).await?.len(), 1);
    assert_eq!(tx.published_stores(2).await?.len(), 2);
    let too_many: Vec<Uuid> = (0..101).map(|_| Uuid::now_v7()).collect();
    assert!(matches!(
        tx.stores_by_ids(&too_many).await,
        Err(AppError::Validation(_))
    ));
    assert_eq!(tx.stores_by_ids(&too_many[..100]).await?, Vec::new());
    assert_eq!(tx.stores_by_ids(&[]).await?, Vec::new());

    // Nenhuma coluna nem valor sensível sai.
    let json = serde_json::to_string(&stores)?;
    assert!(!json.contains(IBAN) && !json.contains("iban"));
    assert!(!json.contains("commission") && !json.contains("split"));
    tx.finish().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn co_sponsored_store_appears_once_with_badges_in_fixed_order(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let [s1, _, _, _, _, s6] = w.s;

    // Canal A: s1 uma só vez, com Câmara antes da Junta (apesar do nome); a contagem é 1.
    let mut tx = open(&w, &w.ca).await?;
    let stores = tx.published_stores(100).await?;
    assert_eq!(stores.len(), 1);
    assert_eq!(badges(&stores[0]), vec![w.camara_a, w.junta_j]);
    let kinds: Vec<SponsorKind> = stores[0].badges.iter().map(|b| b.kind).collect();
    assert_eq!(kinds, vec![SponsorKind::Municipality, SponsorKind::Parish]);
    assert_eq!(stores[0].badges[1].slug, "junta-j");
    assert_eq!(
        stores[0].badges[1].logo_key.as_deref(),
        Some("logos/junta-j.svg")
    );
    // A Câmara e a Junta (entidade sem domínio) devolvem ambas a loja.
    assert_eq!(ids(&tx.stores_by_entity("camara-a", 100).await?), vec![s1]);
    assert_eq!(ids(&tx.stores_by_entity("junta-j", 100).await?), vec![s1]);
    tx.finish().await?;

    // Nacional: s1 uma só vez entre 6; a Junta sem domínio tem a sua página com s1 e s6.
    let mut tx = open(&w, &w.np).await?;
    let stores = tx.published_stores(100).await?;
    assert_eq!(stores.len(), 6);
    assert_eq!(stores.iter().filter(|s| s.id == s1).count(), 1);
    assert_eq!(badges(find(&stores, s1)?), vec![w.camara_a, w.junta_j]);
    // Ordem fixa municipality → parish → association; no mesmo tipo, por nome.
    assert_eq!(
        badges(find(&stores, s6)?),
        vec![w.junta_j, w.junta_k, w.assoc]
    );
    assert_eq!(
        ids(&tx.stores_by_entity("junta-j", 100).await?),
        vec![s1, s6]
    );
    assert_eq!(ids(&tx.stores_by_entity("junta-j", 1).await?), vec![s1]);
    assert_eq!(ids(&tx.stores_by_entity("assoc", 100).await?), vec![s6]);
    assert_eq!(ids(&tx.stores_by_entity("camara-a", 100).await?), vec![s1]);
    assert!(tx.stores_by_entity("nada", 100).await?.is_empty());
    // stores_by_ids devolve os selos também (uma 2.ª consulta, sem N+1).
    let by_ids = tx.stores_by_ids(&[s6, s1]).await?;
    assert_eq!(ids(&by_ids), vec![s1, s6]);
    assert_eq!(badges(&by_ids[1]), vec![w.junta_j, w.junta_k, w.assoc]);
    tx.finish().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn past_or_revoked_sponsorship_leaves_white_label_and_stays_national_without_badge(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let w = world(&opts, &conn).await?;
    let [s1, _, _, s4, s5, _] = w.s;

    // Sem job: `active` com valid_to no passado (s4) e revogado (s5) não saem no canal A.
    let mut tx = open(&w, &w.ca).await?;
    assert_eq!(ids(&tx.published_stores(100).await?), vec![s1]);
    assert_eq!(tx.store_by_slug("s4").await?, None);
    assert_eq!(tx.store_by_slug("s5").await?, None);
    assert!(tx.stores_by_ids(&[s4, s5]).await?.is_empty());
    tx.finish().await?;

    // No nacional ficam, sem o selo da Câmara A.
    let mut tx = open(&w, &w.np).await?;
    for (slug, id) in [("s4", s4), ("s5", s5)] {
        let s = tx
            .store_by_slug(slug)
            .await?
            .ok_or_else(|| anyhow::anyhow!("{slug} fora do nacional"))?;
        assert_eq!(s.id, id);
        assert!(s.badges.is_empty(), "{slug}: {:?}", s.badges);
    }
    assert_eq!(ids(&tx.stores_by_entity("camara-a", 100).await?), vec![s1]);
    tx.finish().await?;
    Ok(())
}
