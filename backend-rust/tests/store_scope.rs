//! Âmbito por loja e por entidade pelo lado da RLS (cartão 03/14; policies RESTRICTIVE da 0035),
//! contra o Postgres real e SEM passar pelo extractor: `StoreScope`/`SponsorScope` de teste
//! (`for_tests`, feature `test-support`) abrem `begin_store_tx`/`begin_sponsor_tx`.
//!
//! Todas as lojas de um país vivem no mesmo tenant (o canal nacional): L1 e L2 são do nacional PT.
//! As pools da app fazem `SET ROLE ptmarket_app` (o dono não prova nada); tenants, DICOFRE e
//! entidades semeiam-se como dono; lojas, produtos e patrocínios pela app, com o âmbito certo.
//! O lado do extractor (404 + `idor`) está em `tests/rbac.rs`.

use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    identity::rbac::{SponsorScope, StoreScope},
    tenancy::{
        CountryCode, ResolvedTenant, TenantId, TenantTx, TenantType, begin_portal_read_tx,
        begin_tenant_tx,
        db::{begin_sponsor_tx, begin_store_tx},
    },
};
use sqlx::{
    PgConnection, PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

type TestResult = anyhow::Result<()>;

/// SQLSTATE de uma linha recusada pela RLS.
const RLS_VIOLATION: &str = "42501";
/// SQLSTATE de violação de UNIQUE.
const UNIQUE_VIOLATION: &str = "23505";

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

fn merchant() -> AuditCtx {
    AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, None)
}

fn municipal() -> AuditCtx {
    AuditCtx::for_tests(ActorType::Municipal, Some(Uuid::now_v7()), None, None)
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

async fn seed_tenant(
    owner: &PgPool,
    slug: &str,
    tenant_type: TenantType,
    country: CountryCode,
) -> sqlx::Result<TenantId> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code)
         VALUES ($1, $2, $3, $2, $4, $5)",
        id,
        slug,
        format!("{slug}.ptmarket.invalid"),
        tenant_type.as_str(),
        country.as_str()
    )
    .execute(owner)
    .await?;
    Ok(TenantId::for_tests(id))
}

/// Câmara A (concelho `9301`) e Junta J (freguesia `930101`) de PT, pelo dono: (câmara, junta).
async fn seed_entities(owner: &PgPool) -> sqlx::Result<(Uuid, Uuid)> {
    sqlx::query!(
        "INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
            ('93', 'district', NULL, 'Distrito Teste', 'T'),
            ('9301', 'municipality', '93', 'Concelho A', 'T'),
            ('930101', 'parish', '9301', 'Freguesia J', 'T')"
    )
    .execute(owner)
    .await?;
    let (camara, junta) = (Uuid::now_v7(), Uuid::now_v7());
    sqlx::query!(
        "INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code) VALUES
            ($1, 'municipality', 'PT', 'Câmara A', 'camara-a', '9301'),
            ($2, 'parish', 'PT', 'Junta J', 'junta-j', '930101')",
        camara,
        junta
    )
    .execute(owner)
    .await?;
    Ok((camara, junta))
}

async fn insert_store(
    conn: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
    slug: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email)
         VALUES ($1, $2, $3, $3, $3, '500000000', 'PT50000000000000000000000', 'loja@test.invalid')",
        id,
        tenant.as_uuid(),
        slug
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Loja pela app com o âmbito da própria loja (o id nasce em Rust).
async fn seed_store(app: &PgPool, tenant: TenantId, slug: &str) -> anyhow::Result<StoreScope> {
    let scope = StoreScope::for_tests(tenant, Uuid::now_v7());
    let mut tx = begin_store_tx(app, &scope, &merchant()).await?;
    insert_store(&mut tx, tenant, scope.store_id(), slug).await?;
    tx.commit().await?;
    Ok(scope)
}

async fn insert_product(
    conn: &mut PgConnection,
    tenant: TenantId,
    store: Uuid,
    published: bool,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps, is_published)
         VALUES ($1, $2, $3, $4, 2300, $5)",
        id,
        tenant.as_uuid(),
        store,
        serde_json::json!({"pt": "Produto"}),
        published
    )
    .execute(conn)
    .await?;
    Ok(id)
}

/// Produto (publicado) com uma variante a 10,00 € na loja do âmbito: (produto, variante).
async fn seed_product(app: &PgPool, scope: &StoreScope) -> anyhow::Result<(Uuid, Uuid)> {
    let mut tx = begin_store_tx(app, scope, &merchant()).await?;
    let product = insert_product(&mut tx, scope.tenant(), scope.store_id(), true).await?;
    let variant = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO product_variants (id, tenant_id, product_id, price_cents)
         VALUES ($1, $2, $3, 1000)",
        variant,
        scope.tenant().as_uuid(),
        product
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((product, variant))
}

/// Pedido de patrocínio pela loja (nasce `pending`, `initiated_by = 'store'`): o id.
async fn request_sponsorship(
    app: &PgPool,
    scope: &StoreScope,
    entity: Uuid,
) -> anyhow::Result<Uuid> {
    let id = Uuid::now_v7();
    let mut tx = begin_store_tx(app, scope, &merchant()).await?;
    sqlx::query!(
        "INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id)
         VALUES ($1, $2, $3, $4)",
        id,
        scope.tenant().as_uuid(),
        scope.store_id(),
        entity
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

async fn count(tx: &mut TenantTx, sql: &'static str, id: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar(sql).bind(id).fetch_one(&mut **tx).await
}

async fn guc(conn: &mut PgConnection, name: &str) -> sqlx::Result<String> {
    let v: Option<String> = sqlx::query_scalar("SELECT current_setting($1, true)")
        .bind(name)
        .fetch_one(conn)
        .await?;
    Ok(v.unwrap_or_default())
}

async fn backend_pid(conn: &mut PgConnection) -> sqlx::Result<i32> {
    sqlx::query_scalar!(r#"SELECT pg_backend_pid() AS "pid!""#)
        .fetch_one(conn)
        .await
}

/// Com o âmbito de L1: UPDATE/DELETE em L2 (mesmo tenant) afetam 0 linhas, SELECT direto de L2 dá 0
/// linhas e INSERT de produto em L2 → erro de RLS. Sem âmbito, nenhuma escrita em loja nenhuma.
/// Com o âmbito de L1, a escrita em L1 passa e o histórico Omnibus fica gravado.
#[sqlx::test(migrations = "../migrations")]
async fn store_scope_isolates_stores_of_the_same_tenant(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let pt = seed_tenant(
        &owner,
        "nacional-pt",
        TenantType::NationalPortal,
        CountryCode::Pt,
    )
    .await?;
    let app = app_pool(&opts, &conn, 2).await?;
    let l1 = seed_store(&app, pt, "loja-1").await?;
    let l2 = seed_store(&app, pt, "loja-2").await?;
    let (_, v1) = seed_product(&app, &l1).await?;
    let (p2, v2) = seed_product(&app, &l2).await?;
    let l2_id = l2.store_id();

    // Âmbito de L1 contra L2 (mesmo tenant, mesmo país).
    let mut tx = begin_store_tx(&app, &l1, &merchant()).await?;
    let r = sqlx::query!("UPDATE stores SET name = 'roubada' WHERE id = $1", l2_id)
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "UPDATE em L2");
    let r = sqlx::query!("UPDATE products SET is_published = false WHERE id = $1", p2)
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "UPDATE de produto de L2");
    let r = sqlx::query!(
        "UPDATE product_variants SET price_cents = 1 WHERE id = $1",
        v2
    )
    .execute(&mut *tx)
    .await?;
    assert_eq!(r.rows_affected(), 0, "UPDATE de variante de L2");
    let r = sqlx::query!("DELETE FROM product_variants WHERE id = $1", v2)
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "DELETE de variante de L2");
    let r = sqlx::query!("DELETE FROM products WHERE id = $1", p2)
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "DELETE de produto de L2");
    let r = sqlx::query!("DELETE FROM stores WHERE id = $1", l2_id)
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "DELETE de L2");
    assert_eq!(
        count(&mut tx, "SELECT count(*) FROM stores WHERE id = $1", l2_id).await?,
        0
    );
    assert_eq!(
        count(
            &mut tx,
            "SELECT count(*) FROM products WHERE store_id = $1",
            l2_id
        )
        .await?,
        0
    );
    assert_eq!(
        count(
            &mut tx,
            "SELECT count(*) FROM product_variants WHERE id = $1",
            v2
        )
        .await?,
        0
    );
    assert_eq!(
        count(
            &mut tx,
            "SELECT count(*) FROM product_price_history WHERE variant_id = $1",
            v2
        )
        .await?,
        0
    );
    // A própria loja continua visível.
    assert_eq!(
        count(
            &mut tx,
            "SELECT count(*) FROM stores WHERE id = $1",
            l1.store_id()
        )
        .await?,
        1
    );
    let res = insert_product(&mut tx, pt, l2_id, true).await;
    assert_eq!(
        res.as_ref().err().and_then(sqlstate).as_deref(),
        Some(RLS_VIOLATION),
        "INSERT de produto em L2: {res:?}"
    );
    tx.rollback().await?;

    // Uma loja nova com outro id que não o do âmbito → erro de RLS.
    let mut tx = begin_store_tx(&app, &l1, &merchant()).await?;
    let res = insert_store(&mut tx, pt, Uuid::now_v7(), "intrusa").await;
    assert_eq!(
        res.as_ref().err().and_then(sqlstate).as_deref(),
        Some(RLS_VIOLATION),
        "{res:?}"
    );
    tx.rollback().await?;

    // Sem âmbito (merchant): nenhuma escrita em loja nenhuma, nenhuma leitura de `stores`.
    let mut tx = begin_tenant_tx(&app, pt, &merchant()).await?;
    let r = sqlx::query!("UPDATE stores SET name = 'x'")
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "UPDATE sem âmbito");
    let r = sqlx::query!("UPDATE product_variants SET price_cents = 1")
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "UPDATE de variantes sem âmbito");
    let r = sqlx::query!("DELETE FROM products")
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "DELETE sem âmbito");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM stores")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(n, 0, "stores sem âmbito");
    let res = insert_product(&mut tx, pt, l1.store_id(), true).await;
    assert_eq!(
        res.as_ref().err().and_then(sqlstate).as_deref(),
        Some(RLS_VIOLATION),
        "INSERT de produto sem âmbito: {res:?}"
    );
    tx.rollback().await?;

    // Âmbito de L1 em L1: a escrita passa e o Omnibus grava o preço novo.
    let mut tx = begin_store_tx(&app, &l1, &merchant()).await?;
    let l1_id = l1.store_id();
    let r = sqlx::query!("UPDATE stores SET name = 'Loja Um' WHERE id = $1", l1_id)
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 1);
    let r = sqlx::query!(
        "UPDATE product_variants SET price_cents = 900 WHERE id = $1",
        v1
    )
    .execute(&mut *tx)
    .await?;
    assert_eq!(r.rows_affected(), 1);
    tx.commit().await?;
    let mut tx = begin_store_tx(&app, &l1, &merchant()).await?;
    let prices: Vec<i64> = sqlx::query_scalar(
        "SELECT price_cents FROM product_price_history WHERE variant_id = $1 ORDER BY recorded_at, id",
    )
    .bind(v1)
    .fetch_all(&mut *tx)
    .await?;
    assert_eq!(prices, vec![1000, 900], "histórico Omnibus");
    tx.rollback().await?;

    // L2 ficou intacta (lida com o seu próprio âmbito).
    let mut tx = begin_store_tx(&app, &l2, &merchant()).await?;
    let name: String = sqlx::query_scalar("SELECT name FROM stores WHERE id = $1")
        .bind(l2_id)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(name, "loja-2");
    let price: i64 = sqlx::query_scalar("SELECT price_cents FROM product_variants WHERE id = $1")
        .bind(v2)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(price, 1000);
    tx.rollback().await?;
    Ok(())
}

/// Co-patrocínio: a loja pediu à Câmara e à Junta; com o âmbito da Câmara (no canal nacional da
/// loja) só se vê e só se decide o patrocínio da Câmara; o da Junta fica intacto. Noutro tenant (o
/// canal da Câmara) a Câmara não vê nada. A loja vê os dois pedidos, mas não os decide.
#[sqlx::test(migrations = "../migrations")]
async fn sponsor_scope_sees_and_decides_only_its_own_sponsorship(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let pt = seed_tenant(
        &owner,
        "nacional-pt",
        TenantType::NationalPortal,
        CountryCode::Pt,
    )
    .await?;
    let canal = seed_tenant(&owner, "canal-a", TenantType::Municipal, CountryCode::Pt).await?;
    let (camara, junta) = seed_entities(&owner).await?;
    let app = app_pool(&opts, &conn, 2).await?;
    let l1 = seed_store(&app, pt, "loja-1").await?;
    let sp_camara = request_sponsorship(&app, &l1, camara).await?;
    let sp_junta = request_sponsorship(&app, &l1, junta).await?;
    let store = l1.store_id();
    let by_store = "SELECT count(*) FROM store_sponsorships WHERE store_id = $1";

    // A Câmara: vê só o seu; decide só o seu.
    let camara_scope = SponsorScope::for_tests(camara);
    let mut tx = begin_sponsor_tx(&app, pt, &camara_scope, &municipal()).await?;
    let seen: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, sponsor_entity_id FROM store_sponsorships WHERE store_id = $1")
            .bind(store)
            .fetch_all(&mut *tx)
            .await?;
    assert_eq!(seen, vec![(sp_camara, camara)]);
    assert_eq!(
        count(&mut tx, "SELECT count(*) FROM stores WHERE id = $1", store).await?,
        0
    );
    let r = sqlx::query!(
        "UPDATE store_sponsorships SET status = 'active', valid_from = now() WHERE store_id = $1",
        store
    )
    .execute(&mut *tx)
    .await?;
    assert_eq!(r.rows_affected(), 1, "só o patrocínio da Câmara");
    let r = sqlx::query!(
        "UPDATE store_sponsorships SET status = 'rejected' WHERE id = $1",
        sp_junta
    )
    .execute(&mut *tx)
    .await?;
    assert_eq!(r.rows_affected(), 0, "o da Junta não se altera");
    tx.commit().await?;

    // No tenant do canal da Câmara (não o nacional da loja): nada.
    let mut tx = begin_sponsor_tx(&app, canal, &camara_scope, &municipal()).await?;
    assert_eq!(count(&mut tx, by_store, store).await?, 0);
    tx.rollback().await?;

    // A Junta vê o seu, ainda pendente.
    let mut tx = begin_sponsor_tx(&app, pt, &SponsorScope::for_tests(junta), &municipal()).await?;
    let seen: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, status::text FROM store_sponsorships WHERE store_id = $1")
            .bind(store)
            .fetch_all(&mut *tx)
            .await?;
    assert_eq!(seen, vec![(sp_junta, "pending".to_owned())]);
    tx.rollback().await?;

    // A loja vê os dois, mas não decide nenhum.
    let mut tx = begin_store_tx(&app, &l1, &merchant()).await?;
    assert_eq!(count(&mut tx, by_store, store).await?, 2);
    let r = sqlx::query!(
        "UPDATE store_sponsorships SET status = 'rejected' WHERE id = $1",
        sp_junta
    )
    .execute(&mut *tx)
    .await?;
    assert_eq!(r.rows_affected(), 0, "a loja não decide");
    tx.rollback().await?;
    Ok(())
}

/// Os GUCs de âmbito são locais à transação: na MESMA ligação, uma transação sem âmbito depois de
/// uma de loja (COMMIT) ou de entidade (ROLLBACK) não herda nada, e uma de loja não herda a entidade.
#[sqlx::test(migrations = "../migrations")]
async fn scope_gucs_do_not_leak_between_transactions_on_the_same_connection(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let pt = seed_tenant(
        &owner,
        "nacional-pt",
        TenantType::NationalPortal,
        CountryCode::Pt,
    )
    .await?;
    let (camara, _) = seed_entities(&owner).await?;
    // Uma só ligação: cada transação reutiliza a anterior.
    let app = app_pool(&opts, &conn, 1).await?;
    let l1 = seed_store(&app, pt, "loja-1").await?;
    let pid = backend_pid(&mut *app.acquire().await?).await?;

    let mut tx = begin_store_tx(&app, &l1, &merchant()).await?;
    assert_eq!(backend_pid(&mut tx).await?, pid);
    assert_eq!(
        guc(&mut tx, "app.store_id").await?,
        l1.store_id().to_string()
    );
    assert_eq!(guc(&mut tx, "app.sponsor_entity_id").await?, "");
    tx.commit().await?;

    let mut tx = begin_tenant_tx(&app, pt, &merchant()).await?;
    assert_eq!(
        backend_pid(&mut tx).await?,
        pid,
        "tem de ser a mesma ligação"
    );
    assert_eq!(guc(&mut tx, "app.store_id").await?, "", "loja herdada");
    assert_eq!(
        count(
            &mut tx,
            "SELECT count(*) FROM stores WHERE id = $1",
            l1.store_id()
        )
        .await?,
        0
    );
    tx.rollback().await?;

    let mut tx = begin_sponsor_tx(&app, pt, &SponsorScope::for_tests(camara), &municipal()).await?;
    assert_eq!(
        guc(&mut tx, "app.sponsor_entity_id").await?,
        camara.to_string()
    );
    assert_eq!(guc(&mut tx, "app.store_id").await?, "");
    tx.rollback().await?;

    let mut tx = begin_store_tx(&app, &l1, &merchant()).await?;
    assert_eq!(backend_pid(&mut tx).await?, pid);
    assert_eq!(
        guc(&mut tx, "app.sponsor_entity_id").await?,
        "",
        "entidade herdada"
    );
    tx.rollback().await?;

    // Fora de qualquer transação, na mesma ligação: vazio.
    let mut c = app.acquire().await?;
    assert_eq!(backend_pid(&mut c).await?, pid);
    assert_eq!(guc(&mut c, "app.store_id").await?, "");
    assert_eq!(guc(&mut c, "app.sponsor_entity_id").await?, "");
    Ok(())
}

/// `store_by_slug` sem `ORDER BY` (adenda do 08b ao `tenancy::portal`): um só `national_portal` por
/// país (0035) e um só slug por tenant (0003), por isso um slug identifica uma única loja no canal.
#[sqlx::test(migrations = "../migrations")]
async fn store_slug_is_unique_in_the_national_channel(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let pt = seed_tenant(
        &owner,
        "nacional-pt",
        TenantType::NationalPortal,
        CountryCode::Pt,
    )
    .await?;
    let again = seed_tenant(
        &owner,
        "nacional-pt-2",
        TenantType::NationalPortal,
        CountryCode::Pt,
    )
    .await;
    assert_eq!(
        again.as_ref().err().and_then(sqlstate).as_deref(),
        Some(UNIQUE_VIOLATION),
        "2.º national_portal PT: {again:?}"
    );
    let app = app_pool(&opts, &conn, 2).await?;
    let l1 = seed_store(&app, pt, "mesmo-slug").await?;
    let dup = StoreScope::for_tests(pt, Uuid::now_v7());
    let mut tx = begin_store_tx(&app, &dup, &merchant()).await?;
    let res = insert_store(&mut tx, pt, dup.store_id(), "mesmo-slug").await;
    assert_eq!(
        res.as_ref().err().and_then(sqlstate).as_deref(),
        Some(UNIQUE_VIOLATION),
        "slug repetido no tenant: {res:?}"
    );
    tx.rollback().await?;

    let channel = ResolvedTenant::for_tests(pt, TenantType::NationalPortal, CountryCode::Pt);
    let ctx = AuditCtx::for_tests(ActorType::Anonymous, None, None, None);
    let mut tx = begin_portal_read_tx(&app, &channel, &ctx).await?;
    let found = tx.store_by_slug("mesmo-slug").await?.map(|s| s.id);
    assert_eq!(found, Some(l1.store_id()));
    assert_eq!(tx.store_by_slug("nada").await?, None);
    tx.finish().await?;
    Ok(())
}

/// `app.store_id` de uma loja de OUTRO tenant (nacional ES) numa transação do tenant PT: o merchant
/// não a vê nem lhe mexe (o `tenant_isolation` soma-se ao âmbito por loja).
#[sqlx::test(migrations = "../migrations")]
async fn store_scope_of_another_tenant_sees_and_changes_nothing(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let pt = seed_tenant(
        &owner,
        "nacional-pt",
        TenantType::NationalPortal,
        CountryCode::Pt,
    )
    .await?;
    let es = seed_tenant(
        &owner,
        "nacional-es",
        TenantType::NationalPortal,
        CountryCode::Es,
    )
    .await?;
    let app = app_pool(&opts, &conn, 2).await?;
    let les = seed_store(&app, es, "tienda").await?;
    let les_id = les.store_id();

    let cross = StoreScope::for_tests(pt, les_id);
    let mut tx = begin_store_tx(&app, &cross, &merchant()).await?;
    let seen = sqlx::query_scalar!("SELECT id FROM stores WHERE id = $1", les_id)
        .fetch_all(&mut *tx)
        .await?;
    assert!(seen.is_empty(), "SELECT da loja ES: {seen:?}");
    let r = sqlx::query!("UPDATE stores SET name = 'roubada' WHERE id = $1", les_id)
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "UPDATE da loja ES");
    let r = sqlx::query!("DELETE FROM stores WHERE id = $1", les_id)
        .execute(&mut *tx)
        .await?;
    assert_eq!(r.rows_affected(), 0, "DELETE da loja ES");
    tx.commit().await?;

    // A loja ES ficou intacta (lida com o seu próprio âmbito).
    let mut tx = begin_store_tx(&app, &les, &merchant()).await?;
    let name = sqlx::query_scalar!("SELECT name FROM stores WHERE id = $1", les_id)
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(name, "tienda");
    tx.rollback().await?;
    Ok(())
}
