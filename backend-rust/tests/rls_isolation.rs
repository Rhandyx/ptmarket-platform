//! Isolamento por tenant contra o Postgres real (RLS forçado) + outbox transacional.
//!
//! As pools da app fazem `SET ROLE ptmarket_app` em cada ligação nova: o dono das tabelas
//! não prova nada. Os tenants semeiam-se como dono (tabela global, sem RLS); as lojas só
//! podem ser criadas pela app dentro de `begin_tenant_tx`. Uma loja só vive num tenant
//! `national_portal` (trinco da 0033, sem opt-in): os tenants A e B destes testes são os canais
//! nacionais PT e ES (um por país, 0035), para provar o isolamento por `tenant_id` com lojas dos dois
//! lados. O ator é `admin` (exceção única ao âmbito por loja da 0035): só o `tenant_isolation` filtra.
//!
//! Evento global numa `TenantTx`: impossível por tipo (`append_global` só aceita `PlatformTx`);
//! a BD recusa-o também (42501), provado abaixo com SQL direto. Todas as transações levam `AuditCtx`.

use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    error::AppError,
    outbox::{NewEvent, append, append_global},
    tenancy::{TenantId, begin_tenant_tx, db::begin_platform_tx},
};
use sqlx::{
    PgConnection, PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

type TestResult = anyhow::Result<()>;

/// Ator `admin` (sem impersonação): a única exceção ao âmbito por loja da 0035, por isso aqui só o
/// `tenant_isolation` filtra (é ele que estes testes provam; o âmbito por loja está em
/// `tests/store_scope.rs`).
fn actor() -> AuditCtx {
    AuditCtx::for_tests(ActorType::Admin, Some(Uuid::now_v7()), None, None)
}

/// SQLSTATE devolvido pelo PostgreSQL quando uma linha viola a política RLS.
const RLS_VIOLATION: &str = "42501";

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

/// Só para verificar o outbox: a app tem apenas INSERT, o worker é quem lê.
async fn worker_pool(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
) -> sqlx::Result<PgPool> {
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

async fn owner_pool(opts: &PoolOptions<Postgres>, conn: &PgConnectOptions) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(1)
        .connect_with(conn.clone())
        .await
}

/// Tenant `national_portal` (o único tipo que pode ter lojas, 0033) do país `country` (um só por
/// país, 0035: A é o PT e B o ES).
async fn seed_tenant(owner: &PgPool, slug: &str, country: &str) -> sqlx::Result<TenantId> {
    let id = Uuid::now_v7();
    let domain = format!("{slug}.test.invalid");
    sqlx::query!(
        "INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code)
         VALUES ($1, $2, $3, $4, 'national_portal', $5)",
        id,
        slug,
        domain,
        slug,
        country
    )
    .execute(owner)
    .await?;
    Ok(TenantId::for_tests(id))
}

async fn insert_store(conn: &mut PgConnection, tenant: TenantId, slug: &str) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email)
         VALUES ($1, $2, $3, $4, $5, '500000000', 'PT50000000000000000000000', 'loja@test.invalid')",
        Uuid::now_v7(),
        tenant.as_uuid(),
        slug,
        slug,
        slug
    )
    .execute(conn)
    .await?;
    Ok(())
}

async fn seed_store(app: &PgPool, tenant: TenantId, slug: &str) -> anyhow::Result<()> {
    let mut tx = begin_tenant_tx(app, tenant, &actor()).await?;
    insert_store(&mut tx, tenant, slug).await?;
    tx.commit().await?;
    Ok(())
}

async fn count_stores(conn: &mut PgConnection) -> sqlx::Result<i64> {
    sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM stores"#)
        .fetch_one(conn)
        .await
}

async fn count_events(worker: &PgPool, aggregate_id: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM outbox_events WHERE aggregate_id = $1"#,
        aggregate_id
    )
    .fetch_one(worker)
    .await
}

fn is_rls_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|c| c == RLS_VIOLATION)
}

fn app_error_is_rls_violation(e: &AppError) -> bool {
    match e {
        AppError::Internal(inner) => inner
            .downcast_ref::<sqlx::Error>()
            .is_some_and(is_rls_violation),
        _ => false,
    }
}

fn event(aggregate_id: Uuid) -> NewEvent {
    NewEvent {
        aggregate: "store".into(),
        aggregate_id,
        event_type: "store.created".into(),
        payload: serde_json::json!({ "store_id": aggregate_id, "nested": { "ok": true } }),
    }
}

#[sqlx::test(migrations = "../migrations")]
async fn tenant_sees_only_its_own_stores(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "nacional-a", "PT").await?;
    let b = seed_tenant(&owner, "nacional-b", "ES").await?;
    let app = app_pool(&opts, &conn, 2).await?;
    seed_store(&app, a, "a1").await?;
    seed_store(&app, a, "a2").await?;
    seed_store(&app, b, "b1").await?;

    let mut tx = begin_tenant_tx(&app, a, &actor()).await?;
    let tenants = sqlx::query_scalar!("SELECT tenant_id FROM stores")
        .fetch_all(&mut *tx)
        .await?;
    assert_eq!(tenants.len(), 2);
    assert!(tenants.iter().all(|t| *t == a.as_uuid()));
    tx.rollback().await?;

    let mut tx = begin_tenant_tx(&app, b, &actor()).await?;
    assert_eq!(count_stores(&mut tx).await?, 1);
    tx.rollback().await?;

    let mut c = app.acquire().await?;
    assert_eq!(count_stores(&mut c).await?, 0, "sem contexto = zero linhas");
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn other_tenant_rows_are_rejected_inside_tenant_tx(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "nacional-a", "PT").await?;
    let b = seed_tenant(&owner, "nacional-b", "ES").await?;
    let app = app_pool(&opts, &conn, 2).await?;
    seed_store(&app, b, "b1").await?;

    // INSERT com tenant_id de B na transação de A: Err (sem panic).
    let mut tx = begin_tenant_tx(&app, a, &actor()).await?;
    let res = insert_store(&mut tx, b, "intrusa").await;
    assert!(
        res.as_ref().is_err_and(is_rls_violation),
        "esperado erro RLS, obtido {res:?}"
    );
    tx.rollback().await?;

    // UPDATE às lojas de B a partir de A não toca em nada.
    let mut tx = begin_tenant_tx(&app, a, &actor()).await?;
    let b_uuid = b.as_uuid();
    let updated = sqlx::query!(
        "UPDATE stores SET name = 'roubada' WHERE tenant_id = $1",
        b_uuid
    )
    .execute(&mut *tx)
    .await?;
    assert_eq!(updated.rows_affected(), 0);
    tx.commit().await?;

    let mut tx = begin_tenant_tx(&app, b, &actor()).await?;
    let names = sqlx::query_scalar!("SELECT name FROM stores")
        .fetch_all(&mut *tx)
        .await?;
    assert_eq!(names, vec!["b1".to_string()]);
    tx.rollback().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn tenant_context_does_not_leak_after_commit_or_rollback(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "nacional-a", "PT").await?;
    // Uma só ligação: a query seguinte reutiliza a ligação da transação anterior.
    let app = app_pool(&opts, &conn, 1).await?;

    let mut c = app.acquire().await?;
    let pid_before = sqlx::query_scalar!(r#"SELECT pg_backend_pid() AS "pid!""#)
        .fetch_one(&mut *c)
        .await?;
    drop(c);

    // Fim por COMMIT.
    let mut tx = begin_tenant_tx(&app, a, &actor()).await?;
    insert_store(&mut tx, a, "a1").await?;
    assert_eq!(count_stores(&mut tx).await?, 1);
    tx.commit().await?;

    let mut c = app.acquire().await?;
    let pid = sqlx::query_scalar!(r#"SELECT pg_backend_pid() AS "pid!""#)
        .fetch_one(&mut *c)
        .await?;
    assert_eq!(pid, pid_before, "tem de ser a mesma ligação");
    let ctx = sqlx::query_scalar!("SELECT current_setting('app.current_tenant_id', true)")
        .fetch_one(&mut *c)
        .await?;
    assert!(
        ctx.unwrap_or_default().is_empty(),
        "contexto sobreviveu ao COMMIT"
    );
    assert_eq!(count_stores(&mut c).await?, 0);
    drop(c);

    // Fim por ROLLBACK.
    let mut tx = begin_tenant_tx(&app, a, &actor()).await?;
    assert_eq!(count_stores(&mut tx).await?, 1);
    tx.rollback().await?;

    let mut c = app.acquire().await?;
    let pid = sqlx::query_scalar!(r#"SELECT pg_backend_pid() AS "pid!""#)
        .fetch_one(&mut *c)
        .await?;
    assert_eq!(pid, pid_before, "tem de ser a mesma ligação");
    assert_eq!(
        count_stores(&mut c).await?,
        0,
        "contexto sobreviveu ao ROLLBACK"
    );
    Ok(())
}

/// INSERT direto (contorna o `outbox`) para provar a política da BD.
async fn insert_raw_event(
    conn: &mut PgConnection,
    tenant: Option<Uuid>,
    aggregate_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO outbox_events (id, tenant_id, aggregate, aggregate_id, event_type, payload)
         VALUES ($1, $2, 'store', $3, 'store.raw', $4)",
        Uuid::now_v7(),
        tenant,
        aggregate_id,
        serde_json::json!({})
    )
    .execute(conn)
    .await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn outbox_append_respects_tenant_and_transaction(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "nacional-a", "PT").await?;
    let b = seed_tenant(&owner, "nacional-b", "ES").await?;
    let app = app_pool(&opts, &conn, 2).await?;
    let worker = worker_pool(&opts, &conn).await?;

    // Tenant A grava o seu evento; o tenant vem da TenantTx.
    let agg = Uuid::now_v7();
    let mut tx = begin_tenant_tx(&app, a, &actor()).await?;
    let id = append(&mut tx, event(agg)).await?;
    tx.commit().await?;
    assert_eq!(count_events(&worker, agg).await?, 1);
    let row = sqlx::query!(
        r#"SELECT tenant_id, payload, published_at IS NULL AS "unpublished!" FROM outbox_events WHERE id = $1"#,
        id
    )
    .fetch_one(&worker)
    .await?;
    assert_eq!(row.tenant_id, Some(a.as_uuid()));
    assert_eq!(row.payload["nested"]["ok"], serde_json::json!(true));
    assert!(row.unpublished);

    // Evento global numa transação sem contexto: OK.
    let agg_g = Uuid::now_v7();
    let mut tx = begin_platform_tx(&app, &actor()).await?;
    let gid = append_global(&mut tx, event(agg_g)).await?;
    tx.commit().await?;
    let tenant_of_global =
        sqlx::query_scalar!("SELECT tenant_id FROM outbox_events WHERE id = $1", gid)
            .fetch_one(&worker)
            .await?;
    assert_eq!(tenant_of_global, None);

    // Na BD, dentro da transação de A: evento de B e evento global são recusados (42501).
    let agg_x = Uuid::now_v7();
    for target in [Some(b.as_uuid()), None] {
        let mut tx = begin_tenant_tx(&app, a, &actor()).await?;
        let res = insert_raw_event(&mut tx, target, agg_x).await;
        assert!(
            res.as_ref().is_err_and(is_rls_violation),
            "esperado erro RLS para {target:?}, obtido {res:?}"
        );
        tx.rollback().await?;
    }

    // append_global numa PlatformTx com contexto de tenant forçado à mão: Err (sem panic).
    let mut tx = begin_platform_tx(&app, &actor()).await?;
    let a_text = a.as_uuid().to_string();
    sqlx::query!(
        "SELECT set_config('app.current_tenant_id', $1, true)",
        a_text
    )
    .fetch_one(&mut *tx)
    .await?;
    let res = append_global(&mut tx, event(agg_x)).await;
    assert!(
        res.as_ref().is_err_and(app_error_is_rls_violation),
        "esperado erro RLS, obtido {res:?}"
    );
    tx.rollback().await?;
    assert_eq!(count_events(&worker, agg_x).await?, 0);

    // Rollback não deixa evento.
    let agg_rb = Uuid::now_v7();
    let mut tx = begin_tenant_tx(&app, a, &actor()).await?;
    append(&mut tx, event(agg_rb)).await?;
    tx.rollback().await?;
    assert_eq!(count_events(&worker, agg_rb).await?, 0);
    Ok(())
}
