//! `AuditCtx` obrigatório (spec 13 §3.1–3.2) contra o Postgres real: o ator chega ao L1 (trigger),
//! morre com a transação, `audit::record` grava na mesma transação (máscara, rollback, anti-IDOR)
//! e a cadeia continua contígua quando duas transações REPEATABLE READ competem pela cabeça.
//!
//! As pools da app fazem `SET ROLE ptmarket_app` em cada ligação nova. As leituras de eventos são
//! feitas como app dentro de uma `TenantTx` (política `tenant_read`).
//!
//! Leituras de `audit.*` sem `query!`: a verificação em compilação (EXPLAIN) corre como o migrator,
//! que a selagem deixou sem privilégios em `audit.*`. SQL estático, tudo por parâmetro.

use std::net::IpAddr;

use ptmarket_api::{
    audit::{ActorType, AuditCtx, AuditEvent, Outcome, record},
    error::AppError,
    tenancy::{TenantId, TenantTx, begin_tenant_tx, db::begin_platform_tx},
};
use sqlx::{
    PgConnection, PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

type TestResult = anyhow::Result<()>;
/// actor_type, actor_id, request_id, host(ip), tenant_id
type L1Row = (String, Option<Uuid>, Option<Uuid>, Option<String>, Option<Uuid>);
/// actor_type, actor_id, request_id, outcome, changes, tenant_id
type RecordRow = (
    String,
    Option<Uuid>,
    Option<Uuid>,
    String,
    Option<serde_json::Value>,
    Option<Uuid>,
);

/// Mutação da app sem `app.actor_type` (0010).
const NO_ACTOR: &str = "PTA01";
/// Falha de serialização (REPEATABLE READ / SERIALIZABLE): o chamador repete a transação.
const SERIALIZATION_FAILURE: &str = "40001";

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

/// Como `app_pool`, mas todas as transações em REPEATABLE READ.
async fn app_pool_repeatable_read(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
    max: u32,
) -> sqlx::Result<PgPool> {
    opts.clone()
        .max_connections(max)
        .after_connect(|c, _meta| {
            Box::pin(async move {
                sqlx::query!("SET ROLE ptmarket_app")
                    .execute(&mut *c)
                    .await?;
                sqlx::query!("SET default_transaction_isolation = 'repeatable read'")
                    .execute(&mut *c)
                    .await?;
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

async fn insert_store(conn: &mut PgConnection, tenant: TenantId, slug: &str) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email)
         VALUES ($1, $2, $3, $4, $5, '500000000', 'PT50000000000000000000000', 'loja@test.invalid')",
        id,
        tenant.as_uuid(),
        slug,
        slug,
        slug
    )
    .execute(conn)
    .await?;
    Ok(id)
}

fn merchant(ip: Option<IpAddr>) -> AuditCtx {
    AuditCtx::for_tests(ActorType::Merchant, Some(Uuid::now_v7()), None, ip)
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

fn app_error_sqlstate(e: &AppError) -> Option<String> {
    match e {
        AppError::Internal(inner) => inner.downcast_ref::<sqlx::Error>().and_then(sqlstate),
        _ => None,
    }
}

fn event(action: &'static str, changes: Option<serde_json::Value>) -> AuditEvent {
    AuditEvent {
        action,
        target_type: Some("store"),
        target_id: Some(Uuid::now_v7().to_string()),
        outcome: Outcome::Success,
        reason: None,
        changes,
        store_id: None,
    }
}

async fn count_event(tx: &mut TenantTx, id: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT count(*) FROM audit.audit_events WHERE id = $1")
        .bind(id)
        .fetch_one(&mut **tx)
        .await
}

async fn backend_pid(conn: &mut PgConnection) -> sqlx::Result<i32> {
    sqlx::query_scalar!(r#"SELECT pg_backend_pid() AS "pid!""#)
        .fetch_one(conn)
        .await
}

/// Na mesma ligação, uma transação crua só com o tenant (sem ator): o INSERT tem de falhar com PTA01.
async fn insert_without_actor_fails(app: &PgPool, tenant: TenantId, slug: &str) -> TestResult {
    let mut tx = app.begin().await?;
    let t = tenant.as_uuid().to_string();
    sqlx::query!("SELECT set_config('app.current_tenant_id', $1, true)", t)
        .fetch_one(&mut *tx)
        .await?;
    let actor = sqlx::query_scalar!("SELECT current_setting('app.actor_type', true)")
        .fetch_one(&mut *tx)
        .await?;
    assert!(actor.unwrap_or_default().is_empty(), "o ator sobreviveu");
    let res = insert_store(&mut tx, tenant, slug).await;
    assert_eq!(
        res.as_ref().err().and_then(sqlstate).as_deref(),
        Some(NO_ACTOR),
        "esperado PTA01, obtido {res:?}"
    );
    tx.rollback().await?;
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn l1_event_carries_ctx_and_actor_dies_with_tx(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    // Uma só ligação: depois da transação, a query seguinte reutiliza-a.
    let app = app_pool(&opts, &conn, 1).await?;
    let pid_before = backend_pid(&mut *app.acquire().await?).await?;

    let ip: IpAddr = "203.0.113.7".parse()?;
    let ctx = merchant(Some(ip));
    let mut tx = begin_tenant_tx(&app, a, &ctx).await?;
    let store_id = insert_store(&mut tx, a, "a1").await?;
    let target = store_id.to_string();
    let (actor_type, actor_id, request_id, ev_ip, tenant_id): L1Row = sqlx::query_as(
        "SELECT actor_type::text, actor_id, request_id, host(ip), tenant_id
         FROM audit.audit_events WHERE action = 'stores.insert' AND target_id = $1",
    )
    .bind(target)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(actor_type, "merchant");
    assert_eq!(actor_id, ctx.actor_id());
    assert_eq!(request_id, Some(ctx.request_id()));
    assert_eq!(ev_ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(tenant_id, Some(a.as_uuid()));
    tx.commit().await?;

    // Depois do COMMIT: mesma ligação, sem ator.
    assert_eq!(backend_pid(&mut *app.acquire().await?).await?, pid_before);
    insert_without_actor_fails(&app, a, "sem-ator-1").await?;

    // Depois do ROLLBACK: idem.
    let mut tx = begin_tenant_tx(&app, a, &ctx).await?;
    insert_store(&mut tx, a, "a2").await?;
    tx.rollback().await?;
    assert_eq!(backend_pid(&mut *app.acquire().await?).await?, pid_before);
    insert_without_actor_fails(&app, a, "sem-ator-2").await?;

    // E fora de qualquer transação explícita também.
    let mut c = app.acquire().await?;
    let res = insert_store(&mut c, a, "sem-ator-3").await;
    assert!(res.is_err(), "INSERT sem ator passou: {res:?}");
    Ok(())
}

#[sqlx::test(migrations = "../migrations")]
async fn record_writes_masked_event_in_same_tx_and_respects_tenant(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let b = seed_tenant(&owner, "camara-b").await?;
    let app = app_pool(&opts, &conn, 2).await?;

    // Evento semântico com segredos: sai mascarado.
    let ctx = merchant(None);
    let changes = serde_json::json!({
        "password": "hunter2-secreta",
        "iban": "PT50000201231234567890154",
        "nested": { "note": "conta PT50 0002 0123 1234 5678 9015 4", "plan": "pro" }
    });
    let mut tx = begin_tenant_tx(&app, a, &ctx).await?;
    assert!(!ctx.is_recorded());
    let id = record(&mut tx, event("store.settings_changed", Some(changes))).await?;
    assert!(ctx.is_recorded(), "record tem de marcar o AuditCtx");
    let (actor_type, actor_id, request_id, outcome, changes, tenant_id): RecordRow =
        sqlx::query_as(
            "SELECT actor_type::text, actor_id, request_id, outcome::text, changes, tenant_id
             FROM audit.audit_events WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    assert_eq!(actor_type, "merchant");
    assert_eq!(actor_id, ctx.actor_id());
    assert_eq!(request_id, Some(ctx.request_id()));
    assert_eq!(outcome, "success");
    assert_eq!(tenant_id, Some(a.as_uuid()));
    let stored = changes.unwrap_or_default();
    let text = stored.to_string();
    assert!(!text.contains("hunter2"), "password por mascarar: {text}");
    assert!(
        !text.contains("PT50000201231234567890154") && !text.contains("9015 4"),
        "IBAN por mascarar: {text}"
    );
    assert_eq!(stored["nested"]["plan"], "pro", "o resto fica intacto");

    // Rollback não deixa evento.
    let ctx_rb = merchant(None);
    let mut tx = begin_tenant_tx(&app, a, &ctx_rb).await?;
    let rb_id = record(&mut tx, event("store.settings_changed", None)).await?;
    assert_eq!(count_event(&mut tx, rb_id).await?, 1);
    tx.rollback().await?;
    let mut tx = begin_tenant_tx(&app, a, &ctx_rb).await?;
    assert_eq!(
        count_event(&mut tx, rb_id).await?,
        0,
        "rollback deixou evento"
    );
    assert_eq!(count_event(&mut tx, id).await?, 1);
    tx.rollback().await?;

    // Anti-IDOR: o tenant B não lê o evento de A.
    let mut tx = begin_tenant_tx(&app, b, &merchant(None)).await?;
    assert_eq!(count_event(&mut tx, id).await?, 0, "B leu o evento de A");
    tx.rollback().await?;

    // Plataforma (sem tenant): job de sistema grava; nenhum tenant o lê.
    let sys = AuditCtx::system("audit_ctx_test");
    let mut ptx = begin_platform_tx(&app, &sys).await?;
    let pid = record(&mut ptx, event("platform.job_ran", None)).await?;
    ptx.commit().await?;
    assert!(sys.is_recorded());
    let mut tx = begin_tenant_tx(&app, a, &merchant(None)).await?;
    assert_eq!(count_event(&mut tx, pid).await?, 0);
    tx.rollback().await?;
    Ok(())
}

/// Uma tentativa: abre, grava, confirma. O erro volta tal e qual (o chamador decide se repete).
async fn record_once(app: &PgPool, tenant: TenantId, ctx: &AuditCtx) -> Result<Uuid, AppError> {
    let mut tx = begin_tenant_tx(app, tenant, ctx).await?;
    let id = record(&mut tx, event("store.ping", None)).await?;
    tx.commit().await?;
    Ok(id)
}

/// Repete a transação inteira só em 40001 (máx. 5 tentativas).
async fn record_with_retry(
    app: &PgPool,
    tenant: TenantId,
    ctx: &AuditCtx,
) -> Result<(Uuid, u32), AppError> {
    let mut attempt = 1;
    loop {
        match record_once(app, tenant, ctx).await {
            Ok(id) => return Ok((id, attempt)),
            Err(e)
                if attempt < 5
                    && app_error_sqlstate(&e).as_deref() == Some(SERIALIZATION_FAILURE) =>
            {
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[sqlx::test(migrations = "../migrations")]
async fn chain_race_in_repeatable_read_retries_and_stays_contiguous(
    opts: PgPoolOptions,
    conn: PgConnectOptions,
) -> TestResult {
    let owner = owner_pool(&opts, &conn).await?;
    let a = seed_tenant(&owner, "camara-a").await?;
    let app = app_pool_repeatable_read(&opts, &conn, 2).await?;

    // Cadeia já iniciada (cabeça existe).
    record_once(&app, a, &merchant(None)).await?;

    // T1 e T2 tiram o snapshot antes de qualquer escrita na cadeia.
    let ctx1 = merchant(None);
    let ctx2 = merchant(None);
    let mut t1 = begin_tenant_tx(&app, a, &ctx1).await?;
    let mut t2 = begin_tenant_tx(&app, a, &ctx2).await?;
    record(&mut t1, event("store.ping", None)).await?;
    // T2 bloqueia na cabeça (FOR UPDATE) até T1 confirmar; depois recebe 40001.
    let racer = tokio::spawn(async move {
        let res = record(&mut t2, event("store.ping", None)).await;
        (t2, res)
    });
    t1.commit().await?;
    let (t2, res) = racer.await?;
    assert_eq!(
        res.as_ref().err().and_then(app_error_sqlstate).as_deref(),
        Some(SERIALIZATION_FAILURE),
        "esperado 40001, obtido {res:?}"
    );
    assert!(!ctx2.is_recorded(), "falhou: não pode ficar marcado");
    t2.rollback().await?;

    // O chamador repete a transação inteira: passa.
    let (_, attempts) = record_with_retry(&app, a, &ctx2).await?;
    assert_eq!(attempts, 1);
    assert!(ctx2.is_recorded());

    // Mais corridas em paralelo, todas com repetição.
    let mut jobs = Vec::new();
    for _ in 0..4 {
        let app = app.clone();
        jobs.push(tokio::spawn(async move {
            record_with_retry(&app, a, &merchant(None)).await
        }));
    }
    for j in jobs {
        j.await??;
    }

    // Cadeia contígua e sem repetidos: tenants.insert (L1, 'db' do seed) + inicial + T1 + T2 repetida + 4.
    let mut tx = begin_tenant_tx(&app, a, &merchant(None)).await?;
    let a_uuid = a.as_uuid();
    let seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT chain_seq FROM audit.audit_events
         WHERE chain_key = $1 AND retention_class = 'standard'
         ORDER BY chain_seq",
    )
    .bind(a_uuid)
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    let expected: Vec<i64> = (1..=i64::try_from(seqs.len())?).collect();
    assert_eq!(seqs, expected, "cadeia com buracos ou repetidos");
    assert_eq!(seqs.len(), 8);
    Ok(())
}
