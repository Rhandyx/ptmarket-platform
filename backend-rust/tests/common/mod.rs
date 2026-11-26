//! Ajudas partilhadas pelos testes de staff (cartão 03/13): o staff só tem sessão no
//! `PLATFORM_ADMIN_HOST`, por isso os seus eventos ficam com `tenant_id` NULL e a app só os lê pela
//! porta do super_admin (`identity_admin_read_events`, 0025/0026).

use ptmarket_api::{
    audit::{ActorType, AuditCtx},
    identity::{Subject, session},
    tenancy::db::begin_platform_tx,
};
use serde_json::Value;
use sqlx::{
    PgPool, Postgres,
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

/// Ligação REAL como `ptmarket_app` (a porta da timeline exige session_user = ptmarket_app). A
/// password de dev (`dev_app`) só vale em `127.0.0.1`/`localhost`; noutro host
/// `PTM_APP_PASSWORD` é obrigatória.
pub async fn app_login_pool(
    opts: &PoolOptions<Postgres>,
    conn: &PgConnectOptions,
) -> anyhow::Result<PgPool> {
    let local = matches!(conn.get_host(), "127.0.0.1" | "localhost");
    let pw = match std::env::var("PTM_APP_PASSWORD") {
        Ok(pw) => pw,
        Err(_) if local => "dev_app".to_owned(),
        Err(_) => anyhow::bail!("PTM_APP_PASSWORD em falta (DATABASE_URL não local)"),
    };
    let opts: PgPoolOptions = opts.clone();
    Ok(opts
        .max_connections(8)
        .connect_with(conn.clone().username("ptmarket_app").password(&pw))
        .await?)
}

/// `super_admin` leitor (TOTP ligado pelo dono e sessão de plataforma elevada), só para ler os
/// eventos da plataforma nos testes.
pub struct PlatformReader {
    user: Uuid,
    session: Uuid,
}

impl PlatformReader {
    pub async fn new(owner: &PgPool, app: &PgPool) -> anyhow::Result<Self> {
        let user = Uuid::now_v7();
        let mut tx = owner.begin().await?;
        sqlx::query("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE user_roles NO FORCE ROW LEVEL SECURITY")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO users (id, email, full_name, is_active, totp_secret_enc, totp_enabled)
             VALUES ($1, $2, 'Leitor dos Testes', true, 'v1:teste:leitor', true)",
        )
        .bind(user)
        .bind(format!("leitor-{user}@x.pt"))
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO user_roles (id, user_id, role) VALUES ($1, $2, 'super_admin')")
            .bind(Uuid::now_v7())
            .bind(user)
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE users FORCE ROW LEVEL SECURITY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE user_roles FORCE ROW LEVEL SECURITY")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let ctx = AuditCtx::for_tests(ActorType::Admin, Some(user), None, None);
        let mut tx = begin_platform_tx(app, &ctx).await?;
        let (sid, _) = session::create(&mut tx, Subject::User(user), None, &ctx).await?;
        sqlx::query("UPDATE sessions SET mfa_verified_at = now() WHERE id = $1")
            .bind(sid.as_uuid())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Self {
            user,
            session: sid.as_uuid(),
        })
    }

    /// Eventos de `actor` (`None` = de todos, anónimos incluídos) na última hora, de todos os
    /// tenants e da plataforma, mais recentes primeiro, cada um como JSON (`action`, `outcome`,
    /// `reason`, `actor_type`, `actor_id`, `tenant_id`, `target_id`). A leitura não fica gravada
    /// (rollback).
    pub async fn events(&self, app: &PgPool, actor: Option<Uuid>) -> anyhow::Result<Vec<Value>> {
        let ctx = AuditCtx::for_tests(ActorType::Admin, Some(self.user), None, None)
            .with_session_for_tests(self.session);
        let mut tx = begin_platform_tx(app, &ctx).await?;
        let mut out = Vec::new();
        // Cursor da página seguinte: (created_at em µs desde a época, id).
        let mut cursor: Option<(i64, Uuid)> = None;
        loop {
            let rows: Vec<(Value, i64, Uuid)> = sqlx::query_as(
                "SELECT jsonb_build_object('action', e.action, 'outcome', e.outcome,
                            'reason', e.reason, 'actor_type', e.actor_type, 'actor_id', e.actor_id,
                            'tenant_id', e.tenant_id, 'target_id', e.target_id),
                        (extract(epoch FROM e.created_at) * 1000000)::int8, e.id
                 FROM public.identity_admin_read_events(
                        now() - interval '1 hour', now() + interval '1 hour', NULL::uuid, NULL::uuid,
                        $1::uuid, NULL::uuid, NULL::text, NULL::text,
                        'epoch'::timestamptz + $2::int8 * interval '1 microsecond', $3::uuid,
                        100) AS e",
            )
            .bind(actor)
            .bind(cursor.map(|c| c.0))
            .bind(cursor.map(|c| c.1))
            .fetch_all(&mut *tx)
            .await?;
            let n = rows.len();
            cursor = rows.last().map(|r| (r.1, r.2));
            out.extend(rows.into_iter().map(|r| r.0));
            if n < 100 {
                break;
            }
        }
        tx.rollback().await?;
        Ok(out)
    }
}

/// Quantos eventos cumprem `f`.
pub fn count(evs: &[Value], f: impl Fn(&Value) -> bool) -> usize {
    evs.iter().filter(|e| f(e)).count()
}

/// `e[k] == v` (texto).
pub fn is(e: &Value, k: &str, v: &str) -> bool {
    e[k].as_str() == Some(v)
}
