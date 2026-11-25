//! Estado partilhado da aplicação.

use std::sync::Arc;

use deadpool_redis::Runtime;
use secrecy::ExposeSecret;
use sqlx::postgres::PgPoolOptions;

use crate::{config::Config, storage::NullStorage, storage::StorageBackend};

#[derive(Clone)]
pub struct AppState {
    /// Escritas, checkout, stock, admin.
    pub db_primary: sqlx::PgPool,
    /// Leituras públicas, catálogo, pesquisa.
    pub db_replica: sqlx::PgPool,
    pub redis: deadpool_redis::Pool,
    pub storage: Arc<dyn StorageBackend>,
}

impl AppState {
    /// Pools preguiçosos: arranca sem BD; ligações só no primeiro uso.
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let lazy = |url: &str| {
            PgPoolOptions::new()
                .max_connections(10)
                .acquire_timeout(std::time::Duration::from_secs(1))
                .connect_lazy(url)
        };
        let redis = deadpool_redis::Config::from_url(cfg.redis_url.expose_secret())
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|_| anyhow::anyhow!("REDIS_URL inválida"))?;
        Ok(Self {
            db_primary: lazy(cfg.database_primary_url.expose_secret())
                .map_err(|_| anyhow::anyhow!("DATABASE_PRIMARY_URL inválida"))?,
            db_replica: lazy(cfg.database_replica_url.expose_secret())
                .map_err(|_| anyhow::anyhow!("DATABASE_REPLICA_URL inválida"))?,
            redis,
            storage: Arc::new(NullStorage),
        })
    }
}
