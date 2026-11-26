//! Transação só de leitura do portal nacional.
//!
//! `begin_portal_read_tx` só abre para um tenant `national_portal` (senão `Forbidden`; o handler
//! junta a marca `DENIED_NOT_PORTAL` à resposta e a caixa negra grava o `denied`). Dentro dela a BD
//! deixa ver lojas/produtos/variantes publicados de todos os tenants ativos do mesmo país.
//!
//! As lojas de outros tenants leem-se SÓ na view `portal_stores` (0021: `security_barrier`, já
//! filtrada por publicada + ativa + mesmo país, sem colunas sensíveis); a tabela `stores` só mostra
//! as do próprio tenant. Produtos e variantes continuam nas tabelas.
//!
//! Defesa em profundidade: `PortalReadTx` NÃO dá acesso à ligação: só tem consultas dedicadas,
//! cujas linhas (`PortalStore`) não têm campos sensíveis. Colunas que nunca saem em modo portal
//! (nem existem na view): `PORTAL_FORBIDDEN_COLUMNS`.
//!
//! Exceção à regra `query!` (como a do `audit.*`): a view é `REVOKE ALL FROM PUBLIC` + `SELECT`
//! só para `ptmarket_app`, por isso o migrator não tem SELECT para o `EXPLAIN` da macro. Usa-se
//! `query_as` com SQL estático, cast de tipo exato em cada coluna e argumento, e `FromRow`.
//!
//! Não é aceite pelo outbox nem pela caixa negra de mutações (não é `TenantTx` nem `AuditedTx`):
//! ```compile_fail
//! # use ptmarket_api::{outbox::{NewEvent, append}, tenancy::portal::PortalReadTx};
//! # async fn f(tx: &mut PortalReadTx, ev: NewEvent) {
//! let _ = append(tx, ev).await;
//! # }
//! ```
//! ```compile_fail
//! # use ptmarket_api::{audit::{AuditEvent, record}, tenancy::portal::PortalReadTx};
//! # async fn f(tx: &mut PortalReadTx, ev: AuditEvent) {
//! let _ = record(tx, ev).await;
//! # }
//! ```
//! Nem dá a ligação (não há SQL livre em modo portal):
//! ```compile_fail
//! # use ptmarket_api::tenancy::portal::PortalReadTx;
//! # async fn f(tx: &mut PortalReadTx) {
//! let _ = sqlx::query("SELECT iban FROM stores").fetch_all(&mut **tx).await;
//! # }
//! ```

use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    audit::{AuditCtx, Denied},
    error::AppError,
    tenancy::{
        TenantId,
        db::{PortalMode, db_error, set_context},
        resolver::{ResolvedTenant, TenantType},
    },
};

/// Marca de recusa para a resposta de um tenant que não é o portal nacional.
pub const DENIED_NOT_PORTAL: Denied = Denied("not_national_portal");

/// Colunas de `stores` que nunca são selecionadas em modo portal (nem qualquer `*_enc`/`*_key`)
/// e que a view `portal_stores` não tem.
pub const PORTAL_FORBIDDEN_COLUMNS: [&str; 6] = [
    "iban",
    "invoicing_credentials_enc",
    "eupago_split_key",
    "stripe_account_id",
    "custom_commission_bps",
    "kyc_verified",
];

/// Máximo de linhas por consulta do portal.
pub const MAX_PORTAL_ROWS: i64 = 100;

/// Loja vista pelo portal nacional: só dados públicos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct PortalStore {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub slug: String,
}

/// Transação só de leitura no modo portal nacional, com tenant e ator fixados.
#[derive(Debug)]
pub struct PortalReadTx {
    tenant: TenantId,
    tx: Transaction<'static, Postgres>,
}

impl PortalReadTx {
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Lojas publicadas no portal (view `portal_stores`, já filtrada pela BD), por nome; no
    /// máximo `MAX_PORTAL_ROWS` (o `limit` é limitado a 1..=100). As 4 colunas são `NOT NULL`
    /// em `stores`.
    pub async fn published_stores(&mut self, limit: i64) -> Result<Vec<PortalStore>, AppError> {
        let limit = limit.clamp(1, MAX_PORTAL_ROWS);
        sqlx::query_as::<_, PortalStore>(
            "SELECT id::uuid AS id, tenant_id::uuid AS tenant_id, name::text AS name,
                    slug::text AS slug
             FROM portal_stores
             ORDER BY name, id
             LIMIT $1::int8",
        )
        .bind(limit)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(db_error)
    }

    /// Fecha a transação (só leitura: nada a confirmar).
    pub async fn finish(self) -> Result<(), AppError> {
        self.tx.rollback().await.map_err(db_error)
    }

    /// Só para testes de integração: a ligação crua (provar o READ ONLY e o RLS). Não existe em
    /// `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn conn_for_tests(&mut self) -> &mut sqlx::PgConnection {
        &mut self.tx
    }
}

/// Abre a transação do portal: só para tenants `national_portal` (senão `Forbidden`). Faz
/// `SET TRANSACTION READ ONLY` e fixa o tenant, o ator e `app.portal_national = 'on'` só para ela.
pub async fn begin_portal_read_tx(
    replica: &PgPool,
    tenant: &ResolvedTenant,
    ctx: &AuditCtx,
) -> Result<PortalReadTx, AppError> {
    if tenant.tenant_type() != TenantType::NationalPortal {
        return Err(AppError::Forbidden);
    }
    let mut tx = replica.begin().await.map_err(db_error)?;
    sqlx::query!("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    set_context(&mut tx, Some(tenant.id()), ctx, PortalMode::On).await?;
    Ok(PortalReadTx {
        tenant: tenant.id(),
        tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Os campos de `PortalStore` (as colunas da consulta): nenhum é sensível.
    #[test]
    fn portal_store_has_no_sensitive_column() {
        let s = PortalStore {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            name: String::new(),
            slug: String::new(),
        };
        let json = serde_json::to_value(&s).unwrap_or_default();
        let mut keys: Vec<&str> = json
            .as_object()
            .map(|o| o.keys().map(String::as_str).collect())
            .unwrap_or_default();
        keys.sort_unstable();
        assert_eq!(keys, ["id", "name", "slug", "tenant_id"]);
        for k in &keys {
            assert!(!PORTAL_FORBIDDEN_COLUMNS.contains(k), "{k}");
            assert!(!k.ends_with("_enc") && !k.ends_with("_key"), "{k}");
        }
    }

    /// O código deste módulo (fora dos testes e da doc) nunca nomeia uma coluna sensível.
    #[test]
    fn module_sql_never_names_sensitive_columns() {
        let src = include_str!("portal.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or_default();
        let sql: String = code
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| !l.contains("PORTAL_FORBIDDEN_COLUMNS"))
            .collect::<Vec<_>>()
            .join("\n");
        for col in PORTAL_FORBIDDEN_COLUMNS {
            let quoted = format!("\"{col}\"");
            let bare: Vec<&str> = sql.matches(col).collect();
            let in_const = sql.matches(quoted.as_str()).count();
            assert_eq!(bare.len(), in_const, "{col} aparece fora da lista");
        }
    }
}
