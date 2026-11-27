//! Transação só de leitura do catálogo por canal (spec 14 §1.1).
//!
//! `begin_portal_read_tx` abre para qualquer tenant resolvido pelo `Host`: é o canal do pedido.
//! - Canal nacional (`national_portal`): liga `app.portal_national = 'on'` e a BD mostra todas as
//!   lojas ativas desse canal (todas as do país; sem opt-out; `shipping_scope` não esconde a loja).
//! - Canal white-label (os outros tipos): a flag fica desligada e a BD mostra só as lojas com ≥ 1
//!   patrocínio `active` e vigente de uma entidade ativa cujo `channel_tenant_id` é este canal.
//!
//! As lojas leem-se SÓ na view `portal_stores` (0033: `security_barrier`, já filtrada pelo canal do
//! contexto, sem colunas sensíveis) e os selos na view `portal_store_badges` (só das lojas
//! visíveis); a tabela `stores` só mostra as do próprio tenant. `portal_stores` é a forma ÚNICA de
//! ler lojas fora do backoffice: outros módulos usam `stores_by_ids`.
//!
//! Defesa em profundidade: `PortalReadTx` NÃO dá acesso à ligação: só tem consultas dedicadas,
//! cujas linhas (`PortalStore`) não têm campos sensíveis. Colunas que nunca saem em modo portal
//! (nem existem na view): `PORTAL_FORBIDDEN_COLUMNS`.
//!
//! Exceção à regra `query!` (como a do `audit.*`): as views são `REVOKE ALL FROM PUBLIC` + `SELECT`
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
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    audit::AuditCtx,
    error::{AppError, FieldError},
    tenancy::{
        TenantId,
        db::{PortalMode, db_error, set_context},
        resolver::{CountryCode, ResolvedTenant, TenantType},
    },
};

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

/// Máximo de linhas por consulta do portal (e de ids em `stores_by_ids`).
pub const MAX_PORTAL_ROWS: i64 = 100;

/// `stores.shipping_scope` (0029). Não esconde a loja: só limita o que o checkout oferece.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShippingScope {
    National,
    LocalOnly,
    PickupOnly,
}

impl ShippingScope {
    fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "national" => Ok(Self::National),
            "local_only" => Ok(Self::LocalOnly),
            "pickup_only" => Ok(Self::PickupOnly),
            _ => Err(AppError::Internal(anyhow::anyhow!(
                "stores.shipping_scope desconhecido"
            ))),
        }
    }
}

/// `sponsor_entities.kind` (0028). A ordem das variantes é a ordem fixa dos selos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorKind {
    Municipality,
    Parish,
    Association,
}

impl SponsorKind {
    fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "municipality" => Ok(Self::Municipality),
            "parish" => Ok(Self::Parish),
            "association" => Ok(Self::Association),
            _ => Err(AppError::Internal(anyhow::anyhow!(
                "sponsor_entities.kind desconhecido"
            ))),
        }
    }
}

/// Selo de uma entidade patrocinadora (patrocínio `active` e vigente de entidade ativa).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreBadge {
    pub sponsor_entity_id: Uuid,
    pub kind: SponsorKind,
    pub name: String,
    pub slug: String,
    pub logo_key: Option<String>,
}

/// Loja vista pelo canal: só dados públicos. `badges` pela ordem fixa municipality → parish →
/// association; no mesmo tipo, por nome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortalStore {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub slug: String,
    /// Denominação legal (DSA: dado público do vendedor).
    pub legal_name: String,
    pub nif: String,
    pub shipping_scope: ShippingScope,
    pub storefront_dicofre: Option<String>,
    pub badges: Vec<StoreBadge>,
}

/// Linha de `portal_stores` (antes dos selos).
#[derive(sqlx::FromRow)]
struct StoreRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    slug: String,
    legal_name: String,
    nif: String,
    shipping_scope: String,
    storefront_dicofre: Option<String>,
}

/// Linha de `portal_store_badges`.
#[derive(sqlx::FromRow)]
struct BadgeRow {
    store_id: Uuid,
    sponsor_entity_id: Uuid,
    kind: String,
    name: String,
    slug: String,
    logo_key: Option<String>,
}

/// Colunas de `portal_stores` lidas pelo módulo (todas `NOT NULL` em `stores`, menos o DICOFRE).
macro_rules! store_select {
    ($rest:literal) => {
        concat!(
            "SELECT s.id::uuid AS id, s.tenant_id::uuid AS tenant_id, s.name::text AS name,
                    s.slug::text AS slug, s.legal_name::text AS legal_name, s.nif::text AS nif,
                    s.shipping_scope::text AS shipping_scope,
                    s.storefront_dicofre::text AS storefront_dicofre
             FROM portal_stores s ",
            $rest
        )
    };
}

/// Transação só de leitura no canal do pedido, com tenant e ator fixados.
#[derive(Debug)]
pub struct PortalReadTx {
    tenant: TenantId,
    tx: Transaction<'static, Postgres>,
}

impl PortalReadTx {
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Lojas visíveis neste canal, por nome; no máximo `MAX_PORTAL_ROWS` (o `limit` é limitado a
    /// 1..=100). Uma loja co-patrocinada sai uma só vez, com todos os selos.
    pub async fn published_stores(&mut self, limit: i64) -> Result<Vec<PortalStore>, AppError> {
        let limit = limit.clamp(1, MAX_PORTAL_ROWS);
        let rows =
            sqlx::query_as::<_, StoreRow>(store_select!("ORDER BY s.name, s.id LIMIT $1::int8"))
                .bind(limit)
                .fetch_all(&mut *self.tx)
                .await
                .map_err(db_error)?;
        self.with_badges(rows).await
    }

    /// Lojas visíveis neste canal com selo da entidade `entity_slug` (página `/entidade/<slug>`),
    /// por nome; `limit` em 1..=100. As lojas visíveis são todas do país do canal e o slug da
    /// entidade é único por país.
    pub async fn stores_by_entity(
        &mut self,
        entity_slug: &str,
        limit: i64,
    ) -> Result<Vec<PortalStore>, AppError> {
        let limit = limit.clamp(1, MAX_PORTAL_ROWS);
        let rows = sqlx::query_as::<_, StoreRow>(store_select!(
            "WHERE EXISTS (SELECT 1 FROM portal_store_badges b
                           WHERE b.store_id = s.id AND b.slug = $1::text)
             ORDER BY s.name, s.id LIMIT $2::int8"
        ))
        .bind(entity_slug)
        .bind(limit)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(db_error)?;
        self.with_badges(rows).await
    }

    /// A loja `slug` se for visível NESTE canal; `None` caso contrário (não revela se existe
    /// noutro canal).
    pub async fn store_by_slug(&mut self, slug: &str) -> Result<Option<PortalStore>, AppError> {
        let rows = sqlx::query_as::<_, StoreRow>(store_select!("WHERE s.slug = $1::text LIMIT 1"))
            .bind(slug)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(db_error)?;
        Ok(self.with_badges(rows).await?.into_iter().next())
    }

    /// As lojas de `ids` visíveis neste canal (as outras ficam de fora, sem erro), por nome. É por
    /// aqui que outros módulos obtêm nome, NIF e DICOFRE de lojas sem ler `stores`. Mais de
    /// `MAX_PORTAL_ROWS` ids → `Validation`.
    pub async fn stores_by_ids(&mut self, ids: &[Uuid]) -> Result<Vec<PortalStore>, AppError> {
        if ids.len() > MAX_PORTAL_ROWS as usize {
            return Err(AppError::Validation(vec![FieldError {
                field: "ids".to_owned(),
                message: format!("máximo {MAX_PORTAL_ROWS} lojas por pedido"),
            }]));
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, StoreRow>(store_select!(
            "WHERE s.id = ANY($1::uuid[]) ORDER BY s.name, s.id"
        ))
        .bind(ids)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(db_error)?;
        self.with_badges(rows).await
    }

    /// Junta os selos às lojas numa só consulta (`store_id = ANY($1)`, sem N+1).
    async fn with_badges(&mut self, rows: Vec<StoreRow>) -> Result<Vec<PortalStore>, AppError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        let badges = sqlx::query_as::<_, BadgeRow>(
            "SELECT b.store_id::uuid AS store_id, b.sponsor_entity_id::uuid AS sponsor_entity_id,
                    b.kind::text AS kind, b.name::text AS name, b.slug::text AS slug,
                    b.logo_key::text AS logo_key
             FROM portal_store_badges b
             WHERE b.store_id = ANY($1::uuid[])
             ORDER BY b.store_id,
                      CASE b.kind WHEN 'municipality' THEN 1 WHEN 'parish' THEN 2
                                  WHEN 'association' THEN 3 ELSE 4 END,
                      b.name, b.sponsor_entity_id",
        )
        .bind(&ids)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(db_error)?;
        let mut out = rows
            .into_iter()
            .map(|r| {
                Ok(PortalStore {
                    id: r.id,
                    tenant_id: r.tenant_id,
                    name: r.name,
                    slug: r.slug,
                    legal_name: r.legal_name,
                    nif: r.nif,
                    shipping_scope: ShippingScope::parse(&r.shipping_scope)?,
                    storefront_dicofre: r.storefront_dicofre,
                    badges: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        for b in badges {
            let badge = StoreBadge {
                sponsor_entity_id: b.sponsor_entity_id,
                kind: SponsorKind::parse(&b.kind)?,
                name: b.name,
                slug: b.slug,
                logo_key: b.logo_key,
            };
            if let Some(s) = out.iter_mut().find(|s| s.id == b.store_id) {
                s.badges.push(badge);
            }
        }
        Ok(out)
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

/// Abre a transação de leitura do canal do pedido (qualquer tipo de tenant). Faz
/// `SET TRANSACTION READ ONLY` e fixa o tenant e o ator só para ela; `app.portal_national = 'on'`
/// só quando o tenant resolvido é `national_portal`.
pub async fn begin_portal_read_tx(
    replica: &PgPool,
    tenant: &ResolvedTenant,
    ctx: &AuditCtx,
) -> Result<PortalReadTx, AppError> {
    let mode = if tenant.tenant_type() == TenantType::NationalPortal {
        PortalMode::On
    } else {
        PortalMode::Off
    };
    open_read_tx(replica, tenant.id(), ctx, mode).await
}

async fn open_read_tx(
    pool: &PgPool,
    tenant: TenantId,
    ctx: &AuditCtx,
    mode: PortalMode,
) -> Result<PortalReadTx, AppError> {
    let mut tx = pool.begin().await.map_err(db_error)?;
    sqlx::query!("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    set_context(&mut tx, Some(tenant), ctx, mode).await?;
    Ok(PortalReadTx { tenant, tx })
}

/// Canal nacional de um país (tenant `national_portal` ativo), para quem não tem o tenant no
/// `Host` (ex.: o `sponsor_admin` no `PLATFORM_ADMIN_HOST`). Só `national_portal_for_country` o
/// cria: o tenant vem sempre do país (da entidade), nunca do pedido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NationalPortal {
    id: TenantId,
    country_code: CountryCode,
}

impl NationalPortal {
    pub fn id(&self) -> TenantId {
        self.id
    }

    pub fn country_code(&self) -> CountryCode {
        self.country_code
    }
}

/// O canal nacional ativo do país `country`; `None` se não houver. Mais de um → erro interno
/// (configuração inválida: falha fechado).
pub async fn national_portal_for_country(
    conn: &mut PgConnection,
    country: CountryCode,
) -> Result<Option<NationalPortal>, AppError> {
    let ids = sqlx::query_scalar!(
        "SELECT id FROM tenants
         WHERE tenant_type = 'national_portal' AND country_code = $1 AND is_active
         ORDER BY id LIMIT 2",
        country.as_str()
    )
    .fetch_all(conn)
    .await
    .map_err(db_error)?;
    match ids.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(NationalPortal {
            id: TenantId::new(*id),
            country_code: country,
        })),
        _ => Err(AppError::Internal(anyhow::anyhow!(
            "mais de um national_portal ativo para o país"
        ))),
    }
}

/// Abre a transação de leitura no canal nacional `channel` (`app.portal_national = 'on'`): todas
/// as lojas ativas do país, só pelas consultas dedicadas de `PortalReadTx`.
pub async fn begin_national_read_tx(
    pool: &PgPool,
    channel: &NationalPortal,
    ctx: &AuditCtx,
) -> Result<PortalReadTx, AppError> {
    open_read_tx(pool, channel.id, ctx, PortalMode::On).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(v: &serde_json::Value) -> Vec<String> {
        let mut k: Vec<String> = v
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        k.sort_unstable();
        k
    }

    /// Os campos de `PortalStore` e de `StoreBadge`: nenhum é sensível (sem IBAN, chaves nem
    /// comissões).
    #[test]
    fn portal_store_has_no_sensitive_column() {
        let s = PortalStore {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            name: String::new(),
            slug: String::new(),
            legal_name: String::new(),
            nif: String::new(),
            shipping_scope: ShippingScope::LocalOnly,
            storefront_dicofre: None,
            badges: vec![StoreBadge {
                sponsor_entity_id: Uuid::nil(),
                kind: SponsorKind::Parish,
                name: String::new(),
                slug: String::new(),
                logo_key: None,
            }],
        };
        let json = serde_json::to_value(&s).unwrap_or_default();
        let store_keys = keys(&json);
        assert_eq!(
            store_keys,
            [
                "badges",
                "id",
                "legal_name",
                "name",
                "nif",
                "shipping_scope",
                "slug",
                "storefront_dicofre",
                "tenant_id"
            ]
        );
        assert_eq!(json["shipping_scope"], "local_only");
        let badge_keys = keys(&json["badges"][0]);
        assert_eq!(
            badge_keys,
            ["kind", "logo_key", "name", "slug", "sponsor_entity_id"]
        );
        assert_eq!(json["badges"][0]["kind"], "parish");
        // `logo_key` é a chave pública do logótipo no storage, não um segredo: é a única `*_key`.
        for k in store_keys.iter().chain(&badge_keys) {
            assert!(!PORTAL_FORBIDDEN_COLUMNS.contains(&k.as_str()), "{k}");
            assert!(!k.contains("commission") && !k.contains("iban"), "{k}");
            assert!(
                !k.ends_with("_enc") && (!k.ends_with("_key") || k == "logo_key"),
                "{k}"
            );
        }
    }

    #[test]
    fn sponsor_kind_order_is_the_badge_order() {
        assert!(SponsorKind::Municipality < SponsorKind::Parish);
        assert!(SponsorKind::Parish < SponsorKind::Association);
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
