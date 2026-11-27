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

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

mod catalog;

use catalog::busy_on_timeout;

pub use catalog::{
    MAX_FILTER_CATEGORIES, MAX_PAGE_LIMIT, MAX_SEARCH_CHARS, MAX_SEARCH_TERMS, PortalCategory,
    PortalProduct, PortalProductCard, PortalVariant, ProductFilter, ProductPage,
};

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
/// Desde a 0039 também as de `products`/`product_variants` que as views do catálogo não têm.
pub const PORTAL_FORBIDDEN_COLUMNS: [&str; 11] = [
    "iban",
    "invoicing_credentials_enc",
    "eupago_split_key",
    "stripe_account_id",
    "custom_commission_bps",
    "kyc_verified",
    "stock_qty",
    "sku",
    "compare_at_price_cents",
    "catalog_item_id",
    "ai_enriched",
];

/// Máximo de caracteres de um slug recebido (loja ou entidade; as colunas têm 120).
pub const MAX_SLUG_CHARS: usize = 128;

/// Máximo de caracteres do nome no cursor de `stores_page` (= `stores.name VARCHAR(255)`: um
/// limite menor partiria a paginação em lojas com nomes longos).
pub const MAX_CURSOR_NAME_CHARS: usize = 255;

/// `value` com mais de `max` caracteres (não bytes) → `Validation` em `field`.
fn check_len(field: &str, value: &str, max: usize) -> Result<(), AppError> {
    if value.chars().count() > max {
        return Err(AppError::Validation(vec![FieldError {
            field: field.to_owned(),
            message: format!("máximo {max} caracteres"),
        }]));
    }
    Ok(())
}

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
    /// Isenta de IVA pelo art. 53.º CIVA: os preços desta loja têm IVA 0%.
    pub vat_exempt_art53: bool,
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
    vat_exempt_art53: bool,
}

/// Página de lojas; `next` = cursor `(name, id)` da seguinte (`None` no fim).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StorePage {
    pub items: Vec<PortalStore>,
    pub next: Option<(String, Uuid)>,
}

/// Ficha pública da loja: `PortalStore` + identificação e contacto do comerciante, de exibição
/// obrigatória (DSA art. 30.º; DL 7/2004 art. 10.º; ES Ley 34/2002 art. 10: nome/firma, NIF,
/// morada, contacto). Só colunas de `portal_stores`: nunca IBAN, chaves, comissões, KYC,
/// verificações, plano nem termos.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalStoreProfile {
    #[serde(flatten)]
    pub store: PortalStore,
    pub email: String,
    pub phone: Option<String>,
    pub address_json: Value,
    pub storefront_address: Value,
    /// Coordenadas só com loja física declarada (`storefront_address` preenchida ou
    /// `supports_click_collect`), arredondadas na BD a 3 casas (~100 m: privacidade do ENI que
    /// vende a partir de casa); senão `None`. Texto, só exibição, nunca contas.
    pub geo_lat: Option<String>,
    pub geo_lng: Option<String>,
    pub business_hours: Value,
    pub is_vacation_mode: bool,
    pub vacation_message: Option<String>,
    pub supports_click_collect: bool,
    pub supports_local_courier: bool,
    pub supports_national_shipping: bool,
}

/// Linha de `portal_stores` com as colunas da ficha.
#[derive(sqlx::FromRow)]
struct ProfileRow {
    #[sqlx(flatten)]
    store: StoreRow,
    email: String,
    phone: Option<String>,
    address_json: Value,
    storefront_address: Value,
    geo_lat: Option<String>,
    geo_lng: Option<String>,
    business_hours: Value,
    is_vacation_mode: bool,
    vacation_message: Option<String>,
    supports_click_collect: bool,
    supports_local_courier: bool,
    supports_national_shipping: bool,
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
/// A forma com dois argumentos junta colunas (`", s.x::t AS x, …"`) antes do `FROM`.
macro_rules! store_select {
    ($rest:literal) => {
        store_select!("", $rest)
    };
    ($extra:literal, $rest:literal) => {
        concat!(
            "SELECT s.id::uuid AS id, s.tenant_id::uuid AS tenant_id, s.name::text AS name,
                    s.slug::text AS slug, s.legal_name::text AS legal_name, s.nif::text AS nif,
                    s.shipping_scope::text AS shipping_scope,
                    s.storefront_dicofre::text AS storefront_dicofre,
                    s.vat_exempt_art53::bool AS vat_exempt_art53",
            $extra,
            "
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

    /// Uma página de lojas visíveis neste canal, por `(name, id)`; `after` = `next` da página
    /// anterior (comparação por tuplo: lojas com o mesmo nome não se perdem nem repetem). Com
    /// `entity_slug`, só as lojas com selo dessa entidade. `limit` limitado a 1..=48; lê
    /// `limit + 1` para saber se há mais. Uma loja co-patrocinada sai uma vez, com todos os selos.
    /// `entity_slug` com mais de 128 caracteres ou nome do cursor com mais de 255 (máximo de
    /// `stores.name`) → `Validation`. Faz `SET LOCAL statement_timeout = '2s'` (até ao fim desta
    /// transação); um timeout → `Busy`. 3 consultas: timeout, lojas e selos (2 se a página vier
    /// vazia).
    pub async fn stores_page(
        &mut self,
        entity_slug: Option<&str>,
        after: Option<(String, Uuid)>,
        limit: i64,
    ) -> Result<StorePage, AppError> {
        if let Some(e) = entity_slug {
            check_len("entity_slug", e, MAX_SLUG_CHARS)?;
        }
        if let Some((name, _)) = &after {
            check_len("after", name, MAX_CURSOR_NAME_CHARS)?;
        }
        let limit = limit.clamp(1, MAX_PAGE_LIMIT);
        sqlx::query!("SET LOCAL statement_timeout = '2s'")
            .execute(&mut *self.tx)
            .await
            .map_err(db_error)?;
        let (after_name, after_id) = after.unzip();
        let mut rows = sqlx::query_as::<_, StoreRow>(store_select!(
            "WHERE ($1::text IS NULL OR EXISTS (SELECT 1 FROM portal_store_badges b
                                                 WHERE b.store_id = s.id AND b.slug = $1::text))
               AND ($2::text IS NULL OR (s.name::text, s.id) > ($2::text, $3::uuid))
             ORDER BY s.name::text, s.id
             LIMIT $4::int8"
        ))
        .bind(entity_slug)
        .bind(after_name)
        .bind(after_id)
        .bind(limit + 1)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(|e| busy_on_timeout(db_error(e)))?;
        let next = if rows.len() as i64 > limit {
            rows.truncate(limit as usize);
            rows.last().map(|r| (r.name.clone(), r.id))
        } else {
            None
        };
        let items = self.with_badges(rows).await.map_err(busy_on_timeout)?;
        Ok(StorePage { items, next })
    }

    /// Ficha pública da loja `slug` (dados de exibição obrigatória do comerciante) se for visível
    /// NESTE canal; `None` caso contrário (não revela se existe noutro canal). 2 consultas: loja
    /// e selos. `slug` com mais de 128 caracteres → `Validation`.
    pub async fn store_profile_by_slug(
        &mut self,
        slug: &str,
    ) -> Result<Option<PortalStoreProfile>, AppError> {
        check_len("slug", slug, MAX_SLUG_CHARS)?;
        let Some(row) = sqlx::query_as::<_, ProfileRow>(store_select!(
            ", s.email::text AS email, s.phone::text AS phone,
                    s.address_json::jsonb AS address_json,
                    s.storefront_address::jsonb AS storefront_address,
                    CASE WHEN s.storefront_address <> '{}'::jsonb OR s.supports_click_collect
                         THEN round(s.geo_lat::numeric, 3)::text END AS geo_lat,
                    CASE WHEN s.storefront_address <> '{}'::jsonb OR s.supports_click_collect
                         THEN round(s.geo_lng::numeric, 3)::text END AS geo_lng,
                    s.business_hours::jsonb AS business_hours,
                    s.is_vacation_mode::bool AS is_vacation_mode,
                    s.vacation_message::text AS vacation_message,
                    s.supports_click_collect::bool AS supports_click_collect,
                    s.supports_local_courier::bool AS supports_local_courier,
                    s.supports_national_shipping::bool AS supports_national_shipping",
            "WHERE s.slug = $1::text LIMIT 1"
        ))
        .bind(slug)
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(db_error)?
        else {
            return Ok(None);
        };
        let Some(store) = self.with_badges(vec![row.store]).await?.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(PortalStoreProfile {
            store,
            email: row.email,
            phone: row.phone,
            address_json: row.address_json,
            storefront_address: row.storefront_address,
            geo_lat: row.geo_lat,
            geo_lng: row.geo_lng,
            business_hours: row.business_hours,
            is_vacation_mode: row.is_vacation_mode,
            vacation_message: row.vacation_message,
            supports_click_collect: row.supports_click_collect,
            supports_local_courier: row.supports_local_courier,
            supports_national_shipping: row.supports_national_shipping,
        }))
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
                    vat_exempt_art53: r.vat_exempt_art53,
                    badges: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        // Por loja, pela ordem da consulta (municipality → parish → association; depois nome).
        let mut by_store: HashMap<Uuid, Vec<StoreBadge>> = HashMap::with_capacity(out.len());
        for b in badges {
            by_store.entry(b.store_id).or_default().push(StoreBadge {
                sponsor_entity_id: b.sponsor_entity_id,
                kind: SponsorKind::parse(&b.kind)?,
                name: b.name,
                slug: b.slug,
                logo_key: b.logo_key,
            });
        }
        for s in &mut out {
            s.badges = by_store.remove(&s.id).unwrap_or_default();
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
            vat_exempt_art53: false,
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
                "tenant_id",
                "vat_exempt_art53"
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
