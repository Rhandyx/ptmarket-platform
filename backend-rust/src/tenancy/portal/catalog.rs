//! Catálogo público por canal (cartão 04/02; spec 14 §1.1): produtos, variantes e categorias lidos
//! SÓ pelas views da 0039 (`portal_products`, `portal_product_variants`, `portal_categories`), já
//! filtradas pelo canal do contexto (as mesmas lojas de `portal_stores`). As tabelas `products`,
//! `product_variants` e `product_price_history` dão 0 linhas fora do backoffice.
//!
//! - Mesma exceção à regra `query!` de `portal_stores`: `query_as` com SQL estático, cast de tipo
//!   exato em cada coluna e argumento. Nada de SQL montado: as variantes de filtro são strings
//!   fixas (`concat!`).
//! - Índices da 0039: as listagens filtram por `tenant_id` = canal nacional do país do canal (as
//!   lojas vivem todas aí, 0030/0033; num canal white-label não é o tenant do pedido) e ordenam por
//!   `id DESC` com `id < cursor` e `LIMIT`, compatível com `products_tenant_*_published_idx`.
//! - Stock só como `in_stock` (nunca a quantidade). Dinheiro sempre `i64` em cêntimos (PVP com IVA
//!   incluído); o Omnibus aqui é só comparação, sem contas.
//! - Art. 53.º: `vat_rate_bps` efetivo = 0 quando a loja é `vat_exempt_art53`.

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::{MAX_PORTAL_ROWS, PortalReadTx, PortalStore};
use crate::{
    error::{AppError, FieldError},
    tenancy::db::db_error,
};

/// Máximo de produtos por página de `products_page` (o `limit` é limitado a 1..=48).
pub const MAX_PAGE_LIMIT: i64 = 48;

/// Máximo de caracteres do texto de `search_products` (depois do `trim`; caracteres, não bytes).
pub const MAX_SEARCH_CHARS: usize = 200;

/// Máximo de termos (com 2 ou mais caracteres) do texto de `search_products`.
pub const MAX_SEARCH_TERMS: usize = 8;

/// Termos com menos caracteres do que isto são ignorados na pesquisa.
const MIN_TERM_CHARS: usize = 2;

/// Máximo de categorias no filtro de `products_page` (a categoria e as descendentes).
pub const MAX_FILTER_CATEGORIES: usize = 200;

/// Filtros de `products_page` (todos opcionais; combinam-se por E).
#[derive(Debug, Clone, Default)]
pub struct ProductFilter {
    /// Produtos destas categorias (quem chama junta as descendentes); no máximo 200. Lista vazia =
    /// nenhum produto.
    pub category_ids: Option<Vec<Uuid>>,
    /// Produtos desta loja (só se for visível no canal).
    pub store_id: Option<Uuid>,
    /// Produtos de lojas com selo da entidade com este slug (página `/entidade/<slug>`).
    pub entity_slug: Option<String>,
}

/// Categoria do catálogo, com `has_products` no canal do pedido.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortalCategory {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub slug: String,
    /// Nome por língua (`{"pt": …, "es": …}`).
    pub name: Value,
    pub is_featured: bool,
    pub sort_order: i32,
    /// Há produto visível neste canal nesta categoria ou numa descendente.
    pub has_products: bool,
}

/// Produto numa lista (cartão de produto).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalProductCard {
    pub id: Uuid,
    pub title: Value,
    pub images: Value,
    pub category_id: Option<Uuid>,
    pub store: PortalStore,
    /// Taxa de IVA efetiva em bps: 0 se a loja estiver isenta (art. 53.º CIVA).
    pub vat_rate_bps: i32,
    /// Preço mais baixo das variantes ativas (cêntimos, IVA incluído).
    pub price_from_cents: i64,
    pub variants_count: i64,
    /// Alguma variante ativa com stock.
    pub in_stock: bool,
    /// Omnibus: só com exatamente 1 variante ativa (ver `previous_lowest`).
    pub previous_lowest_cents: Option<i64>,
}

/// Variante ativa de um produto.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalVariant {
    pub id: Uuid,
    pub ean: Option<String>,
    pub attributes: Value,
    /// PVP em cêntimos, IVA incluído.
    pub price_cents: i64,
    pub in_stock: bool,
    /// Omnibus (ver `previous_lowest`).
    pub previous_lowest_cents: Option<i64>,
}

/// Página de produto: os dados do cartão + descrição, atributos e todas as variantes ativas (por
/// preço e id).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortalProduct {
    pub id: Uuid,
    pub title: Value,
    pub description: Value,
    pub images: Value,
    pub attributes: Value,
    pub category_id: Option<Uuid>,
    pub is_perishable: bool,
    pub store: PortalStore,
    /// Taxa de IVA efetiva em bps: 0 se a loja estiver isenta (art. 53.º CIVA).
    pub vat_rate_bps: i32,
    pub price_from_cents: i64,
    pub variants_count: i64,
    pub in_stock: bool,
    /// Omnibus do produto: só com exatamente 1 variante ativa (como no cartão).
    pub previous_lowest_cents: Option<i64>,
    pub variants: Vec<PortalVariant>,
}

/// Uma página de produtos; `next` = cursor da seguinte (`None` no fim).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProductPage {
    pub items: Vec<PortalProductCard>,
    pub next: Option<Uuid>,
}

/// Omnibus (DL 70/2007 art. 5.º, red. DL 109-G/2021; ES art. 20 Ley 7/1996): o preço anterior a
/// mostrar é o mais baixo dos 30 dias antes da redução, e só quando o preço atual está abaixo dele
/// (redução). Subida, igual ou preço nunca alterado (`NULL`) → `None`. Só comparação.
fn previous_lowest(price_cents: i64, lowest_30d_cents: Option<i64>) -> Option<i64> {
    lowest_30d_cents.filter(|&lowest| price_cents < lowest)
}

/// Taxa de IVA efetiva (art. 53.º CIVA → 0).
fn effective_vat_bps(store: &PortalStore, product_vat_bps: i32) -> i32 {
    if store.vat_exempt_art53 {
        0
    } else {
        product_vat_bps
    }
}

/// Linha de `portal_products` para listas.
#[derive(sqlx::FromRow)]
struct CardRow {
    id: Uuid,
    store_id: Uuid,
    category_id: Option<Uuid>,
    title: Value,
    images: Value,
    vat_rate_bps: i32,
}

/// Linha de `portal_products` para a página de produto.
#[derive(sqlx::FromRow)]
struct ProductRow {
    id: Uuid,
    store_id: Uuid,
    category_id: Option<Uuid>,
    title: Value,
    description: Value,
    images: Value,
    attributes: Value,
    vat_rate_bps: i32,
    is_perishable: bool,
}

/// Resumo das variantes ativas de um produto (uma linha por produto, agregada na BD).
#[derive(sqlx::FromRow)]
struct VariantSummaryRow {
    product_id: Uuid,
    price_from_cents: i64,
    variants_count: i64,
    in_stock: bool,
    /// `lowest_price_30d_cents` da variante quando há só uma (com mais, não se usa).
    lowest_30d_cents: Option<i64>,
}

/// Linha de `portal_product_variants`.
#[derive(sqlx::FromRow)]
struct VariantRow {
    id: Uuid,
    ean: Option<String>,
    attributes: Value,
    price_cents: i64,
    lowest_price_30d_cents: Option<i64>,
    in_stock: bool,
}

/// Linha de `portal_categories`.
#[derive(sqlx::FromRow)]
struct CategoryRow {
    id: Uuid,
    parent_id: Option<Uuid>,
    slug: String,
    name: Value,
    is_featured: bool,
    sort_order: i32,
    has_direct_products: bool,
}

/// `tenant_id` das lojas visíveis: o `national_portal` do país do canal `$1` (no canal nacional é
/// ele próprio; um só por país, `tenants_one_national_portal_per_country`). Subconsulta escalar
/// (InitPlan): o planeador usa-a como condição de índice.
macro_rules! store_tenant {
    () => {
        "(SELECT n.id FROM tenants c
          JOIN tenants n ON n.country_code = c.country_code AND n.tenant_type = 'national_portal'
          WHERE c.id = $1::uuid)"
    };
}

/// Colunas do cartão; `$1` = tenant do canal.
macro_rules! card_select {
    ($rest:literal) => {
        concat!(
            "SELECT p.id::uuid AS id, p.store_id::uuid AS store_id,
                    p.category_id::uuid AS category_id, p.title::jsonb AS title,
                    p.images::jsonb AS images, p.vat_rate_bps::int4 AS vat_rate_bps
             FROM portal_products p
             WHERE p.tenant_id = ",
            store_tenant!(),
            " ",
            $rest
        )
    };
}

/// Filtro opcional da entidade (`$3`) por `portal_store_badges`.
macro_rules! entity_filter {
    () => {
        "($3::text IS NULL OR EXISTS (SELECT 1 FROM portal_store_badges b
                                       WHERE b.store_id = p.store_id AND b.slug = $3::text))"
    };
}

/// Página geral: `$2` cursor, `$3` entidade, `$4` limit.
const PAGE_ALL: &str = concat!(
    card_select!("AND p.id < $2::uuid AND "),
    entity_filter!(),
    " ORDER BY p.id DESC LIMIT $4::int8"
);

/// Página por loja (índice por loja): `$5` loja, `$6` categorias (ou NULL).
const PAGE_BY_STORE: &str = concat!(
    card_select!("AND p.store_id = $5::uuid AND p.id < $2::uuid AND "),
    entity_filter!(),
    " AND ($6::uuid[] IS NULL OR p.category_id = ANY($6::uuid[]))
     ORDER BY p.id DESC LIMIT $4::int8"
);

/// Página por categorias (índice por categoria): `$5` categorias.
const PAGE_BY_CATEGORIES: &str = concat!(
    card_select!("AND p.category_id = ANY($5::uuid[]) AND p.id < $2::uuid AND "),
    entity_filter!(),
    " ORDER BY p.id DESC LIMIT $4::int8"
);

/// Cartões de `ids` (`$2`).
const CARDS_BY_IDS: &str = card_select!("AND p.id = ANY($2::uuid[])");

/// Produto `$2` com as colunas da página de produto.
const PRODUCT_BY_ID: &str = concat!(
    "SELECT p.id::uuid AS id, p.store_id::uuid AS store_id, p.category_id::uuid AS category_id,
            p.title::jsonb AS title, p.description::jsonb AS description,
            p.images::jsonb AS images, p.attributes::jsonb AS attributes,
            p.vat_rate_bps::int4 AS vat_rate_bps, p.is_perishable::bool AS is_perishable
     FROM portal_products p
     WHERE p.tenant_id = ",
    store_tenant!(),
    " AND p.id = $2::uuid"
);

/// Resumo das variantes dos produtos `$2` (agregado por produto).
const VARIANT_SUMMARIES: &str = concat!(
    "SELECT v.product_id::uuid AS product_id, min(v.price_cents)::int8 AS price_from_cents,
            count(*)::int8 AS variants_count, bool_or(v.in_stock)::bool AS in_stock,
            min(v.lowest_price_30d_cents)::int8 AS lowest_30d_cents
     FROM portal_product_variants v
     WHERE v.tenant_id = ",
    store_tenant!(),
    " AND v.product_id = ANY($2::uuid[])
     GROUP BY v.product_id"
);

/// Variantes do produto `$2`, por preço e id.
const VARIANTS_OF: &str = concat!(
    "SELECT v.id::uuid AS id, v.ean::text AS ean, v.attributes::jsonb AS attributes,
            v.price_cents::int8 AS price_cents,
            v.lowest_price_30d_cents::int8 AS lowest_price_30d_cents,
            v.in_stock::bool AS in_stock
     FROM portal_product_variants v
     WHERE v.tenant_id = ",
    store_tenant!(),
    " AND v.product_id = ANY($2::uuid[])
     ORDER BY v.price_cents, v.id"
);

/// Ids da pesquisa (0040: `portal_search_product_ids`, DEFINER, só ids visíveis no canal do
/// contexto). Mesma exceção à regra `query!` das views: SQL estático e casts exatos. `$1` texto,
/// `$2` cursor (ou NULL), `$3` limite.
const SEARCH_IDS: &str = "SELECT r.id::uuid AS id
     FROM portal_search_product_ids($1::text, $2::uuid, $3::int4) AS r(id)
     ORDER BY r.id DESC";

fn invalid_query(message: String) -> AppError {
    AppError::Validation(vec![FieldError {
        field: "q".to_owned(),
        message,
    }])
}

/// Texto da pesquisa normalizado antes da BD: `trim`; caracteres de controlo (`\0`, `\n`, …)
/// no meio → `Validation`; vazio ou mais de 200 caracteres →
/// `Validation`; termos (por espaços) com menos de 2 caracteres ignorados; mais de 8 termos →
/// `Validation`; nenhum termo → `None` (página vazia, sem BD). Os termos ficam unidos por um
/// espaço.
fn search_terms(q: &str) -> Result<Option<String>, AppError> {
    let q = q.trim();
    if q.chars().any(char::is_control) {
        return Err(invalid_query("caracteres de controlo".to_owned()));
    }
    let chars = q.chars().count();
    if chars == 0 || chars > MAX_SEARCH_CHARS {
        return Err(invalid_query(format!(
            "entre 1 e {MAX_SEARCH_CHARS} caracteres"
        )));
    }
    let terms: Vec<&str> = q
        .split_whitespace()
        .filter(|t| t.chars().count() >= MIN_TERM_CHARS)
        .collect();
    if terms.len() > MAX_SEARCH_TERMS {
        return Err(invalid_query(format!("máximo {MAX_SEARCH_TERMS} termos")));
    }
    Ok((!terms.is_empty()).then(|| terms.join(" ")))
}

/// `statement_timeout` (SQLSTATE 57014) → `Busy` (503 + `Retry-After`), sem o texto da BD; os
/// outros erros ficam iguais.
pub(super) fn busy_on_timeout(e: AppError) -> AppError {
    let timed_out = match &e {
        AppError::Internal(inner) => matches!(
            inner.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::Database(db)) if db.code().as_deref() == Some("57014")
        ),
        _ => false,
    };
    if timed_out { AppError::Busy } else { e }
}

fn too_many(field: &str, max: usize, what: &str) -> AppError {
    AppError::Validation(vec![FieldError {
        field: field.to_owned(),
        message: format!("máximo {max} {what} por pedido"),
    }])
}

/// Marca `has_products` nas categorias com produto direto e em todos os ascendentes. Resiste a
/// ciclos e a pais desconhecidos (para de subir).
fn propagate_has_products(cats: &mut [PortalCategory], direct: &[bool]) {
    let index: HashMap<Uuid, usize> = cats.iter().enumerate().map(|(i, c)| (c.id, i)).collect();
    // `done[i]`: i e todos os ascendentes já estão marcados.
    let mut done = vec![false; cats.len()];
    for start in 0..cats.len() {
        if !direct.get(start).copied().unwrap_or(false) || done[start] {
            continue;
        }
        let mut i = start;
        loop {
            done[i] = true;
            cats[i].has_products = true;
            match cats[i].parent_id.and_then(|p| index.get(&p).copied()) {
                Some(p) if !done[p] => i = p,
                _ => break,
            }
        }
    }
}

impl PortalReadTx {
    /// Todas as categorias, por `sort_order` e `slug`, com `has_products` neste canal (direto ou de
    /// uma descendente, propagado em memória). 1 consulta.
    pub async fn categories(&mut self) -> Result<Vec<PortalCategory>, AppError> {
        let rows = sqlx::query_as::<_, CategoryRow>(
            "SELECT c.id::uuid AS id, c.parent_id::uuid AS parent_id, c.slug::text AS slug,
                    c.name::jsonb AS name, c.is_featured::bool AS is_featured,
                    c.sort_order::int4 AS sort_order,
                    c.has_direct_products::bool AS has_direct_products
             FROM portal_categories c
             ORDER BY c.sort_order, c.slug
             LIMIT 2000",
        )
        .fetch_all(&mut *self.tx)
        .await
        .map_err(db_error)?;
        let direct: Vec<bool> = rows.iter().map(|r| r.has_direct_products).collect();
        let mut cats: Vec<PortalCategory> = rows
            .into_iter()
            .map(|r| PortalCategory {
                id: r.id,
                parent_id: r.parent_id,
                slug: r.slug,
                name: r.name,
                is_featured: r.is_featured,
                sort_order: r.sort_order,
                has_products: false,
            })
            .collect();
        propagate_has_products(&mut cats, &direct);
        Ok(cats)
    }

    /// Uma página de produtos visíveis neste canal, mais recentes primeiro (`id DESC`, UUIDv7);
    /// `after` = `next` da página anterior. `limit` limitado a 1..=48; lê `limit + 1` para saber se
    /// há mais. Mais de 200 categorias no filtro → `Validation`. 4 consultas: produtos, resumo das
    /// variantes e `stores_by_ids` (lojas + selos).
    pub async fn products_page(
        &mut self,
        filter: &ProductFilter,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<ProductPage, AppError> {
        let limit = limit.clamp(1, MAX_PAGE_LIMIT);
        if let Some(cats) = &filter.category_ids {
            if cats.len() > MAX_FILTER_CATEGORIES {
                return Err(too_many(
                    "category_ids",
                    MAX_FILTER_CATEGORIES,
                    "categorias",
                ));
            }
            if cats.is_empty() {
                return Ok(ProductPage {
                    items: Vec::new(),
                    next: None,
                });
            }
        }
        let tenant = self.tenant.as_uuid();
        let cursor = after.unwrap_or(Uuid::max());
        let entity = filter.entity_slug.as_deref();
        let fetch = limit + 1;
        let rows = match (filter.store_id, &filter.category_ids) {
            (Some(store), cats) => {
                sqlx::query_as::<_, CardRow>(PAGE_BY_STORE)
                    .bind(tenant)
                    .bind(cursor)
                    .bind(entity)
                    .bind(fetch)
                    .bind(store)
                    .bind(cats.as_deref())
                    .fetch_all(&mut *self.tx)
                    .await
            }
            (None, Some(cats)) => {
                sqlx::query_as::<_, CardRow>(PAGE_BY_CATEGORIES)
                    .bind(tenant)
                    .bind(cursor)
                    .bind(entity)
                    .bind(fetch)
                    .bind(cats.as_slice())
                    .fetch_all(&mut *self.tx)
                    .await
            }
            (None, None) => {
                sqlx::query_as::<_, CardRow>(PAGE_ALL)
                    .bind(tenant)
                    .bind(cursor)
                    .bind(entity)
                    .bind(fetch)
                    .fetch_all(&mut *self.tx)
                    .await
            }
        }
        .map_err(db_error)?;
        let mut rows = rows;
        let next = if rows.len() as i64 > limit {
            rows.truncate(limit as usize);
            rows.last().map(|r| r.id)
        } else {
            None
        };
        let items = self.cards(rows).await?;
        Ok(ProductPage { items, next })
    }

    /// Pesquisa de produtos visíveis neste canal pelo título (pt/es, sem acentos: "pao" encontra
    /// "Pão"), mais recentes primeiro (`id DESC`); `after` = `next` da página anterior.
    ///
    /// Texto (`search_terms`, antes da BD): `trim`; vazio ou mais de 200 caracteres →
    /// `Validation`; termos (separados por espaços) com menos de 2 caracteres são ignorados; mais
    /// de 8 termos → `Validation`; se não sobrar nenhum, página vazia sem ir à BD. Aspas e
    /// operadores são só texto (`websearch_to_tsquery`, sem erro).
    ///
    /// `limit` limitado a 1..=48; pede `limit + 1` ids. Antes da chamada faz
    /// `SET LOCAL statement_timeout = '2s'` (fica até ao fim desta transação); um timeout
    /// (57014) → `Busy` (503 + `Retry-After`). Os cartões vêm de `products_by_ids` (volta a
    /// filtrar pelas views: dupla verificação; mantém a ordem). 2 consultas (timeout + ids) + as 4
    /// de `products_by_ids` (nenhuma destas se não houver resultados).
    pub async fn search_products(
        &mut self,
        q: &str,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<ProductPage, AppError> {
        let empty = ProductPage {
            items: Vec::new(),
            next: None,
        };
        let Some(text) = search_terms(q)? else {
            return Ok(empty);
        };
        let limit = limit.clamp(1, MAX_PAGE_LIMIT);
        // `limit + 1` ≤ 49 = máximo da função.
        let fetch = i32::try_from(limit + 1)
            .map_err(|_| AppError::Internal(anyhow::anyhow!("limite da pesquisa")))?;
        sqlx::query!("SET LOCAL statement_timeout = '2s'")
            .execute(&mut *self.tx)
            .await
            .map_err(db_error)?;
        let mut ids: Vec<Uuid> = sqlx::query_scalar(SEARCH_IDS)
            .bind(text)
            .bind(after)
            .bind(fetch)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(|e| busy_on_timeout(db_error(e)))?;
        let next = if ids.len() as i64 > limit {
            ids.truncate(limit as usize);
            ids.last().copied()
        } else {
            None
        };
        let items = self.products_by_ids(&ids).await.map_err(busy_on_timeout)?;
        Ok(ProductPage { items, next })
    }

    /// Os produtos de `ids` visíveis neste canal, pela ordem de `ids` (repetidos uma vez); os
    /// invisíveis ficam de fora sem erro. Mais de 100 ids → `Validation`. 4 consultas: produtos,
    /// resumo das variantes e `stores_by_ids` (lojas + selos); nenhuma com `ids` vazio.
    pub async fn products_by_ids(
        &mut self,
        ids: &[Uuid],
    ) -> Result<Vec<PortalProductCard>, AppError> {
        if ids.len() > MAX_PORTAL_ROWS as usize {
            return Err(too_many("ids", MAX_PORTAL_ROWS as usize, "produtos"));
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, CardRow>(CARDS_BY_IDS)
            .bind(self.tenant.as_uuid())
            .bind(ids)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(db_error)?;
        let mut cards: HashMap<Uuid, PortalProductCard> = self
            .cards(rows)
            .await?
            .into_iter()
            .map(|c| (c.id, c))
            .collect();
        Ok(ids.iter().filter_map(|id| cards.remove(id)).collect())
    }

    /// O produto `id` se for visível NESTE canal, com todas as variantes ativas (por preço e id);
    /// `None` caso contrário (não revela se existe noutro canal). 4 consultas: produto, variantes
    /// e `stores_by_ids` (loja + selos).
    pub async fn product_by_id(&mut self, id: Uuid) -> Result<Option<PortalProduct>, AppError> {
        let tenant = self.tenant.as_uuid();
        let Some(row) = sqlx::query_as::<_, ProductRow>(PRODUCT_BY_ID)
            .bind(tenant)
            .bind(id)
            .fetch_optional(&mut *self.tx)
            .await
            .map_err(db_error)?
        else {
            return Ok(None);
        };
        let variants = sqlx::query_as::<_, VariantRow>(VARIANTS_OF)
            .bind(tenant)
            .bind([row.id].as_slice())
            .fetch_all(&mut *self.tx)
            .await
            .map_err(db_error)?;
        // Sem variante ativa ou loja (mudou entre consultas): não é visível.
        let Some(price_from_cents) = variants.iter().map(|v| v.price_cents).min() else {
            return Ok(None);
        };
        let Some(store) = self
            .stores_by_ids(&[row.store_id])
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let previous_lowest_cents = match variants.as_slice() {
            [only] => previous_lowest(only.price_cents, only.lowest_price_30d_cents),
            _ => None,
        };
        Ok(Some(PortalProduct {
            id: row.id,
            title: row.title,
            description: row.description,
            images: row.images,
            attributes: row.attributes,
            category_id: row.category_id,
            is_perishable: row.is_perishable,
            vat_rate_bps: effective_vat_bps(&store, row.vat_rate_bps),
            store,
            price_from_cents,
            variants_count: variants.len() as i64,
            in_stock: variants.iter().any(|v| v.in_stock),
            previous_lowest_cents,
            variants: variants
                .into_iter()
                .map(|v| PortalVariant {
                    id: v.id,
                    ean: v.ean,
                    attributes: v.attributes,
                    price_cents: v.price_cents,
                    in_stock: v.in_stock,
                    previous_lowest_cents: previous_lowest(v.price_cents, v.lowest_price_30d_cents),
                })
                .collect(),
        }))
    }

    /// Junta o resumo das variantes (1 consulta) e as lojas (`stores_by_ids`: 2 consultas) às
    /// linhas, mantendo a ordem. Linha sem variante ativa ou sem loja visível (mudou entre
    /// consultas) fica de fora.
    async fn cards(&mut self, rows: Vec<CardRow>) -> Result<Vec<PortalProductCard>, AppError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let product_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        let summaries: HashMap<Uuid, VariantSummaryRow> =
            sqlx::query_as::<_, VariantSummaryRow>(VARIANT_SUMMARIES)
                .bind(self.tenant.as_uuid())
                .bind(&product_ids)
                .fetch_all(&mut *self.tx)
                .await
                .map_err(db_error)?
                .into_iter()
                .map(|s| (s.product_id, s))
                .collect();
        let mut seen = HashSet::new();
        let store_ids: Vec<Uuid> = rows
            .iter()
            .map(|r| r.store_id)
            .filter(|id| seen.insert(*id))
            .collect();
        let stores: HashMap<Uuid, PortalStore> = self
            .stores_by_ids(&store_ids)
            .await?
            .into_iter()
            .map(|s| (s.id, s))
            .collect();
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let sum = summaries.get(&r.id)?;
                let store = stores.get(&r.store_id)?.clone();
                let previous_lowest_cents = if sum.variants_count == 1 {
                    previous_lowest(sum.price_from_cents, sum.lowest_30d_cents)
                } else {
                    None
                };
                Some(PortalProductCard {
                    id: r.id,
                    title: r.title,
                    images: r.images,
                    category_id: r.category_id,
                    vat_rate_bps: effective_vat_bps(&store, r.vat_rate_bps),
                    store,
                    price_from_cents: sum.price_from_cents,
                    variants_count: sum.variants_count,
                    in_stock: sum.in_stock,
                    previous_lowest_cents,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PORTAL_FORBIDDEN_COLUMNS, ShippingScope};
    use super::*;

    fn store(art53: bool) -> PortalStore {
        PortalStore {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            name: String::new(),
            slug: String::new(),
            legal_name: String::new(),
            nif: String::new(),
            shipping_scope: ShippingScope::National,
            storefront_dicofre: None,
            vat_exempt_art53: art53,
            badges: Vec::new(),
        }
    }

    /// Todas as chaves de um JSON, a qualquer profundidade.
    fn all_keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    out.push(k.clone());
                    all_keys(x, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| all_keys(x, out)),
            _ => {}
        }
    }

    #[test]
    fn search_terms_limits() -> Result<(), AppError> {
        assert_eq!(
            search_terms("  Pão  de   ló ")?,
            Some("Pão de ló".to_owned())
        );
        // Termos de 1 carácter ignorados; se não sobrar nada, sem BD.
        assert_eq!(search_terms("a b c")?, None);
        assert_eq!(search_terms("pão a")?, Some("pão".to_owned()));
        // 200 caracteres (não bytes): "ã" tem 2 bytes.
        assert!(search_terms(&"ã".repeat(200))?.is_some());
        for bad in [
            String::new(),
            "   ".to_owned(),
            "ã".repeat(201),
            "aa ".repeat(9),
            "pão\0".to_owned(),
            "pão\nbolo".to_owned(),
            "pão\u{7f}".to_owned(),
        ] {
            assert!(
                matches!(search_terms(&bad), Err(AppError::Validation(_))),
                "{bad:?}"
            );
        }
        // Espaços à volta (incluindo `\n`) saem no `trim`.
        assert_eq!(search_terms("\tpão\n")?, Some("pão".to_owned()));
        // 8 termos passam; os curtos não contam para o máximo.
        assert!(search_terms(&format!("{} x y z", "aa ".repeat(8)))?.is_some());
        Ok(())
    }

    #[test]
    fn non_timeout_errors_are_kept() {
        assert!(matches!(
            busy_on_timeout(AppError::Conflict),
            AppError::Conflict
        ));
        let e = busy_on_timeout(AppError::Internal(anyhow::anyhow!("x")));
        assert!(matches!(e, AppError::Internal(_)));
    }

    #[test]
    fn omnibus_only_on_a_real_reduction() {
        assert_eq!(previous_lowest(800, Some(1000)), Some(1000));
        assert_eq!(previous_lowest(1000, Some(1000)), None);
        assert_eq!(previous_lowest(1200, Some(1000)), None);
        assert_eq!(previous_lowest(1000, None), None);
    }

    #[test]
    fn art53_store_has_zero_vat() {
        assert_eq!(effective_vat_bps(&store(true), 2300), 0);
        assert_eq!(effective_vat_bps(&store(false), 2300), 2300);
    }

    #[test]
    fn has_products_propagates_to_every_ancestor_and_survives_cycles() {
        let id = |n: u128| Uuid::from_u128(n);
        let cat = |n: u128, parent: Option<u128>| PortalCategory {
            id: id(n),
            parent_id: parent.map(id),
            slug: n.to_string(),
            name: Value::Null,
            is_featured: false,
            sort_order: 0,
            has_products: false,
        };
        // 1 ← 2 ← 3 (direto); 4 sem produtos; 5 ↔ 6 (ciclo, 6 direto); 7 com pai desconhecido.
        let mut cats = vec![
            cat(3, Some(2)),
            cat(1, None),
            cat(2, Some(1)),
            cat(4, Some(1)),
            cat(5, Some(6)),
            cat(6, Some(5)),
            cat(7, Some(99)),
        ];
        let direct = [true, false, false, false, false, true, true];
        propagate_has_products(&mut cats, &direct);
        let has: Vec<bool> = cats.iter().map(|c| c.has_products).collect();
        assert_eq!(has, [true, true, true, false, true, true, true]);
    }

    /// Nenhuma chave sensível sai em cartões, produtos ou páginas (recursivo, lojas e selos
    /// incluídos).
    #[test]
    fn catalog_dtos_have_no_sensitive_keys() {
        let variant = PortalVariant {
            id: Uuid::nil(),
            ean: None,
            attributes: serde_json::json!({}),
            price_cents: 1,
            in_stock: true,
            previous_lowest_cents: None,
        };
        let card = PortalProductCard {
            id: Uuid::nil(),
            title: serde_json::json!({}),
            images: serde_json::json!([]),
            category_id: None,
            store: store(false),
            vat_rate_bps: 0,
            price_from_cents: 1,
            variants_count: 1,
            in_stock: true,
            previous_lowest_cents: None,
        };
        let product = PortalProduct {
            id: Uuid::nil(),
            title: serde_json::json!({}),
            description: serde_json::json!({}),
            images: serde_json::json!([]),
            attributes: serde_json::json!({}),
            category_id: None,
            is_perishable: false,
            store: store(false),
            vat_rate_bps: 0,
            price_from_cents: 1,
            variants_count: 1,
            in_stock: true,
            previous_lowest_cents: None,
            variants: vec![variant],
        };
        let page = ProductPage {
            items: vec![card],
            next: None,
        };
        let mut keys = Vec::new();
        all_keys(&serde_json::to_value(&page).unwrap_or_default(), &mut keys);
        all_keys(
            &serde_json::to_value(&product).unwrap_or_default(),
            &mut keys,
        );
        assert!(keys.contains(&"in_stock".to_owned()));
        assert!(keys.contains(&"previous_lowest_cents".to_owned()));
        for k in &keys {
            assert!(!PORTAL_FORBIDDEN_COLUMNS.contains(&k.as_str()), "{k}");
            assert!(!k.starts_with("compare_at"), "{k}");
            assert!(!k.contains("commission") && !k.contains("iban"), "{k}");
            assert!(!k.contains("stock_qty") && k != "sku", "{k}");
        }
    }

    /// O código deste módulo (fora dos testes e da doc) nunca nomeia uma coluna proibida.
    #[test]
    fn module_sql_never_names_forbidden_columns() {
        let src = include_str!("catalog.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or_default();
        let sql: String = code
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for col in PORTAL_FORBIDDEN_COLUMNS {
            assert!(!sql.contains(col), "{col} aparece no código do catálogo");
        }
    }
}
