//! Patrocínios de uma loja (`store_sponsorships`) vistos pelo cálculo da comissão (spec 14 §3).
//!
//! "Ativo" = `status = 'active' AND at <@ tstzrange(valid_from, valid_to)`: nunca depende do job que
//! passa a `expired`. A leitura exige um `TenantTx` já com o âmbito da loja (ou ator admin): a RLS
//! (0035) esconde os patrocínios das outras lojas; o filtro por `tenant_id` e `store_id` vai na query.
//!
//! Pedidos do lojista (cartão 03/19): a loja só PEDE (`pending`, `initiated_by = 'store'`); quem
//! aprova é o `sponsor_admin` da entidade. A loja nunca escreve estado, datas, bps nem `decided_by`.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    error::AppError,
    money::Bps,
    sponsors::eligibility::{self, SponsorSummary},
    tenancy::{TenantTx, db::db_error, store_terms},
};

/// `commission_override_bps` com que nasce um patrocínio (DEFAULT da coluna, 0031): a previsão do
/// formulário de registo mostra este valor; o efetivo é sempre o da linha `active`.
pub const NEW_SPONSORSHIP_OVERRIDE_BPS: Bps = Bps::ZERO;

/// Patrocínio ativo no instante pedido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveSponsorship {
    pub sponsor_entity_id: Uuid,
    pub override_bps: Bps,
}

/// Microssegundos desde a época Unix (negativos antes de 1970); fora de `i64` → erro.
pub(crate) fn epoch_micros(at: SystemTime) -> Result<i64, AppError> {
    let out_of_range = || AppError::Internal(anyhow::anyhow!("instante fora do intervalo"));
    match at.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_micros()).map_err(|_| out_of_range()),
        Err(e) => i64::try_from(e.duration().as_micros())
            .map(|m| -m)
            .map_err(|_| out_of_range()),
    }
}

/// Patrocínios `active` da loja com `at` dentro da vigência, ordenados pela entidade.
pub async fn active_at(
    tx: &mut TenantTx,
    store_id: Uuid,
    at: SystemTime,
) -> Result<Vec<ActiveSponsorship>, AppError> {
    let tenant = tx.tenant().as_uuid();
    let at = epoch_micros(at)?;
    let rows = sqlx::query!(
        "SELECT sponsor_entity_id, commission_override_bps FROM store_sponsorships
         WHERE tenant_id = $1 AND store_id = $2 AND status = 'active'
           AND ('epoch'::timestamptz + $3::int8 * interval '1 microsecond')
               <@ tstzrange(valid_from, valid_to)
         ORDER BY sponsor_entity_id",
        tenant,
        store_id,
        at
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    rows.into_iter()
        .map(|r| {
            Ok(ActiveSponsorship {
                sponsor_entity_id: r.sponsor_entity_id,
                override_bps: Bps::new(r.commission_override_bps)
                    .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Pedidos do lojista (cartão 03/19)
// ---------------------------------------------------------------------------------------------

/// Máximo de pedidos `pending` de uma loja ao mesmo tempo.
pub const MAX_PENDING_PER_STORE: i64 = 10;
/// Máximo de linhas na lista do lojista.
pub const LIST_LIMIT: i64 = 100;

/// Resultado de um pedido de patrocínio da loja.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOutcome {
    /// Linha criada (`pending`): o id.
    Created(Uuid),
    /// Loja sem `storefront_dicofre`.
    StoreAddressMissing,
    /// Entidade inexistente, inativa, de outro país ou que não cobre a freguesia (sem distinção).
    NotEligible,
    /// Já existe `pending`, ou `active` vigente, para o par (loja, entidade).
    AlreadyRequested,
    /// A loja já tem `MAX_PENDING_PER_STORE` pedidos `pending`.
    TooManyPending,
}

impl RequestOutcome {
    /// Código estável da recusa (corpo da resposta e `reason` da caixa negra).
    pub fn code(self) -> Option<&'static str> {
        match self {
            Self::Created(_) => None,
            Self::StoreAddressMissing => Some("store_address_missing"),
            Self::NotEligible => Some("not_eligible"),
            Self::AlreadyRequested => Some("already_requested"),
            Self::TooManyPending => Some("too_many_pending"),
        }
    }
}

/// Índice único de um `pending` por par (0031).
const ONE_PENDING_INDEX: &str = "store_sponsorships_one_pending_key";

/// Pede o patrocínio da entidade `entity_id` para a loja `store_id` (a linha nasce `pending`, com
/// `initiated_by = 'store'` e `requested_by = user_id`; nunca datas, estado, bps nem `decided_by`).
///
/// `tx` TEM de vir de `begin_store_tx` com o âmbito da loja. A linha da loja fica bloqueada
/// (`FOR NO KEY UPDATE`) até ao fim da transação: pedidos simultâneos da mesma loja passam um a um
/// (limite de `pending` sem corridas). Uma recusa não grava nada (a transação continua utilizável).
pub async fn request(
    tx: &mut TenantTx,
    store_id: Uuid,
    entity_id: Uuid,
    user_id: Uuid,
) -> Result<RequestOutcome, AppError> {
    let tenant = tx.tenant().as_uuid();
    let locked = sqlx::query_scalar!(
        "SELECT id FROM stores WHERE id = $1 AND tenant_id = $2 FOR NO KEY UPDATE",
        store_id,
        tenant
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    if locked.is_none() {
        return Err(AppError::NotFound);
    }
    let terms = store_terms::commission_terms(tx, store_id).await?;
    let Some(dicofre) = terms.storefront_dicofre else {
        return Ok(RequestOutcome::StoreAddressMissing);
    };
    if !entity_requestable(tx, entity_id).await?
        || !eligibility::covers(tx, entity_id, &dicofre).await?
    {
        return Ok(RequestOutcome::NotEligible);
    }
    let r = sqlx::query!(
        r#"SELECT
              EXISTS(SELECT 1 FROM store_sponsorships
                     WHERE tenant_id = $1 AND store_id = $2 AND sponsor_entity_id = $3
                       AND (status = 'pending'
                            OR (status = 'active' AND now() <@ tstzrange(valid_from, valid_to))))
                  AS "already!",
              (SELECT count(*) FROM store_sponsorships
               WHERE tenant_id = $1 AND store_id = $2 AND status = 'pending') AS "pending!""#,
        tenant,
        store_id,
        entity_id
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(db_error)?;
    if r.already {
        return Ok(RequestOutcome::AlreadyRequested);
    }
    if r.pending >= MAX_PENDING_PER_STORE {
        return Ok(RequestOutcome::TooManyPending);
    }
    let id = Uuid::now_v7();
    let mut sp = sqlx::Connection::begin(&mut **tx).await.map_err(db_error)?;
    let inserted = sqlx::query!(
        "INSERT INTO store_sponsorships
             (id, tenant_id, store_id, sponsor_entity_id, initiated_by, requested_by)
         VALUES ($1, $2, $3, $4, 'store', $5)",
        id,
        tenant,
        store_id,
        entity_id,
        user_id
    )
    .execute(&mut *sp)
    .await;
    match inserted {
        Ok(_) => {
            sp.commit().await.map_err(db_error)?;
            Ok(RequestOutcome::Created(id))
        }
        Err(sqlx::Error::Database(db))
            if db.code().as_deref() == Some("23505")
                && db.constraint() == Some(ONE_PENDING_INDEX) =>
        {
            sp.rollback().await.map_err(db_error)?;
            Ok(RequestOutcome::AlreadyRequested)
        }
        Err(e) => Err(db_error(e)),
    }
}

/// A entidade existe, está ativa e é do país do tenant do tx (o canal nacional da loja).
async fn entity_requestable(tx: &mut TenantTx, entity_id: Uuid) -> Result<bool, AppError> {
    let tenant = tx.tenant().as_uuid();
    sqlx::query_scalar!(
        r#"SELECT EXISTS(
               SELECT 1 FROM sponsor_entities e JOIN tenants t ON t.country_code = e.country_code
               WHERE e.id = $1 AND e.is_active AND t.id = $2) AS "ok!""#,
        entity_id,
        tenant
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(db_error)
}

/// País do tenant do tx (o canal nacional da loja); tenant invisível → `NotFound`.
pub async fn tenant_country(tx: &mut TenantTx) -> Result<String, AppError> {
    let tenant = tx.tenant().as_uuid();
    sqlx::query_scalar!("SELECT country_code FROM tenants WHERE id = $1", tenant)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?
        .ok_or(AppError::NotFound)
}

/// Pedido/patrocínio da loja visto pelo lojista (sem dados pessoais: nem `requested_by` nem
/// `decided_by`). Datas em RFC 3339 UTC.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StoreSponsorshipItem {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub sponsor: SponsorSummary,
    /// `pending`, `active`, `rejected`, `expired` ou `revoked`.
    pub status: String,
    pub valid_from: Option<String>,
    /// `null` = sem fim.
    pub valid_to: Option<String>,
    /// Comissão com este patrocínio ativo, em bps (o lojista sabe sempre o que paga).
    pub commission_override_bps: i32,
    pub created_at: String,
    pub decided_at: Option<String>,
    pub decision_reason: Option<String>,
}

/// Pedidos e patrocínios da loja, do mais recente para o mais antigo (máximo `LIST_LIMIT`).
pub async fn list_for_store(
    tx: &mut TenantTx,
    store_id: Uuid,
) -> Result<Vec<StoreSponsorshipItem>, AppError> {
    let tenant = tx.tenant().as_uuid();
    let rows = sqlx::query!(
        r#"SELECT s.id, s.status, s.commission_override_bps, s.decision_reason,
                  to_char(s.valid_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_from?",
                  to_char(s.valid_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_to?",
                  to_char(s.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "created_at!",
                  to_char(s.decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "decided_at?",
                  e.id AS sponsor_id, e.kind, e.name, e.slug, e.logo_key
           FROM store_sponsorships s
           JOIN sponsor_entities e ON e.id = s.sponsor_entity_id
           WHERE s.tenant_id = $1 AND s.store_id = $2
           ORDER BY s.created_at DESC, s.id DESC
           LIMIT $3"#,
        tenant,
        store_id,
        LIST_LIMIT
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(rows
        .into_iter()
        .map(|r| StoreSponsorshipItem {
            id: r.id,
            sponsor: SponsorSummary {
                id: r.sponsor_id,
                kind: r.kind,
                name: r.name,
                slug: r.slug,
                logo_key: r.logo_key,
            },
            status: r.status,
            valid_from: r.valid_from,
            valid_to: r.valid_to,
            commission_override_bps: r.commission_override_bps,
            created_at: r.created_at,
            decided_at: r.decided_at,
            decision_reason: r.decision_reason,
        })
        .collect())
}

/// Estado do par (loja, entidade) visto do lojista.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Already {
    None,
    Pending,
    Active,
}

/// Entidade elegível para a loja, com o estado do pedido.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EligibleForStore {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub slug: String,
    pub logo_key: Option<String>,
    pub already: Already,
}

/// Entidades que cobrem a freguesia da loja (ordem fixa dos selos), cada uma com o estado do par:
/// `active` (vigente) prevalece sobre `pending`. Loja sem `storefront_dicofre` → vazio.
pub async fn eligible_for_store(
    tx: &mut TenantTx,
    store_id: Uuid,
) -> Result<Vec<EligibleForStore>, AppError> {
    let terms = store_terms::commission_terms(tx, store_id).await?;
    let Some(dicofre) = terms.storefront_dicofre else {
        return Ok(Vec::new());
    };
    let country = tenant_country(tx).await?;
    let sponsors = eligibility::eligible_for(tx, &dicofre, &country).await?;
    let tenant = tx.tenant().as_uuid();
    let states = sqlx::query!(
        r#"SELECT sponsor_entity_id,
                  bool_or(status = 'active' AND now() <@ tstzrange(valid_from, valid_to)) AS "active!",
                  bool_or(status = 'pending') AS "pending!"
           FROM store_sponsorships
           WHERE tenant_id = $1 AND store_id = $2
           GROUP BY sponsor_entity_id"#,
        tenant,
        store_id
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(sponsors
        .into_iter()
        .map(|s| {
            let st = states.iter().find(|r| r.sponsor_entity_id == s.id);
            let already = match st {
                Some(r) if r.active => Already::Active,
                Some(r) if r.pending => Already::Pending,
                _ => Already::None,
            };
            EligibleForStore {
                id: s.id,
                kind: s.kind,
                name: s.name,
                slug: s.slug,
                logo_key: s.logo_key,
                already,
            }
        })
        .collect())
}
