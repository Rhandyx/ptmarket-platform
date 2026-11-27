//! Endpoints públicos (sem sessão; qualquer `Host` conhecido, incluindo o de plataforma):
//! geografia, entidades elegíveis e a pré-visualização da comissão para o registo. Leitura na
//! réplica; sem dados pessoais; nunca lê `stores`.
//!
//! Endpoints do lojista (cartão 03/19, no fim do ficheiro): pedir e consultar patrocínios da loja,
//! com sessão de staff e o âmbito da loja (`begin_store_tx`).
//!
//! Endpoints do `sponsor_admin` (cartão 03/20, no fim do ficheiro): lista, aprovar, rejeitar e
//! revogar os patrocínios da entidade (`begin_sponsor_tx` no canal nacional do país da entidade).

use std::collections::HashMap;

use axum::{
    Extension, Json,
    extract::{
        FromRequestParts, Path, Query, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    audit::{AuditCtx, AuditEvent, Outcome, record},
    error::AppError,
    identity::{
        elevate::NoImpersonation,
        http::no_store,
        rbac::{DENIED_IDOR, RequireSponsorAdmin, RequireStoreOwner, RequireStoreRole},
    },
    payments::commission::{self, PlanView},
    sponsors::{
        PUBLIC_COUNTRY,
        admin::{self, Decision, EntitySponsorshipPage, ListFilter},
        eligibility::{self, SponsorSummary},
        geo::{self, GeoItem},
        sponsorships::{
            self, EligibleForStore, NEW_SPONSORSHIP_OVERRIDE_BPS, RequestOutcome,
            StoreSponsorshipItem,
        },
    },
    state::AppState,
    tenancy::{
        NationalPortal, PlatformHost, ResolvedTenant, TenantTx, begin_national_read_tx,
        db::{begin_sponsor_tx, begin_store_tx, db_error},
    },
};

const CACHE: &str = "public, max-age=300";
/// A comissão base e os escalões mudam pela consola: cache curta.
const PREVIEW_CACHE: &str = "public, max-age=60";

/// Qualquer `Host` conhecido (tenant ou plataforma); desconhecido → 404, limitado → 429.
pub struct KnownHost;

impl<S: Send + Sync> FromRequestParts<S> for KnownHost {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ResolvedTenant::from_request_parts(parts, state).await {
            Ok(_) => Ok(Self),
            Err(AppError::NotFound) => PlatformHost::from_request_parts(parts, state)
                .await
                .map(|_| Self),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MunicipalitiesQuery {
    pub district: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParishesQuery {
    pub municipality: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EligibleQuery {
    pub dicofre: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissionPreviewQuery {
    pub dicofre: Option<String>,
}

/// Previsão do patrocínio (nada criado nem prometido).
#[derive(Debug, Serialize, ToSchema)]
pub struct SponsoredPreview {
    /// Comissão prevista com patrocínio ativo, em bps.
    pub applied_bps: i32,
    /// Entidades que cobrem a freguesia, na ordem fixa dos selos.
    pub sponsors: Vec<SponsorSummary>,
}

/// Âncora do formulário de registo: só inteiros (cêntimos, bps).
#[derive(Debug, Serialize, ToSchema)]
pub struct CommissionPreview {
    /// Comissão de referência da plataforma, em bps.
    pub reference_bps: i32,
    /// `null` sem `dicofre` ou sem entidades elegíveis.
    pub sponsored: Option<SponsoredPreview>,
    pub plans: Vec<PlanView>,
}

fn bad_request(field: &str, message: &str) -> Response {
    let body = json!({ "error": {
        "code": "bad_request",
        "message": "Parâmetros inválidos.",
        "fields": [{ "field": field, "message": message }],
    }});
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

fn cached<T: serde::Serialize>(v: T) -> Response {
    cached_for(v, CACHE)
}

fn cached_for<T: serde::Serialize>(v: T, cache: &'static str) -> Response {
    let mut resp = Json(v).into_response();
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(cache));
    resp
}

/// Valida a query; erro de forma → 400.
fn query<T>(q: Result<Query<T>, QueryRejection>, field: &str) -> Result<T, Box<Response>> {
    q.map(|Query(v)| v)
        .map_err(|_| Box::new(bad_request(field, "parâmetro em falta ou desconhecido")))
}

async fn conn(s: &AppState) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, AppError> {
    s.db_replica.acquire().await.map_err(db_error)
}

/// Distritos em vigor, por nome.
#[utoipa::path(
    get,
    path = "/api/v1/geo/districts",
    tag = "sponsors",
    responses((status = 200, description = "Distritos", body = Vec<GeoItem>))
)]
pub async fn districts(State(s): State<AppState>, _h: KnownHost) -> Result<Response, AppError> {
    let mut c = conn(&s).await?;
    Ok(cached(geo::districts(&mut c).await?))
}

/// Concelhos em vigor de um distrito, por nome.
#[utoipa::path(
    get,
    path = "/api/v1/geo/municipalities",
    tag = "sponsors",
    params(("district" = String, Query, description = "Código do distrito (2 algarismos)")),
    responses(
        (status = 200, description = "Concelhos", body = Vec<GeoItem>),
        (status = 400, description = "Parâmetro inválido")
    )
)]
pub async fn municipalities(
    State(s): State<AppState>,
    _h: KnownHost,
    q: Result<Query<MunicipalitiesQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let q = match query(q, "district") {
        Ok(q) => q,
        Err(r) => return Ok(*r),
    };
    if !geo::is_district_code(&q.district) {
        return Ok(bad_request("district", "2 algarismos"));
    }
    let mut c = conn(&s).await?;
    Ok(cached(geo::children(&mut c, &q.district).await?))
}

/// Freguesias em vigor de um concelho, por nome.
#[utoipa::path(
    get,
    path = "/api/v1/geo/parishes",
    tag = "sponsors",
    params(("municipality" = String, Query, description = "Código do concelho (4 algarismos)")),
    responses(
        (status = 200, description = "Freguesias", body = Vec<GeoItem>),
        (status = 400, description = "Parâmetro inválido")
    )
)]
pub async fn parishes(
    State(s): State<AppState>,
    _h: KnownHost,
    q: Result<Query<ParishesQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let q = match query(q, "municipality") {
        Ok(q) => q,
        Err(r) => return Ok(*r),
    };
    if !geo::is_municipality_code(&q.municipality) {
        return Ok(bad_request("municipality", "4 algarismos"));
    }
    let mut c = conn(&s).await?;
    Ok(cached(geo::children(&mut c, &q.municipality).await?))
}

/// Entidades que cobrem uma freguesia em vigor, na ordem fixa dos selos.
#[utoipa::path(
    get,
    path = "/api/v1/sponsors/eligible",
    tag = "sponsors",
    params(("dicofre" = String, Query, description = "DICOFRE da freguesia (6 caracteres, ex.: 0302FA)")),
    responses(
        (status = 200, description = "Entidades elegíveis", body = Vec<SponsorSummary>),
        (status = 400, description = "Código com formato inválido"),
        (status = 404, description = "Freguesia inexistente ou fora de vigor")
    )
)]
pub async fn eligible(
    State(s): State<AppState>,
    _h: KnownHost,
    q: Result<Query<EligibleQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let q = match query(q, "dicofre") {
        Ok(q) => q,
        Err(r) => return Ok(*r),
    };
    if !geo::is_parish_code(&q.dicofre) {
        return Ok(bad_request("dicofre", "4 algarismos + 2 de 0-9 A-Z"));
    }
    let mut c = conn(&s).await?;
    if !geo::parish_in_force(&mut c, &q.dicofre).await? {
        return Err(AppError::NotFound);
    }
    Ok(cached(
        eligibility::eligible_for(&mut c, &q.dicofre, PUBLIC_COUNTRY).await?,
    ))
}

/// Pré-visualização da comissão para o formulário de registo: comissão de referência, planos com os
/// escalões da BD e, se a freguesia tiver entidades elegíveis, a previsão com patrocínio.
///
/// `sponsored` é só uma PREVISÃO sujeita à validação da entidade: este endpoint não cria pedido
/// nenhum, não reserva nada e não promete condições. Sem sessão; não lê dados de lojas.
#[utoipa::path(
    get,
    path = "/api/v1/signup/commission-preview",
    tag = "sponsors",
    params(("dicofre" = Option<String>, Query, description = "DICOFRE da freguesia da loja (6 caracteres, opcional)")),
    responses(
        (status = 200, description = "Âncora de comissão (previsão; nada é criado nem prometido)", body = CommissionPreview),
        (status = 400, description = "Código com formato inválido, inexistente ou fora de vigor")
    )
)]
pub async fn commission_preview(
    State(s): State<AppState>,
    _h: KnownHost,
    q: Result<Query<CommissionPreviewQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let q = match query(q, "dicofre") {
        Ok(q) => q,
        Err(r) => return Ok(*r),
    };
    if let Some(d) = &q.dicofre
        && !geo::is_parish_code(d)
    {
        return Ok(bad_request("dicofre", "4 algarismos + 2 de 0-9 A-Z"));
    }
    let mut c = conn(&s).await?;
    let sponsored = match &q.dicofre {
        None => None,
        Some(d) => {
            if !geo::parish_in_force(&mut c, d).await? {
                return Ok(bad_request(
                    "dicofre",
                    "freguesia inexistente ou fora de vigor",
                ));
            }
            let sponsors = eligibility::eligible_for(&mut c, d, PUBLIC_COUNTRY).await?;
            (!sponsors.is_empty()).then(|| SponsoredPreview {
                applied_bps: NEW_SPONSORSHIP_OVERRIDE_BPS.get(),
                sponsors,
            })
        }
    };
    let reference_bps = commission::base_commission_bps(&mut c).await?.get();
    let plans = commission::plans(&mut c).await?;
    Ok(cached_for(
        CommissionPreview {
            reference_bps,
            sponsored,
            plans,
        },
        PREVIEW_CACHE,
    ))
}

// ---------------------------------------------------------------------------------------------
// Lojista (cartão 03/19): pedir e consultar patrocínios. Painel único (`PLATFORM_ADMIN_HOST`: os
// papéis de loja só valem lá); âmbito da loja provado pelo extractor → `begin_store_tx` (RLS 0035).
// ---------------------------------------------------------------------------------------------

/// Evento semântico do pedido (sucesso e recusas 422/409).
const ACTION_REQUESTED: &str = "sponsorship.requested";
const TARGET_SPONSORSHIP: &str = "store_sponsorship";

/// Corpo de `POST /api/v1/stores/{store_id}/sponsorships`: só a entidade (nunca datas, estado nem
/// bps: campo desconhecido → 400).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SponsorshipRequestBody {
    #[schema(value_type = String, format = "uuid")]
    pub sponsor_entity_id: Uuid,
}

/// Pedido criado (sempre `pending`: a entidade aprova no painel).
#[derive(Debug, Serialize, ToSchema)]
pub struct SponsorshipCreated {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub status: String,
}

/// Recusa de negócio com código estável (`{"error":{"code","message"}}`).
fn refusal(status: StatusCode, code: &str, message: &str) -> Response {
    let body = json!({ "error": { "code": code, "message": message } });
    no_store((status, Json(body)).into_response())
}

fn refusal_for(outcome: RequestOutcome) -> Response {
    match outcome {
        RequestOutcome::StoreAddressMissing => refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "store_address_missing",
            "A loja ainda não tem a morada física (freguesia) preenchida.",
        ),
        RequestOutcome::NotEligible => refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "not_eligible",
            "Esta entidade não pode patrocinar a loja.",
        ),
        RequestOutcome::AlreadyRequested => refusal(
            StatusCode::CONFLICT,
            "already_requested",
            "Já existe um pedido pendente ou um patrocínio ativo com esta entidade.",
        ),
        RequestOutcome::TooManyPending => refusal(
            StatusCode::CONFLICT,
            "too_many_pending",
            "A loja já tem o máximo de pedidos pendentes.",
        ),
        RequestOutcome::Created(_) => {
            AppError::Internal(anyhow::anyhow!("refusal_for(Created)")).into_response()
        }
    }
}

/// O dono pede o patrocínio de uma entidade que cubra a freguesia da loja. O pedido nasce
/// `pending`; nenhuma loja fica patrocinada sem a aprovação explícita da entidade.
#[utoipa::path(
    post,
    path = "/api/v1/stores/{store_id}/sponsorships",
    tag = "sponsors",
    params(
        ("store_id" = String, Path, description = "Id da loja"),
        ("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")
    ),
    request_body = SponsorshipRequestBody,
    responses(
        (status = 201, description = "Pedido criado (pending)", body = SponsorshipCreated),
        (status = 400, description = "Corpo inválido ou com campos desconhecidos"),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Não é o dono da loja (`rbac`), 2FA em falta (`mfa_required`) ou sessão de impersonação (`impersonation`)"),
        (status = 404, description = "Loja sem papel do utilizador ou inexistente"),
        (status = 409, description = "`already_requested` ou `too_many_pending`"),
        (status = 422, description = "`store_address_missing` ou `not_eligible`"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn request_sponsorship(
    State(st): State<AppState>,
    r: RequireStoreOwner,
    // Decisão comercial do dono (partilha os dados da loja com a entidade): nunca por impersonação.
    _ni: NoImpersonation,
    ctx: AuditCtx,
    body: Result<Json<SponsorshipRequestBody>, JsonRejection>,
) -> Result<Response, AppError> {
    let Ok(Json(body)) = body else {
        return Ok(no_store(bad_request(
            "sponsor_entity_id",
            "corpo JSON só com sponsor_entity_id (uuid)",
        )));
    };
    let entity = body.sponsor_entity_id;
    let mut tx = begin_store_tx(&st.db_primary, &r.scope(), &ctx).await?;
    let outcome = sponsorships::request(&mut tx, r.store_id, entity, r.user_id).await?;
    let (target_id, result, reason) = match outcome {
        RequestOutcome::Created(id) => (Some(id.to_string()), Outcome::Success, None),
        other => (None, Outcome::Denied, other.code().map(str::to_owned)),
    };
    record(
        &mut tx,
        AuditEvent {
            action: ACTION_REQUESTED,
            target_type: Some(TARGET_SPONSORSHIP),
            target_id,
            outcome: result,
            reason,
            changes: Some(json!({ "sponsor_entity_id": entity })),
            store_id: Some(r.store_id),
        },
    )
    .await?;
    tx.commit().await?;
    match outcome {
        RequestOutcome::Created(id) => {
            let out = SponsorshipCreated {
                id,
                status: "pending".to_owned(),
            };
            Ok(no_store((StatusCode::CREATED, Json(out)).into_response()))
        }
        other => Ok(refusal_for(other)),
    }
}

/// Pedidos e patrocínios da loja (mais recentes primeiro, máximo 100), com a comissão de cada um.
#[utoipa::path(
    get,
    path = "/api/v1/stores/{store_id}/sponsorships",
    tag = "sponsors",
    params(("store_id" = String, Path, description = "Id da loja")),
    responses(
        (status = 200, description = "Patrocínios da loja", body = [StoreSponsorshipItem]),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "2FA em falta (`mfa_required`)"),
        (status = 404, description = "Loja sem papel do utilizador ou inexistente"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn list_sponsorships(
    State(st): State<AppState>,
    r: RequireStoreRole,
    ctx: AuditCtx,
) -> Result<Response, AppError> {
    let mut tx = begin_store_tx(&st.db_primary, &r.scope(), &ctx).await?;
    let items = sponsorships::list_for_store(&mut tx, r.store_id).await?;
    tx.rollback().await?;
    Ok(no_store(Json(items).into_response()))
}

/// Entidades que cobrem a freguesia da loja (ordem fixa dos selos), com o estado do pedido de cada
/// uma. Loja sem morada física → lista vazia.
#[utoipa::path(
    get,
    path = "/api/v1/stores/{store_id}/sponsors/eligible",
    tag = "sponsors",
    params(("store_id" = String, Path, description = "Id da loja")),
    responses(
        (status = 200, description = "Entidades elegíveis para a loja", body = [EligibleForStore]),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "2FA em falta (`mfa_required`)"),
        (status = 404, description = "Loja sem papel do utilizador ou inexistente"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn eligible_for_store(
    State(st): State<AppState>,
    r: RequireStoreRole,
    ctx: AuditCtx,
) -> Result<Response, AppError> {
    let mut tx = begin_store_tx(&st.db_primary, &r.scope(), &ctx).await?;
    let items = sponsorships::eligible_for_store(&mut tx, r.store_id).await?;
    tx.rollback().await?;
    Ok(no_store(Json(items).into_response()))
}

// ---------------------------------------------------------------------------------------------
// sponsor_admin (cartão 03/20): ver, aprovar, rejeitar e revogar os patrocínios da entidade.
// `RequireSponsorAdmin` (2FA sempre) → entidade ativa → canal nacional do país da entidade →
// `begin_sponsor_tx` (RLS 0035). Os dados da loja vêm só do portal (`stores_by_ids`).
// ---------------------------------------------------------------------------------------------

const ACTION_APPROVED: &str = "sponsorship.approved";
const ACTION_REJECTED: &str = "sponsorship.rejected";
/// Kind crítico `sponsorship_revoked` (0038).
const ACTION_REVOKED: &str = "sponsorship.revoked";

/// Filtros de `GET /api/v1/sponsors/{entity_id}/sponsorships`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityListQuery {
    pub status: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

/// Corpo de `approve`: vigência opcional (RFC 3339). `valid_from` por defeito = agora, nunca
/// anterior a agora − 1 min; `valid_to` (`null` = sem fim) > `valid_from`. Nada mais (estado, bps
/// ou outro campo → 400).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
}

/// Corpo de `reject` e `revoke`: só o motivo (1..=500 caracteres).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionReasonBody {
    pub reason: String,
}

/// Patrocínio depois da decisão.
#[derive(Debug, Serialize, ToSchema)]
pub struct SponsorshipDecision {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// `active`, `rejected` ou `revoked`.
    pub status: String,
    pub valid_from: Option<String>,
    /// `null` = sem fim.
    pub valid_to: Option<String>,
}

/// 404 + `Denied("idor")`: patrocínio de outra entidade, inexistente, ou entidade desativada.
fn idor() -> Response {
    no_store((Extension(DENIED_IDOR), AppError::NotFound).into_response())
}

/// Id do patrocínio no caminho; inválido → `None` (404 + `idor`, como inexistente).
fn sponsorship_id(path: Result<Path<HashMap<String, String>>, PathRejection>) -> Option<Uuid> {
    let Path(p) = path.ok()?;
    Uuid::parse_str(p.get("id")?).ok()
}

/// Canal nacional da entidade e a transação de entidade nele. Entidade inexistente ou desativada
/// → `Err(404 + idor)` antes de qualquer leitura de patrocínios.
async fn sponsor_tx(
    st: &AppState,
    r: &RequireSponsorAdmin,
    ctx: &AuditCtx,
) -> Result<Result<(NationalPortal, TenantTx), Response>, AppError> {
    let mut conn = st.db_primary.acquire().await.map_err(db_error)?;
    let Some(channel) = admin::channel_for_entity(&mut conn, r.entity_id()).await? else {
        return Ok(Err(idor()));
    };
    drop(conn);
    let tx = begin_sponsor_tx(&st.db_primary, channel.id(), &r.scope(), ctx).await?;
    Ok(Ok((channel, tx)))
}

fn decision_refusal(d: &Decision) -> Response {
    match d {
        Decision::NotFound => idor(),
        Decision::InvalidTransition { .. } => refusal(
            StatusCode::CONFLICT,
            "invalid_transition",
            "O estado atual deste patrocínio não permite esta ação.",
        ),
        Decision::Overlap { .. } => refusal(
            StatusCode::CONFLICT,
            "overlapping_period",
            "Já existe um patrocínio ativo desta entidade para a loja nesse período.",
        ),
        Decision::NotEligible { .. } => refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "not_eligible",
            "A entidade não pode patrocinar esta loja.",
        ),
        Decision::Done(_) => {
            AppError::Internal(anyhow::anyhow!("decision_refusal(Done)")).into_response()
        }
    }
}

/// Grava a decisão (ou a recusa 409/422) na caixa negra, na transação `tx`, e confirma. IDOR:
/// nada gravado aqui (rollback; o middleware grava a recusa pela marca `idor`).
async fn finish_decision(
    mut tx: TenantTx,
    action: &'static str,
    entity_id: Uuid,
    id: Uuid,
    decision: Decision,
    reason: Option<&str>,
) -> Result<Response, AppError> {
    let (store_id, outcome, code, from, to) = match &decision {
        Decision::NotFound => {
            tx.rollback().await?;
            return Ok(idor());
        }
        Decision::Done(d) => (
            d.store_id,
            Outcome::Success,
            None,
            d.valid_from.clone(),
            d.valid_to.clone(),
        ),
        Decision::InvalidTransition { store_id } => (
            *store_id,
            Outcome::Denied,
            Some("invalid_transition"),
            None,
            None,
        ),
        Decision::Overlap { store_id } => (
            *store_id,
            Outcome::Denied,
            Some("overlapping_period"),
            None,
            None,
        ),
        Decision::NotEligible { store_id } => {
            (*store_id, Outcome::Denied, Some("not_eligible"), None, None)
        }
    };
    record(
        &mut tx,
        AuditEvent {
            action,
            target_type: Some(TARGET_SPONSORSHIP),
            target_id: Some(id.to_string()),
            outcome,
            reason: code.map(str::to_owned),
            changes: Some(json!({
                "sponsor_entity_id": entity_id,
                "valid_from": from,
                "valid_to": to,
                "reason": reason,
            })),
            store_id: Some(store_id),
        },
    )
    .await?;
    tx.commit().await?;
    match decision {
        Decision::Done(d) => Ok(no_store(
            Json(SponsorshipDecision {
                id: d.id,
                status: d.status.to_owned(),
                valid_from: d.valid_from,
                valid_to: d.valid_to,
            })
            .into_response(),
        )),
        other => Ok(decision_refusal(&other)),
    }
}

/// Pedidos e patrocínios da entidade, do mais recente para o mais antigo, com os dados públicos
/// da loja (nunca IBAN, contactos, comissões nem compradores). Lojas inativas ficam de fora.
#[utoipa::path(
    get,
    path = "/api/v1/sponsors/{entity_id}/sponsorships",
    tag = "sponsors",
    params(
        ("entity_id" = String, Path, description = "Id da entidade patrocinadora"),
        ("status" = Option<String>, Query, description = "pending, active, rejected, expired ou revoked"),
        ("cursor" = Option<String>, Query, description = "`next_cursor` da página anterior"),
        ("limit" = Option<i64>, Query, description = "1..=100 (por defeito 50)")
    ),
    responses(
        (status = 200, description = "Página de patrocínios da entidade", body = EntitySponsorshipPage),
        (status = 400, description = "Filtros inválidos"),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Sem `sponsor_admin` (`rbac`) ou 2FA em falta (`mfa_required`)"),
        (status = 404, description = "Outra entidade, inexistente ou desativada (`idor`)"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn entity_sponsorships(
    State(st): State<AppState>,
    r: RequireSponsorAdmin,
    ctx: AuditCtx,
    q: Result<Query<EntityListQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let q = match query(q, "status") {
        Ok(q) => q,
        Err(r) => return Ok(no_store(*r)),
    };
    if let Some(s) = &q.status
        && !admin::STATUSES.contains(&s.as_str())
    {
        return Ok(no_store(bad_request("status", "estado desconhecido")));
    }
    let limit = q.limit.unwrap_or(admin::DEFAULT_LIST_LIMIT);
    if !(1..=admin::MAX_LIST_LIMIT).contains(&limit) {
        return Ok(no_store(bad_request("limit", "entre 1 e 100")));
    }
    let cursor = match q.cursor.as_deref() {
        None => None,
        Some(c) => match admin::parse_cursor(c) {
            Some(c) => Some(c),
            None => return Ok(no_store(bad_request("cursor", "cursor inválido"))),
        },
    };
    let (channel, mut tx) = match sponsor_tx(&st, &r, &ctx).await? {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    // Primário (não a réplica): com lag, uma loja acabada de criar ficaria fora da lista sem aviso.
    let mut portal = begin_national_read_tx(&st.db_primary, &channel, &ctx).await?;
    let filter = ListFilter {
        status: q.status,
        cursor,
        limit,
    };
    let page = admin::list_for_entity(&mut tx, &mut portal, r.entity_id(), &filter).await;
    portal.finish().await?;
    tx.rollback().await?;
    Ok(no_store(Json(page?).into_response()))
}

/// Aprova um pedido `pending` (→ `active`), com a elegibilidade revista pela morada da loja.
#[utoipa::path(
    post,
    path = "/api/v1/sponsors/{entity_id}/sponsorships/{id}/approve",
    tag = "sponsors",
    params(
        ("entity_id" = String, Path, description = "Id da entidade patrocinadora"),
        ("id" = String, Path, description = "Id do patrocínio"),
        ("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")
    ),
    request_body = ApproveBody,
    responses(
        (status = 200, description = "Patrocínio ativo", body = SponsorshipDecision),
        (status = 400, description = "Corpo inválido, campos desconhecidos ou vigência inválida"),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Sem `sponsor_admin` (`rbac`), 2FA em falta (`mfa_required`) ou impersonação (`impersonation`)"),
        (status = 404, description = "Patrocínio de outra entidade ou inexistente, ou entidade desativada (`idor`)"),
        (status = 409, description = "`invalid_transition` ou `overlapping_period`"),
        (status = 422, description = "`not_eligible`"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn approve_sponsorship(
    State(st): State<AppState>,
    r: RequireSponsorAdmin,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    path: Result<Path<HashMap<String, String>>, PathRejection>,
    body: Result<Json<ApproveBody>, JsonRejection>,
) -> Result<Response, AppError> {
    let Some(id) = sponsorship_id(path) else {
        return Ok(idor());
    };
    let Ok(Json(body)) = body else {
        return Ok(no_store(bad_request(
            "body",
            "corpo JSON só com valid_from e valid_to (opcionais)",
        )));
    };
    let parse = |v: &Option<String>| match v {
        None => Ok(None),
        Some(s) => admin::parse_rfc3339_us(s).map(Some).ok_or(()),
    };
    let Ok(from) = parse(&body.valid_from) else {
        return Ok(no_store(bad_request(
            "valid_from",
            "data RFC 3339 inválida",
        )));
    };
    let Ok(to) = parse(&body.valid_to) else {
        return Ok(no_store(bad_request("valid_to", "data RFC 3339 inválida")));
    };
    let (channel, mut tx) = match sponsor_tx(&st, &r, &ctx).await? {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let now = admin::db_now_us(&mut tx).await?;
    let from = from.unwrap_or(now);
    if from < now - admin::VALID_FROM_TOLERANCE_US {
        tx.rollback().await?;
        return Ok(no_store(bad_request(
            "valid_from",
            "não pode ser anterior a agora",
        )));
    }
    if from > now + admin::VALID_FROM_MAX_AHEAD_US {
        tx.rollback().await?;
        return Ok(no_store(bad_request(
            "valid_from",
            "no máximo 366 dias a partir de agora",
        )));
    }
    if to.is_some_and(|t| t <= from) {
        tx.rollback().await?;
        return Ok(no_store(bad_request(
            "valid_to",
            "tem de ser posterior a valid_from",
        )));
    }
    let mut portal = begin_national_read_tx(&st.db_primary, &channel, &ctx).await?;
    let decision =
        admin::approve(&mut tx, &mut portal, r.entity_id(), id, r.user_id, from, to).await;
    portal.finish().await?;
    finish_decision(tx, ACTION_APPROVED, r.entity_id(), id, decision?, None).await
}

/// Rejeita um pedido `pending` (→ `rejected`) com motivo.
#[utoipa::path(
    post,
    path = "/api/v1/sponsors/{entity_id}/sponsorships/{id}/reject",
    tag = "sponsors",
    params(
        ("entity_id" = String, Path, description = "Id da entidade patrocinadora"),
        ("id" = String, Path, description = "Id do patrocínio"),
        ("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")
    ),
    request_body = DecisionReasonBody,
    responses(
        (status = 200, description = "Pedido rejeitado", body = SponsorshipDecision),
        (status = 400, description = "Corpo inválido, campos desconhecidos ou motivo fora de 1..=500"),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Sem `sponsor_admin` (`rbac`), 2FA em falta (`mfa_required`) ou impersonação (`impersonation`)"),
        (status = 404, description = "Patrocínio de outra entidade ou inexistente, ou entidade desativada (`idor`)"),
        (status = 409, description = "`invalid_transition`"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn reject_sponsorship(
    State(st): State<AppState>,
    r: RequireSponsorAdmin,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    path: Result<Path<HashMap<String, String>>, PathRejection>,
    body: Result<Json<DecisionReasonBody>, JsonRejection>,
) -> Result<Response, AppError> {
    decide_with_reason(st, r, ctx, path, body, ACTION_REJECTED).await
}

/// Revoga um patrocínio `active` (→ `revoked`; a BD fecha a vigência agora) com motivo. Evento
/// crítico da caixa negra. A loja continua no portal e volta à exceção ou ao plano se não tiver
/// outro patrocínio ativo.
#[utoipa::path(
    post,
    path = "/api/v1/sponsors/{entity_id}/sponsorships/{id}/revoke",
    tag = "sponsors",
    params(
        ("entity_id" = String, Path, description = "Id da entidade patrocinadora"),
        ("id" = String, Path, description = "Id do patrocínio"),
        ("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")
    ),
    request_body = DecisionReasonBody,
    responses(
        (status = 200, description = "Patrocínio revogado", body = SponsorshipDecision),
        (status = 400, description = "Corpo inválido, campos desconhecidos ou motivo fora de 1..=500"),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Sem `sponsor_admin` (`rbac`), 2FA em falta (`mfa_required`) ou impersonação (`impersonation`)"),
        (status = 404, description = "Patrocínio de outra entidade ou inexistente, ou entidade desativada (`idor`)"),
        (status = 409, description = "`invalid_transition`"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn revoke_sponsorship(
    State(st): State<AppState>,
    r: RequireSponsorAdmin,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    path: Result<Path<HashMap<String, String>>, PathRejection>,
    body: Result<Json<DecisionReasonBody>, JsonRejection>,
) -> Result<Response, AppError> {
    decide_with_reason(st, r, ctx, path, body, ACTION_REVOKED).await
}

async fn decide_with_reason(
    st: AppState,
    r: RequireSponsorAdmin,
    ctx: AuditCtx,
    path: Result<Path<HashMap<String, String>>, PathRejection>,
    body: Result<Json<DecisionReasonBody>, JsonRejection>,
    action: &'static str,
) -> Result<Response, AppError> {
    let Some(id) = sponsorship_id(path) else {
        return Ok(idor());
    };
    let Ok(Json(body)) = body else {
        return Ok(no_store(bad_request("reason", "corpo JSON só com reason")));
    };
    let Some(reason) = admin::valid_reason(&body.reason) else {
        return Ok(no_store(bad_request(
            "reason",
            "entre 1 e 500 caracteres, sem caracteres de controlo",
        )));
    };
    let (_channel, mut tx) = match sponsor_tx(&st, &r, &ctx).await? {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let decision = if action == ACTION_REVOKED {
        admin::revoke(&mut tx, r.entity_id(), id, r.user_id, reason).await?
    } else {
        admin::reject(&mut tx, r.entity_id(), id, r.user_id, reason).await?
    };
    finish_decision(tx, action, r.entity_id(), id, decision, Some(reason)).await
}
