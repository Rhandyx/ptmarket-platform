//! Endpoints públicos (sem sessão; qualquer `Host` conhecido, incluindo o de plataforma):
//! geografia, entidades elegíveis e a pré-visualização da comissão para o registo. Leitura na
//! réplica; sem dados pessoais; nunca lê `stores`.
//!
//! Endpoints do lojista (cartão 03/19, no fim do ficheiro): pedir e consultar patrocínios da loja,
//! com sessão de staff e o âmbito da loja (`begin_store_tx`).

use axum::{
    Json,
    extract::{
        FromRequestParts, Query, State,
        rejection::{JsonRejection, QueryRejection},
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
        rbac::{RequireStoreOwner, RequireStoreRole},
    },
    payments::commission::{self, PlanView},
    sponsors::{
        PUBLIC_COUNTRY,
        eligibility::{self, SponsorSummary},
        geo::{self, GeoItem},
        sponsorships::{
            self, EligibleForStore, NEW_SPONSORSHIP_OVERRIDE_BPS, RequestOutcome,
            StoreSponsorshipItem,
        },
    },
    state::AppState,
    tenancy::{
        PlatformHost, ResolvedTenant,
        db::{begin_store_tx, db_error},
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
