//! Endpoints públicos (sem sessão; qualquer `Host` conhecido, incluindo o de plataforma):
//! geografia, entidades elegíveis e a pré-visualização da comissão para o registo. Leitura na
//! réplica; sem dados pessoais; nunca lê `stores`.

use axum::{
    Json,
    extract::{FromRequestParts, Query, State, rejection::QueryRejection},
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::{
    error::AppError,
    payments::commission::{self, PlanView},
    sponsors::{
        PUBLIC_COUNTRY,
        eligibility::{self, SponsorSummary},
        geo::{self, GeoItem},
        sponsorships::NEW_SPONSORSHIP_OVERRIDE_BPS,
    },
    state::AppState,
    tenancy::{PlatformHost, ResolvedTenant, db::db_error},
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
