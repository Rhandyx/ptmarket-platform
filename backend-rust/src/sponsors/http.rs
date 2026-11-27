//! Endpoints públicos (sem sessão; qualquer `Host` conhecido, incluindo o de plataforma):
//! geografia e entidades elegíveis. Leitura na réplica; sem dados pessoais.

use axum::{
    Json,
    extract::{FromRequestParts, Query, State, rejection::QueryRejection},
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    error::AppError,
    sponsors::{
        PUBLIC_COUNTRY,
        eligibility::{self, SponsorSummary},
        geo::{self, GeoItem},
    },
    state::AppState,
    tenancy::{PlatformHost, ResolvedTenant, db::db_error},
};

const CACHE: &str = "public, max-age=300";

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

fn bad_request(field: &str, message: &str) -> Response {
    let body = json!({ "error": {
        "code": "bad_request",
        "message": "Parâmetros inválidos.",
        "fields": [{ "field": field, "message": message }],
    }});
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

fn cached<T: serde::Serialize>(v: T) -> Response {
    let mut resp = Json(v).into_response();
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(CACHE));
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
