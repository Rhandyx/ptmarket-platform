//! HTTP do `tenancy`: layer que resolve o `Host`, extractores e `GET /api/v1/tenant`.
//!
//! A layer `resolve_host` fica POR FORA da caixa negra e nunca recusa: só põe `ResolvedHost` (e,
//! se for um tenant, o `TenantId` que o middleware de auditoria lê) nas extensões e apaga o
//! `X-Internal-Token`. Quem recusa (404) são os extractores, por dentro da caixa negra.

use axum::{
    Json,
    extract::{FromRequestParts, Request, State},
    http::request::Parts,
    middleware::Next,
    response::Response,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    error::AppError,
    state::AppState,
    tenancy::{
        db::db_error,
        host::X_INTERNAL_TOKEN,
        resolver::{CountryCode, ResolvedHost, ResolvedTenant, TenantType},
    },
};

/// Layer (`from_fn_with_state`) que resolve o `Host` de cada pedido. Por fora da caixa negra.
pub async fn resolve_host(State(s): State<AppState>, mut req: Request, next: Next) -> Response {
    let resolved = s.hosts.resolve(req.headers(), req.uri()).await;
    // O segredo do proxy interno nunca chega aos handlers nem a logs.
    req.headers_mut().remove(X_INTERNAL_TOKEN);
    if let ResolvedHost::Tenant(t) = resolved {
        req.extensions_mut().insert(t.id());
    }
    req.extensions_mut().insert(resolved);
    next.run(req).await
}

fn resolved_host(parts: &Parts) -> Result<ResolvedHost, AppError> {
    parts
        .extensions
        .get::<ResolvedHost>()
        .copied()
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "ResolvedHost em falta: rota sem a layer resolve_host"
            ))
        })
}

/// Rotas de tenant: só um `Host` de tenant ativo; tudo o resto → 404 genérico (BD em baixo → 503).
impl<S: Send + Sync> FromRequestParts<S> for ResolvedTenant {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match resolved_host(parts)? {
            ResolvedHost::Tenant(t) => Ok(t),
            ResolvedHost::Unavailable => Err(AppError::ServiceUnavailable),
            ResolvedHost::Platform | ResolvedHost::Unknown => Err(AppError::NotFound),
        }
    }
}

/// Extractor das rotas de plataforma: só `PLATFORM_ADMIN_HOST`; um tenant (ou outro host) → 404.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformHost;

impl<S: Send + Sync> FromRequestParts<S> for PlatformHost {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match resolved_host(parts)? {
            ResolvedHost::Platform => Ok(PlatformHost),
            ResolvedHost::Unavailable => Err(AppError::ServiceUnavailable),
            ResolvedHost::Tenant(_) | ResolvedHost::Unknown => Err(AppError::NotFound),
        }
    }
}

/// `tenants.template_layout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TemplateLayout {
    Bairro,
    Editorial,
    Catalogo,
}

impl TemplateLayout {
    fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "bairro" => Ok(Self::Bairro),
            "editorial" => Ok(Self::Editorial),
            "catalogo" => Ok(Self::Catalogo),
            _ => Err(AppError::Internal(anyhow::anyhow!(
                "tenants.template_layout desconhecido"
            ))),
        }
    }
}

/// Dados públicos do tenant do `Host` (nunca ids internos nem comissões).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TenantInfo {
    pub slug: String,
    pub name: String,
    pub tenant_type: TenantType,
    pub country_code: CountryCode,
    /// ISO 4217 (ex.: `EUR`).
    pub currency: String,
    pub template_layout: TemplateLayout,
    #[schema(value_type = Object)]
    pub theme_config: serde_json::Value,
    #[schema(value_type = Object)]
    pub legal_config: serde_json::Value,
}

// Anónimo; leitura comum (`AuditClass::ReadAsync`, posta em `http::api`).
/// Dados públicos do tenant do domínio pedido.
#[utoipa::path(
    get,
    path = "/api/v1/tenant",
    tag = "tenancy",
    responses(
        (status = 200, description = "Tenant do Host", body = TenantInfo),
        (status = 404, description = "Host desconhecido, inválido ou tenant inativo"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn tenant_info(
    State(s): State<AppState>,
    tenant: ResolvedTenant,
) -> Result<Json<TenantInfo>, AppError> {
    let row = sqlx::query!(
        "SELECT slug, name, tenant_type, country_code, currency, template_layout,
                theme_config, legal_config
         FROM tenants WHERE id = $1 AND is_active",
        tenant.id().as_uuid()
    )
    .fetch_optional(&s.db_replica)
    .await
    .map_err(db_error)?
    .ok_or(AppError::NotFound)?;
    Ok(Json(TenantInfo {
        slug: row.slug,
        name: row.name,
        tenant_type: TenantType::parse(&row.tenant_type)?,
        country_code: CountryCode::parse(&row.country_code)?,
        currency: row.currency,
        template_layout: TemplateLayout::parse(&row.template_layout)?,
        theme_config: row.theme_config,
        legal_config: row.legal_config,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_info_never_exposes_internal_fields() {
        let info = TenantInfo {
            slug: "s".into(),
            name: "n".into(),
            tenant_type: TenantType::NationalPortal,
            country_code: CountryCode::Pt,
            currency: "EUR".into(),
            template_layout: TemplateLayout::Catalogo,
            theme_config: serde_json::json!({}),
            legal_config: serde_json::json!({}),
        };
        let v = serde_json::to_value(&info).unwrap_or_default();
        let mut keys: Vec<&str> = v
            .as_object()
            .map(|o| o.keys().map(String::as_str).collect())
            .unwrap_or_default();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "country_code",
                "currency",
                "legal_config",
                "name",
                "slug",
                "template_layout",
                "tenant_type",
                "theme_config"
            ]
        );
        assert_eq!(v["tenant_type"], "national_portal");
        assert_eq!(v["country_code"], "PT");
        assert_eq!(v["template_layout"], "catalogo");
    }
}
