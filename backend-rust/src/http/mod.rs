//! Camada HTTP: router, middleware e endpoints de saúde.

pub mod audit_layer;
pub mod client_ip;
pub mod health;
pub mod telemetry;

use std::time::Duration;

use axum::{Router, http::HeaderName, http::StatusCode, routing::get};
use tower::ServiceBuilder;
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    http::{
        audit_layer::{AuditLayerState, audited},
        client_ip::TrustedProxies,
    },
    state::AppState,
};

pub const MAX_BODY_BYTES: usize = 1024 * 1024;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Router sem proxies de confiança (`CF-Connecting-IP` nunca conta).
pub fn router(state: AppState) -> Router {
    router_with(state, TrustedProxies::none())
}

/// Router completo. As rotas da API entram em `api` e passam todas pela caixa negra
/// (`audit_layer`); `/healthz` e `/readyz` ficam fora (sem utilizador). Para o IP do cliente,
/// servir com `into_make_service_with_connect_info::<SocketAddr>()`.
pub fn router_with(state: AppState, trusted: TrustedProxies) -> Router {
    let audit = AuditLayerState::new(state.db_primary.clone(), state.redis.clone(), trusted);
    let api: Router<AppState> = Router::new();
    let rid = HeaderName::from_static("x-request-id");
    // TraceLayer por omissão não regista corpos nem cabeçalhos.
    let layers = ServiceBuilder::new()
        .layer(SetRequestIdLayer::new(rid.clone(), MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(rid))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES));
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .merge(audited(api, audit))
        .with_state(state)
        .layer(layers)
}
