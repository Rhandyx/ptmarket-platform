//! Camada HTTP: router, middleware e endpoints de saúde.

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

use crate::state::AppState;

pub const MAX_BODY_BYTES: usize = 1024 * 1024;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub fn router(state: AppState) -> Router {
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
        .with_state(state)
        .layer(layers)
}
