//! Camada HTTP: router, middleware e endpoints de saúde.

pub mod audit_layer;
pub mod client_ip;
pub mod health;
pub mod openapi;
pub mod telemetry;

use std::time::Duration;

use axum::{
    Extension, Router,
    body::Body,
    http::{HeaderName, Request, StatusCode},
    routing::get,
};
use tower::ServiceBuilder;
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::Span;

use crate::{
    audit::AuditClass,
    http::{
        audit_layer::{AuditLayerState, MakeRequestUuidV7, audited, take_client_request_id},
        client_ip::TrustedProxies,
    },
    state::AppState,
    tenancy,
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
    let app = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .merge(api(state.clone(), audit))
        .with_state(state);
    with_edge_layers(app)
}

/// Rotas da API, de fora para dentro: `resolve_host` (tenant pelo `Host`; nunca recusa) →
/// `AuditClass` → caixa negra → handler (os extractores `ResolvedTenant`/`PlatformHost` recusam
/// com 404 por dentro da caixa negra).
pub fn api(state: AppState, audit: AuditLayerState) -> Router<AppState> {
    let read_async = Router::new().route("/api/v1/tenant", get(tenancy::http::tenant_info));
    with_host_resolution(
        Router::new().merge(audited(read_async, audit).layer(Extension(AuditClass::ReadAsync))),
        state,
    )
}

/// Aplica a resolução do tenant pelo `Host` (por fora da caixa negra) às rotas de `router`.
pub fn with_host_resolution(router: Router<AppState>, state: AppState) -> Router<AppState> {
    router.route_layer(axum::middleware::from_fn_with_state(
        state,
        tenancy::http::resolve_host,
    ))
}

/// Layers de entrada (por esta ordem, de fora para dentro): o `x-request-id` do cliente sai do
/// pedido para `ClientRequestId`; a `SetRequestIdLayer` gera SEMPRE um UUIDv7; o span `request`
/// dos logs leva esse id; a resposta (também o 408 do timeout) leva-o no `x-request-id`; timeout;
/// limite do corpo. A caixa negra usa o mesmo id como `request_id`.
pub fn with_edge_layers(router: Router) -> Router {
    edge_layers(router, REQUEST_TIMEOUT)
}

/// Só para testes: as mesmas layers com outro timeout. Não existe em `cargo build --release`.
#[cfg(feature = "test-support")]
pub fn with_edge_layers_for_tests(router: Router, timeout: Duration) -> Router {
    edge_layers(router, timeout)
}

fn edge_layers(router: Router, timeout: Duration) -> Router {
    let rid = HeaderName::from_static("x-request-id");
    // O span só leva o método e o id: nem corpo, nem cabeçalhos, nem caminho/query (podem trazer
    // tokens; a rota-modelo só se conhece depois do roteamento, na caixa negra).
    let layers = ServiceBuilder::new()
        .layer(axum::middleware::from_fn(take_client_request_id))
        .layer(SetRequestIdLayer::new(rid.clone(), MakeRequestUuidV7))
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        .layer(PropagateRequestIdLayer::new(rid))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES));
    router.layer(layers)
}

fn request_span(req: &Request<Body>) -> Span {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .and_then(|r| r.header_value().to_str().ok())
        .unwrap_or_default();
    tracing::info_span!(
        "request",
        method = %req.method(),
        request_id = %request_id,
    )
}
