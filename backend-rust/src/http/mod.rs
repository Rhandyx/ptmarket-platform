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
    routing::{any, delete, get, post},
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
    admin,
    audit::AuditClass,
    http::{
        audit_layer::{AuditLayerState, MakeRequestUuidV7, audited, take_client_request_id},
        client_ip::TrustedProxies,
    },
    identity::{
        self, Sessions,
        http::{with_csrf, with_request_host, with_sessions},
    },
    state::AppState,
    tenancy,
};

pub const MAX_BODY_BYTES: usize = 1024 * 1024;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Router sem proxies de confiança (`CF-Connecting-IP` nunca conta) e sem sessões.
pub fn router(state: AppState) -> Router {
    router_with(state, TrustedProxies::none())
}

/// Router completo SEM sessões (todos os pedidos são anónimos; sem `/api/v1/auth/*`). As rotas da
/// API entram em `api` e passam todas pela caixa negra (`audit_layer`); `/healthz` e `/readyz`
/// ficam fora (sem utilizador). Para o IP do cliente, servir com
/// `into_make_service_with_connect_info::<SocketAddr>()`.
pub fn router_with(state: AppState, trusted: TrustedProxies) -> Router {
    build(state, trusted, None)
}

/// Router completo COM sessões (cookie `__Host-`, CSRF e `/api/v1/auth/*`): o do binário.
pub fn router_with_sessions(
    state: AppState,
    trusted: TrustedProxies,
    sessions: Sessions,
) -> Router {
    build(state, trusted, Some(sessions))
}

fn build(state: AppState, trusted: TrustedProxies, sessions: Option<Sessions>) -> Router {
    let audit = AuditLayerState::new(state.db_primary.clone(), state.redis.clone(), trusted);
    let app = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .merge(api(state.clone(), audit, sessions))
        .with_state(state);
    with_edge_layers(app)
}

/// Rotas da API, de fora para dentro: `capture_host` (host efetivo para o CSRF; só com
/// `sessions`) → `resolve_host` (tenant pelo `Host`; nunca recusa) →
/// `authenticate` (sessão → `Actor`; só com `sessions`) → `AuditClass` → caixa negra →
/// `csrf_guard` (mutações com sessão) → handler (os extractores `ResolvedTenant`/`PlatformHost`
/// recusam com 404 por dentro da caixa negra).
pub fn api(
    state: AppState,
    audit: AuditLayerState,
    sessions: Option<Sessions>,
) -> Router<AppState> {
    let read_async = Router::new().route("/api/v1/tenant", get(tenancy::http::tenant_info));
    let Some(sessions) = sessions else {
        return with_host_resolution(
            Router::new().merge(audited(read_async, audit).layer(Extension(AuditClass::ReadAsync))),
            state,
        );
    };
    // Dados pessoais e sessões: leituras síncronas na caixa negra.
    let read_sync = Router::new()
        .route("/api/v1/auth/session", get(identity::http::session_status))
        .route("/api/v1/auth/logout", post(identity::http::logout))
        .route("/api/v1/auth/register", post(identity::customers::register))
        .route("/api/v1/auth/login", post(identity::login::login))
        .route(
            "/api/v1/me",
            get(identity::customers::get_me).patch(identity::customers::patch_me),
        )
        // Backoffice (cartão 02/19): login de staff e dados do próprio.
        .route("/api/v1/staff/auth/login", post(identity::staff::login))
        .route("/api/v1/staff/me", get(identity::staff::me))
        // 2FA TOTP (cartão 02/20): antes do 2FA (`RequireStaffPreMfa`) + CSRF.
        .route(
            "/api/v1/staff/mfa/totp/enroll",
            post(identity::totp::enroll),
        )
        .route(
            "/api/v1/staff/mfa/totp/confirm",
            post(identity::totp::confirm),
        )
        .route("/api/v1/staff/mfa/verify", post(identity::totp::verify))
        // Passkeys (cartão 02/21): gestão com sessão (`RequireStaff` + CSRF) e login anónimo
        // (`Origin` obrigatória: `ANONYMOUS_ORIGIN_PATHS`).
        .route(
            "/api/v1/staff/passkeys/register/start",
            post(identity::passkey::register_start),
        )
        .route(
            "/api/v1/staff/passkeys/register/finish",
            post(identity::passkey::register_finish),
        )
        .route("/api/v1/staff/passkeys", get(identity::passkey::list))
        .route(
            "/api/v1/staff/passkeys/{id}",
            delete(identity::passkey::remove),
        )
        .route(
            "/api/v1/staff/auth/passkey/start",
            post(identity::passkey::login_start),
        )
        .route(
            "/api/v1/staff/auth/passkey/finish",
            post(identity::passkey::login_finish),
        );
    // Consola de plataforma: o gate (`RequireSuperAdmin`) vale para o grupo INTEIRO (`.layer`),
    // incluindo os caminhos desconhecidos: qualquer caminho sob `/api/v1/superadmin` dá o mesmo 404
    // + `superadmin_gate`, exista ou não. O "fallback" é uma rota catch-all (e não `.fallback`):
    // as layers de fora (host, sessão, caixa negra, CSRF) são `route_layer` e só cobrem rotas.
    let superadmin = Router::new()
        .route("/whoami", get(identity::rbac::superadmin_whoami))
        // Timeline da caixa negra (cartão 02/23).
        .route("/audit/events", get(admin::audit_timeline::list_events))
        .route("/", any(identity::rbac::superadmin_not_found))
        .route("/{*rest}", any(identity::rbac::superadmin_not_found))
        .layer(axum::middleware::from_fn(identity::rbac::superadmin_gate));
    let read_sync = read_sync.nest("/api/v1/superadmin", superadmin);
    // Rotas de prova dos extractores de RBAC: só existem com a feature `test-support` (testes).
    #[cfg(feature = "test-support")]
    let read_sync = read_sync
        .route(
            "/api/v1/_test/stores/{store_id}",
            get(identity::rbac::test_store),
        )
        .route(
            "/api/v1/_test/stores/{store_id}/name",
            axum::routing::put(identity::rbac::test_store_name),
        )
        .route(
            "/api/v1/_test/stores/{store_id}/owner",
            get(identity::rbac::test_store_owner),
        )
        .route(
            "/api/v1/_test/sponsors/{entity_id}",
            get(identity::rbac::test_sponsor),
        )
        .route(
            "/api/v1/_test/tenants/{tenant_id}/admin",
            get(identity::rbac::test_tenant_admin),
        );
    let read_async = with_csrf(read_async, sessions.clone());
    let read_sync = with_csrf(read_sync, sessions.clone());
    let routes = Router::new()
        .merge(audited(read_async, audit.clone()).layer(Extension(AuditClass::ReadAsync)))
        .merge(audited(read_sync, audit).layer(Extension(AuditClass::ReadSync)));
    let routes = with_host_resolution(with_sessions(routes, sessions.clone()), state);
    with_request_host(routes, sessions)
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
