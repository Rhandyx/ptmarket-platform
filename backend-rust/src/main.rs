use std::net::SocketAddr;

use ptmarket_api::{
    config::Config,
    http,
    http::client_ip::TrustedProxies,
    identity::{Login, Registration, Sessions},
    state::AppState,
};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    http::telemetry::init();
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Mensagens de Config/estado nunca contêm segredos.
            eprintln!("erro de arranque: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    // Sem CSRF_KEY o binário não arranca (as sessões precisam dela).
    let csrf_key = cfg.require_csrf_key()?;
    let state = AppState::from_config(&cfg)?;
    let mut sessions = Sessions::new(state.db_primary.clone(), state.redis.clone(), csrf_key)
        .with_internal_token(cfg.internal_proxy_token.clone());
    // Sem TURNSTILE_SECRET o registo e o login de clientes respondem 503 (falha fechado; nunca sem captcha).
    // Em staging/production `Config` já recusa o arranque sem ela (cartão 02/24b).
    if cfg.turnstile_secret.is_some() {
        sessions = sessions
            .with_registration(Registration::from_config(&cfg)?)
            .with_login(Login::from_config(&cfg)?);
    } else {
        tracing::warn!("TURNSTILE_SECRET ausente: /api/v1/auth/register e /api/v1/auth/login respondem 503");
    }
    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, app_env = ?cfg.app_env, "a escutar");
    let trusted = TrustedProxies::new(cfg.trusted_proxy_cidrs);
    // ConnectInfo: o peer TCP decide se `CF-Connecting-IP`/`x-request-id` contam (caixa negra).
    let app = http::router_with_sessions(state, trusted, sessions)
        .into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
