use std::net::SocketAddr;

use ptmarket_api::{config::Config, http, http::client_ip::TrustedProxies, state::AppState};

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
    let state = AppState::from_config(&cfg)?;
    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, "a escutar");
    let trusted = TrustedProxies::new(cfg.trusted_proxy_cidrs);
    // ConnectInfo: o peer TCP decide se `CF-Connecting-IP`/`x-request-id` contam (caixa negra).
    let app = http::router_with(state, trusted).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
