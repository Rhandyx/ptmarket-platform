use ptmarket_api::{config::Config, http, state::AppState};

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
    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
