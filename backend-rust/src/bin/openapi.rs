//! Escreve `openapi.json` (contrato com o frontend).

use utoipa::OpenApi;

fn main() -> anyhow::Result<()> {
    let json = ptmarket_api::http::health::ApiDoc::openapi().to_pretty_json()?;
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json"),
        json + "\n",
    )?;
    Ok(())
}
