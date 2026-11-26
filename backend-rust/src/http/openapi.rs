//! Documento OpenAPI (contrato com o frontend): `cargo run --bin openapi` escreve `openapi.json`.

use utoipa::OpenApi;

use crate::{http::health, tenancy};

#[derive(OpenApi)]
#[openapi(
    paths(health::healthz, health::readyz, tenancy::http::tenant_info),
    info(title = "PT Market API", version = "0.1.0")
)]
pub struct ApiDoc;
