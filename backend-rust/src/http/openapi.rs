//! Documento OpenAPI (contrato com o frontend): `cargo run --bin openapi` escreve `openapi.json`.

use utoipa::OpenApi;

use crate::{http::health, identity, tenancy};

#[derive(OpenApi)]
#[openapi(
    paths(
        health::healthz,
        health::readyz,
        tenancy::http::tenant_info,
        identity::http::session_status,
        identity::http::logout,
        identity::customers::register,
        identity::customers::get_me,
        identity::customers::patch_me
    ),
    info(title = "PT Market API", version = "0.1.0")
)]
pub struct ApiDoc;
