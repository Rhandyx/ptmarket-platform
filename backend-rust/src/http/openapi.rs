//! Documento OpenAPI (contrato com o frontend): `cargo run --bin openapi` escreve `openapi.json`.

use utoipa::OpenApi;

use crate::{admin, http::health, identity, tenancy};

#[derive(OpenApi)]
#[openapi(
    paths(
        health::healthz,
        health::readyz,
        tenancy::http::tenant_info,
        identity::http::session_status,
        identity::http::logout,
        identity::customers::register,
        identity::login::login,
        identity::customers::get_me,
        identity::customers::patch_me,
        identity::staff::login,
        identity::staff::me,
        identity::totp::enroll,
        identity::totp::confirm,
        identity::totp::verify,
        identity::passkey::register_start,
        identity::passkey::register_finish,
        identity::passkey::list,
        identity::passkey::remove,
        identity::passkey::login_start,
        identity::passkey::login_finish,
        identity::rbac::superadmin_whoami,
        admin::audit_timeline::list_events
    ),
    info(title = "PT Market API", version = "0.1.0")
)]
pub struct ApiDoc;
