//! Fronteira do módulo `identity`: contas, sessões e RBAC.
//!
//! Nunca lê tabelas de outros módulos; chama as funções públicas deles.

pub mod breach;
pub mod captcha;
pub mod crypto;
pub mod csrf;
pub mod customers;
pub mod elevate;
pub mod email;
pub mod http;
pub mod login;
pub mod nif;
pub mod passkey;
pub mod password;
pub mod rbac;
pub mod recovery;
pub mod session;
pub mod staff;
pub mod throttle;
pub mod totp;

pub use breach::{BreachChecker, HibpRange, NullBreachChecker};
pub use captcha::{CaptchaVerifier, TurnstileVerifier};
pub use customers::Registration;
pub use http::{RequireCustomer, SessionInfo, Sessions};
pub use login::{Login, PasswordCheck};
pub use passkey::Passkeys;
pub use password::{Password, Verified};
pub use rbac::{
    RequireStaff, RequireStaffPreMfa, RequireStoreOwner, RequireStoreRole, RequireSuperAdmin,
    RequireTenantAdmin, Role, RoleGrant, StaffRoles, StoreAccess, StoreViewForTenantAdmin,
};
pub use session::{CookieKind, CookieValue, SessionId, Subject};
pub use throttle::{AccountKey, account_hash};
pub use totp::Totp;
