//! Fronteira do módulo `identity`: contas, sessões e RBAC.
//!
//! Nunca lê tabelas de outros módulos; chama as funções públicas deles.

pub mod breach;
pub mod captcha;
pub mod csrf;
pub mod customers;
pub mod email;
pub mod http;
pub mod login;
pub mod nif;
pub mod password;
pub mod rbac;
pub mod session;
pub mod staff;
pub mod throttle;

pub use breach::{BreachChecker, HibpRange, NullBreachChecker};
pub use captcha::{CaptchaVerifier, TurnstileVerifier};
pub use customers::Registration;
pub use http::{RequireCustomer, SessionInfo, Sessions};
pub use login::{Login, PasswordCheck};
pub use password::{Password, Verified};
pub use rbac::{
    RequireStaff, RequireStoreOwner, RequireStoreRole, RequireTenantAdmin, Role, RoleGrant,
    StaffRoles, StoreAccess, StoreViewForTenantAdmin,
};
pub use session::{CookieKind, CookieValue, SessionId, Subject};
pub use throttle::{AccountKey, account_hash};
