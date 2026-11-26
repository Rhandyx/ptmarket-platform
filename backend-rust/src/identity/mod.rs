//! Fronteira do módulo `identity`: contas, sessões e RBAC.
//!
//! Nunca lê tabelas de outros módulos; chama as funções públicas deles.

pub mod breach;
pub mod csrf;
pub mod http;
pub mod password;
pub mod session;

pub use breach::{BreachChecker, HibpRange, NullBreachChecker};
pub use http::{RequireCustomer, SessionInfo, Sessions};
pub use password::{Password, Verified};
pub use session::{CookieKind, CookieValue, SessionId, Subject};
