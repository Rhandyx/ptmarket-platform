//! Fronteira do módulo `identity`: contas, sessões e RBAC.
//!
//! Nunca lê tabelas de outros módulos; chama as funções públicas deles.

pub mod breach;
pub mod password;

pub use breach::{BreachChecker, HibpRange, NullBreachChecker};
pub use password::{Password, Verified};
