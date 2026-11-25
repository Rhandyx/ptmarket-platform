//! Fronteira do módulo `tenancy`: Câmaras, lojas e domínios.
//!
//! Nunca lê tabelas de outros módulos; chama as funções públicas deles.

pub mod db;

pub use db::{TenantId, begin_tenant_tx};
