//! Fronteira do módulo `tenancy`: Câmaras, lojas e domínios.
//!
//! Nunca lê tabelas de outros módulos; chama as funções públicas deles.
//! O tenant de um pedido vem SÓ do `Host` (`resolver`, único sítio que cria `TenantId`).

pub mod db;
pub mod host;
pub mod http;
pub mod portal;
pub mod resolver;
pub mod store_terms;

pub use db::{TenantId, TenantTx, begin_tenant_tx};
pub use http::PlatformHost;
pub use portal::{
    NationalPortal, PortalCategory, PortalProduct, PortalProductCard, PortalReadTx, PortalStore,
    PortalVariant, ProductFilter, ProductPage, ShippingScope, SponsorKind, StoreBadge,
    begin_national_read_tx, begin_portal_read_tx, national_portal_for_country,
};
pub use resolver::{CountryCode, HostResolver, ResolvedHost, ResolvedTenant, TenantType};
