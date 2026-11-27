//! Módulo `sponsors`: geografia (DICOFRE) e entidades patrocinadoras elegíveis (cartão 03/17).
//!
//! Dono de `geo_dicofre`, `sponsor_entities`, `sponsor_entity_areas` e `store_sponsorships`:
//! nenhum outro módulo as lê diretamente. A leitura pública não leva dados pessoais.

pub mod eligibility;
pub mod geo;
pub mod http;

/// País das listas públicas neste épico (sem pesquisa por código postal nem Espanha).
pub const PUBLIC_COUNTRY: &str = "PT";
