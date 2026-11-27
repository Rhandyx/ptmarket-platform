//! Elegibilidade pela morada física da loja (spec 14 §2): Câmara cobre o concelho, Junta a
//! freguesia, Associação uma lista de áreas.

use serde::Serialize;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{error::AppError, tenancy::db::db_error};

/// Entidade elegível (sem canal nem contactos).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SponsorSummary {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub slug: String,
    pub logo_key: Option<String>,
}

/// Entidades ativas do país que cobrem a freguesia `dicofre`, na ordem fixa dos selos
/// (Câmara, Junta, Associação; depois o nome).
pub async fn eligible_for(
    db: &mut PgConnection,
    dicofre: &str,
    country: &str,
) -> Result<Vec<SponsorSummary>, AppError> {
    sqlx::query_as!(
        SponsorSummary,
        "SELECT e.id, e.kind, e.name, e.slug, e.logo_key FROM sponsor_entities e
         WHERE e.is_active AND e.country_code = $2 AND (
               (e.kind = 'municipality' AND e.area_code = left($1, 4))
            OR (e.kind = 'parish' AND e.area_code = $1)
            OR (e.kind = 'association' AND EXISTS (
                  SELECT 1 FROM sponsor_entity_areas a
                  WHERE a.sponsor_entity_id = e.id AND left($1, length(a.area_code)) = a.area_code)))
         ORDER BY CASE e.kind WHEN 'municipality' THEN 1 WHEN 'parish' THEN 2 ELSE 3 END, e.name",
        dicofre,
        country
    )
    .fetch_all(db)
    .await
    .map_err(db_error)
}

/// A entidade cobre a freguesia `dicofre`? Aceita códigos fora de vigor (patrocínios antigos);
/// não olha a `is_active` nem ao país (quem chama decide).
pub async fn covers(
    db: &mut PgConnection,
    entity_id: Uuid,
    dicofre: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM sponsor_entities e WHERE e.id = $1 AND (
               (e.kind = 'municipality' AND e.area_code = left($2, 4))
            OR (e.kind = 'parish' AND e.area_code = $2)
            OR (e.kind = 'association' AND EXISTS (
                  SELECT 1 FROM sponsor_entity_areas a
                  WHERE a.sponsor_entity_id = e.id AND left($2, length(a.area_code)) = a.area_code)))
        ) AS "covered!""#,
        entity_id,
        dicofre
    )
    .fetch_one(db)
    .await
    .map_err(db_error)
}
