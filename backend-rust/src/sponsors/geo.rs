//! Geografia pública: distritos, concelhos e freguesias em vigor (`valid_to IS NULL`).

use serde::Serialize;
use sqlx::PgConnection;
use utoipa::ToSchema;

use crate::{error::AppError, tenancy::db::db_error};

/// Código DICOFRE + nome.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GeoItem {
    pub code: String,
    pub name: String,
}

/// Distrito: 2 algarismos.
pub fn is_district_code(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Concelho: 4 algarismos.
pub fn is_municipality_code(s: &str) -> bool {
    s.len() == 4 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Freguesia: 4 algarismos + 2 de `[0-9A-Z]` (a CAOP 2025 tem códigos como `0302FA`).
pub fn is_parish_code(s: &str) -> bool {
    s.len() == 6
        && is_municipality_code(&s[..4])
        && s.bytes()
            .skip(4)
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

pub async fn districts(db: &mut PgConnection) -> Result<Vec<GeoItem>, AppError> {
    sqlx::query_as!(
        GeoItem,
        "SELECT code, name FROM geo_dicofre
         WHERE level = 'district' AND valid_to IS NULL ORDER BY name, code"
    )
    .fetch_all(db)
    .await
    .map_err(db_error)
}

pub async fn children(db: &mut PgConnection, parent: &str) -> Result<Vec<GeoItem>, AppError> {
    sqlx::query_as!(
        GeoItem,
        "SELECT code, name FROM geo_dicofre
         WHERE parent_code = $1 AND valid_to IS NULL ORDER BY name, code",
        parent
    )
    .fetch_all(db)
    .await
    .map_err(db_error)
}

/// Freguesia existente E em vigor (o que se oferece a quem se regista).
pub async fn parish_in_force(db: &mut PgConnection, code: &str) -> Result<bool, AppError> {
    let row = sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM geo_dicofre
            WHERE code = $1 AND level = 'parish' AND valid_to IS NULL) AS "ok!""#,
        code
    )
    .fetch_one(db)
    .await
    .map_err(db_error)?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_formats() {
        assert!(is_district_code("03"));
        assert!(!is_district_code("3"));
        assert!(is_municipality_code("0302"));
        assert!(!is_municipality_code("03A2"));
        assert!(is_parish_code("030201"));
        assert!(is_parish_code("0302FA"));
        assert!(!is_parish_code("0302fa"));
        assert!(!is_parish_code("1106"));
        assert!(!is_parish_code("03A2FA"));
        assert!(!is_parish_code("0302F"));
        assert!(!is_parish_code("0302É1"));
    }
}
