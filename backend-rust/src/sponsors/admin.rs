//! Patrocínios vistos e decididos pelo `sponsor_admin` de uma entidade (cartão 03/20; spec 14 §2,
//! §3, §7, §9).
//!
//! A transação é SEMPRE `begin_sponsor_tx` com o `SponsorScope` do extractor, no canal nacional do
//! país da entidade (`channel_for_entity`: o tenant vem da entidade, nunca do pedido). Anti-IDOR em
//! duas camadas: cada query leva `AND sponsor_entity_id = $entity` e a RLS (0035) só mostra e deixa
//! alterar os patrocínios da entidade do GUC. Os dados da loja vêm só de
//! `tenancy::portal::stores_by_ids` (canal nacional: lojas ativas; campos públicos): nunca `stores`.
//!
//! Transições (a BD também as impõe, 0031): `pending → active | rejected`; `active → revoked`. Em
//! `revoked` a BD põe `valid_to = agora`. A app nunca escreve `commission_override_bps`.

use serde::Serialize;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    error::AppError,
    sponsors::eligibility,
    tenancy::{
        NationalPortal, PortalReadTx, TenantTx, db::db_error, national_portal_for_country,
        resolver::CountryCode,
    },
};

/// Máximo de linhas por página da lista da entidade.
pub const MAX_LIST_LIMIT: i64 = 100;
/// Linhas por página sem `limit`.
pub const DEFAULT_LIST_LIMIT: i64 = 50;
/// `valid_from` nunca anterior a agora − 1 min (relógio da BD), em µs.
pub const VALID_FROM_TOLERANCE_US: i64 = 60_000_000;
/// `valid_from` nunca posterior a agora + 366 dias (relógio da BD), em µs: uma aprovação não
/// reserva a janela do par (loja, entidade) para um futuro distante.
pub const VALID_FROM_MAX_AHEAD_US: i64 = 366 * 86_400 * 1_000_000;
/// Teto do instante do cursor (9999-12-31T23:59:59.999999Z), em µs: acima disto a BD daria
/// "out of range" (5xx) em vez de 400.
const MAX_CURSOR_US: i64 = 253_402_300_799_999_999;
/// Motivo de rejeição/revogação: 1..=500 caracteres (`decision_reason VARCHAR(500)`).
pub const MAX_REASON_CHARS: usize = 500;
/// Tamanho máximo do cursor opaco (`<µs>_<uuid>`).
const MAX_CURSOR_CHARS: usize = 64;
/// Tamanho máximo de um instante RFC 3339 no corpo.
const MAX_DATETIME_CHARS: usize = 40;

/// Estados de `store_sponsorships.status` (0031).
pub const STATUSES: [&str; 5] = ["pending", "active", "rejected", "expired", "revoked"];

/// Canal nacional do país da entidade `entity_id`. Entidade inexistente ou desativada
/// (`is_active = false`) → `None` (o chamador responde 404 + `idor` antes de qualquer leitura de
/// patrocínios); país sem `national_portal` ativo → erro interno.
pub async fn channel_for_entity(
    conn: &mut PgConnection,
    entity_id: Uuid,
) -> Result<Option<NationalPortal>, AppError> {
    let row = sqlx::query!(
        r#"SELECT country_code::text AS "country_code!", is_active FROM sponsor_entities WHERE id = $1"#,
        entity_id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_error)?;
    let Some(row) = row.filter(|r| r.is_active) else {
        return Ok(None);
    };
    let country = CountryCode::parse(row.country_code.trim())?;
    national_portal_for_country(conn, country)
        .await?
        .map(Some)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("país da entidade sem canal nacional")))
}

// ---------------------------------------------------------------------------------------------
// Lista
// ---------------------------------------------------------------------------------------------

/// Filtro já validado da lista.
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub status: Option<String>,
    /// `(created_at em µs desde a época, id)` da última linha da página anterior.
    pub cursor: Option<(i64, Uuid)>,
    pub limit: i64,
}

/// Cursor opaco: `<created_at em µs desde a época>_<id>`.
pub fn parse_cursor(c: &str) -> Option<(i64, Uuid)> {
    if c.len() > MAX_CURSOR_CHARS {
        return None;
    }
    let (us, id) = c.split_once('_')?;
    if us.is_empty() || !us.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let us: i64 = us.parse().ok()?;
    if us > MAX_CURSOR_US {
        return None;
    }
    Some((us, Uuid::try_parse(id).ok()?))
}

/// Loja patrocinada (ou que pede): só os campos públicos do portal (DSA). Nunca IBAN, chaves,
/// comissões, contactos nem dados de compradores (spec 14 §7).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SponsoredStore {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub legal_name: String,
    pub nif: String,
    pub storefront_dicofre: Option<String>,
}

/// Pedido/patrocínio visto pela entidade. Datas em RFC 3339 UTC.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntitySponsorshipItem {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// `pending`, `active`, `rejected`, `expired` ou `revoked`.
    pub status: String,
    pub valid_from: Option<String>,
    /// `null` = sem fim.
    pub valid_to: Option<String>,
    pub store: SponsoredStore,
    pub requested_at: String,
    pub decided_at: Option<String>,
}

/// Página da lista (mais recentes primeiro). `next_cursor` = `null` quando não há mais.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntitySponsorshipPage {
    pub items: Vec<EntitySponsorshipItem>,
    pub next_cursor: Option<String>,
}

/// Lotes lidos no máximo por página (lojas inativas saltadas): passado isto, a página sai mais curta
/// e o `next_cursor` continua a partir da última linha lida.
const MAX_LIST_BATCHES: usize = 5;

/// Linha de `store_sponsorships` para a lista.
struct ListRow {
    id: Uuid,
    store_id: Uuid,
    status: String,
    valid_from: Option<String>,
    valid_to: Option<String>,
    requested_at: String,
    decided_at: Option<String>,
    created_us: i64,
}

async fn list_batch(
    tx: &mut TenantTx,
    entity_id: Uuid,
    status: Option<&str>,
    cursor: Option<(i64, Uuid)>,
    limit: i64,
) -> Result<Vec<ListRow>, AppError> {
    let tenant = tx.tenant().as_uuid();
    let rows = sqlx::query!(
        r#"SELECT s.id, s.store_id, s.status,
                  to_char(s.valid_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_from?",
                  to_char(s.valid_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_to?",
                  to_char(s.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "requested_at!",
                  to_char(s.decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "decided_at?",
                  (extract(epoch FROM s.created_at) * 1000000)::int8 AS "created_us!"
           FROM store_sponsorships s
           WHERE s.tenant_id = $1 AND s.sponsor_entity_id = $2
             AND ($3::text IS NULL OR s.status = $3)
             AND ($4::int8 IS NULL
                  OR (s.created_at, s.id)
                     < ('epoch'::timestamptz + $4 * interval '1 microsecond', $5::uuid))
           ORDER BY s.created_at DESC, s.id DESC
           LIMIT $6"#,
        tenant,
        entity_id,
        status,
        cursor.map(|c| c.0),
        cursor.map(|c| c.1),
        limit
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(rows
        .into_iter()
        .map(|r| ListRow {
            id: r.id,
            store_id: r.store_id,
            status: r.status,
            valid_from: r.valid_from,
            valid_to: r.valid_to,
            requested_at: r.requested_at,
            decided_at: r.decided_at,
            created_us: r.created_us,
        })
        .collect())
}

/// Página dos patrocínios da entidade por `(created_at, id)` DESC, até `limit` itens. As linhas de
/// lojas que o canal nacional não mostra (loja inativa) ficam de fora e lê-se o lote seguinte (no
/// máximo `MAX_LIST_BATCHES`). `next_cursor` = a última linha consumida; `null` sem mais linhas.
pub async fn list_for_entity(
    tx: &mut TenantTx,
    portal: &mut PortalReadTx,
    entity_id: Uuid,
    f: &ListFilter,
) -> Result<EntitySponsorshipPage, AppError> {
    let limit = f.limit.clamp(1, MAX_LIST_LIMIT);
    let want = usize::try_from(limit).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    let mut items = Vec::new();
    let mut cursor = f.cursor;
    for _ in 0..MAX_LIST_BATCHES {
        let rows = list_batch(tx, entity_id, f.status.as_deref(), cursor, limit).await?;
        let full = rows.len() == want;
        let mut ids: Vec<Uuid> = rows.iter().map(|r| r.store_id).collect();
        ids.sort_unstable();
        ids.dedup();
        let stores = portal.stores_by_ids(&ids).await?;
        for r in rows {
            cursor = Some((r.created_us, r.id));
            if let Some(s) = stores.iter().find(|s| s.id == r.store_id) {
                items.push(EntitySponsorshipItem {
                    id: r.id,
                    status: r.status,
                    valid_from: r.valid_from,
                    valid_to: r.valid_to,
                    store: SponsoredStore {
                        id: s.id,
                        name: s.name.clone(),
                        slug: s.slug.clone(),
                        legal_name: s.legal_name.clone(),
                        nif: s.nif.clone(),
                        storefront_dicofre: s.storefront_dicofre.clone(),
                    },
                    requested_at: r.requested_at,
                    decided_at: r.decided_at,
                });
                if items.len() == want {
                    return Ok(page(items, cursor));
                }
            }
        }
        if !full {
            return Ok(page(items, None));
        }
    }
    Ok(page(items, cursor))
}

fn page(items: Vec<EntitySponsorshipItem>, cursor: Option<(i64, Uuid)>) -> EntitySponsorshipPage {
    EntitySponsorshipPage {
        items,
        next_cursor: cursor.map(|(us, id)| format!("{us}_{id}")),
    }
}

// ---------------------------------------------------------------------------------------------
// Decisões
// ---------------------------------------------------------------------------------------------

/// Patrocínio depois da decisão.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    pub id: Uuid,
    pub store_id: Uuid,
    pub status: &'static str,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
}

/// Resultado de uma decisão.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Done(Decided),
    /// Patrocínio de outra entidade ou inexistente (404 + `idor`).
    NotFound,
    /// Estado atual não admite a transição (409); leva a loja para a caixa negra.
    InvalidTransition {
        store_id: Uuid,
    },
    /// A entidade já não cobre a freguesia da loja, ou a loja não está ativa (422).
    NotEligible {
        store_id: Uuid,
    },
    /// Período `active` sobreposto para o mesmo par (EXCLUDE 23P01 → 409).
    Overlap {
        store_id: Uuid,
    },
}

/// Instante "agora" da transação (relógio da BD), em µs desde a época.
pub async fn db_now_us(tx: &mut TenantTx) -> Result<i64, AppError> {
    sqlx::query_scalar!(r#"SELECT (extract(epoch FROM now()) * 1000000)::int8 AS "now!""#)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)
}

/// Bloqueia a linha `id` da entidade (`FOR UPDATE`): `(store_id, status)`.
async fn lock(
    tx: &mut TenantTx,
    entity_id: Uuid,
    id: Uuid,
) -> Result<Option<(Uuid, String)>, AppError> {
    let tenant = tx.tenant().as_uuid();
    let row = sqlx::query!(
        "SELECT store_id, status FROM store_sponsorships
         WHERE id = $1 AND tenant_id = $2 AND sponsor_entity_id = $3
         FOR UPDATE",
        id,
        tenant,
        entity_id
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(row.map(|r| (r.store_id, r.status)))
}

/// EXCLUDE de dois `active` sobrepostos do mesmo par (0031).
const NO_OVERLAP_CONSTRAINT: &str = "store_sponsorships_no_active_overlap";

/// Aprova o pedido `pending` `id` com a vigência `[valid_from_us, valid_to_us)` (µs; já validada
/// pelo chamador: `valid_to_us > valid_from_us`). Volta a verificar a elegibilidade pela morada da
/// loja no canal nacional (`portal`). `decided_by` = `user_id`.
pub async fn approve(
    tx: &mut TenantTx,
    portal: &mut PortalReadTx,
    entity_id: Uuid,
    id: Uuid,
    user_id: Uuid,
    valid_from_us: i64,
    valid_to_us: Option<i64>,
) -> Result<Decision, AppError> {
    let Some((store_id, status)) = lock(tx, entity_id, id).await? else {
        return Ok(Decision::NotFound);
    };
    if status != "pending" {
        return Ok(Decision::InvalidTransition { store_id });
    }
    let store = portal.stores_by_ids(&[store_id]).await?;
    let dicofre = store
        .into_iter()
        .find(|s| s.id == store_id)
        .and_then(|s| s.storefront_dicofre);
    let eligible = match dicofre {
        Some(d) => eligibility::covers(tx, entity_id, &d).await?,
        None => false,
    };
    if !eligible {
        return Ok(Decision::NotEligible { store_id });
    }
    let tenant = tx.tenant().as_uuid();
    let mut sp = sqlx::Connection::begin(&mut **tx).await.map_err(db_error)?;
    let updated = sqlx::query!(
        r#"UPDATE store_sponsorships
           SET status = 'active',
               valid_from = 'epoch'::timestamptz + $4::int8 * interval '1 microsecond',
               valid_to = 'epoch'::timestamptz + $5::int8 * interval '1 microsecond',
               decided_by = $6, decided_at = now(), decision_reason = NULL, updated_at = now()
           WHERE id = $1 AND tenant_id = $2 AND sponsor_entity_id = $3 AND status = 'pending'
           RETURNING
               to_char(valid_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_from?",
               to_char(valid_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_to?""#,
        id,
        tenant,
        entity_id,
        valid_from_us,
        valid_to_us,
        user_id
    )
    .fetch_optional(&mut *sp)
    .await;
    match updated {
        Ok(Some(r)) => {
            sp.commit().await.map_err(db_error)?;
            Ok(Decision::Done(Decided {
                id,
                store_id,
                status: "active",
                valid_from: r.valid_from,
                valid_to: r.valid_to,
            }))
        }
        Ok(None) => {
            sp.rollback().await.map_err(db_error)?;
            Ok(Decision::InvalidTransition { store_id })
        }
        Err(sqlx::Error::Database(db))
            if db.code().as_deref() == Some("23P01")
                && db.constraint() == Some(NO_OVERLAP_CONSTRAINT) =>
        {
            sp.rollback().await.map_err(db_error)?;
            Ok(Decision::Overlap { store_id })
        }
        Err(e) => Err(db_error(e)),
    }
}

/// Rejeita o pedido `pending` `id` com o motivo `reason` (já validado).
pub async fn reject(
    tx: &mut TenantTx,
    entity_id: Uuid,
    id: Uuid,
    user_id: Uuid,
    reason: &str,
) -> Result<Decision, AppError> {
    let Some((store_id, status)) = lock(tx, entity_id, id).await? else {
        return Ok(Decision::NotFound);
    };
    if status != "pending" {
        return Ok(Decision::InvalidTransition { store_id });
    }
    let tenant = tx.tenant().as_uuid();
    let r = sqlx::query!(
        r#"UPDATE store_sponsorships
           SET status = 'rejected', decided_by = $4, decided_at = now(), decision_reason = $5,
               updated_at = now()
           WHERE id = $1 AND tenant_id = $2 AND sponsor_entity_id = $3 AND status = 'pending'
           RETURNING
               to_char(valid_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_from?",
               to_char(valid_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_to?""#,
        id,
        tenant,
        entity_id,
        user_id,
        reason
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(match r {
        Some(r) => Decision::Done(Decided {
            id,
            store_id,
            status: "rejected",
            valid_from: r.valid_from,
            valid_to: r.valid_to,
        }),
        None => Decision::InvalidTransition { store_id },
    })
}

/// Revoga o patrocínio `active` `id` com o motivo `reason` (já validado). A BD fecha a vigência
/// (`valid_to = agora`): a loja deixa de contar como patrocinada por esta entidade de imediato.
pub async fn revoke(
    tx: &mut TenantTx,
    entity_id: Uuid,
    id: Uuid,
    user_id: Uuid,
    reason: &str,
) -> Result<Decision, AppError> {
    let Some((store_id, status)) = lock(tx, entity_id, id).await? else {
        return Ok(Decision::NotFound);
    };
    if status != "active" {
        return Ok(Decision::InvalidTransition { store_id });
    }
    let tenant = tx.tenant().as_uuid();
    let r = sqlx::query!(
        r#"UPDATE store_sponsorships
           SET status = 'revoked', decided_by = $4, decided_at = now(), decision_reason = $5,
               updated_at = now()
           WHERE id = $1 AND tenant_id = $2 AND sponsor_entity_id = $3 AND status = 'active'
           RETURNING
               to_char(valid_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_from?",
               to_char(valid_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "valid_to?""#,
        id,
        tenant,
        entity_id,
        user_id,
        reason
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(match r {
        Some(r) => Decision::Done(Decided {
            id,
            store_id,
            status: "revoked",
            valid_from: r.valid_from,
            valid_to: r.valid_to,
        }),
        None => Decision::InvalidTransition { store_id },
    })
}

// ---------------------------------------------------------------------------------------------
// Validação
// ---------------------------------------------------------------------------------------------

/// Motivo válido: 1..=500 caracteres, não só espaços, sem caracteres de controlo. Devolve-o sem
/// espaços nas pontas.
pub fn valid_reason(raw: &str) -> Option<&str> {
    let r = raw.trim();
    let n = r.chars().count();
    ((1..=MAX_REASON_CHARS).contains(&n) && !r.chars().any(char::is_control)).then_some(r)
}

/// `AAAA-MM-DDTHH:MM:SS[.f{1,9}](Z|±HH:MM)` → µs desde a época (frações abaixo do µs
/// truncadas). Calendário validado (anos 1..=9999, meses, dias e bissextos); `None` se inválido.
pub fn parse_rfc3339_us(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b.len() > MAX_DATETIME_CHARS {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(
            part.iter()
                .fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0')),
        )
    };
    let sep = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(sep(4, b'-') && sep(7, b'-') && (sep(10, b'T') || sep(10, b't')) && sep(13, b':'))
        || !sep(16, b':')
    {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if year < 1 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > days_in_month {
        return None;
    }
    let mut i = 19;
    let mut micros = 0i64;
    if sep(i, b'.') {
        let start = i + 1;
        i = start;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let digits = i - start;
        if digits == 0 || digits > 9 {
            return None;
        }
        let frac = num(start..i)?;
        micros = if digits <= 6 {
            frac * 10i64.pow(u32::try_from(6 - digits).ok()?)
        } else {
            frac / 10i64.pow(u32::try_from(digits - 6).ok()?)
        };
    }
    let offset_s = match b.get(i..)? {
        [b'Z'] | [b'z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if *sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    // Dias desde 1970-01-01 (algoritmo "days from civil", calendário gregoriano proléptico).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_s;
    secs.checked_mul(1_000_000)?.checked_add(micros)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(parse_rfc3339_us("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_us("2026-11-27T10:00:00.5Z"),
            Some(1_795_773_600_500_000)
        );
        assert_eq!(
            parse_rfc3339_us("2026-11-27T11:00:00+01:00"),
            parse_rfc3339_us("2026-11-27T10:00:00Z")
        );
        assert_eq!(
            parse_rfc3339_us("2024-02-29T00:00:00.123456789Z"),
            Some(1_709_164_800_123_456)
        );
        assert_eq!(parse_rfc3339_us("1969-12-31T23:59:59Z"), Some(-1_000_000));
    }

    #[test]
    fn rfc3339_garbage() {
        for bad in [
            "",
            "2026-11-27",
            "2026-11-27T10:00:00",
            "2026-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-11-31T00:00:00Z",
            "2026-11-27T24:00:00Z",
            "2026-11-27T10:00:00.Z",
            "2026-11-27T10:00:00.1234567890Z",
            "2026-11-27T10:00:00+25:00",
            "2026-11-27T10:00:00+0100",
            "0000-01-01T00:00:00Z",
            "2026-11-27 10:00:00Z",
            "+026-11-27T10:00:00Z",
            "2026-11-27T10:00:00ZZ",
        ] {
            assert_eq!(parse_rfc3339_us(bad), None, "{bad}");
        }
    }

    #[test]
    fn reasons() {
        assert_eq!(valid_reason("  motivo  "), Some("motivo"));
        assert_eq!(valid_reason("   "), None);
        assert_eq!(valid_reason(""), None);
        assert_eq!(valid_reason("a\u{0}b"), None);
        assert!(valid_reason(&"é".repeat(500)).is_some());
        assert!(valid_reason(&"é".repeat(501)).is_none());
    }

    #[test]
    fn cursor_round_trip_and_garbage() {
        let id = Uuid::now_v7();
        assert_eq!(
            parse_cursor(&format!("1764150000123456_{id}")),
            Some((1_764_150_000_123_456, id))
        );
        for bad in ["", "_", "abc_def", "-1_x", "12", &"9".repeat(100)] {
            assert_eq!(parse_cursor(bad), None, "{bad}");
        }
        // Acima do ano 9999 → None (400), nunca "out of range" na BD (5xx).
        assert_eq!(parse_cursor(&format!("{}_{id}", i64::MAX)), None);
        assert!(parse_cursor(&format!("{MAX_CURSOR_US}_{id}")).is_some());
    }
}
