//! Timeline da caixa negra na consola do Super-Admin (cartão 02/23):
//! `GET /api/v1/superadmin/audit/events`, dentro do grupo fechado pelo `superadmin_gate`.
//!
//! A leitura global faz-se SÓ por `public.identity_admin_read_events` (porta selada, 0025/0026), que
//! confere `session_user`, o ator `admin` (super_admin com TOTP) e `app.session_id` (sessão de
//! plataforma com 2FA), valida janela/limite/filtros (22023) e grava ela própria
//! `admin.audit_timeline.read` no sucesso, na mesma transação (a app não o duplica). As recusas da BD
//! (42501 → 404 uniforme; 22023 → 400) são gravadas pela app como `denied`, depois de desfazer o
//! SAVEPOINT da leitura (o erro aborta-a).

use axum::{
    Extension, Json,
    extract::{Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    audit::{self, AuditCtx, AuditEvent, Outcome},
    error::{AppError, FieldError},
    identity::{
        http::no_store,
        rbac::{DENIED_SUPERADMIN, RequireSuperAdmin},
    },
    state::AppState,
    tenancy::db::{begin_platform_tx, db_error},
};

/// Ação do evento de leitura (a mesma que a BD grava no sucesso).
pub const READ_ACTION: &str = "admin.audit_timeline.read";
pub const DEFAULT_LIMIT: i32 = 50;
const MAX_TIMESTAMP_CHARS: usize = 35;
const MAX_CURSOR_CHARS: usize = 64;
const MAX_PREFIX_CHARS: usize = 100;
const MAX_OUTCOME_CHARS: usize = 16;

/// Filtros da query (`from`/`to` em RFC 3339 com fuso; `cursor` opaco, devolvido em `next_cursor`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineQuery {
    pub from: String,
    pub to: String,
    pub tenant_id: Option<Uuid>,
    pub store_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub order_id: Option<Uuid>,
    pub action_prefix: Option<String>,
    pub outcome: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i32>,
}

/// Filtros já com a forma verificada; as regras (janela, limite, prefixo, outcome) são da BD.
#[derive(Debug)]
struct Filters {
    q: TimelineQuery,
    cursor: Option<(i64, Uuid)>,
    limit: i32,
}

impl Filters {
    fn parse(q: TimelineQuery) -> Result<Self, Box<(Vec<FieldError>, TimelineQuery)>> {
        let mut errors = Vec::new();
        if !is_rfc3339(&q.from) {
            errors.push(field(
                "from",
                "data RFC 3339 com fuso (ex.: 2026-11-26T10:00:00Z)",
            ));
        }
        if !is_rfc3339(&q.to) {
            errors.push(field(
                "to",
                "data RFC 3339 com fuso (ex.: 2026-11-26T10:00:00Z)",
            ));
        }
        if q.action_prefix
            .as_deref()
            .is_some_and(|p| p.is_empty() || p.chars().count() > MAX_PREFIX_CHARS)
        {
            errors.push(field("action_prefix", "1 a 100 caracteres"));
        }
        if q.outcome
            .as_deref()
            .is_some_and(|o| o.is_empty() || o.len() > MAX_OUTCOME_CHARS)
        {
            errors.push(field("outcome", "success, denied ou error"));
        }
        let cursor = match q.cursor.as_deref() {
            None => None,
            Some(c) => match parse_cursor(c) {
                Some(c) => Some(c),
                None => {
                    errors.push(field("cursor", "cursor inválido"));
                    None
                }
            },
        };
        if !errors.is_empty() {
            return Err(Box::new((errors, q)));
        }
        let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
        Ok(Self { q, cursor, limit })
    }

    /// Filtros usados (ids e datas, sem dados pessoais; o cursor só como booleano), como a BD grava.
    fn changes(&self) -> Value {
        json!({
            "from": self.q.from,
            "to": self.q.to,
            "tenant_id": self.q.tenant_id,
            "store_id": self.q.store_id,
            "actor_id": self.q.actor_id,
            "order_id": self.q.order_id,
            "action_prefix": self.q.action_prefix,
            "outcome": self.q.outcome,
            "cursor": self.cursor.is_some(),
            "limit": self.limit,
        })
    }
}

/// `AAAA-MM-DDTHH:MM:SS[.ffffff](Z|±HH:MM)`: só a forma; o Postgres valida o calendário.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 || b.len() > MAX_TIMESTAMP_CHARS {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let head = digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19);
    if !head {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start || i - start > 6 {
            return false;
        }
    }
    match &b[i..] {
        [b'Z'] => true,
        // Fuso: o Postgres só aceita até ±15:59 (acima: 22009).
        [sign, h1, h2, b':', m1, m2] if *sign == b'+' || *sign == b'-' => {
            [h1, h2, m1, m2].iter().all(|c| c.is_ascii_digit())
                && (h1 - b'0') * 10 + (h2 - b'0') <= 15
                && (m1 - b'0') * 10 + (m2 - b'0') <= 59
        }
        _ => false,
    }
}

/// Cursor opaco: `<created_at em µs desde a época>_<id>` da última linha da página anterior.
fn parse_cursor(c: &str) -> Option<(i64, Uuid)> {
    if c.len() > MAX_CURSOR_CHARS {
        return None;
    }
    let (us, id) = c.split_once('_')?;
    if us.is_empty() || !us.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((us.parse().ok()?, Uuid::try_parse(id).ok()?))
}

fn field(name: &str, message: &str) -> FieldError {
    FieldError {
        field: name.to_owned(),
        message: message.to_owned(),
    }
}

/// 400 com o corpo de validação de sempre (`AppError::Validation` é 422; aqui o contrato é 400).
fn bad_request(errors: Vec<FieldError>) -> Response {
    let mut resp = AppError::Validation(errors).into_response();
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    no_store(resp)
}

/// Evento da caixa negra (`changes` já mascarado na gravação).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimelineEvent {
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// RFC 3339 em UTC com microssegundos.
    pub created_at: String,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub tenant_id: Option<Uuid>,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub store_id: Option<Uuid>,
    pub actor_type: String,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub actor_id: Option<Uuid>,
    pub actor_label: Option<String>,
    #[schema(value_type = Option<String>, format = "uuid")]
    pub impersonator_id: Option<Uuid>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub changes: Option<Value>,
    pub chain_seq: i64,
    /// A verificação da cadeia na vizinhança deste evento não encontrou quebra.
    pub chain_ok: bool,
}

/// Página da timeline (mais recentes primeiro). `next_cursor` = `null` quando não há mais.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimelinePage {
    pub events: Vec<TimelineEvent>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct Row {
    id: Uuid,
    created_at: String,
    created_us: i64,
    tenant_id: Option<Uuid>,
    store_id: Option<Uuid>,
    actor_type: String,
    actor_id: Option<Uuid>,
    actor_label: Option<String>,
    impersonator_id: Option<Uuid>,
    action: String,
    target_type: Option<String>,
    target_id: Option<String>,
    outcome: String,
    reason: Option<String>,
    changes: Option<Value>,
    chain_seq: i64,
    chain_ok: bool,
}

/// Exceção à regra `query!` (`identity_*`, dona `ptmarket_identity`): SQL estático, tudo por
/// parâmetro, cast de tipo exato em cada argumento e coluna. O cursor volta a `timestamptz` em
/// aritmética inteira de µs (sem perda).
const READ_SQL: &str = r#"
SELECT e.id::uuid AS id,
       to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')::text AS created_at,
       (extract(epoch FROM e.created_at) * 1000000)::int8 AS created_us,
       e.tenant_id::uuid AS tenant_id, e.store_id::uuid AS store_id, e.actor_type::text AS actor_type,
       e.actor_id::uuid AS actor_id, e.actor_label::text AS actor_label,
       e.impersonator_id::uuid AS impersonator_id, e.action::text AS action,
       e.target_type::text AS target_type, e.target_id::text AS target_id, e.outcome::text AS outcome,
       e.reason::text AS reason, e.changes::jsonb AS changes, e.chain_seq::int8 AS chain_seq,
       e.chain_ok::bool AS chain_ok
FROM public.identity_admin_read_events(
       $1::text::timestamptz, $2::text::timestamptz, $3::uuid, $4::uuid, $5::uuid, $6::uuid,
       $7::text, $8::text, 'epoch'::timestamptz + $9::int8 * interval '1 microsecond', $10::uuid,
       $11::int4) AS e
"#;

/// Recusa da porta da BD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// 42501: não passou na porta (sessão, papel, TOTP ou ligação) → 404 uniforme.
    Access,
    /// 22023 (e datas que o Postgres não aceita): filtros fora das regras → 400.
    Invalid,
}

impl Refusal {
    fn of(e: &sqlx::Error) -> Option<Self> {
        let code = e.as_database_error()?.code()?;
        match code.as_ref() {
            "42501" => Some(Self::Access),
            "22023" | "22007" | "22008" | "22009" => Some(Self::Invalid),
            _ => None,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Access => "db_access_refused",
            Self::Invalid => "invalid_parameter",
        }
    }

    fn response(self) -> Response {
        match self {
            Self::Access => (Extension(DENIED_SUPERADMIN), AppError::NotFound).into_response(),
            Self::Invalid => bad_request(vec![field(
                "query",
                "janela (from < to; máx. 24 h sem filtro de tenant/loja/ator/encomenda, 31 dias com), \
                 limit 1..100, action_prefix [a-z0-9._] ou outcome inválidos",
            )]),
        }
    }
}

/// Recusa da forma da query (antes da BD): 400 e `denied`/`invalid_parameter` na caixa negra, como
/// as recusas 22023 da BD. Em `changes` só os ids já tipados e os nomes dos campos recusados (nunca
/// o texto cru do pedido).
async fn refuse_invalid(
    st: &AppState,
    ctx: &AuditCtx,
    errors: Vec<FieldError>,
    q: Option<TimelineQuery>,
) -> Result<Response, AppError> {
    let fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
    let changes = match &q {
        Some(q) => json!({
            "tenant_id": q.tenant_id,
            "store_id": q.store_id,
            "actor_id": q.actor_id,
            "order_id": q.order_id,
            "cursor": q.cursor.is_some(),
            "limit": q.limit,
            "invalid_fields": fields,
        }),
        None => json!({ "invalid_fields": fields }),
    };
    let mut tx = begin_platform_tx(&st.db_primary, ctx).await?;
    let ev = AuditEvent {
        action: READ_ACTION,
        target_type: Some("audit_events"),
        target_id: None,
        outcome: Outcome::Denied,
        reason: Some(Refusal::Invalid.reason().to_owned()),
        changes: Some(changes),
        store_id: None,
    };
    audit::record(&mut tx, ev).await.map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(bad_request(errors))
}

/// Falha da gravação síncrona (ou do COMMIT): nenhum dado sai.
fn unavailable(e: AppError) -> AppError {
    tracing::error!(error = ?e, "timeline da auditoria: gravação falhou");
    AppError::ServiceUnavailable
}

/// Timeline global da caixa negra (leitura síncrona; a própria consulta fica na cadeia).
#[utoipa::path(
    get,
    path = "/api/v1/superadmin/audit/events",
    tag = "superadmin",
    params(
        ("from" = String, Query, description = "Início (RFC 3339 com fuso), inclusivo"),
        ("to" = String, Query, description = "Fim (RFC 3339 com fuso), exclusivo. Janela máx. 24 h sem filtro de tenant/loja/ator/encomenda; 31 dias com um deles"),
        ("tenant_id" = Option<String>, Query, format = "uuid", description = "Tenant"),
        ("store_id" = Option<String>, Query, format = "uuid", description = "Loja"),
        ("actor_id" = Option<String>, Query, format = "uuid", description = "Utilizador (ator)"),
        ("order_id" = Option<String>, Query, format = "uuid", description = "Encomenda (alvo `order` ou `changes.order_id`)"),
        ("action_prefix" = Option<String>, Query, description = "Prefixo da ação ([a-z0-9._], até 100)"),
        ("outcome" = Option<String>, Query, description = "success, denied ou error"),
        ("cursor" = Option<String>, Query, description = "`next_cursor` da página anterior"),
        ("limit" = Option<i32>, Query, description = "1..100 (por omissão 50)")
    ),
    responses(
        (status = 200, description = "Eventos, mais recentes primeiro", body = TimelinePage),
        (status = 400, description = "Filtros inválidos (janela, limite, prefixo, outcome, cursor ou datas)"),
        (status = 404, description = "Não encontrado (qualquer falha de acesso à consola)"),
        (status = 503, description = "A gravação da leitura na caixa negra falhou (nenhum dado devolvido)")
    )
)]
pub async fn list_events(
    State(st): State<AppState>,
    Extension(_sa): Extension<RequireSuperAdmin>,
    ctx: AuditCtx,
    query: Result<Query<TimelineQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let Ok(Query(query)) = query else {
        let errors = vec![field("query", "parâmetros inválidos")];
        return refuse_invalid(&st, &ctx, errors, None).await;
    };
    let f = match Filters::parse(query) {
        Ok(f) => f,
        Err(e) => {
            let (errors, q) = *e;
            return refuse_invalid(&st, &ctx, errors, Some(q)).await;
        }
    };
    let mut tx = begin_platform_tx(&st.db_primary, &ctx).await?;
    let read = {
        let mut sp = sqlx::Connection::begin(&mut *tx).await.map_err(db_error)?;
        let r = sqlx::query_as::<_, Row>(READ_SQL)
            .bind(&f.q.from)
            .bind(&f.q.to)
            .bind(f.q.tenant_id)
            .bind(f.q.store_id)
            .bind(f.q.actor_id)
            .bind(f.q.order_id)
            .bind(f.q.action_prefix.as_deref())
            .bind(f.q.outcome.as_deref())
            .bind(f.cursor.map(|c| c.0))
            .bind(f.cursor.map(|c| c.1))
            .bind(f.limit)
            .fetch_all(&mut *sp)
            .await;
        match r {
            Ok(rows) => {
                sp.commit().await.map_err(db_error)?;
                Ok(rows)
            }
            Err(e) => {
                sp.rollback().await.map_err(db_error)?;
                Err(e)
            }
        }
    };
    let rows = match read {
        Ok(rows) => rows,
        Err(e) => {
            let Some(refusal) = Refusal::of(&e) else {
                tracing::error!(error = ?e, "timeline da auditoria: leitura falhou");
                return Err(AppError::ServiceUnavailable);
            };
            if refusal == Refusal::Access {
                tracing::warn!(request_id = %ctx.request_id(), "porta da timeline: 42501");
            }
            let ev = AuditEvent {
                action: READ_ACTION,
                target_type: Some("audit_events"),
                target_id: None,
                outcome: Outcome::Denied,
                reason: Some(refusal.reason().to_owned()),
                changes: Some(f.changes()),
                store_id: None,
            };
            audit::record(&mut tx, ev).await.map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)?;
            return Ok(refusal.response());
        }
    };
    // O evento `admin.audit_timeline.read` foi gravado pela BD nesta transação: sem COMMIT, nada sai.
    tx.commit().await.map_err(unavailable)?;
    let full = usize::try_from(f.limit).is_ok_and(|l| rows.len() == l);
    let next_cursor = rows
        .last()
        .filter(|_| full)
        .map(|r| format!("{}_{}", r.created_us, r.id));
    let events = rows
        .into_iter()
        .map(|r| TimelineEvent {
            id: r.id,
            created_at: r.created_at,
            tenant_id: r.tenant_id,
            store_id: r.store_id,
            actor_type: r.actor_type,
            actor_id: r.actor_id,
            actor_label: r.actor_label,
            impersonator_id: r.impersonator_id,
            action: r.action,
            target_type: r.target_type,
            target_id: r.target_id,
            outcome: r.outcome,
            reason: r.reason,
            changes: r.changes,
            chain_seq: r.chain_seq,
            chain_ok: r.chain_ok,
        })
        .collect();
    Ok(no_store(
        Json(TimelinePage {
            events,
            next_cursor,
        })
        .into_response(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_shape() {
        for ok in [
            "2026-11-26T10:00:00Z",
            "2026-11-26T10:00:00.123456Z",
            "2026-11-26T10:00:00+01:00",
            "2026-11-26T10:00:00.1-03:30",
            "2026-11-26T10:00:00+15:59",
        ] {
            assert!(is_rfc3339(ok), "{ok}");
        }
        for bad in [
            "",
            "2026-11-26",
            "2026-11-26 10:00:00Z",
            "2026-11-26T10:00:00",
            "2026-11-26T10:00:00.Z",
            "2026-11-26T10:00:00.1234567Z",
            "2026-11-26T10:00:00+0100",
            "2026-11-26T10:00:00+16:00",
            "2026-11-26T10:00:00-15:60",
            "now",
            "2026-11-26T10:00:00Z; DROP",
        ] {
            assert!(!is_rfc3339(bad), "{bad}");
        }
    }

    #[test]
    fn cursor_round_trip_and_garbage() {
        let id = Uuid::now_v7();
        let c = format!("{}_{}", 1_764_150_000_123_456_i64, id);
        assert_eq!(parse_cursor(&c), Some((1_764_150_000_123_456, id)));
        for bad in [
            "",
            "_",
            "12_",
            "_x",
            "-1_00000000-0000-0000-0000-000000000000",
            "1_nope",
        ] {
            assert_eq!(parse_cursor(bad), None, "{bad}");
        }
        assert_eq!(parse_cursor(&"9".repeat(100)), None);
    }
}
