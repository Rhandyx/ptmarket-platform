//! `audit::record`: a única porta para eventos semânticos da caixa negra (spec 13 §3.2).
//!
//! Grava na MESMA transação que a alteração (rollback = sem evento). O ator nunca vem daqui:
//! `audit.audit_append` lê-o do contexto fixado por `begin_tenant_tx`/`begin_platform_tx`.

use serde_json::Value;
use uuid::Uuid;

use crate::{
    error::{AppError, FieldError},
    http::telemetry::redact,
    tenancy::db::{AuditedTx, db_error},
};

/// Resultado da ação auditada (CHECK de `audit.audit_events.outcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Denied,
    Error,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

/// Evento semântico. `action` e `target_type` são constantes do código (nunca dados do pedido).
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub action: &'static str,
    pub target_type: Option<&'static str>,
    pub target_id: Option<String>,
    pub outcome: Outcome,
    pub reason: Option<String>,
    /// Passa por `http::telemetry::redact` antes de gravar.
    pub changes: Option<serde_json::Value>,
    pub store_id: Option<Uuid>,
}

/// Limites do evento (acima disto: `AppError::Validation`; nunca se trunca em silêncio).
pub const MAX_CHANGES_BYTES: usize = 64 * 1024;
pub const MAX_REASON_BYTES: usize = 1024;
pub const MAX_TARGET_ID_CHARS: usize = 256;

/// Grava o evento na transação `tx`. A marca `recorded` do `AuditCtx` fica pendente na transação
/// e só passa a valer no `commit` (rollback ou drop sem commit = não registado). Devolve o id.
/// Chamar no fim da transação: o bloqueio da cabeça da cadeia fica até ao COMMIT.
pub async fn record<T: AuditedTx>(tx: &mut T, ev: AuditEvent) -> Result<Uuid, AppError> {
    let ev = prepare(ev)?;
    let changes = ev.changes;
    let (conn, _) = tx.parts();
    let outcome = ev.outcome.as_str();
    // Os 8 argumentos com o tipo exato da assinatura (nunca resolve para uma sobrecarga plantada);
    // p_tenant_id = NULL: o tenant vem sempre do contexto da transação.
    //
    // Exceção à regra `query!`: a verificação em tempo de compilação faz EXPLAIN, que exige EXECUTE
    // em `audit.audit_append`; o migrator (DATABASE_URL de dev/CI) não o tem por desenho (selagem da
    // caixa negra). SQL estático, tudo por parâmetro; o tipo é verificado no teste `audit_ctx`.
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT audit.audit_append($1::text, $2::text, $3::text, $4::text, $5::text,
                                   $6::jsonb, $7::uuid, NULL::uuid)",
    )
    .bind(ev.action)
    .bind(ev.target_type)
    .bind(ev.target_id)
    .bind(outcome)
    .bind(ev.reason)
    .bind(changes)
    .bind(ev.store_id)
    .fetch_one(conn)
    .await
    .map_err(db_error)?;
    let id = id.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "audit_append devolveu NULL (evento não gravado)"
        ))
    })?;
    tx.mark_recorded_on_commit();
    Ok(id)
}

/// NUL → U+FFFD em todo o texto (o `text` e o jsonb recusam-no), máscara em `changes` e limites de
/// tamanho (medidos depois da máscara, sobre o que vai ser gravado).
fn prepare(mut ev: AuditEvent) -> Result<AuditEvent, AppError> {
    ev.target_id = ev.target_id.map(|s| scrub_nul(&s));
    ev.reason = ev.reason.map(|s| scrub_nul(&s));
    if let Some(c) = ev.changes.as_mut() {
        scrub_value(c);
        redact(c);
    }
    let mut errors = Vec::new();
    if ev
        .target_id
        .as_deref()
        .is_some_and(|s| s.chars().count() > MAX_TARGET_ID_CHARS)
    {
        errors.push(field("audit.target_id", "máximo de 256 caracteres"));
    }
    if ev
        .reason
        .as_deref()
        .is_some_and(|s| s.len() > MAX_REASON_BYTES)
    {
        errors.push(field("audit.reason", "máximo de 1 KiB"));
    }
    if let Some(c) = &ev.changes {
        let bytes = serde_json::to_vec(c)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("changes não serializa: {e}")))?;
        if bytes.len() > MAX_CHANGES_BYTES {
            errors.push(field("audit.changes", "máximo de 64 KiB"));
        }
    }
    if errors.is_empty() {
        Ok(ev)
    } else {
        Err(AppError::Validation(errors))
    }
}

fn field(name: &str, message: &str) -> FieldError {
    FieldError {
        field: name.to_owned(),
        message: message.to_owned(),
    }
}

fn scrub_nul(s: &str) -> String {
    s.replace('\0', "\u{FFFD}")
}

/// NUL → U+FFFD em todas as strings e chaves de um JSON.
fn scrub_value(v: &mut Value) {
    match v {
        Value::String(s) if s.contains('\0') => *s = scrub_nul(s),
        Value::Array(a) => a.iter_mut().for_each(scrub_value),
        Value::Object(m) => {
            if m.keys().any(|k| k.contains('\0')) {
                let old = std::mem::take(m);
                for (k, mut val) in old {
                    scrub_value(&mut val);
                    m.insert(scrub_nul(&k), val);
                }
            } else {
                m.values_mut().for_each(scrub_value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(changes: Option<Value>) -> AuditEvent {
        AuditEvent {
            action: "t.x",
            target_type: None,
            target_id: None,
            outcome: Outcome::Success,
            reason: None,
            changes,
            store_id: None,
        }
    }

    #[test]
    fn nul_becomes_replacement_everywhere() {
        let mut e = ev(Some(json!({"a\u{0}": ["x\u{0}y", {"k": "\u{0}"}]})));
        e.reason = Some("r\0".to_owned());
        e.target_id = Some("\0id".to_owned());
        let p = prepare(e);
        assert!(p.is_ok());
        if let Ok(p) = p {
            let text = serde_json::to_string(&p.changes).unwrap_or_default();
            assert!(!text.contains("\\u0000"), "{text}");
            assert_eq!(p.changes.unwrap_or_default()["a\u{FFFD}"][0], "x\u{FFFD}y");
            assert_eq!(p.reason.as_deref(), Some("r\u{FFFD}"));
            assert_eq!(p.target_id.as_deref(), Some("\u{FFFD}id"));
        }
    }

    #[test]
    fn limits_are_validation_never_truncation() {
        let big = json!({"blob": "x".repeat(MAX_CHANGES_BYTES)});
        assert!(matches!(
            prepare(ev(Some(big))),
            Err(AppError::Validation(_))
        ));
        let ok = json!({"blob": "x".repeat(MAX_CHANGES_BYTES - 64)});
        assert!(prepare(ev(Some(ok))).is_ok());

        let mut e = ev(None);
        e.reason = Some("r".repeat(MAX_REASON_BYTES + 1));
        assert!(matches!(prepare(e), Err(AppError::Validation(_))));
        let mut e = ev(None);
        e.reason = Some("r".repeat(MAX_REASON_BYTES));
        assert!(prepare(e).is_ok());

        let mut e = ev(None);
        e.target_id = Some("é".repeat(MAX_TARGET_ID_CHARS + 1));
        assert!(matches!(prepare(e), Err(AppError::Validation(_))));
        let mut e = ev(None);
        e.target_id = Some("é".repeat(MAX_TARGET_ID_CHARS));
        assert!(prepare(e).is_ok());
    }
}
