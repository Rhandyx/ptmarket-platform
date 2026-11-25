//! `audit::record`: a única porta para eventos semânticos da caixa negra (spec 13 §3.2).
//!
//! Grava na MESMA transação que a alteração (rollback = sem evento). O ator nunca vem daqui:
//! `audit.audit_append` lê-o do contexto fixado por `begin_tenant_tx`/`begin_platform_tx`.

use uuid::Uuid;

use crate::{
    error::AppError,
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

/// Grava o evento na transação `tx` e marca o `AuditCtx` como registado. Devolve o id do evento.
/// Chamar no fim da transação: o bloqueio da cabeça da cadeia fica até ao COMMIT.
pub async fn record<T: AuditedTx>(tx: &mut T, ev: AuditEvent) -> Result<Uuid, AppError> {
    let mut changes = ev.changes;
    if let Some(c) = changes.as_mut() {
        redact(c);
    }
    let (conn, ctx) = tx.parts();
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
    ctx.mark_recorded();
    Ok(id)
}
