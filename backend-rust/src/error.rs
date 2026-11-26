//! `AppError`: erro único dos handlers, com corpo JSON estável.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Também para recursos de outro tenant (não revela que existem).
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("validation failed")]
    Validation(Vec<FieldError>),
    #[error("conflict")]
    Conflict,
    /// Capacidade esgotada (ex.: fila de hashes de password cheia). 503 + `Retry-After`.
    #[error("busy")]
    Busy,
    /// Demasiados pedidos deste cliente (ex.: hosts desconhecidos a mais no último minuto). 429 +
    /// `Retry-After` (segundos, no mínimo 1).
    #[error("too many requests")]
    TooManyRequests { retry_after_s: u64 },
    /// Dependência obrigatória indisponível (ex.: caixa negra não gravou): falha fechado, 503.
    #[error("service unavailable")]
    ServiceUnavailable,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Busy => StatusCode::SERVICE_UNAVAILABLE,
            Self::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Validation(_) => "validation",
            Self::Conflict => "conflict",
            Self::Busy => "busy",
            Self::TooManyRequests { .. } => "too_many_requests",
            Self::ServiceUnavailable => "service_unavailable",
            Self::Internal(_) => "internal",
        }
    }

    fn message(&self) -> &'static str {
        match self {
            Self::NotFound => "Recurso não encontrado.",
            Self::Unauthorized => "Autenticação necessária.",
            Self::Forbidden => "Sem permissão.",
            Self::Validation(_) => "Dados inválidos.",
            Self::Conflict => "Conflito com o estado atual.",
            Self::Busy => "Serviço ocupado. Tente novamente dentro de instantes.",
            Self::TooManyRequests { .. } => "Demasiados pedidos. Tente novamente mais tarde.",
            Self::ServiceUnavailable => "Serviço temporariamente indisponível.",
            Self::Internal(_) => "Erro interno.",
        }
    }
}

/// Segundos sugeridos em `Retry-After` para `AppError::Busy`.
const RETRY_AFTER_BUSY_SECS: &str = "1";

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let Self::Internal(e) = &self {
            tracing::error!(error = ?e, "erro interno");
        }
        let mut error = serde_json::json!({ "code": self.code(), "message": self.message() });
        if let Self::Validation(fields) = &self {
            error["fields"] = serde_json::json!(fields);
        }
        let mut resp = (self.status(), Json(serde_json::json!({ "error": error }))).into_response();
        let retry_after = match &self {
            Self::Busy => Some(axum::http::HeaderValue::from_static(RETRY_AFTER_BUSY_SECS)),
            Self::TooManyRequests { retry_after_s } => {
                Some(axum::http::HeaderValue::from((*retry_after_s).max(1)))
            }
            _ => None,
        };
        if let Some(v) = retry_after {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn parts(e: AppError) -> (StatusCode, serde_json::Value) {
        let r = e.into_response();
        let status = r.status();
        let bytes = r
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[tokio::test]
    async fn each_variant_maps_status_and_code() {
        let cases = [
            (AppError::NotFound, 404, "not_found"),
            (AppError::Unauthorized, 401, "unauthorized"),
            (AppError::Forbidden, 403, "forbidden"),
            (AppError::Validation(vec![]), 422, "validation"),
            (AppError::Conflict, 409, "conflict"),
            (AppError::Busy, 503, "busy"),
            (
                AppError::TooManyRequests { retry_after_s: 7 },
                429,
                "too_many_requests",
            ),
            (AppError::ServiceUnavailable, 503, "service_unavailable"),
            (AppError::Internal(anyhow::anyhow!("x")), 500, "internal"),
        ];
        for (e, status, code) in cases {
            let (s, body) = parts(e).await;
            assert_eq!(s.as_u16(), status);
            assert_eq!(body["error"]["code"], code);
            assert!(body["error"]["message"].is_string());
        }
    }

    #[test]
    fn busy_sets_retry_after() {
        let r = AppError::Busy.into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            r.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        assert!(
            AppError::NotFound
                .into_response()
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .is_none()
        );
    }

    #[tokio::test]
    async fn too_many_requests_sets_retry_after_and_generic_body() {
        let retry = |e: AppError| {
            e.into_response()
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        assert_eq!(
            retry(AppError::TooManyRequests { retry_after_s: 42 }).as_deref(),
            Some("42")
        );
        // Nunca `Retry-After: 0` (o cliente repetiria de imediato).
        assert_eq!(
            retry(AppError::TooManyRequests { retry_after_s: 0 }).as_deref(),
            Some("1")
        );
        let (s, body) = parts(AppError::TooManyRequests { retry_after_s: 42 }).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        let mut keys: Vec<&str> = body["error"]
            .as_object()
            .map(|o| o.keys().map(String::as_str).collect())
            .unwrap_or_default();
        keys.sort_unstable();
        assert_eq!(keys, ["code", "message"]);
        assert!(!body.to_string().contains("42"));
    }

    #[tokio::test]
    async fn internal_hides_original_message() {
        let (_, body) = parts(AppError::Internal(anyhow::anyhow!("senha=abc host=db"))).await;
        let s = body.to_string();
        assert!(!s.contains("senha") && !s.contains("host=db"));
    }

    #[tokio::test]
    async fn validation_lists_fields() {
        let f = FieldError {
            field: "nif".into(),
            message: "inválido".into(),
        };
        let (_, body) = parts(AppError::Validation(vec![f])).await;
        assert_eq!(body["error"]["fields"][0]["field"], "nif");
    }
}
