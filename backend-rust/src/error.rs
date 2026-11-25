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
            Self::Internal(_) => "Erro interno.",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let Self::Internal(e) = &self {
            tracing::error!(error = ?e, "erro interno");
        }
        let mut error = serde_json::json!({ "code": self.code(), "message": self.message() });
        if let Self::Validation(fields) = &self {
            error["fields"] = serde_json::json!(fields);
        }
        (self.status(), Json(serde_json::json!({ "error": error }))).into_response()
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
            (AppError::Internal(anyhow::anyhow!("x")), 500, "internal"),
        ];
        for (e, status, code) in cases {
            let (s, body) = parts(e).await;
            assert_eq!(s.as_u16(), status);
            assert_eq!(body["error"]["code"], code);
            assert!(body["error"]["message"].is_string());
        }
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
