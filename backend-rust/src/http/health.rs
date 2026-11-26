//! `/healthz` (liveness, sem BD) e `/readyz` (readiness, primary + replica).

use std::time::Duration;

use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;

use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct Status {
    pub status: &'static str,
}

#[utoipa::path(get, path = "/healthz", responses((status = 200, body = Status)))]
pub async fn healthz() -> Json<Status> {
    Json(Status { status: "ok" })
}

async fn can_acquire(pool: &sqlx::PgPool) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(1), pool.acquire()).await,
        Ok(Ok(_))
    )
}

#[utoipa::path(
    get,
    path = "/readyz",
    responses((status = 200, body = Status), (status = 503, body = Status))
)]
pub async fn readyz(State(s): State<AppState>) -> (StatusCode, Json<Status>) {
    let (p, r) = tokio::join!(can_acquire(&s.db_primary), can_acquire(&s.db_replica));
    if p && r {
        (StatusCode::OK, Json(Status { status: "ready" }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Status {
                status: "unavailable",
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, http::router};
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Option<axum::Router> {
        let cfg = Config::from_lookup(|k| match k {
            "DATABASE_PRIMARY_URL" | "DATABASE_REPLICA_URL" => {
                Some("postgres://u:segredo1@127.0.0.1:1/db".into())
            }
            "REDIS_URL" => Some("redis://127.0.0.1:1".into()),
            _ => None,
        })
        .ok()?;
        Some(router(AppState::from_config(&cfg).ok()?))
    }

    async fn get(path: &str) -> (u16, String) {
        let Some(app) = app() else {
            return (0, String::new());
        };
        let Ok(req) = Request::get(path).body(Body::empty()) else {
            return (0, String::new());
        };
        let Ok(res) = app.oneshot(req).await;
        let status = res.status().as_u16();
        let bytes = res.into_body().collect().await.map(|b| b.to_bytes());
        (
            status,
            String::from_utf8_lossy(&bytes.unwrap_or_default()).into_owned(),
        )
    }

    #[tokio::test]
    async fn healthz_ok_without_db() {
        let (s, b) = get("/healthz").await;
        assert_eq!((s, b.as_str()), (200, r#"{"status":"ok"}"#));
    }

    #[tokio::test]
    async fn readyz_503_when_db_down_and_no_leak() {
        let (s, b) = get("/readyz").await;
        assert_eq!((s, b.as_str()), (503, r#"{"status":"unavailable"}"#));
        assert!(!b.contains("segredo1") && !b.contains("127.0.0.1"));
    }
}
