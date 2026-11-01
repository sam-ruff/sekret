//! Project logos: small images stored beside the project and served to the UI.

use std::sync::{Arc, LazyLock};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sekret_api::Project;
use sekret_core::permissions::{Action, Subject};
use sekret_store::ProjectLogo;
use serde_json::json;
use tokio::sync::Semaphore;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::{AuditTarget, api_project, audit, load_project};
use crate::auth::{ClientIp, Principal};
use crate::authz::require_any;
use crate::error::{ApiError, ApiResult};
use crate::images::normalise_logo;
use crate::state::AppState;

pub const MAX_LOGO_BYTES: usize = 512 * 1024;

/// The raw image file, sent as the request body.
pub struct LogoFile;

impl utoipa::PartialSchema for LogoFile {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, SchemaFormat, Type};
        ObjectBuilder::new()
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Binary)))
            .into()
    }
}

impl utoipa::ToSchema for LogoFile {}

/// Uploaded SVGs are served as documents nobody can script, even when opened directly.
const LOGO_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

pub fn router() -> OpenApiRouter<AppState> {
    // Applied innermost, so it replaces the global body limit for uploads here.
    OpenApiRouter::new()
        .routes(routes!(get_logo, put_logo, delete_logo))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_LOGO_BYTES))
}

#[utoipa::path(get, path = "/api/v1/projects/{project}/logo", tag = "projects", params(("project" = String, Path)),
    responses((status = 200, description = "The logo image"), (status = 404)), security(("bearer" = [])))]
async fn get_logo(
    State(state): State<AppState>,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Response> {
    let (project, _) = load_project(&state, &principal, &project).await?;
    let logo = state
        .store
        .get_project_logo(&project.id)
        .await?
        .ok_or_else(|| ApiError::not_found("logo"))?;
    let mut response = logo.data.into_response();
    let headers = response.headers_mut();
    let content_type =
        HeaderValue::from_str(&logo.content_type).map_err(|e| ApiError::internal("logo content type", e))?;
    headers.insert(header::CONTENT_TYPE, content_type);
    // The URL carries a version, so a changed logo is a new URL.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=3600"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(LOGO_CSP));
    Ok(response)
}

#[utoipa::path(put, path = "/api/v1/projects/{project}/logo", tag = "projects", params(("project" = String, Path)),
    request_body(content = LogoFile, content_type = "application/octet-stream",
        description = "PNG, JPEG, GIF, WebP or SVG, at most 512 KiB"),
    responses((status = 200, body = Project), (status = 400, body = sekret_api::ErrorBody),
        (status = 413, body = sekret_api::ErrorBody)), security(("bearer" = [])))]
async fn put_logo(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(project): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Project>> {
    let (mut project, rules) = load_project(&state, &principal, &project).await?;
    require_any(&rules, Subject::Settings, Action::Edit)?;
    if !state
        .logo_limiter
        .allow(&format!("{}:{}", principal.kind.as_str(), principal.id))
    {
        return Err(ApiError::too_many_requests());
    }
    if body.len() > MAX_LOGO_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "logos can be at most 512 KiB",
        ));
    }
    let png = decode_off_runtime(body.clone()).await?;
    let content_type = "image/png";
    let now = state.clock.now();
    state
        .store
        .set_project_logo(
            &project.id,
            Some(ProjectLogo {
                content_type: content_type.into(),
                data: png,
            }),
            now,
        )
        .await?;
    project.logo_updated_at = Some(now);
    audit(
        &state,
        &principal,
        ip,
        "project.logo-set",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({"content_type": content_type, "bytes": body.len()}),
    )
    .await;
    Ok(Json(api_project(&project)))
}

/// Logos decoded at once; image work stays off the async workers and cannot occupy every thread.
const LOGO_DECODES: usize = 2;
static DECODE_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(LOGO_DECODES)));
/// Uploads per caller per minute, refused ones included.
pub const LOGO_UPLOADS_PER_MINUTE: u32 = 10;

async fn decode_off_runtime(body: Bytes) -> ApiResult<Vec<u8>> {
    decode_with_slots(&DECODE_SLOTS, body, |data| {
        normalise_logo(data).map_err(|e| e.to_string())
    })
    .await
}

/// The slot moves into the blocking task, so a request that is dropped or times out keeps it
/// until the decode it started has finished.
async fn decode_with_slots(
    slots: &Arc<Semaphore>,
    body: Bytes,
    decode: impl FnOnce(&[u8]) -> Result<Vec<u8>, String> + Send + 'static,
) -> ApiResult<Vec<u8>> {
    let slot = slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| ApiError::internal("logo decode", e))?;
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        decode(&body)
    })
    .await
    .map_err(|e| ApiError::internal("logo decode", e))?
    .map_err(ApiError::bad_request)
}

#[utoipa::path(delete, path = "/api/v1/projects/{project}/logo", tag = "projects", params(("project" = String, Path)),
    responses((status = 200, body = Project)), security(("bearer" = [])))]
async fn delete_logo(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Path(project): Path<String>,
) -> ApiResult<Json<Project>> {
    let (mut project, rules) = load_project(&state, &principal, &project).await?;
    require_any(&rules, Subject::Settings, Action::Edit)?;
    state
        .store
        .set_project_logo(&project.id, None, state.clock.now())
        .await?;
    project.logo_updated_at = None;
    audit(
        &state,
        &principal,
        ip,
        "project.logo-remove",
        AuditTarget {
            project_id: Some(&project.id),
            ..Default::default()
        },
        json!({}),
    )
    .await;
    Ok(Json(api_project(&project)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn an_abandoned_upload_keeps_its_slot_until_the_decode_ends() -> anyhow::Result<()> {
        let slots = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel::<()>();
        let task_slots = slots.clone();
        let upload = tokio::spawn(async move {
            decode_with_slots(&task_slots, Bytes::from_static(b"x"), move |_| {
                let _ = started_tx.send(());
                let _ = finish_rx.recv();
                Ok(Vec::new())
            })
            .await
        });
        started_rx.await?;
        upload.abort();
        let _ = upload.await;
        assert_eq!(slots.available_permits(), 0, "the render still holds its slot");
        finish_tx.send(())?;
        let freed = tokio::time::timeout(Duration::from_secs(5), slots.acquire()).await;
        assert!(freed.is_ok(), "the slot comes back once the render ends");
        Ok(())
    }
}
