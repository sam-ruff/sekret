use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

use crate::error::ApiError;

#[derive(RustEmbed)]
#[folder = "../../web/dist/"]
#[allow_missing = true]
struct Assets;

/// Whether this build carries the web interface; it is left out when `web/dist` was not built first.
pub fn embedded() -> bool {
    Assets::get("index.html").is_some()
}

fn asset(path: &str) -> Option<Response> {
    let file = Assets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let mut response = Response::new(Body::from(file.data.into_owned()));
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    Some(response)
}

/// Serves the embedded frontend, falling back to `index.html` for client-side routes.
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") || path == "api" {
        return ApiError::not_found("endpoint").into_response();
    }
    if let Some(response) = asset(path).filter(|_| !path.is_empty()) {
        return response;
    }
    if path.starts_with("assets/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    asset("index.html").unwrap_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "The web interface was not built into this binary.",
        )
            .into_response()
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_built_interface_is_embedded() {
        let index = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/dist/index.html");
        if std::path::Path::new(index).exists() {
            assert!(
                super::embedded(),
                "web/dist exists but the embed path does not reach it"
            );
        }
    }
}
