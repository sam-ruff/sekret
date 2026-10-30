//! The sekret HTTP server: API, authentication and the embedded web interface.

pub mod admin;
pub mod api;
pub mod auth;
pub mod authz;
pub mod clock;
pub mod config;
pub mod error;
pub mod human;
pub mod images;
pub mod jwt;
pub mod machine;
pub mod net;
pub mod ratelimit;
pub mod rotation;
pub mod secrets;
pub mod state;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod tls;
mod web;

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use sekret_store::Store;
use serde_json::{Value, json};
use tower_http::trace::TraceLayer;

use crate::error::ApiResult;
use crate::state::AppState;

const ROOT_KEY_META: &str = "root_key_fingerprint";

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
                   connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

async fn security_headers(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/") || request.uri().path().starts_with("/auth/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // A handler may set a stricter policy of its own, such as the sandbox on uploaded images.
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(CSP));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if state.config.secure_cookies() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    if is_api {
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
    }
    response
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn ready(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    state.store.get_meta(ROOT_KEY_META).await?;
    Ok(Json(json!({"status": "ready"})))
}

pub fn app(state: AppState) -> Router {
    let (api, openapi) = api::router().split_for_parts();
    Router::new()
        .merge(api)
        .route("/api/openapi.json", get(move || async move { Json(openapi) }))
        .route("/api/v1/health", get(health))
        .route("/api/v1/ready", get(ready))
        .route("/auth/login", get(human::login))
        .route("/auth/callback", get(human::callback))
        .fallback(web::static_handler)
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), security_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub fn web_embedded() -> bool {
    web::embedded()
}

pub fn openapi_json() -> String {
    let (_, openapi) = api::router().split_for_parts();
    openapi.to_pretty_json().unwrap_or_default()
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("the root key does not match the one this database was created with")]
    WrongRootKey,
    #[error("store: {0}")]
    Store(#[from] sekret_store::StoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
}

/// Records the root key fingerprint on first start and refuses to run with a different key.
pub async fn check_root_key(store: &dyn Store, fingerprint: &str) -> Result<(), StartupError> {
    match store.get_meta(ROOT_KEY_META).await? {
        Some(existing) if existing != fingerprint => Err(StartupError::WrongRootKey),
        Some(_) => Ok(()),
        None => Ok(store.set_meta(ROOT_KEY_META, fingerprint).await?),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for ctrl-c");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

pub async fn serve(state: AppState) -> Result<(), StartupError> {
    check_root_key(state.store.as_ref(), &state.root_key.fingerprint()).await?;
    if !web::embedded() {
        tracing::warn!("this build has no web interface; build web/ before the binary to embed it");
    }
    let purge_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        loop {
            interval.tick().await;
            if let Err(error) = purge_state.store.purge_expired(purge_state.clock.now()).await {
                tracing::warn!(%error, "purging expired records failed");
            }
        }
    });
    let rotation_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            match rotation::rotate_due(&rotation_state).await {
                Ok(rotated) if !rotated.is_empty() => tracing::info!(?rotated, "rotated secrets"),
                Ok(_) => {}
                Err(error) => tracing::warn!(error = %error.message, "rotation pass failed"),
            }
        }
    });
    if let Some(settings) = &state.config.tls {
        let config = tls::server_config(settings)?;
        let handle = axum_server::Handle::new();
        let shutdown = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
        });
        tracing::info!(
            address = %state.config.listen,
            url = %state.config.public_url,
            mutual_tls = settings.client_ca_pem.is_some(),
            "sekret listening with TLS"
        );
        let rustls = axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(config));
        axum_server::bind_rustls(state.config.listen, rustls)
            .handle(handle)
            .serve(app(state).into_make_service_with_connect_info::<SocketAddr>())
            .await?;
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(state.config.listen).await?;
    tracing::info!(address = %listener.local_addr()?, url = %state.config.public_url, "sekret listening");
    axum::serve(listener, app(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
