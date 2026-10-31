//! The sekret HTTP server: API, authentication and the embedded web interface.

pub mod admin;
pub mod api;
pub mod auth;
pub mod authz;
pub mod clock;
pub mod config;
pub mod error;
pub mod files;
mod host_socket;
pub mod human;
pub mod images;
pub mod jwt;
pub mod machine;
pub mod net;
pub mod ratelimit;
pub mod rotation;
pub mod seal;
pub mod secrets;
pub mod state;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod tls;
mod web;

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, FromRequestParts, Request, State};
use axum::http::{HeaderValue, Method, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sekret_core::seal::SealState;
use sekret_store::Store;
use serde_json::{Value, json};
use tower_http::timeout::RequestBodyTimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub const ROOT_KEY_META: &str = "root_key_fingerprint";

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

/// Paths that answer whether or not the server is sealed. Signing out and revoking a token need
/// no root key, and should work while sealed; so does an admin reading the full status.
const OPEN_WHILE_SEALED: [&str; 9] = [
    "/api/v1/sys/status",
    "/api/v1/sys/status/detail",
    "/api/v1/sys/init",
    "/api/v1/sys/unseal",
    "/api/v1/sys/passphrase-strength",
    "/api/v1/health",
    "/api/v1/ready",
    "/api/v1/auth/token/revoke",
    "/auth/logout",
];

/// Answers 503 for every API and sign-in route until the root key is in memory.
async fn seal_gate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let gated = (path.starts_with("/api/v1/") || path.starts_with("/auth/")) && !OPEN_WHILE_SEALED.contains(&path);
    if !gated {
        return next.run(request).await;
    }
    match state.keyring.state() {
        SealState::Unsealed => next.run(request).await,
        SealState::Sealed => ApiError::sealed().into_response(),
        SealState::Uninitialised => ApiError::uninitialised().into_response(),
    }
}

/// The largest body any route accepts, read in full before a change may wait on a rotation.
const MAX_BODY: usize = 4 * 1024 * 1024;
/// How long a client may take to send its body.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long any request may take, and a backup, which reads and encrypts the whole database.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const BACKUP_TIMEOUT: Duration = Duration::from_secs(600);

/// Changes outside the system and sign-in routes may encrypt under the root key, so they wait
/// while it is being replaced. They only start waiting once their body has arrived and the caller
/// is authenticated, so a slow or anonymous request cannot hold a rotation, and every writer
/// queued behind it, up. Before writing, the database must still hold this server's root key.
async fn write_gate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let writes = !matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let exempt = path.starts_with("/api/v1/sys/") || path.starts_with("/api/v1/auth/");
    if !writes || exempt || !path.starts_with("/api/v1/") {
        return next.run(request).await;
    }
    let (mut parts, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY).await else {
        return ApiError::new(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "the request body is too large or arrived too slowly",
        )
        .into_response();
    };
    let principal = match auth::Principal::from_request_parts(&mut parts, &state).await {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    parts.extensions.insert(principal);
    let _writing = state.keyring.writing().await;
    if let Err(error) = state.keyring.check_fingerprint(state.store.as_ref()).await {
        return error.into_response();
    }
    next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
        .await
}

/// Ends a request that runs too long. Work that must not stop halfway runs as its own task.
async fn request_timeout(request: Request, next: Next) -> Response {
    let limit = match request.uri().path() {
        "/api/v1/sys/backup" => BACKUP_TIMEOUT,
        _ => REQUEST_TIMEOUT,
    };
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "timeout",
            "the request took too long",
        )
        .into_response(),
    }
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn ready(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    state.keyring.root()?;
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
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), write_gate))
        .layer(TraceLayer::new_for_http())
        // Outside tracing, so a sealed server does not log every refused request as an error.
        .layer(middleware::from_fn_with_state(state.clone(), seal_gate))
        .layer(RequestBodyTimeoutLayer::new(BODY_TIMEOUT))
        .layer(middleware::from_fn(request_timeout))
        .layer(middleware::from_fn_with_state(state.clone(), security_headers))
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
    #[error("this database needs its root key file; pass --root-key-file or set seal.root_key_file")]
    MissingRootKey,
    #[error("root key file {0}")]
    KeyFile(String),
    #[error(
        "the configuration sets seal mode {configured} but the database is in {stored} mode; \
         change it deliberately with `sekret admin set-seal-mode`"
    )]
    ModeConflict {
        configured: &'static str,
        stored: &'static str,
    },
    #[error("setup: {0}")]
    Init(String),
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

/// Log target of the line naming the bound address, so a quiet log level can still keep it.
pub const LISTENING_TARGET: &str = "sekret_server::listening";

/// Runs the server. The keyring must come from [`seal::open_keyring`], which checks the root key.
pub async fn serve(state: AppState) -> Result<(), StartupError> {
    if !web::embedded() {
        tracing::warn!("this build has no web interface; build web/ before the binary to embed it");
    }
    api::clean_stale_staging(&api::staging_base(
        state.config.backup_temp_dir.as_deref(),
        &state.config.database_url,
    ));
    if let Err(error) = auth::revoke_disallowed_users(&state).await {
        tracing::warn!(error = %error.message, "could not check signed-in users against the sign-in lists");
    }
    let socket = state.config.unix_socket.clone();
    if let Some(socket) = &socket {
        host_socket::spawn(state.clone(), socket)?;
    }
    let served = serve_http(state).await;
    if let Some(socket) = &socket {
        host_socket::remove(&socket.path);
    }
    served
}

async fn serve_http(state: AppState) -> Result<(), StartupError> {
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
    let listener = tokio::net::TcpListener::bind(state.config.listen).await?;
    let address = listener.local_addr()?;
    if let Some(settings) = &state.config.tls {
        let config = tls::server_config(settings)?;
        let handle = axum_server::Handle::new();
        let shutdown = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
        });
        let rustls = axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(config));
        let server = axum_server::from_tcp_rustls(listener.into_std()?, rustls)?;
        tracing::info!(
            target: LISTENING_TARGET,
            url = %state.config.public_url,
            tls = true,
            mutual_tls = settings.client_ca_pem.is_some(),
            "listening on {address}"
        );
        server
            .handle(handle)
            .serve(app(state).into_make_service_with_connect_info::<SocketAddr>())
            .await?;
        return Ok(());
    }
    tracing::info!(
        target: LISTENING_TARGET,
        url = %state.config.public_url,
        tls = false,
        "listening on {address}"
    );
    axum::serve(listener, app(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
