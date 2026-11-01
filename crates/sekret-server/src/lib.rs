//! The sekret HTTP server: API, authentication and the embedded web interface.

pub mod admin;
pub mod api;
pub mod auth;
pub mod authz;
pub mod body;
pub mod clock;
pub mod config;
pub mod error;
pub mod files;
pub mod host_socket;
pub mod human;
pub mod images;
pub mod jwt;
pub mod machine;
pub mod net;
pub mod peer;
pub mod ratelimit;
pub mod rotation;
pub mod seal;
pub mod secrets;
pub mod serve;
pub mod state;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod tls;
mod web;

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
use tower_http::timeout::{RequestBodyDeadlineLayer, RequestBodyTimeoutLayer};
use tower_http::trace::TraceLayer;

use crate::body::MAX_BODY;
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

/// How long a request body may take to arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyTimeouts {
    /// The longest pause between two parts of the body.
    pub gap: Duration,
    /// The whole body, however steadily it trickles in. The detached system routes have no
    /// request time limit, so without this a client sending a byte now and then holds a
    /// connection for days.
    pub total: Duration,
    /// The whole body on the sign-in and system routes, which anyone may call and whose bodies
    /// are a few KiB, so a trickle there cannot hold a connection for the full `total`.
    pub open: Duration,
}

impl Default for BodyTimeouts {
    fn default() -> Self {
        Self {
            gap: Duration::from_secs(30),
            // As long as any other request may take, so no upload loses time it had before.
            total: REQUEST_TIMEOUT,
            open: Duration::from_secs(10),
        }
    }
}

/// Routes anyone may call without a token, where a body has [`BodyTimeouts::open`] to arrive.
fn open_route(path: &str) -> bool {
    path.starts_with("/api/v1/auth/") || path.starts_with("/api/v1/sys/")
}

/// Gives bodies on the open routes their shorter deadline, inside the general one.
fn open_body_deadline(request: Request, deadline: Duration) -> Request {
    if !open_route(request.uri().path()) {
        return request;
    }
    request.map(|body| axum::body::Body::new(tower_http::timeout::DeadlineBody::new(deadline, body)))
}

/// Failed authentications one client address may make each minute before requests carrying a
/// credential are turned away unchecked, so junk tokens cannot keep the database busy.
pub const FAILED_AUTH_PER_MINUTE: u32 = 60;

fn carries_credential(state: &AppState, request: &Request) -> bool {
    let headers = request.headers();
    headers.contains_key(header::AUTHORIZATION)
        || auth::cookie_value(headers, auth::session_cookie_name(&state.config)).is_some()
}

/// Answers 429 without a lookup once a client has failed authentication too often, and counts
/// each failure. Sign-in routes are left alone, so a stale cookie never blocks signing in again.
async fn failed_auth_gate(
    State(state): State<AppState>,
    auth::ClientIp(ip): auth::ClientIp,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let checked = path.starts_with("/api/v1/") && !path.starts_with("/api/v1/auth/");
    if !checked || !carries_credential(&state, &request) {
        return next.run(request).await;
    }
    if state.failed_auth_limiter.exhausted(&ratelimit::limiter_key(ip)) {
        return ApiError::too_many_requests().into_response();
    }
    let response = next.run(request).await;
    if response.status() == axum::http::StatusCode::UNAUTHORIZED {
        state.failed_auth_limiter.allow_ip(ip);
    }
    response
}
/// How long any request may take, and a backup, which reads and encrypts the whole database.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const BACKUP_TIMEOUT: Duration = Duration::from_secs(600);
/// System changes that run detached, so they are answered when they finish, however long that is.
const DETACHED_CHANGES: [&str; 5] = [
    "/api/v1/sys/init",
    "/api/v1/sys/unseal",
    "/api/v1/sys/passphrase",
    "/api/v1/sys/unlock-policy",
    "/api/v1/sys/forget-unlock",
];

/// How long a request to `path` may take. The detached changes have no limit: they finish in a
/// task of their own whatever happens to the request, so a timeout would only tell the caller a
/// change failed when it went through.
fn time_limit(path: &str) -> Option<Duration> {
    if DETACHED_CHANGES.contains(&path) {
        return None;
    }
    match path {
        "/api/v1/sys/backup" => Some(BACKUP_TIMEOUT),
        _ => Some(REQUEST_TIMEOUT),
    }
}

/// Changes outside the system and sign-in routes may encrypt under the root key, so they wait
/// while it is being replaced. The caller is authenticated from the headers before the body is
/// read, so an anonymous client cannot make the server buffer one, and the wait only starts once
/// the body has arrived, so a slow request cannot hold a rotation, and every writer queued behind
/// it, up. Each route reads only what it needs, and all writes share one byte budget, so tokens
/// cannot add up to more memory than the server has. Before writing, the database must still hold
/// this server's root key.
async fn write_gate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let writes = !matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let exempt = path.starts_with("/api/v1/sys/") || path.starts_with("/api/v1/auth/");
    if !writes || exempt || !path.starts_with("/api/v1/") {
        return next.run(request).await;
    }
    let limit = body::body_limit(path);
    let (mut parts, body) = request.into_parts();
    let principal = match auth::Principal::from_request_parts(&mut parts, &state).await {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|len| len > limit) {
        return body::too_large().into_response();
    }
    let reserved = declared.unwrap_or(limit);
    let _permit = match state.write_budget.reserve(&principal.id, reserved).await {
        Ok(permit) => permit,
        Err(error) => return error.into_response(),
    };
    let Ok(bytes) = axum::body::to_bytes(body, reserved).await else {
        return body::too_large().into_response();
    };
    parts.extensions.insert(principal);
    let _writing = if uses_root_key(parts.uri.path()) {
        Some(state.keyring.writing().await)
    } else {
        None
    };
    if let Err(error) = state.keyring.check_fingerprint(state.store.as_ref()).await {
        return error.into_response();
    }
    next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
        .await
}

/// Whether a write may encrypt under the root key, and so must not overlap its rotation. A logo
/// is stored as it is, and its upload can wait a long while for a decode slot, which would
/// otherwise hold every rotation up.
fn uses_root_key(path: &str) -> bool {
    let segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    !matches!(segments.as_slice(), ["", "api", "v1", "projects", _, "logo"])
}

/// System changes that write under the root key. Sealing is left out so it always works.
const SYS_WRITES: [&str; 4] = [
    "/api/v1/sys/passphrase",
    "/api/v1/sys/unlock-policy",
    "/api/v1/sys/forget-unlock",
    "/api/v1/sys/backup",
];

/// The write gate skips the system routes, so their changes check here that the database still
/// holds this server's root key, as other writes do.
async fn sys_fingerprint_gate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let writes = !matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let checked = writes && SYS_WRITES.contains(&request.uri().path());
    if !checked || state.keyring.state() != SealState::Unsealed {
        return next.run(request).await;
    }
    if let Err(error) = state.keyring.check_fingerprint(state.store.as_ref()).await {
        return error.into_response();
    }
    next.run(request).await
}

/// Ends a request that runs too long. Work that must not stop halfway runs as its own task.
async fn request_timeout(request: Request, next: Next) -> Response {
    let Some(limit) = time_limit(request.uri().path()) else {
        return next.run(request).await;
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

/// Paths only: queries carry sign-in codes, OIDC state and CLI user codes.
fn request_span(request: &Request) -> tracing::Span {
    tracing::debug_span!("request", method = %request.method(), path = %logged_path(request.uri()))
}

fn logged_path(uri: &axum::http::Uri) -> &str {
    uri.path()
}

pub fn app(state: AppState) -> Router {
    app_with(state, BodyTimeouts::default())
}

pub fn app_with(state: AppState, body: BodyTimeouts) -> Router {
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
        .layer(middleware::from_fn_with_state(state.clone(), failed_auth_gate))
        .layer(middleware::from_fn_with_state(state.clone(), sys_fingerprint_gate))
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        // Outside tracing, so a sealed server does not log every refused request as an error.
        .layer(middleware::from_fn_with_state(state.clone(), seal_gate))
        .layer(tower::util::MapRequestLayer::new(move |request| {
            open_body_deadline(request, body.open)
        }))
        .layer(RequestBodyTimeoutLayer::new(body.gap))
        .layer(RequestBodyDeadlineLayer::new(body.total))
        .layer(middleware::from_fn(request_timeout))
        .layer(middleware::from_fn_with_state(state.clone(), security_headers))
        .layer(middleware::from_fn(peer::record_peer))
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
    #[error(
        "the root key is not the one recorded in the seal epoch marks beside the database, remember file or root \
         key file, so the database may have been given another key; if this is expected, such as after restoring a \
         database made under another root key, run `sekret admin reset-epoch --adopt-root-key` on the host"
    )]
    UnrecognisedRootKey,
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

/// Records the root key fingerprint on first start and refuses to run with a different key. A
/// database that already holds projects but no fingerprint is refused, since nothing here can
/// show the key opens them; [`seal::check_root`] can.
pub async fn check_root_key(store: &dyn Store, fingerprint: &str) -> Result<(), StartupError> {
    match store.get_meta(ROOT_KEY_META).await? {
        Some(existing) if existing != fingerprint => Err(StartupError::WrongRootKey),
        Some(_) => Ok(()),
        None if !store.list_projects().await?.is_empty() => Err(StartupError::WrongRootKey),
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
    let refusal_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            api::flush_refusals(&refusal_state).await;
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
    let tls_config = match &state.config.tls {
        Some(settings) => Some(std::sync::Arc::new(tls::server_config(settings)?)),
        None => None,
    };
    tracing::info!(
        target: LISTENING_TARGET,
        url = %state.config.public_url,
        tls = tls_config.is_some(),
        mutual_tls = state.config.tls.as_ref().is_some_and(|t| t.client_ca_pem.is_some()),
        max_connections = state.config.max_connections,
        "listening on {address}"
    );
    let limits = serve::ConnectionLimits::new(state.config.max_connections).exempting(&state.config.trusted_proxies);
    serve::serve(listener, app(state), tls_config, limits, shutdown_signal()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_logs_leave_out_the_query() -> anyhow::Result<()> {
        let callback: axum::http::Uri = "/auth/callback?code=the-code&state=the-state".parse()?;
        assert_eq!(logged_path(&callback), "/auth/callback");
        let pending: axum::http::Uri = "/api/v1/auth/cli/pending?code=BCDF-GHJK".parse()?;
        assert_eq!(logged_path(&pending), "/api/v1/auth/cli/pending");
        Ok(())
    }

    #[test]
    fn detached_system_changes_are_never_cut_short() {
        assert_eq!(time_limit("/api/v1/sys/passphrase"), None);
        assert_eq!(time_limit("/api/v1/sys/unlock-policy"), None);
        assert_eq!(time_limit("/api/v1/sys/backup"), Some(BACKUP_TIMEOUT));
        assert_eq!(time_limit("/api/v1/projects"), Some(REQUEST_TIMEOUT));
        assert_eq!(time_limit("/api/v1/sys/passphrase/"), Some(REQUEST_TIMEOUT));
    }

    #[test]
    fn every_body_has_a_total_deadline() {
        let timeouts = BodyTimeouts::default();
        assert!(timeouts.total <= REQUEST_TIMEOUT && timeouts.gap <= timeouts.total);
    }

    #[test]
    fn only_logo_uploads_skip_the_rotation_lock() {
        assert!(!uses_root_key("/api/v1/projects/app/logo"));
        assert!(!uses_root_key("/api/v1/projects/app/logo/"));
        for writes in [
            "/api/v1/projects/logo",
            "/api/v1/projects",
            "/api/v1/projects/app/environments/prod/secrets/logo",
            "/api/v1/projects/app/roles/logo",
        ] {
            assert!(uses_root_key(writes), "{writes}");
        }
    }
}
