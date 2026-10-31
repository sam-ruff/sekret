use std::net::IpAddr;
use std::sync::Arc;

use sekret_store::Store;

use crate::clock::Clock;
use crate::config::ServerConfig;
use crate::jwt::JwtVerifier;
use crate::net::{OidcHttp, TokenReviewer};
use crate::ratelimit::{FailureBackoff, RateLimiter};
use crate::seal::Keyring;

pub struct Inner {
    pub store: Arc<dyn Store>,
    pub keyring: Keyring,
    pub config: ServerConfig,
    pub clock: Arc<dyn Clock>,
    pub http: Arc<dyn OidcHttp>,
    pub jwt: JwtVerifier,
    pub token_reviewer: Arc<dyn TokenReviewer>,
    pub login_limiter: RateLimiter<IpAddr>,
    /// Setup, unlock and passphrase attempts, kept apart from sign-in so exhausting one cannot
    /// lock anyone out of the other.
    pub sys_limiter: RateLimiter<IpAddr>,
    /// Wrong passphrases from anywhere slow every later attempt down.
    pub passphrase_backoff: FailureBackoff,
    /// One backup at a time.
    pub backup_lock: tokio::sync::Mutex<()>,
}

pub type AppState = Arc<Inner>;

pub struct Dependencies {
    pub store: Arc<dyn Store>,
    pub keyring: Keyring,
    pub config: ServerConfig,
    pub clock: Arc<dyn Clock>,
    pub http: Arc<dyn OidcHttp>,
    pub token_reviewer: Arc<dyn TokenReviewer>,
}

pub fn build_state(deps: Dependencies) -> AppState {
    let jwt = JwtVerifier::new(deps.http.clone(), deps.clock.clone());
    let login_limiter = RateLimiter::new(deps.config.login_rate_per_minute);
    let sys_limiter = RateLimiter::new(deps.config.login_rate_per_minute);
    Arc::new(Inner {
        store: deps.store,
        keyring: deps.keyring,
        config: deps.config,
        clock: deps.clock,
        http: deps.http,
        jwt,
        token_reviewer: deps.token_reviewer,
        login_limiter,
        sys_limiter,
        passphrase_backoff: FailureBackoff::default(),
        backup_lock: tokio::sync::Mutex::new(()),
    })
}
