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
    /// Wrong passphrases slow later attempts from the same source down.
    pub passphrase_backoff: FailureBackoff,
    /// Passphrase attempts, right or wrong, per IPv4 /24 or IPv6 /48.
    pub passphrase_attempts: RateLimiter<IpAddr>,
    /// Places in line for a key derivation, for network sources with no recent failures.
    pub kdf_queue: Arc<tokio::sync::Semaphore>,
    /// One backup at a time. Owned guards let a backup keep it after its client goes away.
    pub backup_lock: Arc<tokio::sync::Mutex<()>>,
    /// Folds repeated refusals into one audit entry a minute per caller and source.
    pub refusals: crate::ratelimit::AuditThrottle,
}

pub type AppState = Arc<Inner>;

/// Network unlock attempts that may wait in line for a key derivation at once.
pub const KDF_QUEUE_DEPTH: usize = 8;

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
    let passphrase_attempts = RateLimiter::new(deps.config.login_rate_per_minute);
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
        passphrase_attempts,
        kdf_queue: Arc::new(tokio::sync::Semaphore::new(KDF_QUEUE_DEPTH)),
        backup_lock: Arc::new(tokio::sync::Mutex::new(())),
        refusals: crate::ratelimit::AuditThrottle::default(),
    })
}
