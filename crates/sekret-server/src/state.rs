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
    /// Browser sign-in. Kept apart from machine logins and the CLI flow, so a CI fleet or
    /// anonymous junk behind the same address cannot lock a person out.
    pub login_limiter: RateLimiter<IpAddr>,
    /// Machine logins through any auth method.
    pub machine_login_limiter: RateLimiter<IpAddr>,
    /// Starting CLI logins, which anyone may do, per client address.
    pub cli_login_limiter: RateLimiter<IpAddr>,
    /// Looking at, approving and denying CLI logins, per signed-in person, so anonymous starts
    /// from the same address cannot use up their allowance.
    pub cli_review_limiter: RateLimiter<String>,
    /// Bytes and concurrent writes the write gate may buffer.
    pub write_budget: crate::body::WriteBudget,
    /// Setup, unlock and passphrase attempts, kept apart from sign-in so exhausting one cannot
    /// lock anyone out of the other.
    pub sys_limiter: RateLimiter<IpAddr>,
    /// Wrong passphrases slow later attempts from the same source down.
    pub passphrase_backoff: FailureBackoff,
    /// Wrong passphrases through the host socket, which the network limits do not cover.
    pub host_backoff: crate::ratelimit::HostBackoff,
    /// Passphrase attempts, right or wrong, per IPv4 /24 or IPv6 /48.
    pub passphrase_attempts: RateLimiter<IpAddr>,
    /// Places in line for a key derivation, for network sources with no recent failures.
    pub kdf_queue: Arc<tokio::sync::Semaphore>,
    /// One backup at a time. Owned guards let a backup keep it after its client goes away.
    pub backup_lock: Arc<tokio::sync::Mutex<()>>,
    /// Folds repeated refusals into one audit entry a minute per caller and source.
    pub refusals: crate::ratelimit::AuditThrottle,
    /// Logo uploads per principal, since each one may cost a second or two of rendering.
    pub logo_limiter: RateLimiter<String>,
    /// CLI login polls per client address. Generous, as each waiting terminal polls every two seconds.
    pub poll_limiter: RateLimiter<IpAddr>,
    /// Failed authentications per client address, keyed by [`crate::ratelimit::limiter_key`].
    pub failed_auth_limiter: RateLimiter<IpAddr>,
    /// Backups per principal, since each reads the whole database and saves a seal epoch.
    pub backup_limiter: RateLimiter<String>,
}

/// Backups one principal may take each hour.
pub const BACKUPS_PER_HOUR: u32 = 6;

/// Polls allowed per address each minute: a handful of terminals waiting at once.
pub const CLI_POLLS_PER_MINUTE: u32 = 120;

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
    let machine_login_limiter = RateLimiter::new(deps.config.login_rate_per_minute);
    let cli_login_limiter = RateLimiter::new(deps.config.login_rate_per_minute);
    let cli_review_limiter = RateLimiter::new(deps.config.login_rate_per_minute);
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
        machine_login_limiter,
        cli_login_limiter,
        cli_review_limiter,
        write_budget: crate::body::WriteBudget::default(),
        sys_limiter,
        passphrase_backoff: FailureBackoff::default(),
        host_backoff: crate::ratelimit::HostBackoff::default(),
        passphrase_attempts,
        kdf_queue: Arc::new(tokio::sync::Semaphore::new(KDF_QUEUE_DEPTH)),
        backup_lock: Arc::new(tokio::sync::Mutex::new(())),
        refusals: crate::ratelimit::AuditThrottle::default(),
        logo_limiter: RateLimiter::new(crate::api::logo::LOGO_UPLOADS_PER_MINUTE),
        poll_limiter: RateLimiter::new(CLI_POLLS_PER_MINUTE),
        failed_auth_limiter: RateLimiter::new(crate::FAILED_AUTH_PER_MINUTE),
        backup_limiter: RateLimiter::per_hour(BACKUPS_PER_HOUR),
    })
}
