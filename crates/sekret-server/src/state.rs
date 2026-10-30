use std::net::IpAddr;
use std::sync::Arc;

use sekret_core::crypto::RootKey;
use sekret_store::Store;

use crate::clock::Clock;
use crate::config::ServerConfig;
use crate::jwt::JwtVerifier;
use crate::net::{OidcHttp, TokenReviewer};
use crate::ratelimit::RateLimiter;

pub struct Inner {
    pub store: Arc<dyn Store>,
    pub root_key: RootKey,
    pub config: ServerConfig,
    pub clock: Arc<dyn Clock>,
    pub http: Arc<dyn OidcHttp>,
    pub jwt: JwtVerifier,
    pub token_reviewer: Arc<dyn TokenReviewer>,
    pub login_limiter: RateLimiter<IpAddr>,
}

pub type AppState = Arc<Inner>;

pub struct Dependencies {
    pub store: Arc<dyn Store>,
    pub root_key: RootKey,
    pub config: ServerConfig,
    pub clock: Arc<dyn Clock>,
    pub http: Arc<dyn OidcHttp>,
    pub token_reviewer: Arc<dyn TokenReviewer>,
}

pub fn build_state(deps: Dependencies) -> AppState {
    let jwt = JwtVerifier::new(deps.http.clone(), deps.clock.clone());
    let login_limiter = RateLimiter::new(deps.config.login_rate_per_minute);
    Arc::new(Inner {
        store: deps.store,
        root_key: deps.root_key,
        config: deps.config,
        clock: deps.clock,
        http: deps.http,
        jwt,
        token_reviewer: deps.token_reviewer,
        login_limiter,
    })
}
