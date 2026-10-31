use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sekret_api::{
    AuthMethodConfig, AuthMethodKind, JwtLoginRequest, KubernetesAuthConfig, KubernetesMode, OidcAuthConfig,
    REDACTED_CREDENTIAL, TokenResponse, UniversalLoginRequest,
};
use sekret_core::crypto::{RootKey, hash_token, open_credential, seal_credential};
use sekret_core::glob::glob_match;
use sekret_store::{Identity, PrincipalKind, Store};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::{AuditTarget, audit};
use crate::auth::{ClientIp, Principal, TokenKind, TokenRequest, ip_allowed, mint_token};
use crate::error::{ApiError, ApiResult};
use crate::jwt::{Expectations, JwtVerifier, KeySource};
use crate::net::{NetError, TokenReviewRequest, TokenReviewer, check_outbound_url};
use crate::state::AppState;

pub const CLIENT_SECRET_PREFIX: &str = "sks_";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoginError {
    #[error("token rejected: {0}")]
    Token(String),
    #[error("claims not bound: {0}")]
    Binding(String),
    #[error("kubernetes rejected the token")]
    NotAuthenticated,
    #[error("upstream failure: {0}")]
    Upstream(#[from] NetError),
}

/// Validates an auth method configuration before it is saved.
pub fn validate_config(config: &AuthMethodConfig, allow_http: bool) -> ApiResult<()> {
    match config {
        AuthMethodConfig::Oidc(oidc) => {
            check_outbound_url(&oidc.issuer, allow_http).map_err(|e| ApiError::bad_request(e.to_string()))?;
            if let Some(url) = &oidc.jwks_url {
                check_outbound_url(url, allow_http).map_err(|e| ApiError::bad_request(e.to_string()))?;
            }
            oidc.bindings
                .validate()
                .map_err(|e| ApiError::bad_request(e.to_string()))
        }
        AuthMethodConfig::Kubernetes(k8s) => {
            if k8s.namespaces.is_empty() || k8s.service_accounts.is_empty() {
                return Err(ApiError::bad_request(
                    "bind at least one namespace and one service account",
                ));
            }
            if k8s.audiences.is_empty() {
                return Err(ApiError::bad_request("at least one audience is required"));
            }
            if k8s.max_token_lifetime < 1 {
                return Err(ApiError::bad_request("max_token_lifetime must be at least 1 second"));
            }
            for list in [&k8s.namespaces, &k8s.service_accounts, &k8s.audiences] {
                sekret_core::validate::globs(list)?;
            }
            match k8s.mode {
                KubernetesMode::TokenReview => {
                    let host = k8s
                        .host
                        .as_deref()
                        .ok_or_else(|| ApiError::bad_request("host is required"))?;
                    check_outbound_url(host, allow_http).map_err(|e| ApiError::bad_request(e.to_string()))?;
                }
                KubernetesMode::Jwks => {
                    if k8s.issuer.is_none() {
                        return Err(ApiError::bad_request("issuer is required for JWKS mode"));
                    }
                    match (&k8s.jwks, &k8s.jwks_url) {
                        (Some(inline), _) => {
                            serde_json::from_value::<jsonwebtoken::jwk::JwkSet>(inline.clone())
                                .map_err(|_| ApiError::bad_request("jwks is not a valid JWKS document"))?;
                        }
                        (None, Some(url)) => {
                            check_outbound_url(url, allow_http).map_err(|e| ApiError::bad_request(e.to_string()))?;
                        }
                        (None, None) => return Err(ApiError::bad_request("supply jwks or jwks_url")),
                    }
                }
            }
            Ok(())
        }
        AuthMethodConfig::Universal => Ok(()),
    }
}

/// Binds a sealed reviewer token to its identity and to the cluster it was entered for, so
/// someone who can write the database cannot send it to another host, trust another CA or
/// switch the mode.
fn credential_context(identity_id: &str, k8s: &KubernetesAuthConfig) -> String {
    let digest = |value: Option<&str>| hex::encode(&Sha256::digest(value.unwrap_or_default().as_bytes())[..16]);
    let mode = match k8s.mode {
        KubernetesMode::TokenReview => "token-review",
        KubernetesMode::Jwks => "jwks",
    };
    format!(
        "identity:{identity_id}:kubernetes:v2:{mode}:{}:{}",
        digest(k8s.host.as_deref()),
        digest(k8s.ca_cert.as_deref())
    )
}

/// What reviewer tokens were sealed under before they were bound to their cluster.
fn legacy_context(identity_id: &str) -> String {
    format!("identity:{identity_id}:kubernetes")
}

/// Seals the reviewer token for storage. Echoing the redaction marker keeps the stored token.
pub fn seal_for_storage(
    root: &RootKey,
    identity_id: &str,
    config: AuthMethodConfig,
    stored: Option<&AuthMethodConfig>,
) -> ApiResult<AuthMethodConfig> {
    let AuthMethodConfig::Kubernetes(mut k8s) = config else {
        return Ok(config);
    };
    k8s.reviewer_jwt = match k8s.reviewer_jwt.take().filter(|v| !v.trim().is_empty()) {
        None => None,
        Some(value) if value == REDACTED_CREDENTIAL => match stored {
            Some(AuthMethodConfig::Kubernetes(previous)) if previous.reviewer_jwt.is_some() => {
                // The token may only go back to the cluster it was entered for.
                if previous.host != k8s.host || previous.ca_cert != k8s.ca_cert || previous.mode != k8s.mode {
                    return Err(ApiError::bad_request(
                        "enter the reviewer token again when the host, CA or mode changes",
                    ));
                }
                previous.reviewer_jwt.clone()
            }
            _ => return Err(ApiError::bad_request("there is no stored reviewer token to keep")),
        },
        Some(value) => {
            let value = Zeroizing::new(value);
            Some(seal_credential(
                root,
                value.trim(),
                &credential_context(identity_id, &k8s),
            )?)
        }
    };
    Ok(AuthMethodConfig::Kubernetes(k8s))
}

pub fn redact(config: AuthMethodConfig) -> AuthMethodConfig {
    let AuthMethodConfig::Kubernetes(mut k8s) = config else {
        return config;
    };
    if k8s.reviewer_jwt.is_some() {
        k8s.reviewer_jwt = Some(REDACTED_CREDENTIAL.into());
    }
    AuthMethodConfig::Kubernetes(k8s)
}

/// The reviewer token in plain text, opened only for the cluster it was sealed for.
pub fn unseal_reviewer(
    root: &RootKey,
    identity_id: &str,
    k8s: &KubernetesAuthConfig,
) -> ApiResult<Option<Zeroizing<String>>> {
    let Some(sealed) = &k8s.reviewer_jwt else {
        return Ok(None);
    };
    open_credential(root, sealed, &credential_context(identity_id, k8s))
        .map(Some)
        .map_err(|e| ApiError::internal("opening reviewer token", e))
}

/// Re-seals stored credentials under a new root key; `None` when the config holds none.
pub fn reseal(
    old_root: &RootKey,
    new_root: &RootKey,
    identity_id: &str,
    config: &AuthMethodConfig,
) -> ApiResult<Option<AuthMethodConfig>> {
    let AuthMethodConfig::Kubernetes(k8s) = config else {
        return Ok(None);
    };
    let Some(plain) = unseal_reviewer(old_root, identity_id, k8s)? else {
        return Ok(None);
    };
    let mut k8s = k8s.clone();
    k8s.reviewer_jwt = Some(seal_credential(
        new_root,
        &plain,
        &credential_context(identity_id, &k8s),
    )?);
    Ok(Some(AuthMethodConfig::Kubernetes(k8s)))
}

/// Re-seals reviewer tokens stored before they were bound to their cluster. Best effort, since a
/// token that cannot be moved only stops its own logins; false when the database could not be
/// read or written, so the migration is tried again.
pub async fn migrate_reviewer_tokens(store: &dyn Store, root: &RootKey) -> bool {
    let result: ApiResult<usize> = async {
        let mut moved = 0;
        for identity in store.list_identities().await? {
            for mut method in store.list_auth_methods(&identity.id).await? {
                let Ok(AuthMethodConfig::Kubernetes(mut k8s)) = serde_json::from_value(method.config.clone()) else {
                    continue;
                };
                let Some(sealed) = k8s.reviewer_jwt.clone() else {
                    continue;
                };
                if open_credential(root, &sealed, &credential_context(&identity.id, &k8s)).is_ok() {
                    continue;
                }
                let Ok(plain) = open_credential(root, &sealed, &legacy_context(&identity.id)) else {
                    tracing::warn!(identity = %identity.name, "a stored reviewer token cannot be opened; enter it again");
                    continue;
                };
                k8s.reviewer_jwt = Some(seal_credential(root, &plain, &credential_context(&identity.id, &k8s))?);
                method.config = serde_json::to_value(AuthMethodConfig::Kubernetes(k8s))
                    .map_err(|e| ApiError::internal("auth method config", e))?;
                store.put_auth_method(method).await?;
                moved += 1;
            }
        }
        Ok(moved)
    }
    .await;
    match result {
        Ok(0) => true,
        Ok(moved) => {
            tracing::info!(moved, "bound stored reviewer tokens to their clusters");
            true
        }
        Err(error) => {
            tracing::warn!(error = %error.message, "could not re-seal stored reviewer tokens");
            false
        }
    }
}

pub async fn verify_oidc(jwt: &JwtVerifier, config: &OidcAuthConfig, token: &str) -> Result<Value, LoginError> {
    let source = match &config.jwks_url {
        Some(url) => KeySource::Url(url.clone()),
        None => KeySource::Issuer,
    };
    let expect = Expectations {
        issuer: Some(&config.issuer),
        audience: None,
    };
    let claims = jwt
        .verify(token, &source, &expect)
        .await
        .map_err(|e| LoginError::Token(e.to_string()))?;
    config
        .bindings
        .check(&claims)
        .map_err(|e| LoginError::Binding(e.to_string()))?;
    Ok(claims)
}

/// `system:serviceaccount:<namespace>:<name>` into its parts.
pub fn parse_service_account(username: &str) -> Option<(String, String)> {
    let rest = username.strip_prefix("system:serviceaccount:")?;
    let (namespace, name) = rest.split_once(':')?;
    (!namespace.is_empty() && !name.is_empty() && !name.contains(':')).then(|| (namespace.into(), name.into()))
}

/// Refuses tokens that say nothing of when they were issued or live longer than `max` seconds.
fn check_lifetime(claims: &Value, max: i64) -> Result<(), LoginError> {
    let iat = claims["iat"]
        .as_i64()
        .ok_or_else(|| LoginError::Token("no iat".into()))?;
    let exp = claims["exp"]
        .as_i64()
        .ok_or_else(|| LoginError::Token("no exp".into()))?;
    let lifetime = exp.saturating_sub(iat);
    if lifetime > max {
        return Err(LoginError::Token(format!(
            "lifetime of {lifetime}s is over max_token_lifetime {max}s"
        )));
    }
    Ok(())
}

/// A JWT's payload without checking its signature, for tokens the API server has already accepted.
fn unverified_claims(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// `reviewer_token` is the opened reviewer token, when the method has one.
pub async fn verify_kubernetes(
    jwt: &JwtVerifier,
    reviewer: &dyn TokenReviewer,
    config: &KubernetesAuthConfig,
    reviewer_token: Option<Zeroizing<String>>,
    token: &str,
) -> Result<Value, LoginError> {
    let username = match config.mode {
        KubernetesMode::TokenReview => {
            let host = config
                .host
                .as_deref()
                .ok_or_else(|| LoginError::Token("no host configured".into()))?;
            let review = reviewer
                .review(TokenReviewRequest {
                    host: host.to_string(),
                    ca_pem: config.ca_cert.clone(),
                    reviewer: reviewer_token,
                    token: token.to_string(),
                    audiences: config.audiences.clone(),
                })
                .await?;
            // An empty list means the token is only valid for the API server itself.
            let audience_ok = review.audiences.iter().any(|a| config.audiences.contains(a));
            if !review.authenticated || !audience_ok {
                return Err(LoginError::NotAuthenticated);
            }
            // `max_token_lifetime` is always set, so a lifetime that cannot be read is refused.
            let claims = unverified_claims(token).ok_or_else(|| LoginError::Token("claims cannot be read".into()))?;
            check_lifetime(&claims, config.max_token_lifetime)?;
            review.username
        }
        KubernetesMode::Jwks => {
            let source = match (&config.jwks, &config.jwks_url) {
                (Some(inline), _) => KeySource::Inline(
                    serde_json::from_value(inline.clone()).map_err(|_| LoginError::Token("invalid JWKS".into()))?,
                ),
                (None, Some(url)) => KeySource::Url(url.clone()),
                (None, None) => return Err(LoginError::Token("no keys configured".into())),
            };
            let expect = Expectations {
                issuer: config.issuer.as_deref(),
                audience: None,
            };
            let claims = jwt
                .verify(token, &source, &expect)
                .await
                .map_err(|e| LoginError::Token(e.to_string()))?;
            let audiences: Vec<&str> = match &claims["aud"] {
                Value::String(s) => vec![s.as_str()],
                Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            if !audiences.iter().any(|a| config.audiences.iter().any(|c| c == a)) {
                return Err(LoginError::Binding("audience".into()));
            }
            check_lifetime(&claims, config.max_token_lifetime)?;
            claims["sub"].as_str().unwrap_or_default().to_string()
        }
    };
    let (namespace, service_account) =
        parse_service_account(&username).ok_or_else(|| LoginError::Binding("not a service account".into()))?;
    if !config.namespaces.iter().any(|g| glob_match(g, &namespace, None)) {
        return Err(LoginError::Binding("namespace".into()));
    }
    if !config
        .service_accounts
        .iter()
        .any(|g| glob_match(g, &service_account, None))
    {
        return Err(LoginError::Binding("service account".into()));
    }
    Ok(json!({"namespace": namespace, "service_account": service_account}))
}

async fn login_identity(state: &AppState, identity_id: &str, ip: std::net::IpAddr) -> ApiResult<Identity> {
    if !state.login_limiter.allow_ip(ip) {
        return Err(ApiError::too_many_requests());
    }
    let Some(identity) = state.store.get_identity(identity_id).await? else {
        // The id is the caller's choice, so it must not open a fresh audit window per guess.
        audit_failure_as(state, ip, identity_id, "unknown identity", "unknown identity").await;
        return Err(ApiError::login_failed());
    };
    if identity.disabled {
        audit_failure(state, ip, identity_id, "identity disabled").await;
        return Err(ApiError::login_failed());
    }
    if !ip_allowed(&identity.trusted_cidrs, ip) {
        audit_failure(state, ip, identity_id, "address not in trusted_cidrs").await;
        return Err(ApiError::login_failed());
    }
    Ok(identity)
}

/// Records a refused machine login. The caller only ever sees `login_failed`.
async fn audit_failure(state: &AppState, ip: std::net::IpAddr, identity_id: &str, reason: &str) {
    audit_failure_as(state, ip, identity_id, identity_id, reason).await;
}

/// As [`audit_failure`], with repeats folded together under `throttle_subject`.
async fn audit_failure_as(
    state: &AppState,
    ip: std::net::IpAddr,
    identity_id: &str,
    throttle_subject: &str,
    reason: &str,
) {
    let identity = audited_identity_id(identity_id);
    crate::api::audit_refusal(
        state,
        &Principal::system("system"),
        throttle_subject,
        ip,
        "auth.machine-login.failed",
        json!({"identity_id": identity, "reason": reason}),
    )
    .await;
}

/// The identity id from a login request as it may be audited. Anything not shaped like an id,
/// such as a client secret pasted into the wrong field, is replaced by a short hash so repeats
/// can still be matched up.
pub fn audited_identity_id(raw: &str) -> String {
    let is_id = uuid::Uuid::try_parse(raw).is_ok_and(|id| id.to_string() == raw);
    if is_id {
        return raw.to_string();
    }
    let digest = Sha256::digest(raw.as_bytes());
    format!("hash:{}", hex::encode(&digest[..8]))
}

/// [`login_identity`]'s later checks, audited the same way when they refuse.
async fn refused<T>(state: &AppState, ip: std::net::IpAddr, identity: &Identity, reason: &str) -> ApiResult<T> {
    audit_failure(state, ip, &identity.id, reason).await;
    Err(ApiError::login_failed())
}

async fn method_config(
    state: &AppState,
    identity: &Identity,
    kind: AuthMethodKind,
) -> ApiResult<Option<AuthMethodConfig>> {
    let Some(method) = state.store.get_auth_method(&identity.id, kind.as_str()).await? else {
        return Ok(None);
    };
    serde_json::from_value(method.config)
        .map(Some)
        .map_err(|e| ApiError::internal("auth method config", e))
}

/// Token source for logins through an auth method, revoked when the method is removed.
pub fn auth_method_source(identity_id: &str, kind: &str) -> String {
    format!("auth-method:{identity_id}:{kind}")
}

/// Token source for universal logins, revoked when the client secret is revoked.
pub fn client_secret_source(secret_id: &str) -> String {
    format!("client-secret:{secret_id}")
}

async fn issue(
    state: &AppState,
    identity: &Identity,
    method: AuthMethodKind,
    source: String,
    detail: Value,
    ip: std::net::IpAddr,
) -> ApiResult<Json<TokenResponse>> {
    let minted = mint_token(
        state,
        TokenRequest {
            kind: TokenKind::Machine,
            principal_kind: PrincipalKind::Identity,
            principal_id: &identity.id,
            ttl: identity.token_ttl,
            max_ttl: identity.token_max_ttl,
            description: format!("{} login", method.as_str()),
            source,
            auth_time: None,
        },
    )
    .await?;
    let principal = Principal {
        kind: PrincipalKind::Identity,
        id: identity.id.clone(),
        name: identity.name.clone(),
        email: String::new(),
        groups: vec![],
        token_id: minted.record.id.clone(),
        token_kind: minted.record.kind.clone(),
    };
    let detail = json!({"method": method.as_str(), "claims": detail});
    audit(
        state,
        &principal,
        ip,
        "auth.machine-login",
        AuditTarget::default(),
        detail,
    )
    .await;
    Ok(Json(TokenResponse {
        access_token: minted.token.to_string(),
        token_type: "Bearer".into(),
        expires_in: minted.record.expires_at - state.clock.now(),
    }))
}

async fn rejected<T>(state: &AppState, ip: std::net::IpAddr, identity: &Identity, error: LoginError) -> ApiResult<T> {
    tracing::warn!(identity = %identity.name, %error, "machine login rejected");
    let reason = match error {
        LoginError::Token(_) => "token rejected",
        LoginError::Binding(_) => "claims not bound",
        LoginError::NotAuthenticated => "kubernetes rejected the token",
        LoginError::Upstream(_) => "upstream failure",
    };
    refused(state, ip, identity, reason).await
}

#[utoipa::path(post, path = "/api/v1/auth/oidc/login", tag = "auth", request_body = JwtLoginRequest,
    responses((status = 200, body = TokenResponse), (status = 401, body = sekret_api::ErrorBody)))]
pub async fn oidc_login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<JwtLoginRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let identity = login_identity(&state, &request.identity_id, ip).await?;
    let Some(AuthMethodConfig::Oidc(config)) = method_config(&state, &identity, AuthMethodKind::Oidc).await? else {
        return refused(&state, ip, &identity, "no oidc auth method").await;
    };
    let claims = match verify_oidc(&state.jwt, &config, &request.token).await {
        Ok(claims) => claims,
        Err(error) => return rejected(&state, ip, &identity, error).await,
    };
    let detail = json!({"iss": claims["iss"], "sub": claims["sub"]});
    let source = auth_method_source(&identity.id, AuthMethodKind::Oidc.as_str());
    issue(&state, &identity, AuthMethodKind::Oidc, source, detail, ip).await
}

#[utoipa::path(post, path = "/api/v1/auth/kubernetes/login", tag = "auth", request_body = JwtLoginRequest,
    responses((status = 200, body = TokenResponse), (status = 401, body = sekret_api::ErrorBody)))]
pub async fn kubernetes_login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<JwtLoginRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let identity = login_identity(&state, &request.identity_id, ip).await?;
    let Some(AuthMethodConfig::Kubernetes(config)) =
        method_config(&state, &identity, AuthMethodKind::Kubernetes).await?
    else {
        return refused(&state, ip, &identity, "no kubernetes auth method").await;
    };
    let reviewer_token = unseal_reviewer(state.keyring.root()?.as_ref(), &identity.id, &config)?;
    let detail = match verify_kubernetes(
        &state.jwt,
        state.token_reviewer.as_ref(),
        &config,
        reviewer_token,
        &request.token,
    )
    .await
    {
        Ok(detail) => detail,
        Err(error) => return rejected(&state, ip, &identity, error).await,
    };
    let source = auth_method_source(&identity.id, AuthMethodKind::Kubernetes.as_str());
    issue(&state, &identity, AuthMethodKind::Kubernetes, source, detail, ip).await
}

#[utoipa::path(post, path = "/api/v1/auth/universal/login", tag = "auth", request_body = UniversalLoginRequest,
    responses((status = 200, body = TokenResponse), (status = 401, body = sekret_api::ErrorBody)))]
pub async fn universal_login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<UniversalLoginRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let identity = login_identity(&state, &request.client_id, ip).await?;
    if state
        .store
        .get_auth_method(&identity.id, AuthMethodKind::Universal.as_str())
        .await?
        .is_none()
    {
        return refused(&state, ip, &identity, "no universal auth method").await;
    }
    let now = state.clock.now();
    let Some(secret) = state
        .store
        .find_client_secret(&hash_token(&request.client_secret))
        .await?
        .filter(|s| s.identity_id == identity.id && !s.revoked && s.expires_at.is_none_or(|at| at > now))
    else {
        return refused(&state, ip, &identity, "client secret wrong, revoked or expired").await;
    };
    if !state.store.consume_client_secret(&secret.id, now).await? {
        return refused(&state, ip, &identity, "client secret has no uses left").await;
    }
    issue(
        &state,
        &identity,
        AuthMethodKind::Universal,
        client_secret_source(&secret.id),
        json!({"client_secret": secret.prefix}),
        ip,
    )
    .await
}

#[utoipa::path(post, path = "/api/v1/auth/token/renew", tag = "auth",
    responses((status = 200, body = TokenResponse)), security(("bearer" = [])))]
pub async fn renew(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
) -> ApiResult<Json<TokenResponse>> {
    if principal.token_kind == TokenKind::Session.as_str() {
        return Err(ApiError::bad_request("sessions cannot be renewed"));
    }
    let ttl = match principal.kind {
        PrincipalKind::Identity => state
            .store
            .get_identity(&principal.id)
            .await?
            .map(|i| i.token_ttl)
            .ok_or_else(ApiError::unauthorised)?,
        _ => state.config.cli_token_ttl,
    };
    let now = state.clock.now();
    let tokens = state.store.list_principal_tokens(principal.kind, &principal.id).await?;
    let record = tokens
        .into_iter()
        .find(|t| t.id == principal.token_id)
        .ok_or_else(ApiError::unauthorised)?;
    let mut expires_at = (now + ttl).min(record.max_expires_at);
    // Groups and the re-authentication setting may have changed since the token was minted.
    if record.kind == TokenKind::Cli.as_str() {
        let cap = record.created_at + crate::human::cli_max_ttl(&state, &principal.groups);
        expires_at = expires_at.min(cap);
    }
    state.store.extend_token(&record.id, expires_at).await?;
    audit(
        &state,
        &principal,
        ip,
        "auth.token-renew",
        AuditTarget::default(),
        json!({"token": record.id, "expires_at": expires_at}),
    )
    .await;
    Ok(Json(TokenResponse {
        access_token: String::new(),
        token_type: "Bearer".into(),
        expires_in: (expires_at - now).max(0),
    }))
}

#[utoipa::path(post, path = "/api/v1/auth/token/revoke", tag = "auth",
    responses((status = 204)), security(("bearer" = [])))]
pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
) -> ApiResult<axum::http::StatusCode> {
    state.store.revoke_token(&principal.token_id).await?;
    audit(
        &state,
        &principal,
        ip,
        "auth.token-revoke",
        AuditTarget::default(),
        json!({"token": principal.token_id}),
    )
    .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::net::{MockOidcHttp, MockTokenReviewer, TokenReviewResult};
    use crate::testkit::TestIssuer;
    use anyhow::{Context, bail};
    use sekret_api::ClaimBindings;
    use std::sync::Arc;

    /// Most tests need no reviewer token.
    async fn verify_kubernetes(
        jwt: &JwtVerifier,
        reviewer: &dyn TokenReviewer,
        config: &KubernetesAuthConfig,
        token: &str,
    ) -> Result<Value, LoginError> {
        super::verify_kubernetes(jwt, reviewer, config, None, token).await
    }

    fn k8s_config(mode: KubernetesMode) -> KubernetesAuthConfig {
        KubernetesAuthConfig {
            mode,
            host: Some("https://k8s.example.com:6443".into()),
            ca_cert: None,
            reviewer_jwt: None,
            issuer: Some("https://kubernetes.default.svc.cluster.local".into()),
            jwks_url: None,
            jwks: None,
            namespaces: vec!["apps".into()],
            service_accounts: vec!["web-*".into()],
            audiences: vec!["sekret".into()],
            max_token_lifetime: sekret_api::DEFAULT_MAX_TOKEN_LIFETIME,
        }
    }

    const SA: &str = "system:serviceaccount:apps:web-api";

    #[tokio::test]
    async fn jwks_mode_caps_token_lifetime() -> anyhow::Result<()> {
        let issuer = TestIssuer::new("https://kubernetes.default.svc.cluster.local");
        let mut config = k8s_config(KubernetesMode::Jwks);
        config.jwks = Some(issuer.jwks());
        let jwt = verifier(issuer.now);
        let reviewer = MockTokenReviewer::new();
        let token = |lifetime: i64| {
            issuer.sign(json!({"aud": ["sekret"], "sub": SA, "iat": issuer.now, "exp": issuer.now + lifetime}))
        };
        let hour = token(3600)?;
        let year = token(365 * 86400)?;
        assert!(verify_kubernetes(&jwt, &reviewer, &config, &hour).await.is_ok());
        assert!(matches!(
            verify_kubernetes(&jwt, &reviewer, &config, &year).await,
            Err(LoginError::Token(m)) if m.contains("max_token_lifetime")
        ));
        let no_iat = issuer.sign(json!({"aud": ["sekret"], "sub": SA, "iat": null}))?;
        assert_eq!(
            verify_kubernetes(&jwt, &reviewer, &config, &no_iat).await,
            Err(LoginError::Token("no iat".into()))
        );

        config.max_token_lifetime = 600;
        assert!(verify_kubernetes(&jwt, &reviewer, &config, &token(600)?).await.is_ok());
        assert!(verify_kubernetes(&jwt, &reviewer, &config, &hour).await.is_err());
        config.max_token_lifetime = 400 * 86400;
        assert!(verify_kubernetes(&jwt, &reviewer, &config, &year).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn token_review_mode_caps_readable_token_lifetime() -> anyhow::Result<()> {
        let mut reviewer = MockTokenReviewer::new();
        reviewer.expect_review().returning(|_| {
            Ok(TokenReviewResult {
                authenticated: true,
                username: SA.into(),
                audiences: vec!["sekret".into()],
            })
        });
        let mut config = k8s_config(KubernetesMode::TokenReview);
        let jwt = verifier(0);
        let issuer = TestIssuer::new("https://kubernetes.default.svc.cluster.local");
        let token = |lifetime: i64| issuer.sign(json!({"sub": SA, "iat": issuer.now, "exp": issuer.now + lifetime}));
        assert!(verify_kubernetes(&jwt, &reviewer, &config, &token(600)?).await.is_ok());
        assert!(matches!(
            verify_kubernetes(&jwt, &reviewer, &config, &token(86400)?).await,
            Err(LoginError::Token(_))
        ));
        let no_iat = issuer.sign(json!({"sub": SA, "iat": null}))?;
        assert_eq!(
            verify_kubernetes(&jwt, &reviewer, &config, &no_iat).await,
            Err(LoginError::Token("no iat".into()))
        );
        config.max_token_lifetime = 2 * 86400;
        assert!(
            verify_kubernetes(&jwt, &reviewer, &config, &token(86400)?)
                .await
                .is_ok()
        );
        // The lifetime cap always applies, so a token whose claims cannot be read is refused even
        // when the API server accepts it.
        for unreadable in ["opaque", "a.!!!.c", "a.bm90LWpzb24.c"] {
            assert_eq!(
                verify_kubernetes(&jwt, &reviewer, &config, unreadable).await,
                Err(LoginError::Token("claims cannot be read".into())),
                "{unreadable}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_lifetime_cap_must_be_positive() {
        let mut k8s = k8s_config(KubernetesMode::TokenReview);
        k8s.max_token_lifetime = 0;
        assert!(validate_config(&AuthMethodConfig::Kubernetes(k8s), false).is_err());
    }

    #[test]
    fn a_missing_cap_defaults_to_an_hour() -> anyhow::Result<()> {
        let config: KubernetesAuthConfig = serde_json::from_value(json!({
            "mode": "jwks", "namespaces": ["a"], "service_accounts": ["b"]
        }))?;
        assert_eq!(config.max_token_lifetime, 3600);
        Ok(())
    }

    fn verifier(now: i64) -> JwtVerifier {
        JwtVerifier::new(Arc::new(MockOidcHttp::new()), Arc::new(FixedClock::new(now)))
    }

    /// `ApiError` is not a `std::error::Error`, so `anyhow::Context` cannot wrap it.
    fn api(context: &'static str) -> impl FnOnce(ApiError) -> anyhow::Error {
        move |error| anyhow::anyhow!("{context}: {error:?}")
    }

    #[test]
    fn service_account_names() {
        assert_eq!(
            parse_service_account("system:serviceaccount:apps:web"),
            Some(("apps".into(), "web".into()))
        );
        assert_eq!(parse_service_account("system:node:x"), None);
        assert_eq!(parse_service_account("system:serviceaccount:apps:"), None);
        assert_eq!(parse_service_account("system:serviceaccount:a:b:c"), None);
    }

    #[tokio::test]
    async fn token_review_checks_bindings() -> anyhow::Result<()> {
        // The stand-in API server takes the service account from the token's subject.
        let mut reviewer = MockTokenReviewer::new();
        reviewer
            .expect_review()
            .withf(|request| request.reviewer.as_deref().map(String::as_str) == Some("reviewer-jwt"))
            .returning(|request| {
                let sub = unverified_claims(&request.token)
                    .and_then(|claims| claims["sub"].as_str().map(String::from))
                    .unwrap_or_default();
                Ok(TokenReviewResult {
                    authenticated: sub != "bad",
                    username: format!("system:serviceaccount:{sub}"),
                    audiences: vec!["sekret".into()],
                })
            });
        let config = k8s_config(KubernetesMode::TokenReview);
        let jwt = verifier(0);
        let issuer = TestIssuer::new("https://kubernetes.default.svc.cluster.local");
        let token = |sub: &str| issuer.sign(json!({"sub": sub, "iat": issuer.now, "exp": issuer.now + 600}));
        let reviewer_token = Some(Zeroizing::new("reviewer-jwt".to_string()));
        let verify = |token: String| {
            let reviewer_token = reviewer_token.clone();
            let (jwt, reviewer, config) = (&jwt, &reviewer, &config);
            async move { super::verify_kubernetes(jwt, reviewer, config, reviewer_token, &token).await }
        };
        assert!(verify(token("apps:web-1")?).await.is_ok());
        assert_eq!(
            verify(token("kube-system:web-1")?).await,
            Err(LoginError::Binding("namespace".into()))
        );
        assert_eq!(
            verify(token("apps:worker")?).await,
            Err(LoginError::Binding("service account".into()))
        );
        assert_eq!(verify(token("bad")?).await, Err(LoginError::NotAuthenticated));
        Ok(())
    }

    fn with_reviewer(token: &str) -> AuthMethodConfig {
        let mut config = k8s_config(KubernetesMode::TokenReview);
        config.reviewer_jwt = Some(token.into());
        AuthMethodConfig::Kubernetes(config)
    }

    fn reviewer_of(config: &AuthMethodConfig) -> Option<String> {
        match config {
            AuthMethodConfig::Kubernetes(k8s) => k8s.reviewer_jwt.clone(),
            _ => None,
        }
    }

    #[test]
    fn reviewer_tokens_are_sealed_redacted_and_kept() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let sealed = seal_for_storage(&root, "i1", with_reviewer("reviewer-jwt"), None).map_err(api("seal"))?;
        let stored = reviewer_of(&sealed).context("stored")?;
        assert!(!stored.contains("reviewer-jwt"));
        assert_eq!(
            reviewer_of(&redact(sealed.clone())).as_deref(),
            Some(REDACTED_CREDENTIAL)
        );

        let kept =
            seal_for_storage(&root, "i1", with_reviewer(REDACTED_CREDENTIAL), Some(&sealed)).map_err(api("keep"))?;
        assert_eq!(reviewer_of(&kept), Some(stored));
        assert!(seal_for_storage(&root, "i1", with_reviewer(REDACTED_CREDENTIAL), None).is_err());
        let AuthMethodConfig::Kubernetes(mut moved) = with_reviewer(REDACTED_CREDENTIAL) else {
            bail!("kubernetes config expected");
        };
        moved.host = Some("https://attacker.example".into());
        assert!(
            seal_for_storage(&root, "i1", AuthMethodConfig::Kubernetes(moved), Some(&sealed)).is_err(),
            "a stored token is never sent to a new host"
        );
        assert_eq!(
            reviewer_of(&seal_for_storage(&root, "i1", with_reviewer("  "), Some(&sealed)).map_err(api("clear"))?),
            None
        );

        let AuthMethodConfig::Kubernetes(k8s) = kept else {
            bail!("kubernetes config expected");
        };
        let opened = unseal_reviewer(&root, "i1", &k8s).map_err(api("unseal"))?;
        assert_eq!(opened.as_deref().map(String::as_str), Some("reviewer-jwt"));
        assert!(unseal_reviewer(&root, "i2", &k8s).is_err());
        Ok(())
    }

    #[test]
    fn a_sealed_reviewer_token_only_opens_for_its_own_cluster() -> anyhow::Result<()> {
        let root = RootKey::generate().context("root")?;
        let AuthMethodConfig::Kubernetes(sealed) =
            seal_for_storage(&root, "i1", with_reviewer("reviewer-jwt"), None).map_err(api("seal"))?
        else {
            bail!("kubernetes config expected");
        };
        // A database writer copies the sealed token but points it elsewhere.
        let mut other_host = sealed.clone();
        other_host.host = Some("https://attacker.example".into());
        let mut other_ca = sealed.clone();
        other_ca.ca_cert = Some("-----BEGIN CERTIFICATE-----\nattacker\n-----END CERTIFICATE-----".into());
        let mut other_mode = sealed.clone();
        other_mode.mode = KubernetesMode::Jwks;
        for tampered in [other_host, other_ca, other_mode] {
            assert!(unseal_reviewer(&root, "i1", &tampered).is_err(), "{:?}", tampered.host);
        }
        assert!(unseal_reviewer(&root, "i1", &sealed).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn reviewer_tokens_sealed_before_binding_are_moved_on_unlock() -> anyhow::Result<()> {
        use sekret_store::{AuthMethod, MockStore};
        let root = RootKey::generate().context("root")?;
        let mut k8s = k8s_config(KubernetesMode::TokenReview);
        k8s.reviewer_jwt = Some(seal_credential(&root, "reviewer-jwt", &legacy_context("i1")).context("seal")?);
        let method = AuthMethod {
            identity_id: "i1".into(),
            kind: "kubernetes".into(),
            config: serde_json::to_value(AuthMethodConfig::Kubernetes(k8s))?,
            created_at: 0,
        };
        let mut store = MockStore::new();
        store.expect_list_identities().returning(|| {
            Ok(vec![Identity {
                id: "i1".into(),
                name: "web".into(),
                description: String::new(),
                token_ttl: 3600,
                token_max_ttl: 3600,
                trusted_cidrs: Vec::new(),
                disabled: false,
                created_at: 0,
            }])
        });
        store
            .expect_list_auth_methods()
            .returning(move |_| Ok(vec![method.clone()]));
        let saved = Arc::new(std::sync::Mutex::new(None));
        let sink = saved.clone();
        store.expect_put_auth_method().times(1).returning(move |m| {
            if let Ok(mut slot) = sink.lock() {
                *slot = Some(m);
            }
            Ok(())
        });
        assert!(migrate_reviewer_tokens(&store, &root).await);
        let moved = saved.lock().ok().and_then(|m| m.clone()).context("saved")?;
        let AuthMethodConfig::Kubernetes(moved) = serde_json::from_value(moved.config)? else {
            bail!("kubernetes config expected");
        };
        let opened = unseal_reviewer(&root, "i1", &moved).map_err(api("unseal"))?;
        assert_eq!(opened.as_deref().map(String::as_str), Some("reviewer-jwt"));
        Ok(())
    }

    #[test]
    fn reseal_moves_reviewer_tokens_to_the_new_root() -> anyhow::Result<()> {
        let old_root = RootKey::generate().context("root")?;
        let new_root = RootKey::generate().context("root")?;
        let sealed = seal_for_storage(&old_root, "i1", with_reviewer("reviewer-jwt"), None).map_err(api("seal"))?;
        let AuthMethodConfig::Kubernetes(k8s) = reseal(&old_root, &new_root, "i1", &sealed)
            .map_err(api("reseal"))?
            .context("changed")?
        else {
            bail!("kubernetes config expected");
        };
        let opened = unseal_reviewer(&new_root, "i1", &k8s).map_err(api("unseal"))?;
        assert_eq!(opened.as_deref().map(String::as_str), Some("reviewer-jwt"));
        let plain = AuthMethodConfig::Kubernetes(k8s_config(KubernetesMode::Jwks));
        assert_eq!(reseal(&old_root, &new_root, "i1", &plain).map_err(api("reseal"))?, None);
        assert_eq!(
            reseal(&old_root, &new_root, "i1", &AuthMethodConfig::Universal).map_err(api("reseal"))?,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn token_review_upstream_errors_fail_closed() {
        let mut reviewer = MockTokenReviewer::new();
        reviewer.expect_review().returning(|_| Err(NetError::Status(403)));
        let result = verify_kubernetes(&verifier(0), &reviewer, &k8s_config(KubernetesMode::TokenReview), "t").await;
        assert_eq!(result, Err(LoginError::Upstream(NetError::Status(403))));
    }

    #[tokio::test]
    async fn jwks_mode_checks_issuer_audience_and_subject() -> anyhow::Result<()> {
        let issuer = TestIssuer::new("https://kubernetes.default.svc.cluster.local");
        let mut config = k8s_config(KubernetesMode::Jwks);
        config.jwks = Some(issuer.jwks());
        let jwt = verifier(issuer.now);
        let reviewer = MockTokenReviewer::new();
        let good = issuer.sign(json!({"aud": ["sekret"], "sub": "system:serviceaccount:apps:web-api"}))?;
        assert!(verify_kubernetes(&jwt, &reviewer, &config, &good).await.is_ok());
        let wrong_aud = issuer
            .sign(json!({"aud": ["https://kubernetes.default.svc"], "sub": "system:serviceaccount:apps:web-api"}))?;
        assert_eq!(
            verify_kubernetes(&jwt, &reviewer, &config, &wrong_aud).await,
            Err(LoginError::Binding("audience".into()))
        );
        let other_issuer = TestIssuer::new("https://evil.test")
            .sign(json!({"aud": ["sekret"], "sub": "system:serviceaccount:apps:web-api"}))?;
        assert!(matches!(
            verify_kubernetes(&jwt, &reviewer, &config, &other_issuer).await,
            Err(LoginError::Token(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn oidc_login_applies_bindings() -> anyhow::Result<()> {
        let issuer = TestIssuer::new("https://token.actions.githubusercontent.com");
        let config = OidcAuthConfig {
            issuer: issuer.url.clone(),
            jwks_url: Some(issuer.jwks_url()),
            bindings: ClaimBindings {
                audiences: vec!["sekret".into()],
                subjects: vec!["repo:sam-ruff/*:ref:refs/heads/main".into()],
                claims: Default::default(),
            },
        };
        let mut http = MockOidcHttp::new();
        let jwks = issuer.jwks();
        http.expect_get_json().returning(move |_| Ok(jwks.clone()));
        let jwt = JwtVerifier::new(Arc::new(http), Arc::new(FixedClock::new(issuer.now)));
        let good = issuer.sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main"}))?;
        assert!(verify_oidc(&jwt, &config, &good).await.is_ok());
        let branch = issuer.sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/dev"}))?;
        assert!(matches!(
            verify_oidc(&jwt, &config, &branch).await,
            Err(LoginError::Binding(_))
        ));
        Ok(())
    }

    #[test]
    fn config_validation() {
        let mut k8s = k8s_config(KubernetesMode::TokenReview);
        assert!(validate_config(&AuthMethodConfig::Kubernetes(k8s.clone()), false).is_ok());
        k8s.namespaces.clear();
        assert!(validate_config(&AuthMethodConfig::Kubernetes(k8s), false).is_err());
        let mut jwks = k8s_config(KubernetesMode::Jwks);
        assert!(validate_config(&AuthMethodConfig::Kubernetes(jwks.clone()), false).is_err());
        jwks.jwks = Some(json!({"keys": []}));
        assert!(validate_config(&AuthMethodConfig::Kubernetes(jwks), false).is_ok());
        let oidc = OidcAuthConfig {
            issuer: "http://insecure".into(),
            jwks_url: None,
            bindings: ClaimBindings {
                audiences: vec!["a".into()],
                subjects: vec!["*".into()],
                claims: Default::default(),
            },
        };
        assert!(validate_config(&AuthMethodConfig::Oidc(oidc.clone()), false).is_err());
        assert!(validate_config(&AuthMethodConfig::Oidc(oidc), true).is_ok());
    }
}
