use axum::Json;
use axum::extract::State;
use sekret_api::{
    AuthMethodConfig, AuthMethodKind, JwtLoginRequest, KubernetesAuthConfig, KubernetesMode, OidcAuthConfig,
    REDACTED_CREDENTIAL, TokenResponse, UniversalLoginRequest,
};
use sekret_core::crypto::{RootKey, hash_token, open_credential, seal_credential};
use sekret_core::glob::glob_match;
use sekret_store::{Identity, PrincipalKind};
use serde_json::{Value, json};

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

fn credential_context(identity_id: &str) -> String {
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
        Some(value) => Some(seal_credential(root, value.trim(), &credential_context(identity_id))?),
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

pub fn unseal_reviewer(root: &RootKey, identity_id: &str, k8s: &mut KubernetesAuthConfig) -> ApiResult<()> {
    let Some(sealed) = &k8s.reviewer_jwt else {
        return Ok(());
    };
    let plain = open_credential(root, sealed, &credential_context(identity_id))
        .map_err(|e| ApiError::internal("opening reviewer token", e))?;
    k8s.reviewer_jwt = Some(plain.to_string());
    Ok(())
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
    if k8s.reviewer_jwt.is_none() {
        return Ok(None);
    }
    let mut k8s = k8s.clone();
    unseal_reviewer(old_root, identity_id, &mut k8s)?;
    seal_for_storage(new_root, identity_id, AuthMethodConfig::Kubernetes(k8s), None).map(Some)
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

pub async fn verify_kubernetes(
    jwt: &JwtVerifier,
    reviewer: &dyn TokenReviewer,
    config: &KubernetesAuthConfig,
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
                    reviewer: config.reviewer_jwt.clone(),
                    token: token.to_string(),
                    audiences: config.audiences.clone(),
                })
                .await?;
            // An empty list means the token is only valid for the API server itself.
            let audience_ok = review.audiences.iter().any(|a| config.audiences.contains(a));
            if !review.authenticated || !audience_ok {
                return Err(LoginError::NotAuthenticated);
            }
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
    if !state.login_limiter.allow(&ip) {
        return Err(ApiError::too_many_requests());
    }
    let identity = state
        .store
        .get_identity(identity_id)
        .await?
        .ok_or_else(ApiError::login_failed)?;
    if identity.disabled || !ip_allowed(&identity.trusted_cidrs, ip) {
        return Err(ApiError::login_failed());
    }
    Ok(identity)
}

async fn method_config(state: &AppState, identity: &Identity, kind: AuthMethodKind) -> ApiResult<AuthMethodConfig> {
    let method = state
        .store
        .get_auth_method(&identity.id, kind.as_str())
        .await?
        .ok_or_else(ApiError::login_failed)?;
    serde_json::from_value(method.config).map_err(|e| ApiError::internal("auth method config", e))
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

fn rejected(identity: &Identity, error: LoginError) -> ApiError {
    tracing::warn!(identity = %identity.name, %error, "machine login rejected");
    ApiError::login_failed()
}

#[utoipa::path(post, path = "/api/v1/auth/oidc/login", tag = "auth", request_body = JwtLoginRequest,
    responses((status = 200, body = TokenResponse), (status = 401, body = sekret_api::ErrorBody)))]
pub async fn oidc_login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<JwtLoginRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let identity = login_identity(&state, &request.identity_id, ip).await?;
    let AuthMethodConfig::Oidc(config) = method_config(&state, &identity, AuthMethodKind::Oidc).await? else {
        return Err(ApiError::login_failed());
    };
    let claims = verify_oidc(&state.jwt, &config, &request.token)
        .await
        .map_err(|e| rejected(&identity, e))?;
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
    let AuthMethodConfig::Kubernetes(mut config) = method_config(&state, &identity, AuthMethodKind::Kubernetes).await?
    else {
        return Err(ApiError::login_failed());
    };
    unseal_reviewer(&state.root_key, &identity.id, &mut config)?;
    let detail = verify_kubernetes(&state.jwt, state.token_reviewer.as_ref(), &config, &request.token)
        .await
        .map_err(|e| rejected(&identity, e))?;
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
        return Err(ApiError::login_failed());
    }
    let now = state.clock.now();
    let secret = state
        .store
        .find_client_secret(&hash_token(&request.client_secret))
        .await?
        .filter(|s| s.identity_id == identity.id && !s.revoked && s.expires_at.is_none_or(|at| at > now))
        .ok_or_else(ApiError::login_failed)?;
    if !state.store.consume_client_secret(&secret.id, now).await? {
        return Err(ApiError::login_failed());
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
    let expires_at = (now + ttl).min(record.max_expires_at);
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
        expires_in: expires_at - now,
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
        }
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
    async fn token_review_checks_bindings() {
        let mut reviewer = MockTokenReviewer::new();
        reviewer
            .expect_review()
            .withf(|request| request.reviewer.as_deref() == Some("reviewer-jwt"))
            .returning(|request| {
                Ok(TokenReviewResult {
                    authenticated: request.token != "bad",
                    username: format!("system:serviceaccount:{}", request.token),
                    audiences: vec!["sekret".into()],
                })
            });
        let mut config = k8s_config(KubernetesMode::TokenReview);
        config.reviewer_jwt = Some("reviewer-jwt".into());
        let jwt = verifier(0);
        assert!(verify_kubernetes(&jwt, &reviewer, &config, "apps:web-1").await.is_ok());
        assert_eq!(
            verify_kubernetes(&jwt, &reviewer, &config, "kube-system:web-1").await,
            Err(LoginError::Binding("namespace".into()))
        );
        assert_eq!(
            verify_kubernetes(&jwt, &reviewer, &config, "apps:worker").await,
            Err(LoginError::Binding("service account".into()))
        );
        assert_eq!(
            verify_kubernetes(&jwt, &reviewer, &config, "bad").await,
            Err(LoginError::NotAuthenticated)
        );
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

        let AuthMethodConfig::Kubernetes(mut k8s) = kept else {
            bail!("kubernetes config expected");
        };
        let mut other_identity = k8s.clone();
        unseal_reviewer(&root, "i1", &mut k8s).map_err(api("unseal"))?;
        assert_eq!(k8s.reviewer_jwt.as_deref(), Some("reviewer-jwt"));
        assert!(unseal_reviewer(&root, "i2", &mut other_identity).is_err());
        Ok(())
    }

    #[test]
    fn reseal_moves_reviewer_tokens_to_the_new_root() -> anyhow::Result<()> {
        let old_root = RootKey::generate().context("root")?;
        let new_root = RootKey::generate().context("root")?;
        let sealed = seal_for_storage(&old_root, "i1", with_reviewer("reviewer-jwt"), None).map_err(api("seal"))?;
        let AuthMethodConfig::Kubernetes(mut k8s) = reseal(&old_root, &new_root, "i1", &sealed)
            .map_err(api("reseal"))?
            .context("changed")?
        else {
            bail!("kubernetes config expected");
        };
        unseal_reviewer(&new_root, "i1", &mut k8s).map_err(api("unseal"))?;
        assert_eq!(k8s.reviewer_jwt.as_deref(), Some("reviewer-jwt"));
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
