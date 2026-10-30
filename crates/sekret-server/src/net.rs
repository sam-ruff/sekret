use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetError {
    #[error("url not allowed: {0}")]
    UrlNotAllowed(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("unexpected status {0}")]
    Status(u16),
    #[error("response was not valid JSON")]
    Json,
    #[error("response too large")]
    TooLarge,
}

/// Outbound HTTP used for OIDC discovery, JWKS and code exchange.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait OidcHttp: Send + Sync {
    async fn get_json(&self, url: &str) -> Result<Value, NetError>;
    async fn post_form(&self, url: &str, form: Vec<(String, String)>) -> Result<Value, NetError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenReviewResult {
    pub authenticated: bool,
    pub username: String,
    pub audiences: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenReviewRequest {
    pub host: String,
    pub ca_pem: Option<String>,
    /// Bearer for the review call; the reviewed token itself when absent.
    pub reviewer: Option<String>,
    pub token: String,
    pub audiences: Vec<String>,
}

impl TokenReviewRequest {
    pub fn bearer(&self) -> &str {
        self.reviewer.as_deref().unwrap_or(&self.token)
    }
}

/// Kubernetes TokenReview.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TokenReviewer: Send + Sync {
    async fn review(&self, request: TokenReviewRequest) -> Result<TokenReviewResult, NetError>;
}

/// Refuses anything but https (or http when explicitly allowed) and URLs carrying credentials.
pub fn check_outbound_url(raw: &str, allow_http: bool) -> Result<url::Url, NetError> {
    let parsed = url::Url::parse(raw).map_err(|_| NetError::UrlNotAllowed(raw.to_string()))?;
    let scheme_ok = parsed.scheme() == "https" || (allow_http && parsed.scheme() == "http");
    if !scheme_ok || !parsed.username().is_empty() || parsed.password().is_some() || parsed.host().is_none() {
        return Err(NetError::UrlNotAllowed(raw.to_string()));
    }
    Ok(parsed)
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("sekret/", env!("CARGO_PKG_VERSION")))
}

async fn read_json(mut response: reqwest::Response) -> Result<Value, NetError> {
    let status = response.status();
    if !status.is_success() {
        return Err(NetError::Status(status.as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| NetError::Request(e.to_string()))? {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(NetError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| NetError::Json)
}

pub struct ReqwestOidcHttp {
    client: reqwest::Client,
    allow_http: bool,
}

impl ReqwestOidcHttp {
    pub fn new(allow_http: bool) -> Result<Self, NetError> {
        let client = client_builder().build().map_err(|e| NetError::Request(e.to_string()))?;
        Ok(Self { client, allow_http })
    }
}

#[async_trait]
impl OidcHttp for ReqwestOidcHttp {
    async fn get_json(&self, url: &str) -> Result<Value, NetError> {
        let url = check_outbound_url(url, self.allow_http)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| NetError::Request(e.to_string()))?;
        read_json(response).await
    }

    async fn post_form(&self, url: &str, form: Vec<(String, String)>) -> Result<Value, NetError> {
        let url = check_outbound_url(url, self.allow_http)?;
        let response = self
            .client
            .post(url)
            .form(&form)
            .send()
            .await
            .map_err(|e| NetError::Request(e.to_string()))?;
        read_json(response).await
    }
}

pub struct ReqwestTokenReviewer {
    allow_http: bool,
}

impl ReqwestTokenReviewer {
    pub fn new(allow_http: bool) -> Self {
        Self { allow_http }
    }
}

/// Interprets a TokenReview response body.
pub fn parse_token_review(body: &Value) -> TokenReviewResult {
    let status = &body["status"];
    TokenReviewResult {
        authenticated: status["authenticated"].as_bool().unwrap_or(false),
        username: status["user"]["username"].as_str().unwrap_or_default().to_string(),
        audiences: status["audiences"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    }
}

#[async_trait]
impl TokenReviewer for ReqwestTokenReviewer {
    async fn review(&self, request: TokenReviewRequest) -> Result<TokenReviewResult, NetError> {
        let base = check_outbound_url(&request.host, self.allow_http)?;
        let url = base
            .join("/apis/authentication.k8s.io/v1/tokenreviews")
            .map_err(|_| NetError::UrlNotAllowed(request.host.clone()))?;
        let mut builder = client_builder();
        if let Some(pem) = &request.ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
                .map_err(|e| NetError::Request(format!("invalid CA bundle: {e}")))?;
            builder = builder.tls_certs_only(certs);
        }
        let client = builder.build().map_err(|e| NetError::Request(e.to_string()))?;
        let body = serde_json::json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": { "token": request.token, "audiences": request.audiences },
        });
        let response = client
            .post(url)
            .bearer_auth(request.bearer())
            .json(&body)
            .send()
            .await
            .map_err(|e| NetError::Request(e.to_string()))?;
        Ok(parse_token_review(&read_json(response).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn outbound_urls_are_restricted() {
        assert!(check_outbound_url("https://auth.example.com/realms/main", false).is_ok());
        assert!(check_outbound_url("http://auth.example.com", false).is_err());
        assert!(check_outbound_url("http://auth.example.com", true).is_ok());
        assert!(check_outbound_url("file:///etc/passwd", true).is_err());
        assert!(check_outbound_url("https://user:pass@host", false).is_err());
        assert!(check_outbound_url("not a url", true).is_err());
    }

    #[test]
    fn token_review_parsing() {
        let body = serde_json::json!({"status": {"authenticated": true, "user": {"username": "system:serviceaccount:apps:web"}, "audiences": ["sekret"]}});
        let result = parse_token_review(&body);
        assert!(result.authenticated);
        assert_eq!(result.username, "system:serviceaccount:apps:web");
        assert_eq!(result.audiences, vec!["sekret".to_string()]);
        assert!(!parse_token_review(&serde_json::json!({})).authenticated);
    }

    fn review_request(server: &wiremock::MockServer, reviewer: Option<&str>) -> TokenReviewRequest {
        let _ = rustls::crypto::ring::default_provider().install_default();
        TokenReviewRequest {
            host: server.uri(),
            ca_pem: None,
            reviewer: reviewer.map(String::from),
            token: "workload-token".into(),
            audiences: vec!["sekret".into()],
        }
    }

    #[tokio::test]
    async fn review_authenticates_with_the_reviewer_token_when_set() -> anyhow::Result<()> {
        use wiremock::matchers::{body_partial_json, header, method, path};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/apis/authentication.k8s.io/v1/tokenreviews"))
            .and(header("authorization", "Bearer reviewer-token"))
            .and(body_partial_json(
                serde_json::json!({"spec": {"token": "workload-token", "audiences": ["sekret"]}}),
            ))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "status": {"authenticated": true, "user": {"username": "system:serviceaccount:apps:web"}}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let result = ReqwestTokenReviewer::new(true)
            .review(review_request(&server, Some("reviewer-token")))
            .await
            .context("review")?;
        assert!(result.authenticated);
        Ok(())
    }

    #[tokio::test]
    async fn review_falls_back_to_the_presented_token() -> anyhow::Result<()> {
        use wiremock::matchers::{header, method};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(header("authorization", "Bearer workload-token"))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({"status": {}})))
            .expect(1)
            .mount(&server)
            .await;
        let result = ReqwestTokenReviewer::new(true)
            .review(review_request(&server, None))
            .await
            .context("review")?;
        assert!(!result.authenticated);
        Ok(())
    }
}
