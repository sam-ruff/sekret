//! Typed HTTP client for the sekret API, used by the CLI and the Kubernetes operator.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use sekret_api::{
    BatchResult, BatchWrite, CliPollRequest, CliStartResponse, CreateProject, Environment, ErrorBody, GenerateSecret,
    JwtLoginRequest, Me, PolicyOverride, Project, RawSecrets, RestoreRequest, RollbackRequest, Secret, SecretList,
    SecretPolicy, SecretPolicyView, SecretVersion, Snapshot, TokenResponse, UniversalLoginRequest,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("{message} ({status} {code})")]
    Api { status: u16, code: String, message: String },
    #[error("could not reach the server: {0}")]
    Network(String),
    #[error("unexpected response: {0}")]
    Decode(String),
    #[error("invalid configuration: {0}")]
    Config(String),
}

impl ClientError {
    pub fn code(&self) -> Option<&str> {
        match self {
            ClientError::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            ClientError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }
}

pub type ClientResult<T> = Result<T, ClientError>;

/// Identifies a secret or folder within a project environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub project: String,
    pub environment: String,
    pub path: String,
}

/// Every remote call the CLI and operator make.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait SekretApi: Send + Sync {
    async fn cli_start(&self) -> ClientResult<CliStartResponse>;
    async fn cli_poll(&self, device_code: String) -> ClientResult<TokenResponse>;
    async fn oidc_login(&self, identity_id: String, token: String) -> ClientResult<TokenResponse>;
    async fn kubernetes_login(&self, identity_id: String, token: String) -> ClientResult<TokenResponse>;
    async fn universal_login(&self, client_id: String, client_secret: String) -> ClientResult<TokenResponse>;
    async fn revoke(&self) -> ClientResult<()>;
    async fn me(&self) -> ClientResult<Me>;
    async fn list_projects(&self) -> ClientResult<Vec<Project>>;
    async fn create_project(&self, request: CreateProject) -> ClientResult<Project>;
    async fn list_environments(&self, project: String) -> ClientResult<Vec<Environment>>;
    async fn list_secrets(&self, at: Location, recursive: bool, values: bool) -> ClientResult<SecretList>;
    async fn get_secret(&self, at: Location, key: String) -> ClientResult<Secret>;
    async fn write(&self, at: Location, batch: BatchWrite) -> ClientResult<BatchResult>;
    async fn versions(&self, at: Location, key: String, values: bool) -> ClientResult<Vec<SecretVersion>>;
    async fn rollback(&self, at: Location, key: String, version: i64) -> ClientResult<BatchResult>;
    async fn generate(&self, at: Location, key: String, request: GenerateSecret) -> ClientResult<BatchResult>;
    async fn secret_policy(&self, at: Location, key: String) -> ClientResult<SecretPolicyView>;
    async fn set_secret_policy(
        &self,
        at: Location,
        key: String,
        policy: PolicyOverride,
    ) -> ClientResult<SecretPolicyView>;
    async fn project_policy(&self, project: String) -> ClientResult<SecretPolicy>;
    async fn set_project_policy(&self, project: String, policy: SecretPolicy) -> ClientResult<SecretPolicy>;
    async fn raw(&self, at: Location, recursive: bool) -> ClientResult<RawSecrets>;
    async fn snapshots(&self, project: String, environment: String) -> ClientResult<Vec<Snapshot>>;
    async fn restore(&self, at: Location, snapshot: String) -> ClientResult<BatchResult>;
}

pub struct HttpClient {
    http: reqwest::Client,
    base: url::Url,
    token: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
    /// Extra PEM CA certificates to trust, for example a private root.
    pub ca_pem: Option<Vec<u8>>,
    /// PEM client certificate chain followed by its private key, for servers that require mTLS.
    pub identity_pem: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
}

/// Joins a PEM certificate chain and a PEM private key into the form `identity_pem` expects.
/// Both or neither must be given.
pub fn identity_from_files(
    cert: Option<&std::path::Path>,
    key: Option<&std::path::Path>,
) -> ClientResult<Option<Vec<u8>>> {
    let (cert, key) = match (cert, key) {
        (None, None) => return Ok(None),
        (Some(cert), Some(key)) => (cert, key),
        _ => {
            return Err(ClientError::Config(
                "a client certificate needs both a certificate and a key".into(),
            ));
        }
    };
    let read = |path: &std::path::Path| {
        std::fs::read(path).map_err(|e| ClientError::Config(format!("reading {}: {e}", path.display())))
    };
    let mut pem = read(cert)?;
    pem.push(b'\n');
    pem.extend(read(key)?);
    Ok(Some(pem))
}

impl HttpClient {
    pub fn new(base: &str, token: Option<String>, options: ClientOptions) -> ClientResult<Self> {
        let base = url::Url::parse(base).map_err(|e| ClientError::Config(format!("server url: {e}")))?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(ClientError::Config("server url must be http or https".into()));
        }
        let mut builder = reqwest::Client::builder()
            .timeout(options.timeout.unwrap_or(Duration::from_secs(30)))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("sekret-client/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = options.ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| ClientError::Config(format!("CA bundle: {e}")))?;
            builder = builder.tls_certs_merge(certs);
        }
        if let Some(pem) = options.identity_pem {
            let identity = reqwest::Identity::from_pem(&pem)
                .map_err(|e| ClientError::Config(format!("client certificate: {e}")))?;
            builder = builder.identity(identity);
        }
        let http = builder.build().map_err(|e| ClientError::Config(e.to_string()))?;
        Ok(Self { http, base, token })
    }

    fn url(&self, segments: &[&str], query: &[(&str, String)]) -> ClientResult<url::Url> {
        let mut url = self.base.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| ClientError::Config("server url cannot be a base".into()))?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        Ok(url)
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: Method,
        url: url::Url,
        body: Option<&dyn ErasedBody>,
    ) -> ClientResult<T> {
        let mut request = self.http.request(method, url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body.as_json());
        }
        let response = request.send().await.map_err(|e| ClientError::Network(e.to_string()))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        if !status.is_success() {
            let error: Option<ErrorBody> = serde_json::from_slice(&bytes).ok();
            return Err(ClientError::Api {
                status: status.as_u16(),
                code: error.as_ref().map(|e| e.error.clone()).unwrap_or_else(|| "http".into()),
                message: error
                    .map(|e| e.message)
                    .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").into()),
            });
        }
        let bytes = if status == StatusCode::NO_CONTENT || bytes.is_empty() {
            &b"null"[..]
        } else {
            &bytes[..]
        };
        serde_json::from_slice(bytes).map_err(|e| ClientError::Decode(e.to_string()))
    }

    fn secrets_url(&self, at: &Location, tail: &[&str], query: &[(&str, String)]) -> ClientResult<url::Url> {
        let mut segments = vec!["api", "v1", "projects", &at.project, "environments", &at.environment];
        segments.extend_from_slice(tail);
        self.url(&segments, query)
    }
}

/// Lets request bodies of different types share one send path.
trait ErasedBody: Send + Sync {
    fn as_json(&self) -> serde_json::Value;
}

impl<T: Serialize + Send + Sync> ErasedBody for T {
    fn as_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[async_trait]
impl SekretApi for HttpClient {
    async fn cli_start(&self) -> ClientResult<CliStartResponse> {
        self.send(
            Method::POST,
            self.url(&["api", "v1", "auth", "cli", "start"], &[])?,
            None,
        )
        .await
    }

    async fn cli_poll(&self, device_code: String) -> ClientResult<TokenResponse> {
        let body = CliPollRequest { device_code };
        self.send(
            Method::POST,
            self.url(&["api", "v1", "auth", "cli", "poll"], &[])?,
            Some(&body),
        )
        .await
    }

    async fn oidc_login(&self, identity_id: String, token: String) -> ClientResult<TokenResponse> {
        let body = JwtLoginRequest { identity_id, token };
        self.send(
            Method::POST,
            self.url(&["api", "v1", "auth", "oidc", "login"], &[])?,
            Some(&body),
        )
        .await
    }

    async fn kubernetes_login(&self, identity_id: String, token: String) -> ClientResult<TokenResponse> {
        let body = JwtLoginRequest { identity_id, token };
        self.send(
            Method::POST,
            self.url(&["api", "v1", "auth", "kubernetes", "login"], &[])?,
            Some(&body),
        )
        .await
    }

    async fn universal_login(&self, client_id: String, client_secret: String) -> ClientResult<TokenResponse> {
        let body = UniversalLoginRequest {
            client_id,
            client_secret,
        };
        self.send(
            Method::POST,
            self.url(&["api", "v1", "auth", "universal", "login"], &[])?,
            Some(&body),
        )
        .await
    }

    async fn revoke(&self) -> ClientResult<()> {
        self.send(
            Method::POST,
            self.url(&["api", "v1", "auth", "token", "revoke"], &[])?,
            None,
        )
        .await
    }

    async fn me(&self) -> ClientResult<Me> {
        self.send(Method::GET, self.url(&["api", "v1", "me"], &[])?, None).await
    }

    async fn list_projects(&self) -> ClientResult<Vec<Project>> {
        self.send(Method::GET, self.url(&["api", "v1", "projects"], &[])?, None)
            .await
    }

    async fn create_project(&self, request: CreateProject) -> ClientResult<Project> {
        self.send(Method::POST, self.url(&["api", "v1", "projects"], &[])?, Some(&request))
            .await
    }

    async fn list_environments(&self, project: String) -> ClientResult<Vec<Environment>> {
        self.send(
            Method::GET,
            self.url(&["api", "v1", "projects", &project, "environments"], &[])?,
            None,
        )
        .await
    }

    async fn list_secrets(&self, at: Location, recursive: bool, values: bool) -> ClientResult<SecretList> {
        let query = [
            ("path", at.path.clone()),
            ("recursive", recursive.to_string()),
            ("values", values.to_string()),
        ];
        self.send(Method::GET, self.secrets_url(&at, &["secrets"], &query)?, None)
            .await
    }

    async fn get_secret(&self, at: Location, key: String) -> ClientResult<Secret> {
        self.send(
            Method::GET,
            self.secrets_url(&at, &["secrets", &key], &[("path", at.path.clone())])?,
            None,
        )
        .await
    }

    async fn write(&self, at: Location, batch: BatchWrite) -> ClientResult<BatchResult> {
        let batch = BatchWrite {
            path: at.path.clone(),
            ..batch
        };
        self.send(
            Method::POST,
            self.secrets_url(&at, &["secrets", "batch"], &[])?,
            Some(&batch),
        )
        .await
    }

    async fn versions(&self, at: Location, key: String, values: bool) -> ClientResult<Vec<SecretVersion>> {
        let query = [("path", at.path.clone()), ("values", values.to_string())];
        self.send(
            Method::GET,
            self.secrets_url(&at, &["secrets", &key, "versions"], &query)?,
            None,
        )
        .await
    }

    async fn rollback(&self, at: Location, key: String, version: i64) -> ClientResult<BatchResult> {
        let url = self.secrets_url(&at, &["secrets", &key, "rollback"], &[("path", at.path.clone())])?;
        self.send(Method::POST, url, Some(&RollbackRequest { version })).await
    }

    async fn generate(&self, at: Location, key: String, request: GenerateSecret) -> ClientResult<BatchResult> {
        let url = self.secrets_url(&at, &["secrets", &key, "generate"], &[("path", at.path.clone())])?;
        self.send(Method::POST, url, Some(&request)).await
    }

    async fn secret_policy(&self, at: Location, key: String) -> ClientResult<SecretPolicyView> {
        let url = self.secrets_url(&at, &["secrets", &key, "policy"], &[("path", at.path.clone())])?;
        self.send(Method::GET, url, None).await
    }

    async fn set_secret_policy(
        &self,
        at: Location,
        key: String,
        policy: PolicyOverride,
    ) -> ClientResult<SecretPolicyView> {
        let url = self.secrets_url(&at, &["secrets", &key, "policy"], &[("path", at.path.clone())])?;
        self.send(Method::PUT, url, Some(&policy)).await
    }

    async fn project_policy(&self, project: String) -> ClientResult<SecretPolicy> {
        let url = self.url(&["api", "v1", "projects", &project, "secret-policy"], &[])?;
        self.send(Method::GET, url, None).await
    }

    async fn set_project_policy(&self, project: String, policy: SecretPolicy) -> ClientResult<SecretPolicy> {
        let url = self.url(&["api", "v1", "projects", &project, "secret-policy"], &[])?;
        self.send(Method::PUT, url, Some(&policy)).await
    }

    async fn raw(&self, at: Location, recursive: bool) -> ClientResult<RawSecrets> {
        let query = [
            ("project", at.project.clone()),
            ("environment", at.environment.clone()),
            ("path", at.path.clone()),
            ("recursive", recursive.to_string()),
        ];
        self.send(Method::GET, self.url(&["api", "v1", "secrets", "raw"], &query)?, None)
            .await
    }

    async fn snapshots(&self, project: String, environment: String) -> ClientResult<Vec<Snapshot>> {
        let at = Location {
            project,
            environment,
            path: "/".into(),
        };
        self.send(Method::GET, self.secrets_url(&at, &["snapshots"], &[])?, None)
            .await
    }

    async fn restore(&self, at: Location, snapshot: String) -> ClientResult<BatchResult> {
        let body = RestoreRequest { path: at.path.clone() };
        self.send(
            Method::POST,
            self.secrets_url(&at, &["snapshots", &snapshot, "restore"], &[])?,
            Some(&body),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer, token: Option<&str>) -> anyhow::Result<HttpClient> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        HttpClient::new(&server.uri(), token.map(String::from), ClientOptions::default()).context("client")
    }

    fn at() -> Location {
        Location {
            project: "app".into(),
            environment: "prod".into(),
            path: "/db".into(),
        }
    }

    #[tokio::test]
    async fn sends_bearer_token_and_query() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/secrets/raw"))
            .and(query_param("project", "app"))
            .and(query_param("path", "/db"))
            .and(query_param("recursive", "true"))
            .and(header("authorization", "Bearer skt_x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "project": "app", "environment": "prod", "secrets": [{"path": "/db", "key": "A", "value": "1"}]
            })))
            .mount(&server)
            .await;
        let raw = client(&server, Some("skt_x"))?.raw(at(), true).await.context("raw")?;
        assert_eq!(raw.secrets[0].value, "1");
        Ok(())
    }

    #[tokio::test]
    async fn writes_use_the_location_path() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/projects/app/environments/prod/secrets/batch"))
            .and(body_json(json!({"path": "/db", "upserts": [{"key": "A", "value": "1", "comment": "", "tags": null}], "deletes": []})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "created": ["A"], "updated": [], "deleted": [], "unchanged": [], "snapshot_id": "s"
            })))
            .mount(&server)
            .await;
        let batch = BatchWrite {
            path: "/ignored".into(),
            upserts: vec![sekret_api::SecretUpsert {
                key: "A".into(),
                value: "1".into(),
                comment: String::new(),
                tags: None,
            }],
            deletes: vec![],
        };
        let result = client(&server, None)?.write(at(), batch).await.context("write")?;
        assert_eq!(result.created, vec!["A".to_string()]);
        Ok(())
    }

    #[tokio::test]
    async fn api_errors_carry_status_and_code() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/cli/poll"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({"error": "authorization_pending", "message": "waiting"})),
            )
            .mount(&server)
            .await;
        let error = client(&server, None)?
            .cli_poll("d".into())
            .await
            .err()
            .context("expected a pending error")?;
        assert_eq!(error.code(), Some("authorization_pending"));
        assert_eq!(error.status(), Some(400));
        Ok(())
    }

    #[tokio::test]
    async fn no_content_and_network_errors() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/token/revoke"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        assert_eq!(client(&server, Some("t"))?.revoke().await, Ok(()));
        let dead = HttpClient::new("http://127.0.0.1:9", None, ClientOptions::default()).context("client")?;
        assert!(matches!(dead.me().await, Err(ClientError::Network(_))));
        Ok(())
    }

    #[test]
    fn rejects_bad_urls_and_encodes_segments() -> anyhow::Result<()> {
        assert!(HttpClient::new("ftp://x", None, ClientOptions::default()).is_err());
        let _ = rustls::crypto::ring::default_provider().install_default();
        let c =
            HttpClient::new("https://sekret.example.com/base/", None, ClientOptions::default()).context("client")?;
        let url = c.url(&["api", "a b/c"], &[]).context("url")?;
        assert_eq!(url.as_str(), "https://sekret.example.com/base/api/a%20b%2Fc");
        Ok(())
    }
}
