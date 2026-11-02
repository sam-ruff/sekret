//! Typed HTTP client for the sekret API, used by the CLI and the Kubernetes operator.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use sekret_api::{
    BatchResult, BatchWrite, ChangePassphrase, CliPollRequest, CliStartResponse, CreateProject, Environment, ErrorBody,
    GenerateSecret, InitRequest, InitResponse, JwtLoginRequest, Me, PolicyOverride, Project, RawSecrets,
    RestoreRequest, RollbackRequest, Secret, SecretList, SecretPolicy, SecretPolicyView, SecretVersion,
    SetUnlockPolicy, Snapshot, SysStatus, TokenResponse, UniversalLoginRequest, UnsealRequest,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("{message} ({status} {code})")]
    Api {
        status: u16,
        code: String,
        message: String,
        /// Seconds from the response's `Retry-After` header, when it had one.
        retry_after: Option<u64>,
    },
    #[error("could not reach the server: {0}")]
    Network(String),
    #[error("unexpected response: {0}")]
    Decode(String),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("the server's response is larger than the {limit} bytes allowed")]
    TooLarge { limit: usize },
}

/// The most any JSON response may hold, so a hostile server cannot exhaust memory.
pub const RESPONSE_LIMIT: usize = 32 * 1024 * 1024;
/// The most a backup download may hold, which matches the server's own backup cap.
pub const BACKUP_RESPONSE_LIMIT: usize = 1 << 30;

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

    /// How long the server asked the client to wait before trying again.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            ClientError::Api { retry_after, .. } => retry_after.map(Duration::from_secs),
            _ => None,
        }
    }
}

/// `Retry-After` in its delta-seconds form; an HTTP date is ignored.
fn parse_retry_after(value: &str) -> Option<u64> {
    value.trim().parse().ok()
}

pub type ClientResult<T> = Result<T, ClientError>;

/// Server-supplied text made safe to print: control characters other than newline and tab,
/// escape sequences and bidirectional overrides are removed, so a server cannot rewrite the
/// terminal or disguise what it shows.
pub fn terminal_safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            skip_escape_sequence(&mut chars);
            continue;
        }
        if c == '\n' || c == '\t' || !is_unprintable(c) {
            out.push(c);
        }
    }
    out
}

/// JSON text with the C1 controls and bidirectional overrides serde_json leaves raw written as
/// `\uXXXX` escapes, so it reads the same to a parser but cannot rewrite the terminal.
pub fn terminal_safe_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c != '\n' && c != '\t' && c != '\r' && is_unprintable(c) {
            // Every such character is in the Basic Multilingual Plane, so one escape is enough.
            out.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

fn is_unprintable(c: char) -> bool {
    c.is_control() || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Drops the rest of an escape sequence: CSI up to its final byte, OSC, DCS and similar strings
/// up to their terminator, otherwise the single character after the escape.
fn skip_escape_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.next() {
        Some('[') => {
            for c in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    break;
                }
            }
        }
        Some(']' | 'P' | 'X' | '^' | '_') => {
            while let Some(c) = chars.next() {
                if c == '\u{7}' || c == '\u{9c}' {
                    break;
                }
                if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                    chars.next();
                    break;
                }
            }
        }
        _ => {}
    }
}

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
    async fn sys_status(&self) -> ClientResult<SysStatus>;
    /// Every status field; organisation admins only.
    async fn sys_status_detail(&self) -> ClientResult<SysStatus>;
    async fn sys_init(&self, request: InitRequest) -> ClientResult<InitResponse>;
    async fn sys_unseal(&self, request: UnsealRequest) -> ClientResult<SysStatus>;
    async fn sys_seal(&self) -> ClientResult<SysStatus>;
    async fn sys_change_passphrase(&self, request: ChangePassphrase) -> ClientResult<()>;
    /// `remember` and `passphrase-file` need the current passphrase.
    async fn sys_set_unlock_policy(&self, request: SetUnlockPolicy) -> ClientResult<SysStatus>;
    async fn sys_forget_unlock(&self) -> ClientResult<SysStatus>;
    /// The encrypted `.skb` file.
    async fn sys_backup(&self) -> ClientResult<Vec<u8>>;
}

pub struct HttpClient {
    transport: Transport,
    base: url::Url,
    token: Option<String>,
}

enum Transport {
    Reqwest(reqwest::Client),
    /// One already connected and checked Unix socket connection, used for every request.
    #[cfg(unix)]
    Stream(pinned::StreamTransport),
}

/// Reads a body in chunks and stops once it passes `limit`.
async fn read_limited_body(mut response: reqwest::Response, limit: usize) -> ClientResult<Vec<u8>> {
    if response.content_length().is_some_and(|len| len > limit as u64) {
        return Err(ClientError::TooLarge { limit });
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ClientError::Network(e.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(ClientError::TooLarge { limit });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(unix)]
mod pinned {
    use std::time::Duration;

    use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
    use hyper::body::Bytes;
    use hyper::client::conn::http1::SendRequest;
    use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT};
    use hyper_util::rt::TokioIo;
    use reqwest::{Method, StatusCode};

    use super::{ClientError, ClientResult};

    pub(super) struct StreamTransport {
        sender: tokio::sync::Mutex<SendRequest<Full<Bytes>>>,
        timeout: Duration,
    }

    fn network(error: impl std::fmt::Display) -> ClientError {
        ClientError::Network(error.to_string())
    }

    impl StreamTransport {
        pub(super) async fn new(stream: tokio::net::UnixStream, timeout: Duration) -> ClientResult<Self> {
            let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(network)?;
            tokio::spawn(async move {
                // The connection ends when the client is dropped or the server hangs up.
                let _ = connection.await;
            });
            Ok(Self {
                sender: tokio::sync::Mutex::new(sender),
                timeout,
            })
        }

        pub(super) async fn send(
            &self,
            method: Method,
            url: &url::Url,
            token: Option<&str>,
            body: Option<Vec<u8>>,
            limit: usize,
        ) -> ClientResult<(StatusCode, Vec<u8>)> {
            tokio::time::timeout(self.timeout, self.exchange(method, url, token, body, limit))
                .await
                .map_err(|_| ClientError::Network("the request timed out".into()))?
        }

        async fn exchange(
            &self,
            method: Method,
            url: &url::Url,
            token: Option<&str>,
            body: Option<Vec<u8>>,
            limit: usize,
        ) -> ClientResult<(StatusCode, Vec<u8>)> {
            let target = match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().to_string(),
            };
            let mut request = hyper::Request::builder()
                .method(method)
                .uri(target)
                .header(HOST, "localhost")
                .header(USER_AGENT, format!("sekret-client/{}", sekret_api::VERSION));
            if let Some(token) = token {
                request = request.header(AUTHORIZATION, format!("Bearer {token}"));
            }
            if body.is_some() {
                request = request.header(CONTENT_TYPE, "application/json");
            }
            let request = request
                .body(Full::new(Bytes::from(body.unwrap_or_default())))
                .map_err(|e| ClientError::Config(e.to_string()))?;
            let mut sender = self.sender.lock().await;
            sender.ready().await.map_err(network)?;
            let response = sender.send_request(request).await.map_err(network)?;
            let status = response.status();
            let collected = Limited::new(response.into_body(), limit)
                .collect()
                .await
                .map_err(|error| {
                    if error.downcast_ref::<LengthLimitError>().is_some() {
                        return ClientError::TooLarge { limit };
                    }
                    network(error)
                })?;
            Ok((status, collected.to_bytes().to_vec()))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
    /// Extra PEM CA certificates to trust, for example a private root.
    pub ca_pem: Option<Vec<u8>>,
    /// PEM client certificate chain followed by its private key, for servers that require mTLS.
    pub identity_pem: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Versions asked for per history request; the server allows at most 200.
const VERSION_PAGE: usize = 200;
/// The most history versions fetched for one secret.
const MAX_VERSIONS: usize = 100_000;

/// Joins a PEM certificate chain and a PEM private key into the form `identity_pem` expects.
/// Both or neither must be given.
/// The most a PEM file may hold.
const PEM_LIMIT: u64 = 1024 * 1024;

/// Reads a regular file of at most [`PEM_LIMIT`] bytes, so a device or FIFO cannot hang or
/// exhaust the CLI.
fn read_pem(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut contents = Vec::new();
    file.take(PEM_LIMIT + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > PEM_LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("larger than {PEM_LIMIT} bytes"),
        ));
    }
    Ok(contents)
}

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
        read_pem(path).map_err(|e| ClientError::Config(format!("reading {}: {e}", path.display())))
    };
    let mut pem = read(cert)?;
    pem.push(b'\n');
    pem.extend(read(key)?);
    Ok(Some(pem))
}

/// Whether `url` names this machine: `localhost` or a loopback address.
pub fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => {
            let name = name.strip_suffix('.').unwrap_or(name);
            name.eq_ignore_ascii_case("localhost")
        }
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Whether requests to `url` must ignore `http_proxy`, `HTTPS_PROXY`, `ALL_PROXY` and the like.
///
/// A proxy would read plain http, tokens included, and would reach its own loopback rather than
/// ours, so only https to another host may go through one.
pub fn bypasses_proxy(url: &url::Url) -> bool {
    url.scheme() == "http" || is_loopback(url)
}

impl HttpClient {
    pub fn new(base: &str, token: Option<String>, options: ClientOptions) -> ClientResult<Self> {
        let base = url::Url::parse(base).map_err(|e| ClientError::Config(format!("server url: {e}")))?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(ClientError::Config("server url must be http or https".into()));
        }
        let mut builder = reqwest::Client::builder()
            .timeout(options.timeout.unwrap_or(DEFAULT_TIMEOUT))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(format!("sekret-client/{}", sekret_api::VERSION));
        if bypasses_proxy(&base) {
            builder = builder.no_proxy();
        }
        if let Some(pem) = options.ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| ClientError::Config(format!("CA bundle: {e}")))?;
            // A file of something else yields no certificates and would quietly trust only the
            // system roots, so a wrong path is refused rather than ignored.
            if certs.is_empty() {
                return Err(ClientError::Config("CA bundle holds no PEM certificates".into()));
            }
            builder = builder.tls_certs_merge(certs);
        }
        if let Some(pem) = options.identity_pem {
            let identity = reqwest::Identity::from_pem(&pem)
                .map_err(|e| ClientError::Config(format!("client certificate: {e}")))?;
            builder = builder.identity(identity);
        }
        let http = builder.build().map_err(|e| ClientError::Config(e.to_string()))?;
        Ok(Self {
            transport: Transport::Reqwest(http),
            base,
            token,
        })
    }

    /// A client that sends every request over `stream`, a connection the caller has already
    /// checked, so nothing can swap the socket between the check and the request.
    #[cfg(unix)]
    pub async fn over_unix_stream(stream: tokio::net::UnixStream, timeout: Option<Duration>) -> ClientResult<Self> {
        let transport = pinned::StreamTransport::new(stream, timeout.unwrap_or(DEFAULT_TIMEOUT)).await?;
        let base = url::Url::parse("http://localhost").map_err(|e| ClientError::Config(e.to_string()))?;
        Ok(Self {
            transport: Transport::Stream(transport),
            base,
            token: None,
        })
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
        let (status, bytes) = self.send_raw(method, url, body, RESPONSE_LIMIT).await?;
        let bytes = if status == StatusCode::NO_CONTENT || bytes.is_empty() {
            &b"null"[..]
        } else {
            &bytes[..]
        };
        serde_json::from_slice(bytes).map_err(|e| ClientError::Decode(terminal_safe(&e.to_string())))
    }

    /// The status and body of a successful response, or the API error.
    async fn send_raw(
        &self,
        method: Method,
        url: url::Url,
        body: Option<&dyn ErasedBody>,
        limit: usize,
    ) -> ClientResult<(StatusCode, Vec<u8>)> {
        let (status, retry_after, bytes) = match &self.transport {
            Transport::Reqwest(http) => {
                let mut request = http.request(method, url);
                if let Some(token) = &self.token {
                    request = request.bearer_auth(token);
                }
                if let Some(body) = body {
                    request = request.json(&body.as_json());
                }
                let response = request.send().await.map_err(|e| ClientError::Network(e.to_string()))?;
                let status = response.status();
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_retry_after);
                (status, retry_after, read_limited_body(response, limit).await?)
            }
            #[cfg(unix)]
            Transport::Stream(stream) => {
                let body = body
                    .map(|b| serde_json::to_vec(&b.as_json()))
                    .transpose()
                    .map_err(|e| ClientError::Config(e.to_string()))?;
                // The host socket serves only status and unseal, which it never rate limits.
                let (status, bytes) = stream.send(method, &url, self.token.as_deref(), body, limit).await?;
                (status, None, bytes)
            }
        };
        if !status.is_success() {
            let error: Option<ErrorBody> = serde_json::from_slice(&bytes).ok();
            return Err(ClientError::Api {
                status: status.as_u16(),
                code: error
                    .as_ref()
                    .map(|e| terminal_safe(&e.error))
                    .unwrap_or_else(|| "http".into()),
                message: error
                    .map(|e| terminal_safe(&e.message))
                    .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").into()),
                retry_after,
            });
        }
        Ok((status, bytes))
    }

    fn sys_url(&self, action: &str) -> ClientResult<url::Url> {
        self.url(&["api", "v1", "sys", action], &[])
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
        let mut all: Vec<SecretVersion> = Vec::new();
        let mut before: Option<i64> = None;
        loop {
            let mut query = vec![
                ("path", at.path.clone()),
                ("values", values.to_string()),
                ("limit", VERSION_PAGE.to_string()),
            ];
            if let Some(before) = before {
                query.push(("before", before.to_string()));
            }
            let page: Vec<SecretVersion> = self
                .send(
                    Method::GET,
                    self.secrets_url(&at, &["secrets", &key, "versions"], &query)?,
                    None,
                )
                .await?;
            let last = page.last().map(|v| v.version);
            let full = page.len() == VERSION_PAGE;
            all.extend(page);
            // A server that keeps answering the same page would otherwise loop for ever.
            match last {
                Some(oldest) if full && before.is_none_or(|b| oldest < b) && all.len() < MAX_VERSIONS => {
                    before = Some(oldest);
                }
                _ => return Ok(all),
            }
        }
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

    async fn sys_status(&self) -> ClientResult<SysStatus> {
        self.send(Method::GET, self.sys_url("status")?, None).await
    }

    async fn sys_status_detail(&self) -> ClientResult<SysStatus> {
        self.send(
            Method::GET,
            self.url(&["api", "v1", "sys", "status", "detail"], &[])?,
            None,
        )
        .await
    }

    async fn sys_init(&self, request: InitRequest) -> ClientResult<InitResponse> {
        self.send(Method::POST, self.sys_url("init")?, Some(&request)).await
    }

    async fn sys_unseal(&self, request: UnsealRequest) -> ClientResult<SysStatus> {
        self.send(Method::POST, self.sys_url("unseal")?, Some(&request)).await
    }

    async fn sys_seal(&self) -> ClientResult<SysStatus> {
        self.send(Method::POST, self.sys_url("seal")?, None).await
    }

    async fn sys_change_passphrase(&self, request: ChangePassphrase) -> ClientResult<()> {
        self.send(Method::POST, self.sys_url("passphrase")?, Some(&request))
            .await
    }

    async fn sys_set_unlock_policy(&self, request: SetUnlockPolicy) -> ClientResult<SysStatus> {
        self.send(Method::PUT, self.sys_url("unlock-policy")?, Some(&request))
            .await
    }

    async fn sys_forget_unlock(&self) -> ClientResult<SysStatus> {
        self.send(Method::POST, self.sys_url("forget-unlock")?, None).await
    }

    async fn sys_backup(&self) -> ClientResult<Vec<u8>> {
        let (_, bytes) = self
            .send_raw(Method::POST, self.sys_url("backup")?, None, BACKUP_RESPONSE_LIMIT)
            .await?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn a_ca_bundle_without_certificates_is_refused_without_quoting_it() {
        let options = ClientOptions {
            ca_pem: Some(b"token = \"skt_SECRET\"\n".to_vec()),
            identity_pem: None,
            timeout: None,
        };
        let refused = HttpClient::new("https://sekret.test", None, options).err();
        let message = refused.map(|e| e.to_string()).unwrap_or_default();
        assert!(message.contains("holds no PEM certificates"), "{message}");
        assert!(!message.contains("SECRET"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn client_certificate_files_are_bounded_and_regular() {
        let devices = identity_from_files(
            Some(std::path::Path::new("/dev/zero")),
            Some(std::path::Path::new("/dev/zero")),
        );
        assert!(devices.is_err(), "a device is not read");
    }

    #[test]
    fn terminal_safe_json_escapes_c1_controls_and_bidi_overrides() -> anyhow::Result<()> {
        let value = json!({"v": "a\u{85}b\u{9b}c\u{7f}d\u{202e}e\u{2066}f\u{200f}g é ✓", "n": 1});
        let text = serde_json::to_string_pretty(&value)?;
        let safe = terminal_safe_json(&text);
        assert_eq!(terminal_safe(&safe), safe, "{safe}");
        assert!(
            safe.contains("\\u0085") && safe.contains("\\u202e") && safe.contains("é ✓"),
            "{safe}"
        );
        assert!(safe.contains('\n'), "layout is kept");
        let parsed: serde_json::Value = serde_json::from_str(&safe)?;
        assert_eq!(parsed, value);
        Ok(())
    }

    #[test]
    fn oversized_client_certificate_files_are_refused() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!("sekret-client-big-{}.pem", std::process::id()));
        std::fs::write(&path, vec![b'a'; (PEM_LIMIT + 1) as usize]).context("write")?;
        let result = identity_from_files(Some(&path), Some(&path));
        std::fs::remove_file(&path).context("remove")?;
        assert!(result.is_err());
        Ok(())
    }

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

    fn version_json(version: i64) -> serde_json::Value {
        json!({"version": version, "value": null, "value_hidden": false, "deleted": false,
            "comment": "", "tags": [], "actor": "a", "created_at": 0})
    }

    #[tokio::test]
    async fn history_follows_every_page() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let versions = |range: std::ops::RangeInclusive<i64>| range.rev().map(version_json).collect::<Vec<_>>();
        let url = "/api/v1/projects/app/environments/prod/secrets/A/versions";
        Mock::given(method("GET"))
            .and(path(url))
            .and(query_param("before", "51"))
            .respond_with(ResponseTemplate::new(200).set_body_json(versions(1..=50)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(url))
            .and(wiremock::matchers::query_param_is_missing("before"))
            .respond_with(ResponseTemplate::new(200).set_body_json(versions(51..=250)))
            .mount(&server)
            .await;
        let all = client(&server, None)?
            .versions(at(), "A".into(), false)
            .await
            .context("versions")?;
        assert_eq!(all.len(), 250);
        assert_eq!(all.first().map(|v| v.version), Some(250));
        assert_eq!(all.last().map(|v| v.version), Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn history_stops_when_a_server_repeats_a_page() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let page: Vec<_> = (1..=200).rev().map(version_json).collect();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page))
            .expect(2)
            .mount(&server)
            .await;
        let all = client(&server, None)?
            .versions(at(), "A".into(), false)
            .await
            .context("versions")?;
        assert_eq!(all.len(), 400);
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
    async fn backups_come_back_as_raw_bytes() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/sys/backup"))
            .and(header("authorization", "Bearer skt_x"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SKB1\x00\x01".to_vec()))
            .mount(&server)
            .await;
        let bytes = client(&server, Some("skt_x"))?.sys_backup().await.context("backup")?;
        assert_eq!(bytes, b"SKB1\x00\x01");
        Ok(())
    }

    #[tokio::test]
    async fn unseal_sends_the_passphrase_and_reads_the_status() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/sys/unseal"))
            .and(body_json(json!({"passphrase": "violet tractor sings"})))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": "invalid_passphrase", "message": "the passphrase is wrong"
            })))
            .mount(&server)
            .await;
        let error = client(&server, None)?
            .sys_unseal(UnsealRequest {
                passphrase: "violet tractor sings".to_string().into(),
            })
            .await
            .err()
            .context("expected an error")?;
        assert_eq!(error.code(), Some("invalid_passphrase"));
        assert_eq!(error.status(), Some(401));
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
        assert_eq!(error.retry_after(), None);
        Ok(())
    }

    #[tokio::test]
    async fn retry_after_is_carried_on_a_slow_down() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/cli/poll"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "7")
                    .set_body_json(json!({"error": "slow_down", "message": "too many polls"})),
            )
            .mount(&server)
            .await;
        let error = client(&server, None)?
            .cli_poll("d".into())
            .await
            .err()
            .context("expected slow_down")?;
        assert_eq!(error.code(), Some("slow_down"));
        assert_eq!(error.retry_after(), Some(Duration::from_secs(7)));
        Ok(())
    }

    #[test]
    fn only_the_seconds_form_of_retry_after_is_read() {
        assert_eq!(parse_retry_after(" 12 "), Some(12));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("-1"), None);
    }

    #[test]
    fn terminal_escapes_and_controls_are_removed() {
        assert_eq!(terminal_safe("plain text\nline\ttab"), "plain text\nline\ttab");
        assert_eq!(terminal_safe("\u{1b}[2J\u{1b}[1;31mred\u{1b}[0m"), "red");
        assert_eq!(
            terminal_safe("\u{1b}]8;;https://evil.test\u{7}click\u{1b}]8;;\u{1b}\\"),
            "click",
            "OSC 8 hyperlinks are dropped"
        );
        assert_eq!(terminal_safe("\u{1b}]0;title\u{1b}\\after"), "after");
        assert_eq!(terminal_safe("a\rb\u{8}c\u{7}d\u{0}e\u{7f}f"), "abcdef");
        assert_eq!(terminal_safe("x\u{9b}31my"), "x31my", "C1 controls are removed");
        assert_eq!(terminal_safe("ab\u{202e}cd\u{2066}e"), "abcde");
        assert_eq!(terminal_safe("trailing\u{1b}"), "trailing");
    }

    #[tokio::test]
    async fn server_error_text_cannot_drive_the_terminal() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/me"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": "forbidden\u{1b}[2J", "message": "denied\u{1b}]52;c;cm0gLXJmIH4=\u{7}\r\u{1b}[1Aok"
            })))
            .mount(&server)
            .await;
        let error = client(&server, None)?.me().await.err().context("expected an error")?;
        let shown = error.to_string();
        assert!(!shown.chars().any(|c| c.is_control()), "{shown:?}");
        assert_eq!(shown, "deniedok (403 forbidden)");
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

    #[tokio::test]
    async fn oversized_responses_are_refused() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; RESPONSE_LIMIT + 1]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/me"))
            .respond_with(ResponseTemplate::new(500).set_body_bytes(vec![b' '; RESPONSE_LIMIT + 1]))
            .mount(&server)
            .await;
        let api = client(&server, None)?;
        assert_eq!(
            api.list_projects().await.err(),
            Some(ClientError::TooLarge { limit: RESPONSE_LIMIT })
        );
        assert_eq!(
            api.me().await.err(),
            Some(ClientError::TooLarge { limit: RESPONSE_LIMIT }),
            "error bodies are capped too"
        );
        Ok(())
    }

    /// Reads one HTTP/1.1 request head and its body from `stream`.
    #[cfg(unix)]
    async fn read_request(stream: &mut tokio::net::UnixStream) -> anyhow::Result<String> {
        use tokio::io::AsyncReadExt;
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.context("read")?;
            anyhow::ensure!(n > 0, "connection closed");
            data.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&data).to_string();
            let Some(end) = text.find("\r\n\r\n") else {
                continue;
            };
            let length = text[..end]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(String::from)
                })
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                return Ok(text);
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn every_request_goes_over_the_one_checked_stream() -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let (ours, mut theirs) = tokio::net::UnixStream::pair().context("pair")?;
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            let error = r#"{"error":"invalid_passphrase","message":"wrong one!"}"#;
            for reply in [
                "HTTP/1.1 204 No Content\r\n\r\n".to_string(),
                format!(
                    "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{error}",
                    error.len()
                ),
            ] {
                seen.push(read_request(&mut theirs).await?);
                theirs.write_all(reply.as_bytes()).await.context("write")?;
            }
            anyhow::Ok(seen)
        });
        let api = HttpClient::over_unix_stream(ours, Some(Duration::from_secs(5)))
            .await
            .context("client")?;
        api.revoke().await.context("revoke")?;
        let error = api
            .sys_unseal(UnsealRequest {
                passphrase: "violet tractor sings".to_string().into(),
            })
            .await
            .err()
            .context("expected an error")?;
        assert_eq!(error.code(), Some("invalid_passphrase"));
        let seen = server.await.context("join")??;
        assert!(
            seen[0].starts_with("POST /api/v1/auth/token/revoke HTTP/1.1"),
            "{}",
            seen[0]
        );
        assert!(seen[1].starts_with("POST /api/v1/sys/unseal HTTP/1.1"), "{}", seen[1]);
        assert!(
            seen[1].contains(r#""passphrase":"violet tractor sings""#),
            "{}",
            seen[1]
        );
        assert!(seen[1].to_ascii_lowercase().contains("content-type: application/json"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_stream_transport_caps_response_size() -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let (ours, mut theirs) = tokio::net::UnixStream::pair().context("pair")?;
        let server = tokio::spawn(async move {
            read_request(&mut theirs).await?;
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", RESPONSE_LIMIT + 1);
            theirs.write_all(head.as_bytes()).await.context("head")?;
            // The client may hang up part way through, which is the point.
            let _ = theirs.write_all(&vec![b' '; RESPONSE_LIMIT + 1]).await;
            anyhow::Ok(())
        });
        let api = HttpClient::over_unix_stream(ours, Some(Duration::from_secs(20)))
            .await
            .context("client")?;
        assert_eq!(
            api.sys_status().await.err(),
            Some(ClientError::TooLarge { limit: RESPONSE_LIMIT })
        );
        server.await.context("join")??;
        Ok(())
    }

    #[test]
    fn backup_limit_matches_the_server() {
        assert_eq!(BACKUP_RESPONSE_LIMIT, sekret_core::seal::MAX_BACKUP_LEN);
    }

    #[test]
    fn only_https_to_another_host_may_use_a_proxy() -> anyhow::Result<()> {
        let cases = [
            ("http://localhost:8200", true),
            ("http://LocalHost.:8200", true),
            ("http://127.0.0.1", true),
            ("http://127.3.2.1", true),
            ("http://[::1]:8200", true),
            ("https://localhost:8200", true),
            ("https://127.0.0.1", true),
            ("https://[::1]", true),
            ("http://sekret.svc.cluster.local:8200", true),
            ("http://10.0.0.5", true),
            ("https://sekret.example.com", false),
            ("https://10.0.0.5", false),
            ("https://localhost.example.com", false),
        ];
        for (url, bypass) in cases {
            let parsed = url::Url::parse(url).context("url")?;
            assert_eq!(bypasses_proxy(&parsed), bypass, "{url}");
        }
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
