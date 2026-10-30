use std::net::SocketAddr;

use ipnet::IpNet;

/// Human sign-in through an OIDC provider such as Keycloak.
#[derive(Debug, Clone)]
pub struct HumanOidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    /// Claims whose string or string-array values become the user's groups (e.g. `roles`, `groups`).
    pub group_claims: Vec<String>,
    /// Groups that make a user an organisation admin.
    pub admin_groups: Vec<String>,
    /// When non-empty, a user needs one of these groups to sign in at all.
    pub required_groups: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// External base URL, e.g. `https://sekret.example.com`, used for redirects and cookies.
    pub public_url: String,
    pub database_url: String,
    pub oidc: Option<HumanOidcConfig>,
    /// Organisation role every signed-in user receives. Empty for none.
    pub default_org_role: String,
    pub session_ttl: i64,
    pub cli_token_ttl: i64,
    /// Proxies whose `X-Forwarded-For` header is trusted for the client address.
    pub trusted_proxies: Vec<IpNet>,
    /// Permit `http://` issuer and JWKS URLs. Only for development and tests.
    pub allow_insecure_http: bool,
    pub snapshots_to_keep: i64,
    pub login_rate_per_minute: u32,
    /// Serve HTTPS directly; plain HTTP behind a TLS-terminating proxy when absent.
    pub tls: Option<TlsSettings>,
}

#[derive(Clone)]
pub struct TlsSettings {
    /// PEM certificate chain, leaf first.
    pub cert_pem: Vec<u8>,
    pub key_pem: zeroize::Zeroizing<Vec<u8>>,
    /// PEM CA certificates that client certificates must chain to. Turns on mutual TLS.
    pub client_ca_pem: Option<Vec<u8>>,
    /// With a client CA: refuse connections without a certificate, rather than only checking
    /// certificates that are offered.
    pub client_auth_required: bool,
}

impl std::fmt::Debug for TlsSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSettings")
            .field("client_ca", &self.client_ca_pem.is_some())
            .field("client_auth_required", &self.client_auth_required)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    pub fn secure_cookies(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/auth/callback", self.public_url.trim_end_matches('/'))
    }

    pub fn for_tests(database_url: &str) -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            public_url: "http://localhost".into(),
            database_url: database_url.into(),
            oidc: None,
            default_org_role: "org-member".into(),
            session_ttl: 12 * 3600,
            cli_token_ttl: 24 * 3600,
            trusted_proxies: Vec::new(),
            allow_insecure_http: true,
            snapshots_to_keep: 200,
            login_rate_per_minute: 1000,
            tls: None,
        }
    }
}
