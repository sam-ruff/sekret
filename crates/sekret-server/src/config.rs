use std::net::SocketAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use sekret_core::seal::{RememberSecret, SealMode, UnlockPolicy};

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
    /// When non-empty, only these ID token subjects may sign in, whatever their groups, so a
    /// role granted inside the provider is not enough on its own.
    pub allowed_subjects: Vec<String>,
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
    /// Approving a CLI login needs a browser session that signed in with the identity provider
    /// within this many seconds; otherwise the browser is sent to sign in again.
    pub cli_login_max_auth_age: Option<i64>,
    /// Where backups are staged; a private directory beside the SQLite database when absent.
    pub backup_temp_dir: Option<PathBuf>,
    /// Proxies whose `X-Forwarded-For` header is trusted for the client address.
    pub trusted_proxies: Vec<IpNet>,
    /// Permit `http://` issuer and JWKS URLs. Only for development and tests.
    pub allow_insecure_http: bool,
    pub snapshots_to_keep: i64,
    pub login_rate_per_minute: u32,
    /// Serve HTTPS directly; plain HTTP behind a TLS-terminating proxy when absent.
    pub tls: Option<TlsSettings>,
    pub seal: SealSettings,
}

/// How the root key is protected and how first-boot setup is offered.
#[derive(Debug, Clone)]
pub struct SealSettings {
    /// The mode set in configuration; a database initialised in another mode is refused.
    pub mode: Option<SealMode>,
    /// The unlock policy set in configuration, which wins over the one chosen at setup.
    pub unlock: Option<UnlockPolicy>,
    pub root_key_file: Option<PathBuf>,
    /// Device key file for the `remember` unlock policy. There is no default: it must be chosen.
    pub remember_file: Option<PathBuf>,
    /// Mixed into the remember key, so the remember file and database alone cannot unlock.
    pub remember_secret: Option<RememberSecret>,
    /// Offer first-boot setup through the API and web interface.
    pub web_setup: bool,
    /// Where the one-time setup code was written; removed once setup succeeds.
    pub setup_code_file: Option<PathBuf>,
}

impl Default for SealSettings {
    fn default() -> Self {
        Self {
            mode: None,
            unlock: None,
            root_key_file: None,
            remember_file: None,
            remember_secret: None,
            web_setup: true,
            setup_code_file: None,
        }
    }
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
            cli_login_max_auth_age: None,
            backup_temp_dir: None,
            trusted_proxies: Vec::new(),
            allow_insecure_http: true,
            snapshots_to_keep: 200,
            login_rate_per_minute: 1000,
            tls: None,
            seal: SealSettings::default(),
        }
    }
}
