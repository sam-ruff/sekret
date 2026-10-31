use std::net::SocketAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use sekret_core::seal::{RememberSecret, SealMode, UnlockPolicy};

use crate::files::WrittenFile;

/// Human sign-in through an OIDC provider such as Keycloak.
#[derive(Clone)]
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

impl std::fmt::Debug for HumanOidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HumanOidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"(redacted)")
            .field("scopes", &self.scopes)
            .field("group_claims", &self.group_claims)
            .field("admin_groups", &self.admin_groups)
            .field("required_groups", &self.required_groups)
            .field("allowed_subjects", &self.allowed_subjects)
            .finish()
    }
}

pub const DEFAULT_MAX_CONNECTIONS: usize = 512;

/// A Unix socket on the host for unsealing without the network's rate limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixSocketSettings {
    pub path: PathBuf,
    /// 0o600, or 0o660 to let the socket's group in too.
    pub mode: u32,
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
    /// Connections served at once; further ones wait in the listen backlog.
    pub max_connections: usize,
    /// Serve HTTPS directly; plain HTTP behind a TLS-terminating proxy when absent.
    pub tls: Option<TlsSettings>,
    pub seal: SealSettings,
    pub unix_socket: Option<UnixSocketSettings>,
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
    /// The one-time setup code file this start wrote; removed once setup succeeds, if unchanged.
    pub setup_code_file: Option<WrittenFile>,
    /// Files outside the database that remember the highest seal configuration epoch seen, so
    /// an older signed configuration put back into the database is noticed.
    pub epoch_files: Vec<PathBuf>,
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
            epoch_files: Vec::new(),
        }
    }
}

fn sidecar(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Where the epoch high-water mark is kept: beside the SQLite database, the remember file and the
/// root key file, whichever there are, each by its canonical path so that every way of naming
/// a file finds the same mark. A Postgres server with none of the files has nowhere.
pub fn epoch_files(
    database_url: &str,
    remember_file: Option<&std::path::Path>,
    root_key_file: Option<&std::path::Path>,
) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = sekret_store::sqlite_file(database_url)
        .as_deref()
        .into_iter()
        .chain(remember_file)
        .chain(root_key_file)
        .map(|path| sidecar(&sekret_store::canonical_path(path), ".epoch"))
        .collect();
    files.dedup();
    files
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
            max_connections: DEFAULT_MAX_CONNECTIONS,
            tls: None,
            seal: SealSettings::default(),
            unix_socket: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_oidc_client_secret_never_reaches_debug_output() {
        let config = HumanOidcConfig {
            issuer: "https://id.example".into(),
            client_id: "sekret".into(),
            client_secret: "hunter2-client-secret".into(),
            scopes: vec![],
            group_claims: vec![],
            admin_groups: vec![],
            required_groups: vec![],
            allowed_subjects: vec![],
        };
        let shown = format!("{config:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("https://id.example"));
    }

    #[test]
    fn epoch_marks_sit_beside_each_file() {
        let files = epoch_files(
            "sqlite:///var/lib/sekret/sekret.db?mode=rwc",
            Some(std::path::Path::new("/run/sekret/unlock.key")),
            None,
        );
        assert_eq!(
            files,
            vec![
                PathBuf::from("/var/lib/sekret/sekret.db.epoch"),
                PathBuf::from("/run/sekret/unlock.key.epoch")
            ]
        );
        assert!(epoch_files("postgres://db/sekret", None, None).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_database_path_shares_the_real_files_epoch_mark() -> Result<(), std::io::Error> {
        let dir = tempfile::tempdir()?;
        let real = dir.path().join("sekret.db");
        std::fs::write(&real, b"")?;
        let link = dir.path().join("link.db");
        std::os::unix::fs::symlink(&real, &link)?;
        let through_link = epoch_files(&format!("sqlite://{}", link.display()), None, None);
        let direct = epoch_files(&format!("sqlite://{}", real.display()), None, None);
        assert_eq!(through_link, direct);
        Ok(())
    }
}
