//! Server options from flags, environment variables and a YAML file, in that order of precedence.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Args;
use sekret_core::seal::{RememberSecret, SealMode, UnlockPolicy};
use sekret_server::config::{HumanOidcConfig, SealSettings, ServerConfig, TlsSettings};
use sekret_server::files::{SECRET_FILE_LIMIT, TEXT_FILE_LIMIT, read_limited};
use serde::Deserialize;
use zeroize::Zeroizing;

/// The commented example printed by `sekret server --print-config`, kept in step with
/// `docs/sekret.example.yaml`.
pub const EXAMPLE: &str = include_str!("example.yaml");

const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
const DEFAULT_DATABASE_URL: &str = "sqlite://sekret.db?mode=rwc";

#[derive(Debug, Args)]
pub struct StoreArgs {
    /// YAML configuration file; flags and environment variables override it.
    #[arg(long, env = "SEKRET_CONFIG")]
    pub config: Option<PathBuf>,
    /// `sqlite://path?mode=rwc` or `postgres://user:pass@host/db` [default: sqlite://sekret.db?mode=rwc].
    #[arg(long, env = "SEKRET_DATABASE_URL")]
    pub database_url: Option<String>,
    /// File holding the 32-byte root key (raw, base64 or hex), for key-file mode.
    #[arg(long, env = "SEKRET_ROOT_KEY_FILE")]
    pub root_key_file: Option<PathBuf>,
}

/// Where the database and root key are, for the admin commands.
pub struct StoreLocation {
    pub database_url: String,
    pub root_key_file: Option<PathBuf>,
}

impl StoreArgs {
    pub fn locate(&self) -> anyhow::Result<StoreLocation> {
        let file = load(self.config.as_deref())?;
        Ok(StoreLocation {
            database_url: self
                .database_url
                .clone()
                .or(file.database.url)
                .unwrap_or_else(|| DEFAULT_DATABASE_URL.into()),
            root_key_file: self.root_key_file.clone().or(file.seal.root_key_file),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientAuth {
    Required,
    Optional,
}

fn parse_seal_mode(raw: &str) -> Result<SealMode, String> {
    SealMode::parse(raw).ok_or_else(|| "expected passphrase or key-file".into())
}

fn parse_unlock(raw: &str) -> Result<UnlockPolicy, String> {
    UnlockPolicy::parse(raw).ok_or_else(|| "expected manual, remember or passphrase-file".into())
}

#[derive(Debug, Args)]
pub struct ServerArgs {
    #[command(flatten)]
    pub store: StoreArgs,
    /// Print a commented example configuration file with the defaults, then exit.
    #[arg(long)]
    pub print_config: bool,
    /// [default: 0.0.0.0:8080]
    #[arg(long, env = "SEKRET_LISTEN")]
    pub listen: Option<SocketAddr>,
    /// External URL people and machines use, e.g. https://sekret.example.com.
    #[arg(long, env = "SEKRET_PUBLIC_URL")]
    pub public_url: Option<String>,
    #[arg(long, env = "SEKRET_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,
    /// [default: sekret]
    #[arg(long, env = "SEKRET_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,
    #[arg(long, env = "SEKRET_OIDC_CLIENT_SECRET_FILE")]
    pub oidc_client_secret_file: Option<PathBuf>,
    /// [default: openid profile email]
    #[arg(long, env = "SEKRET_OIDC_SCOPES", value_delimiter = ' ')]
    pub oidc_scopes: Option<Vec<String>>,
    /// Token claims whose values become the user's groups [default: roles,groups].
    #[arg(long, env = "SEKRET_OIDC_GROUP_CLAIMS", value_delimiter = ',')]
    pub oidc_group_claims: Option<Vec<String>>,
    /// Groups that make someone an organisation admin [default: sekret-admin].
    #[arg(long, env = "SEKRET_OIDC_ADMIN_GROUPS", value_delimiter = ',')]
    pub oidc_admin_groups: Option<Vec<String>>,
    /// When set, only users in one of these groups may sign in.
    #[arg(long, env = "SEKRET_OIDC_REQUIRED_GROUPS", value_delimiter = ',')]
    pub oidc_required_groups: Option<Vec<String>>,
    /// Organisation role every signed-in person receives; empty for none [default: org-member].
    #[arg(long, env = "SEKRET_DEFAULT_ORG_ROLE")]
    pub default_org_role: Option<String>,
    /// Seconds [default: 43200].
    #[arg(long, env = "SEKRET_SESSION_TTL")]
    pub session_ttl: Option<i64>,
    /// Seconds [default: 86400].
    #[arg(long, env = "SEKRET_CLI_TOKEN_TTL")]
    pub cli_token_ttl: Option<i64>,
    /// Seconds. Approving a CLI login needs a browser sign-in this recent, or the provider is
    /// asked to authenticate again; CLI tokens then cannot be renewed past their TTL [default: unset].
    #[arg(long, env = "SEKRET_CLI_LOGIN_MAX_AUTH_AGE")]
    pub cli_login_max_auth_age: Option<i64>,
    /// Private directory for staging backups [default: beside the SQLite database].
    #[arg(long, env = "SEKRET_BACKUP_TEMP_DIR")]
    pub backup_temp_dir: Option<PathBuf>,
    /// Reverse proxies allowed to set X-Forwarded-For, as CIDRs.
    #[arg(long, env = "SEKRET_TRUSTED_PROXIES", value_delimiter = ',')]
    pub trusted_proxies: Option<Vec<ipnet::IpNet>>,
    /// Allow http:// OIDC issuers and Kubernetes hosts. Development only.
    #[arg(long, env = "SEKRET_ALLOW_INSECURE_HTTP", num_args = 0..=1, default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new())]
    pub allow_insecure_http: Option<bool>,
    /// [default: 200]
    #[arg(long, env = "SEKRET_SNAPSHOTS_TO_KEEP")]
    pub snapshots_to_keep: Option<i64>,
    /// Also limits setup, unlock and passphrase attempts [default: 30].
    #[arg(long, env = "SEKRET_LOGIN_RATE_PER_MINUTE")]
    pub login_rate_per_minute: Option<u32>,
    /// PEM certificate chain to serve HTTPS directly instead of plain HTTP.
    #[arg(long, env = "SEKRET_TLS_CERT_FILE")]
    pub tls_cert_file: Option<PathBuf>,
    /// PEM private key for --tls-cert-file.
    #[arg(long, env = "SEKRET_TLS_KEY_FILE")]
    pub tls_key_file: Option<PathBuf>,
    /// PEM CA certificates that client certificates must chain to; turns on mutual TLS.
    #[arg(long, env = "SEKRET_TLS_CLIENT_CA_FILE")]
    pub tls_client_ca_file: Option<PathBuf>,
    /// With a client CA: `required` refuses connections without a certificate, `optional`
    /// only checks certificates that are offered [default: required].
    #[arg(long, env = "SEKRET_TLS_CLIENT_AUTH", value_enum)]
    pub tls_client_auth: Option<ClientAuth>,
    /// How the root key is protected: passphrase or key-file. Checked against the database.
    #[arg(long, env = "SEKRET_SEAL_MODE", value_parser = parse_seal_mode)]
    pub seal_mode: Option<SealMode>,
    /// How a passphrase-mode server unlocks after a start: manual, remember or passphrase-file.
    #[arg(long, env = "SEKRET_UNLOCK", value_parser = parse_unlock)]
    pub unlock: Option<UnlockPolicy>,
    /// Device key file for the remember policy; required with it, and best kept off the
    /// database's disk.
    #[arg(long, env = "SEKRET_REMEMBER_FILE")]
    pub remember_file: Option<PathBuf>,
    /// File holding a secret of 32 or more characters mixed into the remember key, so the disk
    /// alone cannot unlock; SEKRET_REMEMBER_SECRET also works.
    #[arg(long, env = "SEKRET_REMEMBER_SECRET_FILE")]
    pub remember_secret_file: Option<PathBuf>,
    /// Passphrase for the passphrase-file policy; SEKRET_UNLOCK_PASSPHRASE also works.
    #[arg(long, env = "SEKRET_UNLOCK_PASSPHRASE_FILE")]
    pub unlock_passphrase_file: Option<PathBuf>,
    /// Offer first-boot setup through the API and web interface [default: true].
    #[arg(long, env = "SEKRET_WEB_SETUP", num_args = 0..=1, default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new())]
    pub web_setup: Option<bool>,
    /// Initialise an empty database at start without a person [default: false].
    #[arg(long, env = "SEKRET_AUTO_INIT", num_args = 0..=1, default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new())]
    pub auto_init: Option<bool>,
    /// First passphrase for automatic setup, read once.
    #[arg(long, env = "SEKRET_SETUP_PASSPHRASE_FILE")]
    pub setup_passphrase_file: Option<PathBuf>,
    /// Where automatic setup writes a break-glass admin token (mode 0600).
    #[arg(long, env = "SEKRET_SETUP_ADMIN_TOKEN_FILE")]
    pub setup_admin_token_file: Option<PathBuf>,
    /// Where to write the one-time setup code (mode 0600), as well as the log.
    #[arg(long, env = "SEKRET_SETUP_CODE_FILE")]
    pub setup_code_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub server: ServerSection,
    pub database: DatabaseSection,
    pub auth: AuthSection,
    pub oidc: OidcSection,
    pub tls: TlsSection,
    pub seal: SealSection,
    pub setup: SetupSection,
    pub backup: BackupSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupSection {
    pub temp_dir: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSection {
    pub listen: Option<SocketAddr>,
    pub public_url: Option<String>,
    pub trusted_proxies: Option<Vec<String>>,
    pub allow_insecure_http: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseSection {
    pub url: Option<String>,
    pub snapshots_to_keep: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    pub default_org_role: Option<String>,
    pub session_ttl: Option<i64>,
    pub cli_token_ttl: Option<i64>,
    pub cli_login_max_auth_age: Option<i64>,
    pub login_rate_per_minute: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcSection {
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_file: Option<PathBuf>,
    pub scopes: Option<Vec<String>>,
    pub group_claims: Option<Vec<String>>,
    pub admin_groups: Option<Vec<String>>,
    pub required_groups: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSection {
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub client_ca_file: Option<PathBuf>,
    pub client_auth: Option<ClientAuth>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SealSection {
    pub mode: Option<SealMode>,
    pub root_key_file: Option<PathBuf>,
    pub unlock: Option<UnlockPolicy>,
    pub remember_file: Option<PathBuf>,
    pub remember_secret_file: Option<PathBuf>,
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SetupSection {
    pub web: Option<bool>,
    pub auto_init: Option<bool>,
    pub passphrase_file: Option<PathBuf>,
    pub admin_token_file: Option<PathBuf>,
    pub code_file: Option<PathBuf>,
}

/// Hides the password in anything that looks like `scheme://user:password@host`.
pub fn redact_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("://") {
        let (before, after) = rest.split_at(start + 3);
        out.push_str(before);
        let end = after
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\'' | '`'))
            .unwrap_or(after.len());
        let authority = &after[..end];
        match authority.rfind('@') {
            Some(at) => {
                let userinfo = &authority[..at];
                let user = userinfo.split(':').next().unwrap_or_default();
                out.push_str(user);
                if userinfo.contains(':') {
                    out.push_str(":***");
                }
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

pub fn parse(text: &str) -> anyhow::Result<FileConfig> {
    // No source snippets in errors, which could print a password from the file.
    let mut options = serde_saphyr::Options::default();
    options.strict_booleans = true;
    options.with_snippet = false;
    serde_saphyr::from_str_with_options(text, options)
        .map_err(|e| anyhow::anyhow!("{}", redact_credentials(&e.to_string())))
}

/// Reads the configuration file, or nothing when no file is given.
pub fn load(path: Option<&Path>) -> anyhow::Result<FileConfig> {
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };
    let bytes = read_limited(path, TEXT_FILE_LIMIT).with_context(|| format!("reading {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    parse(text).with_context(|| format!("in {}", path.display()))
}

/// The SQLite file behind a database URL, or `None` for Postgres and in-memory databases.
pub fn sqlite_path(url: &str) -> Option<PathBuf> {
    sekret_store::sqlite_file(url)
}

/// Server options that only matter while starting.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Setup {
    pub auto_init: bool,
    pub passphrase_file: Option<PathBuf>,
    pub admin_token_file: Option<PathBuf>,
    pub code_file: Option<PathBuf>,
    pub unlock_passphrase_file: Option<PathBuf>,
}

pub struct Resolved {
    pub config: ServerConfig,
    pub setup: Setup,
    pub report: Report,
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

fn read_secret_file(path: &Path) -> anyhow::Result<String> {
    let bytes = read_limited(path, SECRET_FILE_LIMIT).with_context(|| format!("reading {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    Ok(text.trim().to_string())
}

/// Secrets the server takes out of its environment as it starts, before any thread can read it.
#[derive(Default)]
pub struct EnvSecrets {
    pub unlock_passphrase: Option<Zeroizing<String>>,
    pub remember_secret: Option<Zeroizing<String>>,
}

pub const UNLOCK_PASSPHRASE_ENV: &str = "SEKRET_UNLOCK_PASSPHRASE";
pub const REMEMBER_SECRET_ENV: &str = "SEKRET_REMEMBER_SECRET";

impl EnvSecrets {
    /// Reads and removes the secret variables. Only call this while the process has one thread.
    pub fn take() -> Self {
        let take = |name: &str| {
            let value = std::env::var(name).ok().map(Zeroizing::new);
            if value.is_some() {
                // SAFETY: called from `main` before the runtime or any other thread starts.
                unsafe { std::env::remove_var(name) };
            }
            value
        };
        Self {
            unlock_passphrase: take(UNLOCK_PASSPHRASE_ENV),
            remember_secret: take(REMEMBER_SECRET_ENV),
        }
    }
}

/// The remember secret from its file, else from the environment.
fn remember_secret(file: Option<&Path>, env: Option<&Zeroizing<String>>) -> anyhow::Result<Option<RememberSecret>> {
    let text = match (file, env) {
        (Some(path), _) => {
            let bytes = read_limited(path, SECRET_FILE_LIMIT).with_context(|| format!("reading {}", path.display()))?;
            Zeroizing::new(
                std::str::from_utf8(&bytes)
                    .with_context(|| format!("{} is not UTF-8", path.display()))?
                    .to_string(),
            )
        }
        (None, Some(value)) => value.clone(),
        (None, None) => return Ok(None),
    };
    Ok(Some(RememberSecret::new(&text).context("the remember secret")?))
}

/// Where a setting's value came from, for the startup log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Flag,
    Env,
    File,
    Default,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Flag => "flag",
            Origin::Env => "environment",
            Origin::File => "file",
            Origin::Default => "default",
        }
    }
}

/// The command line and environment, injected so origins can be tested.
pub struct Sources {
    pub argv: Vec<String>,
    pub env: Box<dyn Fn(&str) -> bool>,
}

impl Sources {
    pub fn process() -> Self {
        Self {
            argv: std::env::args().collect(),
            env: Box::new(|name| std::env::var_os(name).is_some()),
        }
    }

    #[cfg(test)]
    fn none() -> Self {
        Self {
            argv: Vec::new(),
            env: Box::new(|_| false),
        }
    }

    /// Clap prefers a flag over the environment, and both over the file.
    fn origin(&self, flag: &str, env: &str, set: bool, in_file: bool) -> Origin {
        let long = format!("--{flag}");
        let prefixed = format!("--{flag}=");
        if !set {
            return Origin::Default;
        }
        if self.argv.iter().any(|a| *a == long || a.starts_with(&prefixed)) {
            return Origin::Flag;
        }
        if (self.env)(env) {
            return Origin::Env;
        }
        if in_file {
            return Origin::File;
        }
        Origin::Default
    }
}

/// One line of the startup report: a setting, its value without secrets, and its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reported {
    pub name: &'static str,
    pub value: String,
    pub origin: Origin,
}

/// What the server logs as it starts.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub settings: Vec<Reported>,
    pub warnings: Vec<String>,
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn parent_dir(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf())
}

/// The remember file must be a file of its own, never one sekret already uses.
fn check_remember_file(remember: &Path, others: &[(&str, Option<&Path>)]) -> anyhow::Result<()> {
    for (name, other) in others {
        if let Some(other) = other
            && same_path(remember, other)
        {
            bail!(
                "the remember file {} is the same as the {name}; choose a separate file",
                remember.display()
            );
        }
    }
    Ok(())
}

fn oidc(args: &ServerArgs, file: OidcSection) -> anyhow::Result<Option<HumanOidcConfig>> {
    let Some(issuer) = args.oidc_issuer.clone().or(file.issuer) else {
        return Ok(None);
    };
    let secret_file = args
        .oidc_client_secret_file
        .clone()
        .or(file.client_secret_file)
        .context("an OIDC client secret file is required with an OIDC issuer")?;
    Ok(Some(HumanOidcConfig {
        issuer: issuer.trim_end_matches('/').to_string(),
        client_id: args
            .oidc_client_id
            .clone()
            .or(file.client_id)
            .unwrap_or_else(|| "sekret".into()),
        client_secret: read_secret_file(&secret_file)?,
        scopes: args
            .oidc_scopes
            .clone()
            .or(file.scopes)
            .unwrap_or_else(|| strings(&["openid", "profile", "email"])),
        group_claims: args
            .oidc_group_claims
            .clone()
            .or(file.group_claims)
            .unwrap_or_else(|| strings(&["roles", "groups"])),
        admin_groups: args
            .oidc_admin_groups
            .clone()
            .or(file.admin_groups)
            .unwrap_or_else(|| strings(&["sekret-admin"])),
        required_groups: args
            .oidc_required_groups
            .clone()
            .or(file.required_groups)
            .unwrap_or_default(),
    }))
}

fn tls(args: &ServerArgs, file: TlsSection) -> anyhow::Result<Option<TlsSettings>> {
    let cert = args.tls_cert_file.clone().or(file.cert_file);
    let key = args.tls_key_file.clone().or(file.key_file);
    let client_ca = args.tls_client_ca_file.clone().or(file.client_ca_file);
    let (cert, key) = match (cert, key) {
        (Some(cert), Some(key)) => (cert, key),
        (None, None) if client_ca.is_none() => return Ok(None),
        _ => bail!("TLS needs both a certificate file and a key file"),
    };
    let read = |path: &PathBuf| {
        read_limited(path, TEXT_FILE_LIMIT)
            .map(|bytes| bytes.to_vec())
            .with_context(|| format!("reading {}", path.display()))
    };
    let client_auth = args
        .tls_client_auth
        .or(file.client_auth)
        .unwrap_or(ClientAuth::Required);
    Ok(Some(TlsSettings {
        cert_pem: read(&cert)?,
        key_pem: Zeroizing::new(read(&key)?),
        client_ca_pem: client_ca.as_ref().map(read).transpose()?,
        client_auth_required: client_auth == ClientAuth::Required,
    }))
}

/// Merges flags and environment variables (already combined by clap) over the file, then defaults.
#[cfg(test)]
pub fn resolve(args: &ServerArgs, file: FileConfig) -> anyhow::Result<Resolved> {
    resolve_with(args, file, &EnvSecrets::default(), &Sources::none())
}

/// [`resolve`], with the secrets taken from the environment and where each value came from.
pub fn resolve_with(
    args: &ServerArgs,
    file: FileConfig,
    env_secrets: &EnvSecrets,
    sources: &Sources,
) -> anyhow::Result<Resolved> {
    let FileConfig {
        server,
        database,
        auth,
        oidc: oidc_file,
        tls: tls_file,
        seal,
        setup,
        backup,
    } = file;
    let public_url = args
        .public_url
        .clone()
        .or(server.public_url)
        .context("a public URL is required: --public-url, SEKRET_PUBLIC_URL or server.public_url")?;
    if !public_url.starts_with("http://") && !public_url.starts_with("https://") {
        bail!("the public URL must start with http:// or https://");
    }
    let trusted_proxies = match (&args.trusted_proxies, server.trusted_proxies) {
        (Some(flag), _) => flag.clone(),
        (None, Some(file)) => file
            .iter()
            .map(|cidr| cidr.parse().with_context(|| format!("trusted proxy {cidr}")))
            .collect::<anyhow::Result<_>>()?,
        (None, None) => Vec::new(),
    };
    let listen = match args.listen.or(server.listen) {
        Some(listen) => listen,
        None => DEFAULT_LISTEN.parse().context("default listen address")?,
    };
    let database_url = args
        .store
        .database_url
        .clone()
        .or(database.url)
        .unwrap_or_else(|| DEFAULT_DATABASE_URL.into());
    let mut report = Report::default();
    let mut note = |name: &'static str, flag: &str, env: &str, value: Option<String>, in_file: bool| {
        let origin = sources.origin(flag, env, value.is_some(), in_file);
        report.settings.push(Reported {
            name,
            value: value.unwrap_or_else(|| "unset".into()),
            origin,
        });
        origin
    };
    let shown = |p: &Option<PathBuf>| p.as_ref().map(|p| p.display().to_string());
    let remember_file = args.remember_file.clone().or(seal.remember_file.clone());
    let remember_secret_file = args.remember_secret_file.clone().or(seal.remember_secret_file.clone());
    let unlock_passphrase_file = args.unlock_passphrase_file.clone().or(seal.passphrase_file.clone());
    let setup_passphrase_file = args.setup_passphrase_file.clone().or(setup.passphrase_file.clone());
    let root_key_file = args.store.root_key_file.clone().or(seal.root_key_file.clone());
    let unlock = args.unlock.or(seal.unlock);
    let mode = args.seal_mode.or(seal.mode);
    let web_setup = args.web_setup.or(setup.web);
    let auto_init = args.auto_init.or(setup.auto_init);
    let admin_token_file = args.setup_admin_token_file.clone().or(setup.admin_token_file.clone());
    let code_file = args.setup_code_file.clone().or(setup.code_file.clone());
    let max_auth_age = args.cli_login_max_auth_age.or(auth.cli_login_max_auth_age);
    if max_auth_age.is_some_and(|age| age <= 0) {
        bail!("cli_login_max_auth_age must be a positive number of seconds");
    }
    note(
        "seal.mode",
        "seal-mode",
        "SEKRET_SEAL_MODE",
        mode.map(|m| m.as_str().into()),
        seal.mode.is_some(),
    );
    let unlock_origin = note(
        "seal.unlock",
        "unlock",
        "SEKRET_UNLOCK",
        unlock.map(|u| u.as_str().into()),
        seal.unlock.is_some(),
    );
    note(
        "seal.root_key_file",
        "root-key-file",
        "SEKRET_ROOT_KEY_FILE",
        shown(&root_key_file),
        seal.root_key_file.is_some(),
    );
    note(
        "seal.remember_file",
        "remember-file",
        "SEKRET_REMEMBER_FILE",
        shown(&remember_file),
        seal.remember_file.is_some(),
    );
    let unlock_file_origin = note(
        "seal.passphrase_file",
        "unlock-passphrase-file",
        "SEKRET_UNLOCK_PASSPHRASE_FILE",
        shown(&unlock_passphrase_file),
        seal.passphrase_file.is_some(),
    );
    note(
        "setup.web",
        "web-setup",
        "SEKRET_WEB_SETUP",
        web_setup.map(|w| w.to_string()),
        setup.web.is_some(),
    );
    let auto_origin = note(
        "setup.auto_init",
        "auto-init",
        "SEKRET_AUTO_INIT",
        auto_init.map(|a| a.to_string()),
        setup.auto_init.is_some(),
    );
    let setup_file_origin = note(
        "setup.passphrase_file",
        "setup-passphrase-file",
        "SEKRET_SETUP_PASSPHRASE_FILE",
        shown(&setup_passphrase_file),
        setup.passphrase_file.is_some(),
    );
    note(
        "setup.admin_token_file",
        "setup-admin-token-file",
        "SEKRET_SETUP_ADMIN_TOKEN_FILE",
        shown(&admin_token_file),
        setup.admin_token_file.is_some(),
    );
    note(
        "setup.code_file",
        "setup-code-file",
        "SEKRET_SETUP_CODE_FILE",
        shown(&code_file),
        setup.code_file.is_some(),
    );
    note(
        "auth.cli_login_max_auth_age",
        "cli-login-max-auth-age",
        "SEKRET_CLI_LOGIN_MAX_AUTH_AGE",
        max_auth_age.map(|a| a.to_string()),
        auth.cli_login_max_auth_age.is_some(),
    );
    let remember_secret_set = remember_secret_file.is_some() || env_secrets.remember_secret.is_some();
    let secret_origin = match (&remember_secret_file, &env_secrets.remember_secret) {
        (Some(_), _) => sources.origin(
            "remember-secret-file",
            "SEKRET_REMEMBER_SECRET_FILE",
            true,
            seal.remember_secret_file.is_some(),
        ),
        (None, Some(_)) => Origin::Env,
        (None, None) => Origin::Default,
    };
    report.settings.push(Reported {
        name: "seal.remember_secret",
        value: if remember_secret_set {
            "set".into()
        } else {
            "unset".into()
        },
        origin: secret_origin,
    });

    let warnings = &mut report.warnings;
    let overrides_file = [
        ("seal.unlock", unlock_origin, seal.unlock.is_some()),
        (
            "seal.passphrase_file",
            unlock_file_origin,
            seal.passphrase_file.is_some(),
        ),
        ("setup.auto_init", auto_origin, setup.auto_init.is_some()),
        (
            "setup.passphrase_file",
            setup_file_origin,
            setup.passphrase_file.is_some(),
        ),
    ];
    for (name, origin, in_file) in overrides_file {
        if origin == Origin::Env && in_file {
            warnings.push(format!(
                "{name} in the configuration file is overridden by an environment variable; check the service's \
                 environment is meant to set it"
            ));
        }
    }
    if unlock == Some(UnlockPolicy::PassphraseFile) && unlock_origin == Origin::Env {
        warnings.push(
            "the passphrase-file unlock policy comes from SEKRET_UNLOCK in the environment; the server will unlock \
             itself from a passphrase on disk or in the environment"
                .into(),
        );
    }
    let db_file = sqlite_path(&database_url);
    if let Some(remember) = &remember_file {
        check_remember_file(
            remember,
            &[
                ("database", db_file.as_deref()),
                ("root key file", root_key_file.as_deref()),
                ("unlock passphrase file", unlock_passphrase_file.as_deref()),
                ("setup passphrase file", setup_passphrase_file.as_deref()),
                ("remember secret file", remember_secret_file.as_deref()),
            ],
        )?;
        if let Some(db) = &db_file
            && parent_dir(db) == parent_dir(remember)
        {
            warnings.push(format!(
                "the remember file {} is in the database's directory, so a copy of that directory can unlock the \
                 server; keep it on another disk or set seal.remember_secret_file",
                remember.display()
            ));
        }
    }
    let config = ServerConfig {
        listen,
        public_url: public_url.trim_end_matches('/').to_string(),
        oidc: oidc(args, oidc_file)?,
        default_org_role: args
            .default_org_role
            .clone()
            .or(auth.default_org_role)
            .unwrap_or_else(|| "org-member".into()),
        session_ttl: args.session_ttl.or(auth.session_ttl).unwrap_or(12 * 3600),
        cli_token_ttl: args.cli_token_ttl.or(auth.cli_token_ttl).unwrap_or(24 * 3600),
        cli_login_max_auth_age: max_auth_age,
        backup_temp_dir: args.backup_temp_dir.clone().or(backup.temp_dir),
        trusted_proxies,
        allow_insecure_http: args.allow_insecure_http.or(server.allow_insecure_http).unwrap_or(false),
        snapshots_to_keep: args
            .snapshots_to_keep
            .or(database.snapshots_to_keep)
            .unwrap_or(200)
            .max(1),
        login_rate_per_minute: args.login_rate_per_minute.or(auth.login_rate_per_minute).unwrap_or(30),
        tls: tls(args, tls_file)?,
        seal: SealSettings {
            mode,
            unlock,
            root_key_file,
            remember_file,
            remember_secret: remember_secret(remember_secret_file.as_deref(), env_secrets.remember_secret.as_ref())?,
            web_setup: web_setup.unwrap_or(true),
            setup_code_file: code_file.clone(),
        },
        database_url,
    };
    server_warnings(&config, &mut report.warnings);
    let setup = Setup {
        auto_init: auto_init.unwrap_or(false),
        passphrase_file: setup_passphrase_file,
        admin_token_file,
        code_file,
        unlock_passphrase_file,
    };
    Ok(Resolved { config, setup, report })
}

/// Settings that quietly weaken the server.
fn server_warnings(config: &ServerConfig, warnings: &mut Vec<String>) {
    if config.allow_insecure_http {
        warnings.push("allow_insecure_http is on: OIDC and Kubernetes calls may use plain http".into());
    }
    if config.public_url.starts_with("http://") && !config.listen.ip().is_loopback() {
        warnings.push(format!(
            "the public URL {} is plain http but the server listens on {}; cookies and tokens travel unencrypted",
            config.public_url, config.listen
        ));
    }
    for net in sekret_server::auth::broad_proxy_ranges(&config.trusted_proxies) {
        let everything = net.prefix_len() == 0;
        warnings.push(format!(
            "trusted proxy range {net} is {}; any client in it can set its own address with X-Forwarded-For",
            if everything {
                "the whole internet"
            } else {
                "shorter than /8"
            }
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Harness {
        #[command(flatten)]
        args: ServerArgs,
    }

    /// Parses flags; clap also reads SEKRET_* variables, which these tests expect to be unset.
    fn args(flags: &[&str]) -> anyhow::Result<ServerArgs> {
        let mut argv = vec!["sekret"];
        argv.extend_from_slice(flags);
        Ok(Harness::try_parse_from(argv)?.args)
    }

    #[test]
    fn the_example_parses_and_matches_the_defaults() -> anyhow::Result<()> {
        let file = parse(EXAMPLE)?;
        assert_eq!(file.server.public_url.as_deref(), Some("https://sekret.example.com"));
        let from_example = resolve(&args(&[])?, file)?;
        let from_defaults = resolve(
            &args(&["--public-url", "https://sekret.example.com"])?,
            FileConfig::default(),
        )?;
        assert_eq!(
            format!("{:?}", from_example.config),
            format!("{:?}", from_defaults.config)
        );
        assert_eq!(from_example.setup, from_defaults.setup);
        Ok(())
    }

    #[test]
    fn the_docs_copy_of_the_example_is_current() -> anyhow::Result<()> {
        let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/sekret.example.yaml");
        let text = std::fs::read_to_string(&docs).context("docs/sekret.example.yaml")?;
        assert!(
            text == EXAMPLE,
            "docs/sekret.example.yaml is out of date; run `sekret server --print-config > docs/sekret.example.yaml`"
        );
        Ok(())
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert!(parse("server:\n  listn: 0.0.0.0:80\n").is_err());
        assert!(parse("servers: {}\n").is_err());
        assert!(parse("seal:\n  mode: sealed\n").is_err());
    }

    #[test]
    fn flags_beat_the_file_and_the_file_beats_defaults() -> anyhow::Result<()> {
        let file = parse(
            "server:\n  public_url: https://from-file\n  listen: 127.0.0.1:9000\n\
             database:\n  url: sqlite:///var/lib/sekret/db?mode=rwc\n  snapshots_to_keep: 5\n\
             seal:\n  mode: key-file\n  unlock: remember\n  root_key_file: /etc/sekret/root.key\n\
             setup:\n  web: false\n  auto_init: true\n",
        )?;
        let resolved = resolve(
            &args(&["--listen", "127.0.0.1:7000", "--unlock", "manual", "--web-setup"])?,
            file,
        )?;
        let config = resolved.config;
        assert_eq!(config.listen.to_string(), "127.0.0.1:7000");
        assert_eq!(config.public_url, "https://from-file");
        assert_eq!(config.snapshots_to_keep, 5);
        assert_eq!(config.login_rate_per_minute, 30);
        assert_eq!(config.seal.mode, Some(SealMode::KeyFile));
        assert_eq!(config.seal.unlock, Some(UnlockPolicy::Manual));
        assert!(config.seal.web_setup);
        assert_eq!(config.seal.root_key_file, Some(PathBuf::from("/etc/sekret/root.key")));
        assert_eq!(config.seal.remember_file, None, "there is no default remember file");
        assert!(resolved.setup.auto_init);
        Ok(())
    }

    #[test]
    fn booleans_in_the_file_are_strict() {
        assert!(parse("setup:\n  web: false\n").is_ok());
        for loose in ["no", "off", "yes", "on", "False1"] {
            assert!(parse(&format!("setup:\n  web: {loose}\n")).is_err(), "{loose}");
        }
    }

    #[test]
    fn config_errors_never_show_a_database_password() {
        let error = parse("database:\n  url: postgres://sekret:hunter2secret@db/sekret\n  snapshots_to_keep: many\n")
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(!error.is_empty());
        assert!(!error.contains("hunter2secret"), "{error}");
        assert_eq!(
            redact_credentials("at postgres://u:p4ss@h:5432/db and https://h/x"),
            "at postgres://u:***@h:5432/db and https://h/x"
        );
        assert_eq!(redact_credentials("sqlite://a.db"), "sqlite://a.db");
    }

    #[test]
    fn the_remember_file_must_be_its_own_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let db = dir.path().join("sekret.db");
        let url = format!("sqlite://{}?mode=rwc", db.display());
        let same_as_db = args(&[
            "--public-url",
            "https://x",
            "--database-url",
            &url,
            "--remember-file",
            &db.display().to_string(),
        ])?;
        assert!(resolve(&same_as_db, FileConfig::default()).is_err());
        let key = dir.path().join("root.key");
        let same_as_key = args(&[
            "--public-url",
            "https://x",
            "--root-key-file",
            &key.display().to_string(),
            "--remember-file",
            &key.display().to_string(),
        ])?;
        assert!(resolve(&same_as_key, FileConfig::default()).is_err());
        let beside = args(&[
            "--public-url",
            "https://x",
            "--database-url",
            &url,
            "--remember-file",
            &dir.path().join("unlock.key").display().to_string(),
        ])?;
        let resolved = resolve(&beside, FileConfig::default())?;
        assert!(
            resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("database's directory")),
            "{:?}",
            resolved.report.warnings
        );
        Ok(())
    }

    #[test]
    fn the_remember_secret_comes_from_a_file_or_the_environment() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("secret");
        std::fs::write(&path, format!("{}\n", "s".repeat(32))).context("write")?;
        let flags = args(&[
            "--public-url",
            "https://x",
            "--remember-secret-file",
            &path.display().to_string(),
        ])?;
        let resolved = resolve(&flags, FileConfig::default())?;
        assert!(resolved.config.seal.remember_secret.is_some());
        let env = EnvSecrets {
            remember_secret: Some(Zeroizing::new("e".repeat(40))),
            ..EnvSecrets::default()
        };
        let resolved = resolve_with(
            &args(&["--public-url", "https://x"])?,
            FileConfig::default(),
            &env,
            &Sources::none(),
        )?;
        assert!(resolved.config.seal.remember_secret.is_some());
        let short = EnvSecrets {
            remember_secret: Some(Zeroizing::new("too short".into())),
            ..EnvSecrets::default()
        };
        assert!(
            resolve_with(
                &args(&["--public-url", "https://x"])?,
                FileConfig::default(),
                &short,
                &Sources::none()
            )
            .is_err()
        );
        let file = parse(&format!("seal:\n  remember_secret_file: {}\n", path.display()))?;
        let resolved = resolve(&args(&["--public-url", "https://x"])?, file)?;
        assert!(resolved.config.seal.remember_secret.is_some());
        Ok(())
    }

    #[test]
    fn origins_and_weakening_settings_are_reported() -> anyhow::Result<()> {
        let file = parse(
            "seal:\n  unlock: manual\nserver:\n  trusted_proxies: [\"0.0.0.0/0\"]\n  allow_insecure_http: true\n",
        )?;
        let sources = Sources {
            argv: vec!["sekret".into(), "server".into()],
            env: Box::new(|name| name == "SEKRET_UNLOCK"),
        };
        let mut flags = args(&["--public-url", "http://sekret.example.com", "--listen", "0.0.0.0:8080"])?;
        flags.unlock = Some(UnlockPolicy::PassphraseFile);
        let resolved = resolve_with(&flags, file, &EnvSecrets::default(), &sources)?;
        let unlock = resolved
            .report
            .settings
            .iter()
            .find(|s| s.name == "seal.unlock")
            .context("unlock")?;
        assert_eq!(unlock.origin, Origin::Env);
        assert_eq!(unlock.value, "passphrase-file");
        let warnings = resolved.report.warnings.join("\n");
        for expected in [
            "seal.unlock in the configuration file is overridden",
            "passphrase-file unlock policy comes from SEKRET_UNLOCK",
            "allow_insecure_http",
            "plain http",
            "0.0.0.0/0 is the whole internet",
        ] {
            assert!(warnings.contains(expected), "{expected} missing from {warnings}");
        }
        let flagged = Sources {
            argv: vec!["sekret".into(), "--unlock=manual".into()],
            env: Box::new(|_| true),
        };
        assert_eq!(flagged.origin("unlock", "SEKRET_UNLOCK", true, true), Origin::Flag);
        assert_eq!(
            Sources::none().origin("unlock", "SEKRET_UNLOCK", true, true),
            Origin::File
        );
        assert_eq!(
            Sources::none().origin("unlock", "SEKRET_UNLOCK", false, false),
            Origin::Default
        );
        assert!(!format!("{:?}", resolved.report).contains("secret value"));
        Ok(())
    }

    #[test]
    fn new_options_resolve_from_flags_and_the_file() -> anyhow::Result<()> {
        let file = parse("auth:\n  cli_login_max_auth_age: 900\nbackup:\n  temp_dir: /var/lib/sekret/tmp\n")?;
        let resolved = resolve(&args(&["--public-url", "https://x"])?, file)?;
        assert_eq!(resolved.config.cli_login_max_auth_age, Some(900));
        assert_eq!(
            resolved.config.backup_temp_dir,
            Some(PathBuf::from("/var/lib/sekret/tmp"))
        );
        let file = parse("auth:\n  cli_login_max_auth_age: 900\n")?;
        let resolved = resolve(
            &args(&["--public-url", "https://x", "--cli-login-max-auth-age", "60"])?,
            file,
        )?;
        assert_eq!(resolved.config.cli_login_max_auth_age, Some(60));
        assert!(
            resolve(
                &args(&["--public-url", "https://x", "--cli-login-max-auth-age", "0"])?,
                FileConfig::default()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn booleans_accept_flags_and_values() -> anyhow::Result<()> {
        let resolved = resolve(
            &args(&["--public-url", "http://x", "--web-setup=false", "--allow-insecure-http"])?,
            FileConfig::default(),
        )?;
        assert!(!resolved.config.seal.web_setup);
        assert!(resolved.config.allow_insecure_http);
        Ok(())
    }

    #[test]
    fn a_public_url_is_required_and_checked() -> anyhow::Result<()> {
        assert!(resolve(&args(&[])?, FileConfig::default()).is_err());
        assert!(resolve(&args(&["--public-url", "ftp://x"])?, FileConfig::default()).is_err());
        Ok(())
    }

    #[test]
    fn tls_needs_both_halves() -> anyhow::Result<()> {
        let only_cert = args(&["--public-url", "https://x", "--tls-cert-file", "/nonexistent"])?;
        let error = resolve(&only_cert, FileConfig::default())
            .err()
            .context("expected an error")?;
        assert!(error.to_string().contains("both"));
        Ok(())
    }

    #[test]
    fn sqlite_paths_come_from_urls() {
        assert_eq!(sqlite_path("sqlite://a/b.db?mode=rwc"), Some(PathBuf::from("a/b.db")));
        assert_eq!(sqlite_path("sqlite:///abs.db"), Some(PathBuf::from("/abs.db")));
        assert_eq!(sqlite_path("sqlite::memory:"), None);
        assert_eq!(sqlite_path("postgres://x/y"), None);
    }

    #[test]
    fn store_args_read_the_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("sekret.yaml");
        std::fs::write(&path, "database:\n  url: sqlite://x.db\nseal:\n  root_key_file: /k\n").context("write")?;
        let store = StoreArgs {
            config: Some(path),
            database_url: None,
            root_key_file: None,
        };
        let located = store.locate()?;
        assert_eq!(located.database_url, "sqlite://x.db");
        assert_eq!(located.root_key_file, Some(PathBuf::from("/k")));
        Ok(())
    }
}
