//! Server options from flags, environment variables and a YAML file, in that order of precedence.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Args;
use sekret_core::seal::{RememberSecret, SealMode, UnlockPolicy};
use sekret_server::config::{HumanOidcConfig, SealSettings, ServerConfig, TlsSettings, UnixSocketSettings};
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
    /// As a flag, a password in it is visible to other users in the process list; prefer
    /// --database-url-file.
    #[arg(long, env = DATABASE_URL_ENV)]
    pub database_url: Option<String>,
    /// File holding the database URL, so a Postgres password stays out of the process list and
    /// the environment.
    #[arg(long, env = "SEKRET_DATABASE_URL_FILE")]
    pub database_url_file: Option<PathBuf>,
    /// File holding the 32-byte root key (raw, base64 or hex), for key-file mode.
    #[arg(long, env = "SEKRET_ROOT_KEY_FILE")]
    pub root_key_file: Option<PathBuf>,
    /// Device key file for the remember policy; required with it, and best kept off the
    /// database's disk. Admin commands read it to check and keep the seal epoch mark beside it.
    #[arg(long, env = "SEKRET_REMEMBER_FILE")]
    pub remember_file: Option<PathBuf>,
    /// File outside the database for the seal epoch mark; required on Postgres without a
    /// remember or root key file. Admin commands read and raise it the way the server does.
    #[arg(long, env = "SEKRET_EPOCH_FILE")]
    pub epoch_file: Option<PathBuf>,
}

pub const DATABASE_URL_ENV: &str = "SEKRET_DATABASE_URL";

/// The database URL once flag, environment and file have been weighed.
#[derive(Debug)]
pub struct DatabaseChoice {
    pub url: String,
    pub origin: Origin,
    /// `database.url` or `database.url_file`, whichever was used.
    pub key: &'static str,
    /// The URL file the URL was read from, when it came from one.
    pub file: Option<PathBuf>,
    /// Sources that were set but lost.
    pub ignored: Vec<String>,
}

fn rank(origin: Origin) -> u8 {
    match origin {
        Origin::Flag => 3,
        Origin::Env => 2,
        Origin::File => 1,
        Origin::Default => 0,
    }
}

/// Picks the database URL from `--database-url`, `--database-url-file`, their environment
/// variables and the file, in the usual order. The URL and the URL file set at the same level
/// is a mistake rather than something to guess about.
pub fn choose_database(
    args: &StoreArgs,
    section: &DatabaseSection,
    sources: &Sources,
) -> anyhow::Result<DatabaseChoice> {
    enum Candidate<'a> {
        Url(&'a str),
        File(&'a Path),
    }
    let mut candidates: Vec<(&'static str, Origin, Candidate<'_>)> = Vec::new();
    if let Some(url) = &args.database_url {
        let origin = sources.origin("database-url", DATABASE_URL_ENV, true, false);
        candidates.push(("database.url", origin, Candidate::Url(url)));
    }
    if let Some(path) = &args.database_url_file {
        let origin = sources.origin("database-url-file", "SEKRET_DATABASE_URL_FILE", true, false);
        candidates.push(("database.url_file", origin, Candidate::File(path)));
    }
    if let Some(url) = &section.url {
        candidates.push(("database.url", Origin::File, Candidate::Url(url)));
    }
    if let Some(path) = &section.url_file {
        candidates.push(("database.url_file", Origin::File, Candidate::File(path)));
    }
    candidates.sort_by_key(|(_, origin, _)| std::cmp::Reverse(rank(*origin)));
    let Some((key, origin, winner)) = candidates.first() else {
        return Ok(DatabaseChoice {
            url: DEFAULT_DATABASE_URL.into(),
            origin: Origin::Default,
            key: "database.url",
            file: None,
            ignored: Vec::new(),
        });
    };
    if let Some((other, _, _)) = candidates.get(1).filter(|(_, o, _)| rank(*o) == rank(*origin)) {
        bail!(
            "{key} and {other} are both set by the {}; set only one",
            origin.as_str()
        );
    }
    let (url, file) = match winner {
        Candidate::Url(url) => (url.to_string(), None),
        Candidate::File(path) => {
            let url = read_secret_file(path)?;
            if url.is_empty() {
                bail!("the database URL file {} is empty", path.display());
            }
            (url, Some(path.to_path_buf()))
        }
    };
    let ignored = candidates
        .iter()
        .skip(1)
        .map(|(name, lost, _)| {
            format!(
                "{name} from the {} is ignored because {key} from the {} wins",
                lost.as_str(),
                origin.as_str()
            )
        })
        .collect();
    Ok(DatabaseChoice {
        url,
        origin: *origin,
        key,
        file,
        ignored,
    })
}

/// Where the database and root key are, for the admin commands.
pub struct StoreLocation {
    pub database_url: String,
    pub root_key_file: Option<PathBuf>,
    /// Found the way the server finds it, so the epoch mark beside it is read and kept up to date.
    pub remember_file: Option<PathBuf>,
    pub epoch_file: Option<PathBuf>,
}

impl StoreLocation {
    pub fn epoch_files(&self) -> Vec<PathBuf> {
        sekret_server::config::epoch_files(
            &self.database_url,
            self.remember_file.as_deref(),
            self.root_key_file.as_deref(),
            self.epoch_file.as_deref(),
        )
    }
}

impl StoreArgs {
    pub fn locate(&self, sources: &Sources) -> anyhow::Result<StoreLocation> {
        let file = load(self.config.as_deref())?;
        Ok(StoreLocation {
            database_url: choose_database(self, &file.database, sources)?.url,
            root_key_file: self.root_key_file.clone().or(file.seal.root_key_file),
            remember_file: self.remember_file.clone().or(file.seal.remember_file),
            epoch_file: self.epoch_file.clone().or(file.seal.epoch_file),
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
    /// When set, only ID tokens with one of these subjects (`sub`) may sign in, whatever their groups.
    #[arg(long, env = "SEKRET_OIDC_ALLOWED_SUBJECTS", value_delimiter = ',')]
    pub oidc_allowed_subjects: Option<Vec<String>>,
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
    /// Connections served at once; more wait until one closes [default: 512].
    #[arg(long, env = "SEKRET_MAX_CONNECTIONS")]
    pub max_connections: Option<usize>,
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
    /// Unix socket for `sekret sys unseal --socket`, outside the network's rate limits.
    #[arg(long, env = "SEKRET_UNIX_SOCKET")]
    pub unix_socket: Option<PathBuf>,
    /// 0600, or 0660 to let the socket's group unseal too [default: 0600].
    #[arg(long, env = "SEKRET_UNIX_SOCKET_MODE")]
    pub unix_socket_mode: Option<String>,
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
    pub unix_socket: Option<PathBuf>,
    pub unix_socket_mode: Option<String>,
    pub max_connections: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseSection {
    pub url: Option<String>,
    pub url_file: Option<PathBuf>,
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
    pub allowed_subjects: Option<Vec<String>>,
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
    pub epoch_file: Option<PathBuf>,
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
    /// Reads and removes the secret variables, overwriting their values first so they no longer
    /// show in `/proc/<pid>/environ`. Only call this from `main` while the process has one thread.
    pub fn take() -> anyhow::Result<Self> {
        scrub_database_url()?;
        Ok(Self {
            unlock_passphrase: take_secret(UNLOCK_PASSPHRASE_ENV)?,
            remember_secret: take_secret(REMEMBER_SECRET_ENV)?,
        })
    }
}

/// Removes the database URL, which can hold a Postgres password, once clap has read it. Only
/// call this from `main` while the process has one thread.
pub fn scrub_database_url() -> anyhow::Result<()> {
    take_secret(DATABASE_URL_ENV).map(drop)
}

/// Removes and overwrites each named variable once clap has read what it needs, so a program
/// `sekret run` starts cannot read them from its parent's `/proc/<pid>/environ`. Only call this
/// from `main` while the process has one thread.
pub fn scrub_env(names: &[&str]) -> anyhow::Result<()> {
    for name in names {
        take_secret(name)?;
    }
    Ok(())
}

fn take_secret(name: &str) -> anyhow::Result<Option<Zeroizing<String>>> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(None);
    };
    scrub_environ(name);
    // SAFETY: called from `main` before the runtime or any other thread starts, so nothing else
    // reads or changes the environment while it is changed here.
    unsafe { std::env::remove_var(name) };
    let value = raw
        .into_string()
        .map_err(|_| anyhow::anyhow!("{name} is not valid UTF-8"))?;
    Ok(Some(Zeroizing::new(value)))
}

/// Overwrites the value of `name` with zero bytes in the process's own environment block. The
/// kernel serves `/proc/<pid>/environ` from that memory, and removing a variable only unlinks
/// it, so without this the value stays readable there for the life of the process.
#[cfg(unix)]
fn scrub_environ(name: &str) {
    unsafe extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }
    let prefix = format!("{name}=");
    // SAFETY: only called from `main` while the process has one thread, so nothing reads or
    // changes the environment meanwhile. `environ` is the C library's null-terminated array of
    // pointers to NUL-terminated strings that the process owns and may write. Each string's
    // length is measured before it is touched, and the writes stay within those bytes.
    unsafe {
        let mut entry = environ;
        if entry.is_null() {
            return;
        }
        while !(*entry).is_null() {
            let text = (*entry).cast::<u8>();
            let len = libc::strlen(*entry);
            let matches = len >= prefix.len() && std::slice::from_raw_parts(text, prefix.len()) == prefix.as_bytes();
            if matches {
                for offset in prefix.len()..len {
                    std::ptr::write_volatile(text.add(offset), 0);
                }
            }
            entry = entry.add(1);
        }
    }
}

#[cfg(not(unix))]
fn scrub_environ(_name: &str) {}

/// The remember secret from the source that won.
fn remember_secret(
    from: Option<&SecretFrom>,
    env: Option<&Zeroizing<String>>,
) -> anyhow::Result<Option<RememberSecret>> {
    let text = match (from, env) {
        (Some(SecretFrom::File(path)), _) => {
            let bytes = read_limited(path, SECRET_FILE_LIMIT).with_context(|| format!("reading {}", path.display()))?;
            Zeroizing::new(
                std::str::from_utf8(&bytes)
                    .with_context(|| format!("{} is not UTF-8", path.display()))?
                    .to_string(),
            )
        }
        (Some(SecretFrom::Env), Some(value)) => value.clone(),
        _ => return Ok(None),
    };
    Ok(Some(RememberSecret::new(&text).context("the remember secret")?))
}

/// Where a secret is read from once flag, environment and file have been weighed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretFrom {
    File(PathBuf),
    /// The variable holding the value itself.
    Env,
}

/// The names of the ways one secret can be given, for messages.
struct SecretNames {
    flag: &'static str,
    file_env: &'static str,
    value_env: &'static str,
    key: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
struct SecretChoice {
    from: Option<SecretFrom>,
    origin: Origin,
    /// Sources that were set but lost.
    ignored: Vec<String>,
}

/// Picks a secret's source in the documented order: the flag, then the environment, then the
/// file. Of the two environment variables, the one naming a file wins over the value itself.
fn choose_secret(
    names: &SecretNames,
    argument: Option<(&Path, Origin)>,
    in_file: Option<&Path>,
    env_value: bool,
) -> SecretChoice {
    let mut candidates: Vec<(&'static str, Origin, SecretFrom)> = Vec::new();
    if let Some((path, origin)) = argument {
        let name = if origin == Origin::Flag {
            names.flag
        } else {
            names.file_env
        };
        candidates.push((name, origin, SecretFrom::File(path.to_path_buf())));
    }
    if env_value {
        candidates.push((names.value_env, Origin::Env, SecretFrom::Env));
    }
    if let Some(path) = in_file {
        candidates.push((names.key, Origin::File, SecretFrom::File(path.to_path_buf())));
    }
    let mut candidates = candidates.into_iter();
    let Some((winner, origin, from)) = candidates.next() else {
        return SecretChoice {
            from: None,
            origin: Origin::Default,
            ignored: Vec::new(),
        };
    };
    SecretChoice {
        from: Some(from),
        origin,
        ignored: candidates
            .map(|(name, _, _)| format!("{name} is set but ignored, because {winner} wins"))
            .collect(),
    }
}

const REMEMBER_SECRET_NAMES: SecretNames = SecretNames {
    flag: "--remember-secret-file",
    file_env: "SEKRET_REMEMBER_SECRET_FILE",
    value_env: REMEMBER_SECRET_ENV,
    key: "seal.remember_secret_file",
};

const UNLOCK_PASSPHRASE_NAMES: SecretNames = SecretNames {
    flag: "--unlock-passphrase-file",
    file_env: "SEKRET_UNLOCK_PASSPHRASE_FILE",
    value_env: UNLOCK_PASSPHRASE_ENV,
    key: "seal.passphrase_file",
};

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
    /// The command line and the names in the environment now, before any secret variable is
    /// removed from it.
    pub fn process() -> Self {
        let present: std::collections::HashSet<String> = std::env::vars_os()
            .filter_map(|(name, _)| name.into_string().ok())
            .collect();
        Self {
            // args() panics on an argument that is not UTF-8, such as a path.
            argv: std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect(),
            env: Box::new(move |name| present.contains(name)),
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

/// Collects each setting's value and origin, and the settings in the file that an environment
/// variable overrode.
struct Notes<'a> {
    sources: &'a Sources,
    report: Report,
    overridden: Vec<&'static str>,
}

impl Notes<'_> {
    fn note(&mut self, name: &'static str, flag: &str, env: &str, value: Option<String>, in_file: bool) -> Origin {
        let origin = self.sources.origin(flag, env, value.is_some(), in_file);
        self.record(name, value, origin, in_file);
        origin
    }

    fn record(&mut self, name: &'static str, value: Option<String>, origin: Origin, in_file: bool) {
        if origin == Origin::Env && in_file {
            self.overridden.push(name);
        }
        self.report.settings.push(Reported {
            name,
            value: value.unwrap_or_else(|| "unset".into()),
            origin,
        });
    }
}

use sekret_store::canonical_path as resolved;

/// The device of the nearest existing ancestor of `path`.
#[cfg(unix)]
fn device(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    resolved(path)
        .ancestors()
        .find_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.dev())
}

#[cfg(not(unix))]
fn device(_path: &Path) -> Option<u64> {
    None
}

fn same_path(a: &Path, b: &Path) -> bool {
    a == b || resolved(a) == resolved(b)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Files the server writes or deletes must each be a file of their own, never one sekret reads,
/// another one it writes, or a part of the database.
fn check_distinct(written: &[(&str, Option<&Path>)], read: &[(&str, Option<&Path>)]) -> anyhow::Result<()> {
    for (index, (name, path)) in written.iter().enumerate() {
        let Some(path) = path else {
            continue;
        };
        let others = written.iter().skip(index + 1).chain(read.iter());
        for (other_name, other) in others {
            if let Some(other) = other
                && same_path(path, other)
            {
                bail!(
                    "the {name} {} is the same file as the {other_name}; choose a separate file",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// Owner, group and mode of a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirFacts {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// Why users other than `uid` (with primary group `gid`) could replace a file in `dir`. A sticky
/// directory, such as a Kubernetes secret mount, only lets each owner replace their own entries.
pub fn replaceable_in(dir: DirFacts, uid: u32, gid: u32) -> Option<&'static str> {
    if dir.uid != uid && dir.uid != 0 {
        return Some("its directory belongs to another user, who can replace it");
    }
    if dir.mode & 0o1000 != 0 {
        return None;
    }
    if dir.mode & 0o002 != 0 {
        return Some("its directory is writable by every user, so anyone can replace it");
    }
    // With user private groups the group holds only this user.
    let private_group = dir.gid == gid && gid == uid;
    if dir.mode & 0o020 != 0 && !private_group {
        return Some("its directory is writable by its group, whose members can replace it");
    }
    None
}

#[cfg(unix)]
fn directory_exposure(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let parent = |p: &Path| {
        p.parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    };
    let mut dirs = vec![parent(path)];
    if let Ok(target) = std::fs::canonicalize(path) {
        dirs.push(parent(&target));
    }
    // SAFETY: geteuid and getegid have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    dirs.iter().find_map(|dir| {
        let meta = std::fs::metadata(dir).ok()?;
        let facts = DirFacts {
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
        };
        replaceable_in(facts, uid, gid).map(|why| format!("{} is in {}, and {why}", path.display(), dir.display()))
    })
}

#[cfg(not(unix))]
fn directory_exposure(_path: &Path) -> Option<String> {
    None
}

/// Why a file holding a key, passphrase or credential is exposed: others can read it, another
/// user owns it, or its directory lets others replace it.
pub fn secret_file_exposure(path: &Path) -> Option<String> {
    sekret_server::files::exposure(path).or_else(|| directory_exposure(path))
}

/// Warnings for key, passphrase and secret files that other users can read or replace.
fn exposure_warnings(files: &[(&str, Option<&Path>)]) -> Vec<String> {
    files
        .iter()
        .filter_map(|(name, path)| {
            path.and_then(secret_file_exposure)
                .map(|why| format!("the {name}: {why}"))
        })
        .collect()
}

/// Whether a database URL carries a password, in its user info or as a `password` parameter.
fn has_password(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|url| {
        url.password().is_some() || url.query_pairs().any(|(key, _)| key.eq_ignore_ascii_case("password"))
    })
}

/// The remember file is meant to live apart from the database, so that a copy of the
/// database's disk or directory cannot unlock the server on its own.
fn remember_warnings(remember: &Path, database: Option<&Path>, warnings: &mut Vec<String>) {
    let Some(database) = database else {
        return;
    };
    let db_dir = resolved(database)
        .parent()
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
    // A subdirectory of the database's directory is usually on the same disk and in the same copies.
    if resolved(remember).starts_with(&db_dir) {
        warnings.push(format!(
            "the remember file {} is under the database's directory, so a copy of that directory can unlock the \
             server; keep it on another disk or set seal.remember_secret_file",
            remember.display()
        ));
        return;
    }
    if device(remember).is_some() && device(remember) == device(database) {
        warnings.push(format!(
            "the remember file {} is on the same filesystem as the database, so a copy of that disk can unlock the \
             server; keep it on another disk or set seal.remember_secret_file",
            remember.display()
        ));
    }
}

fn parse_socket_mode(raw: &str) -> anyhow::Result<u32> {
    match raw.trim_start_matches("0o") {
        "0600" | "600" => Ok(0o600),
        "0660" | "660" => Ok(0o660),
        _ => bail!("unix_socket_mode must be 0600 or 0660, not {raw}"),
    }
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
        allowed_subjects: args
            .oidc_allowed_subjects
            .clone()
            .or(file.allowed_subjects)
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
        .or(server.public_url.clone())
        .context("a public URL is required: --public-url, SEKRET_PUBLIC_URL or server.public_url")?;
    if !public_url.starts_with("http://") && !public_url.starts_with("https://") {
        bail!("the public URL must start with http:// or https://");
    }
    let proxies_in_file = server.trusted_proxies.is_some();
    let insecure_in_file = server.allow_insecure_http.is_some();
    let allow_insecure_http = args.allow_insecure_http.or(server.allow_insecure_http).unwrap_or(false);
    let role_in_file = auth.default_org_role.is_some();
    let default_org_role = args
        .default_org_role
        .clone()
        .or(auth.default_org_role.clone())
        .unwrap_or_else(|| "org-member".into());
    let oidc_secret_file = args
        .oidc_client_secret_file
        .clone()
        .or(oidc_file.client_secret_file.clone());
    let tls_key_file = args.tls_key_file.clone().or(tls_file.key_file.clone());
    let socket_path = args.unix_socket.clone().or(server.unix_socket.clone());
    let socket_mode = args
        .unix_socket_mode
        .clone()
        .or(server.unix_socket_mode.clone())
        .map(|raw| parse_socket_mode(&raw))
        .transpose()?
        .unwrap_or(0o600);
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
    let database_choice = choose_database(&args.store, &database, sources)?;
    let database_url = database_choice.url.clone();
    let mut notes = Notes {
        sources,
        report: Report::default(),
        overridden: Vec::new(),
    };
    let shown = |p: &Option<PathBuf>| p.as_ref().map(|p| p.display().to_string());
    let remember_file = args.store.remember_file.clone().or(seal.remember_file.clone());
    let epoch_file = args.store.epoch_file.clone().or(seal.epoch_file.clone());
    fn argument<'p>(sources: &Sources, path: &'p Option<PathBuf>, flag: &str, env: &str) -> Option<(&'p Path, Origin)> {
        path.as_deref().map(|p| (p, sources.origin(flag, env, true, false)))
    }
    let remember_choice = choose_secret(
        &REMEMBER_SECRET_NAMES,
        argument(
            sources,
            &args.remember_secret_file,
            "remember-secret-file",
            "SEKRET_REMEMBER_SECRET_FILE",
        ),
        seal.remember_secret_file.as_deref(),
        env_secrets.remember_secret.is_some(),
    );
    let unlock_choice = choose_secret(
        &UNLOCK_PASSPHRASE_NAMES,
        argument(
            sources,
            &args.unlock_passphrase_file,
            "unlock-passphrase-file",
            "SEKRET_UNLOCK_PASSPHRASE_FILE",
        ),
        seal.passphrase_file.as_deref(),
        env_secrets.unlock_passphrase.is_some(),
    );
    let chosen_file = |choice: &SecretChoice| match &choice.from {
        Some(SecretFrom::File(path)) => Some(path.clone()),
        _ => None,
    };
    let remember_secret_file = chosen_file(&remember_choice);
    let unlock_passphrase_file = chosen_file(&unlock_choice);
    let setup_passphrase_file = args.setup_passphrase_file.clone().or(setup.passphrase_file.clone());
    let root_key_file = args.store.root_key_file.clone().or(seal.root_key_file.clone());
    let unlock = args.unlock.or(seal.unlock);
    let mode = args.seal_mode.or(seal.mode);
    if mode == Some(SealMode::Passphrase)
        && let Some(key) = &root_key_file
    {
        bail!(
            "seal.mode is passphrase but seal.root_key_file is set to {}, which would let the server unlock \
             itself without the passphrase; remove the root key file setting, leave seal.mode unset to use the \
             key file as an emergency way in, or switch modes with `sekret admin set-seal-mode`",
            key.display()
        );
    }
    let client_auth_without_ca = args.tls_client_auth.or(tls_file.client_auth).is_some()
        && args.tls_client_ca_file.is_none()
        && tls_file.client_ca_file.is_none();
    let config_has_password = database.url.as_deref().is_some_and(has_password);
    let web_setup = args.web_setup.or(setup.web);
    let auto_init = args.auto_init.or(setup.auto_init);
    let admin_token_file = args.setup_admin_token_file.clone().or(setup.admin_token_file.clone());
    let code_file = args.setup_code_file.clone().or(setup.code_file.clone());
    let max_auth_age = args.cli_login_max_auth_age.or(auth.cli_login_max_auth_age);
    if max_auth_age.is_some_and(|age| age <= 0) {
        bail!("cli_login_max_auth_age must be a positive number of seconds");
    }
    let max_connections = args
        .max_connections
        .or(server.max_connections)
        .unwrap_or(sekret_server::config::DEFAULT_MAX_CONNECTIONS);
    if max_connections == 0 {
        bail!("max_connections must be at least 1");
    }
    let session_ttl = args.session_ttl.or(auth.session_ttl).unwrap_or(12 * 3600);
    let cli_token_ttl = args.cli_token_ttl.or(auth.cli_token_ttl).unwrap_or(24 * 3600);
    let ttl_warnings: Vec<String> = [
        check_ttl("auth.session_ttl", session_ttl, SESSION_TTL_USUAL_DAYS)?,
        check_ttl("auth.cli_token_ttl", cli_token_ttl, CLI_TOKEN_TTL_USUAL_DAYS)?,
    ]
    .into_iter()
    .flatten()
    .collect();
    let snapshots_to_keep = args
        .snapshots_to_keep
        .or(database.snapshots_to_keep)
        .unwrap_or(200)
        .max(1);
    let login_rate_per_minute = args.login_rate_per_minute.or(auth.login_rate_per_minute).unwrap_or(30);
    let backup_temp_dir = args.backup_temp_dir.clone().or(backup.temp_dir.clone());
    notes.note(
        "server.listen",
        "listen",
        "SEKRET_LISTEN",
        Some(listen.to_string()),
        server.listen.is_some(),
    );
    notes.note(
        "server.public_url",
        "public-url",
        "SEKRET_PUBLIC_URL",
        Some(public_url.clone()),
        server.public_url.is_some(),
    );
    notes.note(
        "server.unix_socket",
        "unix-socket",
        "SEKRET_UNIX_SOCKET",
        shown(&socket_path),
        server.unix_socket.is_some(),
    );
    notes.note(
        "server.unix_socket_mode",
        "unix-socket-mode",
        "SEKRET_UNIX_SOCKET_MODE",
        Some(format!("{socket_mode:04o}")),
        server.unix_socket_mode.is_some(),
    );
    let url_file_shown = args
        .store
        .database_url_file
        .clone()
        .or(database.url_file.clone())
        .map(|p| p.display().to_string());
    notes.record(
        database_choice.key,
        match database_choice.key {
            "database.url_file" => url_file_shown,
            _ => Some(redact_credentials(&database_url)),
        },
        database_choice.origin,
        database.url.is_some() || database.url_file.is_some(),
    );
    notes.note(
        "database.snapshots_to_keep",
        "snapshots-to-keep",
        "SEKRET_SNAPSHOTS_TO_KEEP",
        Some(snapshots_to_keep.to_string()),
        database.snapshots_to_keep.is_some(),
    );
    notes.note(
        "auth.session_ttl",
        "session-ttl",
        "SEKRET_SESSION_TTL",
        Some(session_ttl.to_string()),
        auth.session_ttl.is_some(),
    );
    notes.note(
        "auth.cli_token_ttl",
        "cli-token-ttl",
        "SEKRET_CLI_TOKEN_TTL",
        Some(cli_token_ttl.to_string()),
        auth.cli_token_ttl.is_some(),
    );
    notes.note(
        "auth.login_rate_per_minute",
        "login-rate-per-minute",
        "SEKRET_LOGIN_RATE_PER_MINUTE",
        Some(login_rate_per_minute.to_string()),
        auth.login_rate_per_minute.is_some(),
    );
    notes.note(
        "oidc.issuer",
        "oidc-issuer",
        "SEKRET_OIDC_ISSUER",
        args.oidc_issuer.clone().or(oidc_file.issuer.clone()),
        oidc_file.issuer.is_some(),
    );
    notes.note(
        "oidc.client_id",
        "oidc-client-id",
        "SEKRET_OIDC_CLIENT_ID",
        args.oidc_client_id.clone().or(oidc_file.client_id.clone()),
        oidc_file.client_id.is_some(),
    );
    notes.note(
        "oidc.client_secret_file",
        "oidc-client-secret-file",
        "SEKRET_OIDC_CLIENT_SECRET_FILE",
        shown(&oidc_secret_file),
        oidc_file.client_secret_file.is_some(),
    );
    notes.note(
        "oidc.scopes",
        "oidc-scopes",
        "SEKRET_OIDC_SCOPES",
        args.oidc_scopes
            .clone()
            .or(oidc_file.scopes.clone())
            .map(|s| s.join(" ")),
        oidc_file.scopes.is_some(),
    );
    notes.note(
        "tls.cert_file",
        "tls-cert-file",
        "SEKRET_TLS_CERT_FILE",
        shown(&args.tls_cert_file.clone().or(tls_file.cert_file.clone())),
        tls_file.cert_file.is_some(),
    );
    notes.note(
        "tls.key_file",
        "tls-key-file",
        "SEKRET_TLS_KEY_FILE",
        shown(&tls_key_file),
        tls_file.key_file.is_some(),
    );
    notes.note(
        "tls.client_ca_file",
        "tls-client-ca-file",
        "SEKRET_TLS_CLIENT_CA_FILE",
        shown(&args.tls_client_ca_file.clone().or(tls_file.client_ca_file.clone())),
        tls_file.client_ca_file.is_some(),
    );
    notes.note(
        "tls.client_auth",
        "tls-client-auth",
        "SEKRET_TLS_CLIENT_AUTH",
        args.tls_client_auth
            .or(tls_file.client_auth)
            .map(|a| format!("{a:?}").to_lowercase()),
        tls_file.client_auth.is_some(),
    );
    notes.note(
        "backup.temp_dir",
        "backup-temp-dir",
        "SEKRET_BACKUP_TEMP_DIR",
        shown(&backup_temp_dir),
        backup.temp_dir.is_some(),
    );
    notes.note(
        "seal.mode",
        "seal-mode",
        "SEKRET_SEAL_MODE",
        mode.map(|m| m.as_str().into()),
        seal.mode.is_some(),
    );
    let unlock_origin = notes.note(
        "seal.unlock",
        "unlock",
        "SEKRET_UNLOCK",
        unlock.map(|u| u.as_str().into()),
        seal.unlock.is_some(),
    );
    notes.note(
        "seal.root_key_file",
        "root-key-file",
        "SEKRET_ROOT_KEY_FILE",
        shown(&root_key_file),
        seal.root_key_file.is_some(),
    );
    notes.note(
        "auth.default_org_role",
        "default-org-role",
        "SEKRET_DEFAULT_ORG_ROLE",
        Some(default_org_role.clone()),
        role_in_file,
    );
    notes.note(
        "server.trusted_proxies",
        "trusted-proxies",
        "SEKRET_TRUSTED_PROXIES",
        (!trusted_proxies.is_empty()).then(|| {
            trusted_proxies
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }),
        proxies_in_file,
    );
    notes.note(
        "server.allow_insecure_http",
        "allow-insecure-http",
        "SEKRET_ALLOW_INSECURE_HTTP",
        Some(allow_insecure_http.to_string()),
        insecure_in_file,
    );
    let oidc_lists = [
        (
            "oidc.group_claims",
            "oidc-group-claims",
            "SEKRET_OIDC_GROUP_CLAIMS",
            &args.oidc_group_claims,
            &oidc_file.group_claims,
        ),
        (
            "oidc.admin_groups",
            "oidc-admin-groups",
            "SEKRET_OIDC_ADMIN_GROUPS",
            &args.oidc_admin_groups,
            &oidc_file.admin_groups,
        ),
        (
            "oidc.required_groups",
            "oidc-required-groups",
            "SEKRET_OIDC_REQUIRED_GROUPS",
            &args.oidc_required_groups,
            &oidc_file.required_groups,
        ),
        (
            "oidc.allowed_subjects",
            "oidc-allowed-subjects",
            "SEKRET_OIDC_ALLOWED_SUBJECTS",
            &args.oidc_allowed_subjects,
            &oidc_file.allowed_subjects,
        ),
    ];
    for (name, flag, env, given, in_file) in oidc_lists {
        let value = given.as_ref().or(in_file.as_ref()).map(|v| v.join(","));
        notes.note(name, flag, env, value, in_file.is_some());
    }
    notes.note(
        "seal.remember_file",
        "remember-file",
        "SEKRET_REMEMBER_FILE",
        shown(&remember_file),
        seal.remember_file.is_some(),
    );
    notes.note(
        "seal.epoch_file",
        "epoch-file",
        "SEKRET_EPOCH_FILE",
        shown(&epoch_file),
        seal.epoch_file.is_some(),
    );
    let secret_shown = |choice: &SecretChoice, env: &str| {
        choice.from.as_ref().map(|from| match from {
            SecretFrom::File(path) => path.display().to_string(),
            SecretFrom::Env => env.to_string(),
        })
    };
    notes.record(
        "seal.remember_secret",
        secret_shown(&remember_choice, REMEMBER_SECRET_ENV),
        remember_choice.origin,
        seal.remember_secret_file.is_some(),
    );
    notes.record(
        "seal.passphrase_file",
        secret_shown(&unlock_choice, UNLOCK_PASSPHRASE_ENV),
        unlock_choice.origin,
        seal.passphrase_file.is_some(),
    );
    notes.note(
        "setup.web",
        "web-setup",
        "SEKRET_WEB_SETUP",
        web_setup.map(|w| w.to_string()),
        setup.web.is_some(),
    );
    notes.note(
        "setup.auto_init",
        "auto-init",
        "SEKRET_AUTO_INIT",
        auto_init.map(|a| a.to_string()),
        setup.auto_init.is_some(),
    );
    notes.note(
        "setup.passphrase_file",
        "setup-passphrase-file",
        "SEKRET_SETUP_PASSPHRASE_FILE",
        shown(&setup_passphrase_file),
        setup.passphrase_file.is_some(),
    );
    notes.note(
        "setup.admin_token_file",
        "setup-admin-token-file",
        "SEKRET_SETUP_ADMIN_TOKEN_FILE",
        shown(&admin_token_file),
        setup.admin_token_file.is_some(),
    );
    notes.note(
        "setup.code_file",
        "setup-code-file",
        "SEKRET_SETUP_CODE_FILE",
        shown(&code_file),
        setup.code_file.is_some(),
    );
    notes.note(
        "auth.cli_login_max_auth_age",
        "cli-login-max-auth-age",
        "SEKRET_CLI_LOGIN_MAX_AUTH_AGE",
        max_auth_age.map(|a| a.to_string()),
        auth.cli_login_max_auth_age.is_some(),
    );
    notes.note(
        "server.max_connections",
        "max-connections",
        "SEKRET_MAX_CONNECTIONS",
        Some(max_connections.to_string()),
        server.max_connections.is_some(),
    );

    let Notes {
        mut report, overridden, ..
    } = notes;
    let warnings = &mut report.warnings;
    for name in overridden {
        warnings.push(format!(
            "{name} in the configuration file is overridden by an environment variable; check the service's \
             environment is meant to set it"
        ));
    }
    let ignored = database_choice
        .ignored
        .iter()
        .chain(&remember_choice.ignored)
        .chain(&unlock_choice.ignored);
    warnings.extend(ignored.cloned());
    warnings.extend(ttl_warnings);
    if let Some(warning) = unlock_from_env_warning(unlock, unlock_origin) {
        warnings.push(warning);
    }
    if let Some(warning) = database_flag_warning(&database_choice) {
        warnings.push(warning);
    }
    if let Some(warning) = args.store.config.as_deref().and_then(config_writers) {
        warnings.push(warning);
    }
    if let Some(warning) = default_role_warning(&default_org_role) {
        warnings.push(warning);
    }
    if client_auth_without_ca {
        warnings.push(
            "tls.client_auth is set but tls.client_ca_file is not, so client certificates are not checked; set \
             tls.client_ca_file to turn on mutual TLS"
                .into(),
        );
    }
    let db_file = sqlite_path(&database_url);
    let db_parts = db_file
        .as_deref()
        .map(|db| [sibling(db, "-wal"), sibling(db, "-shm"), sekret_store::lock_file(db)]);
    let db_part = |i: usize| db_parts.as_ref().map(|parts| parts[i].as_path());
    let epoch_of = |path: &Option<PathBuf>| path.as_deref().map(|p| sibling(&resolved(p), ".epoch"));
    let db_epoch = epoch_of(&db_file);
    let remember_epoch = epoch_of(&remember_file);
    let root_key_epoch = epoch_of(&root_key_file);
    check_distinct(
        &[
            ("remember file", remember_file.as_deref()),
            ("setup code file", code_file.as_deref()),
            ("setup admin token file", admin_token_file.as_deref()),
            ("unix socket", socket_path.as_deref()),
            ("database's lock file", db_part(2)),
            ("database's epoch file", db_epoch.as_deref()),
            ("remember file's epoch file", remember_epoch.as_deref()),
            ("root key file's epoch file", root_key_epoch.as_deref()),
            ("epoch file", epoch_file.as_deref()),
        ],
        &[
            ("database", db_file.as_deref()),
            ("database's write-ahead log", db_part(0)),
            ("database's shared memory file", db_part(1)),
            ("root key file", root_key_file.as_deref()),
            ("unlock passphrase file", unlock_passphrase_file.as_deref()),
            ("setup passphrase file", setup_passphrase_file.as_deref()),
            ("remember secret file", remember_secret_file.as_deref()),
            ("configuration file", args.store.config.as_deref()),
            ("OIDC client secret file", oidc_secret_file.as_deref()),
            ("TLS key file", tls_key_file.as_deref()),
        ],
    )?;
    if let Some(remember) = &remember_file {
        remember_warnings(remember, db_file.as_deref(), warnings);
    }
    warnings.extend(exposure_warnings(&[
        ("root key file", root_key_file.as_deref()),
        ("remember file", remember_file.as_deref()),
        ("remember secret file", remember_secret_file.as_deref()),
        ("unlock passphrase file", unlock_passphrase_file.as_deref()),
        ("setup passphrase file", setup_passphrase_file.as_deref()),
        ("OIDC client secret file", oidc_secret_file.as_deref()),
        ("TLS key file", tls_key_file.as_deref()),
        (
            "database URL file",
            database_choice.file.as_deref().filter(|_| has_password(&database_url)),
        ),
        (
            "configuration file, which holds a database password,",
            args.store.config.as_deref().filter(|_| config_has_password),
        ),
    ]));
    let epoch_files = sekret_server::config::epoch_files(
        &database_url,
        remember_file.as_deref(),
        root_key_file.as_deref(),
        epoch_file.as_deref(),
    );
    let config = ServerConfig {
        listen,
        public_url: public_url.trim_end_matches('/').to_string(),
        oidc: oidc(args, oidc_file)?,
        default_org_role,
        session_ttl,
        cli_token_ttl,
        cli_login_max_auth_age: max_auth_age,
        backup_temp_dir,
        trusted_proxies,
        allow_insecure_http,
        snapshots_to_keep,
        login_rate_per_minute,
        max_connections,
        tls: tls(args, tls_file)?,
        seal: SealSettings {
            mode,
            unlock,
            root_key_file,
            remember_file,
            remember_secret: remember_secret(remember_choice.from.as_ref(), env_secrets.remember_secret.as_ref())?,
            web_setup: web_setup.unwrap_or(true),
            // Filled in once the code is written.
            setup_code_file: None,
            epoch_files,
        },
        unix_socket: socket_path.map(|path| UnixSocketSettings {
            path,
            mode: socket_mode,
        }),
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
    if config.public_url.starts_with("https://") && config.tls.is_none() && !config.listen.ip().is_loopback() {
        warnings.push(format!(
            "the public URL {} is https but the server itself speaks plain http on {}, so anyone who can reach that \
             address skips the proxy's TLS; listen on 127.0.0.1 or the proxy's interface, or set tls",
            config.public_url, config.listen
        ));
    }
    warnings.extend(sekret_server::auth::proxy_range_warnings(&config.trusted_proxies));
    if let Some(warning) = open_sign_in_warning(config.oidc.as_ref(), &config.default_org_role) {
        warnings.push(warning);
    }
    if config.login_rate_per_minute > LOGIN_RATE_USUAL_MOST {
        warnings.push(format!(
            "auth.login_rate_per_minute is {}, which also lets each address try that many unseal and setup \
             passphrases a minute; keep it at {LOGIN_RATE_USUAL_MOST} or below unless that is really intended",
            config.login_rate_per_minute
        ));
    }
}

/// Past this, the passphrase guessing rate the same setting allows is worth a warning.
const LOGIN_RATE_USUAL_MOST: u32 = 300;

/// With no restriction, every account at the provider can sign in and gets the default role.
/// Not refused, since a single-tenant provider is already a restriction sekret cannot see.
fn open_sign_in_warning(oidc: Option<&HumanOidcConfig>, default_org_role: &str) -> Option<String> {
    let oidc = oidc?;
    if !oidc.required_groups.is_empty() || !oidc.allowed_subjects.is_empty() || default_org_role.is_empty() {
        return None;
    }
    let admins = match (oidc.group_claims.is_empty(), oidc.admin_groups.is_empty()) {
        (false, false) => format!(
            ", and anyone whose {} claim holds {} becomes an organisation admin",
            oidc.group_claims.join(" or "),
            oidc.admin_groups.join(" or ")
        ),
        _ => String::new(),
    };
    Some(format!(
        "OIDC sign-in is open to every account at {}: oidc.required_groups and oidc.allowed_subjects are empty, \
         so anyone the provider signs in becomes {default_org_role}{admins}; set oidc.required_groups or \
         oidc.allowed_subjects, or set auth.default_org_role to \"\" (an empty list means no restriction, not no one)",
        oidc.issuer,
    ))
}

/// Giving every signed-in person a powerful organisation role is almost never meant.
fn default_role_warning(role: &str) -> Option<String> {
    let what = match role {
        "org-admin" => "makes everyone who can sign in an organisation admin",
        "backup-reader" => "lets everyone who can sign in download encrypted backups of the whole database",
        _ => return None,
    };
    Some(format!(
        "auth.default_org_role is {role}, which {what}; use org-member unless that is really intended"
    ))
}

const DAY: i64 = 24 * 3600;
const SESSION_TTL_USUAL_DAYS: i64 = 30;
const CLI_TOKEN_TTL_USUAL_DAYS: i64 = 90;
/// No token lifetime may be longer; past this it is most likely milliseconds.
const TTL_CEILING: i64 = 365 * DAY;

/// Refuses a token lifetime that is not positive or is over a year, and warns about one longer
/// than `usual_days`, since a stolen token stays useful that long.
fn check_ttl(name: &str, seconds: i64, usual_days: i64) -> anyhow::Result<Option<String>> {
    if seconds <= 0 {
        bail!("{name} must be a positive number of seconds, not {seconds}");
    }
    if seconds > TTL_CEILING {
        bail!(
            "{name} is {seconds} seconds, which is over a year; it is in seconds, not milliseconds, and may be at \
             most {TTL_CEILING}"
        );
    }
    if seconds <= usual_days * DAY {
        return Ok(None);
    }
    Ok(Some(format!(
        "{name} is {} days, longer than the recommended most of {usual_days}; a stolen token stays useful for \
         that long",
        seconds / DAY
    )))
}

/// An unlock policy weaker than `manual` slipped in through the environment, rather than chosen
/// in the configuration file or on the command line.
fn unlock_from_env_warning(unlock: Option<UnlockPolicy>, origin: Origin) -> Option<String> {
    if origin != Origin::Env {
        return None;
    }
    let policy = unlock?;
    let what = match policy {
        UnlockPolicy::Manual => return None,
        UnlockPolicy::Remember => {
            "once unsealed, the server will unlock itself after every restart from the remember file"
        }
        UnlockPolicy::PassphraseFile => "the server will unlock itself from a passphrase on disk or in the environment",
    };
    Some(format!(
        "the {} unlock policy comes from SEKRET_UNLOCK in the environment; {what}",
        policy.as_str()
    ))
}

/// A password in `--database-url` stays in the process list, which every local user can read,
/// for as long as the server runs.
fn database_flag_warning(choice: &DatabaseChoice) -> Option<String> {
    if choice.origin != Origin::Flag || choice.file.is_some() || !has_password(&choice.url) {
        return None;
    }
    Some(
        "--database-url carries a password, which every local user can read in the process list while the server \
         runs; use --database-url-file or SEKRET_DATABASE_URL_FILE instead"
            .into(),
    )
}

/// Why someone other than the server's user or root could change a file: it belongs to another
/// user, or its mode lets its group or everyone write to it.
pub fn writable_by_others(file: DirFacts, uid: u32, gid: u32) -> Option<&'static str> {
    if file.uid != uid && file.uid != 0 {
        return Some("belongs to another user");
    }
    if file.mode & 0o002 != 0 {
        return Some("can be written by every user");
    }
    let private_group = file.gid == gid && gid == uid;
    if file.mode & 0o020 != 0 && !private_group {
        return Some("can be written by its group");
    }
    None
}

/// The configuration file decides who signs in and who is an admin, so anyone else who can
/// change or replace it can make themselves one at the next restart.
#[cfg(unix)]
fn config_writers(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    // SAFETY: geteuid and getegid have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let facts = DirFacts {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
    };
    let why = writable_by_others(facts, uid, gid)
        .map(|why| format!("{} {why}", path.display()))
        .or_else(|| directory_exposure(path))?;
    Some(format!(
        "the configuration file: {why}; whoever can change it decides who signs in and who is an admin"
    ))
}

#[cfg(not(unix))]
fn config_writers(_path: &Path) -> Option<String> {
    None
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
        std::fs::create_dir(dir.path().join("unlock")).context("subdir")?;
        let nested = args(&[
            "--public-url",
            "https://x",
            "--database-url",
            &url,
            "--remember-file",
            &dir.path().join("unlock").join("remember.key").display().to_string(),
        ])?;
        let resolved = resolve(&nested, FileConfig::default())?;
        assert!(
            resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("database's directory")),
            "a remember file in a subdirectory of the database's directory still warns: {:?}",
            resolved.report.warnings
        );
        let elsewhere_dir = tempfile::tempdir().context("other dir")?;
        let elsewhere = args(&[
            "--public-url",
            "https://x",
            "--database-url",
            &url,
            "--remember-file",
            &elsewhere_dir.path().join("remember.key").display().to_string(),
        ])?;
        let resolved = resolve(&elsewhere, FileConfig::default())?;
        assert!(
            !resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("database's directory")),
            "{:?}",
            resolved.report.warnings
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn remember_files_reached_through_symlinks_or_missing_folders_still_warn() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let db = dir.path().join("data").join("sekret.db");
        std::fs::create_dir(dir.path().join("data")).context("data")?;
        // A symlink elsewhere that leads back into the database's directory.
        let elsewhere = tempfile::tempdir().context("elsewhere")?;
        let link = elsewhere.path().join("keys");
        std::os::unix::fs::symlink(dir.path().join("data"), &link).context("symlink")?;
        let mut warnings = Vec::new();
        remember_warnings(&link.join("not-yet").join("unlock.key"), Some(&db), &mut warnings);
        assert!(
            warnings.iter().any(|w| w.contains("database's directory")),
            "{warnings:?}"
        );
        // On the same filesystem but outside the directory.
        let mut warnings = Vec::new();
        remember_warnings(&elsewhere.path().join("unlock.key"), Some(&db), &mut warnings);
        let same_disk = device(elsewhere.path()) == device(&db);
        assert_eq!(
            warnings.iter().any(|w| w.contains("same filesystem")),
            same_disk,
            "{warnings:?}"
        );
        Ok(())
    }

    #[test]
    fn relative_and_missing_paths_resolve_from_the_nearest_existing_folder() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let real = std::fs::canonicalize(dir.path()).context("canonical")?;
        assert_eq!(resolved(&dir.path().join("a/b/c.key")), real.join("a/b/c.key"));
        let cwd = std::env::current_dir().context("cwd")?;
        assert_eq!(resolved(Path::new("x.key")), resolved(&cwd.join("x.key")));
        Ok(())
    }

    #[test]
    fn written_files_must_each_be_their_own_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let db = dir.path().join("sekret.db");
        let url = format!("sqlite://{}?mode=rwc", db.display());
        let wal = format!("{}-wal", db.display());
        for clash in [db.display().to_string(), wal] {
            let flags = args(&[
                "--public-url",
                "https://x",
                "--database-url",
                &url,
                "--setup-code-file",
                &clash,
            ])?;
            let error = resolve(&flags, FileConfig::default()).err().context("refused")?;
            assert!(error.to_string().contains("same file"), "{error}");
        }
        let token = dir.path().join("token").display().to_string();
        let flags = args(&[
            "--public-url",
            "https://x",
            "--setup-code-file",
            &token,
            "--setup-admin-token-file",
            &token,
        ])?;
        assert!(resolve(&flags, FileConfig::default()).is_err());
        assert!(
            default_role_warning("org-admin").is_some(),
            "org-admin for everyone is warned about"
        );
        assert!(default_role_warning("backup-reader").is_some());
        assert!(default_role_warning("org-member").is_none());
        Ok(())
    }

    #[test]
    fn oidc_open_to_everyone_at_the_provider_is_warned_about() {
        let open = HumanOidcConfig {
            issuer: "https://accounts.example.com".into(),
            client_id: "sekret".into(),
            client_secret: "s".into(),
            scopes: strings(&["openid"]),
            group_claims: strings(&["roles", "groups"]),
            admin_groups: strings(&["sekret-admin"]),
            required_groups: Vec::new(),
            allowed_subjects: Vec::new(),
        };
        let warning = open_sign_in_warning(Some(&open), "org-member").unwrap_or_default();
        for expected in [
            "https://accounts.example.com",
            "org-member",
            "roles or groups",
            "sekret-admin",
        ] {
            assert!(warning.contains(expected), "{expected} missing from {warning}");
        }
        assert!(
            open_sign_in_warning(None, "org-member").is_none(),
            "no OIDC, no warning"
        );
        assert!(
            open_sign_in_warning(Some(&open), "").is_none(),
            "no default role is a restriction"
        );

        let grouped = HumanOidcConfig {
            required_groups: strings(&["staff"]),
            ..open.clone()
        };
        assert!(open_sign_in_warning(Some(&grouped), "org-member").is_none());
        let pinned = HumanOidcConfig {
            allowed_subjects: strings(&["owner"]),
            ..open.clone()
        };
        assert!(open_sign_in_warning(Some(&pinned), "org-member").is_none());
        let no_admins = HumanOidcConfig {
            admin_groups: Vec::new(),
            ..open
        };
        let warning = open_sign_in_warning(Some(&no_admins), "org-member").unwrap_or_default();
        assert!(!warning.contains("organisation admin"), "{warning}");
    }

    #[test]
    fn the_remember_secret_comes_from_a_file_or_the_environment() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("secret");
        std::fs::write(&path, "xX0cbCqZ2IpCHTTEMxOxIhogaYMr4nufQk3TEU8lrgY=\n").context("write")?;
        let flags = args(&[
            "--public-url",
            "https://x",
            "--remember-secret-file",
            &path.display().to_string(),
        ])?;
        let resolved = resolve(&flags, FileConfig::default())?;
        assert!(resolved.config.seal.remember_secret.is_some());
        let env = EnvSecrets {
            remember_secret: Some(Zeroizing::new("jMvJGjs1rlsZhRRrc5VnYCIQg/Hbw1zYRqMi5us1Xmw=".into())),
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
    fn token_lifetimes_must_be_positive_and_under_a_year() -> anyhow::Result<()> {
        for bad in [0, -1, i64::MIN, 86_400_000, i64::MAX] {
            assert!(check_ttl("auth.session_ttl", bad, 30).is_err(), "{bad}");
        }
        let error = check_ttl("auth.cli_token_ttl", 86_400_000, 90)
            .err()
            .context("milliseconds refused")?;
        assert!(error.to_string().contains("milliseconds"), "{error}");
        assert_eq!(check_ttl("auth.session_ttl", 12 * 3600, 30)?, None);
        assert_eq!(check_ttl("auth.session_ttl", 30 * DAY, 30)?, None);
        let long = check_ttl("auth.session_ttl", 40 * DAY, 30)?.context("a long session is warned about")?;
        assert!(long.contains("40 days"), "{long}");
        assert!(check_ttl("auth.cli_token_ttl", TTL_CEILING, 90)?.is_some());

        let public = ["--public-url", "https://x"];
        for flag in ["--session-ttl=0", "--cli-token-ttl=-5", "--cli-token-ttl=86400000"] {
            let mut argv = public.to_vec();
            argv.push(flag);
            assert!(resolve(&args(&argv)?, FileConfig::default()).is_err(), "{flag}");
        }
        for yaml in ["auth:\n  session_ttl: 0\n", "auth:\n  cli_token_ttl: 86400000\n"] {
            assert!(resolve(&args(&public)?, parse(yaml)?).is_err(), "{yaml}");
        }
        // Only the value that wins is judged.
        let mut argv = public.to_vec();
        argv.push("--session-ttl=3600");
        let resolved = resolve(&args(&argv)?, parse("auth:\n  session_ttl: 0\n")?)?;
        assert_eq!(resolved.config.session_ttl, 3600);
        let resolved = resolve(&args(&public)?, parse("auth:\n  cli_token_ttl: 9000000\n")?)?;
        assert!(
            resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("auth.cli_token_ttl")),
            "{:?}",
            resolved.report.warnings
        );
        Ok(())
    }

    #[test]
    fn a_weaker_unlock_policy_from_the_environment_is_warned_about() {
        for policy in [UnlockPolicy::Remember, UnlockPolicy::PassphraseFile] {
            let warning = unlock_from_env_warning(Some(policy), Origin::Env).unwrap_or_default();
            assert!(
                warning.contains(policy.as_str()) && warning.contains("SEKRET_UNLOCK"),
                "{warning}"
            );
            assert_eq!(unlock_from_env_warning(Some(policy), Origin::File), None);
            assert_eq!(unlock_from_env_warning(Some(policy), Origin::Flag), None);
        }
        assert_eq!(unlock_from_env_warning(Some(UnlockPolicy::Manual), Origin::Env), None);
        assert_eq!(unlock_from_env_warning(None, Origin::Env), None);
    }

    #[test]
    fn remember_from_the_environment_is_reported_at_startup() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let mut flags = args(&["--public-url", "https://x"])?;
        flags.unlock = Some(UnlockPolicy::Remember);
        flags.store.remember_file = Some(dir.path().join("remember"));
        let resolved = resolve_with(&flags, FileConfig::default(), &EnvSecrets::default(), &all_from_env())?;
        assert!(
            resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("remember unlock policy comes from SEKRET_UNLOCK")),
            "{:?}",
            resolved.report.warnings
        );
        let resolved = resolve(&flags, FileConfig::default())?;
        assert!(
            !resolved.report.warnings.iter().any(|w| w.contains("SEKRET_UNLOCK")),
            "{:?}",
            resolved.report.warnings
        );
        Ok(())
    }

    #[test]
    fn a_database_password_on_the_command_line_is_warned_about() {
        let choice = |url: &str, origin: Origin, file: Option<&str>| DatabaseChoice {
            url: url.into(),
            origin,
            key: "database.url",
            file: file.map(PathBuf::from),
            ignored: Vec::new(),
        };
        let warning = database_flag_warning(&choice("postgres://u:pw@db/s", Origin::Flag, None)).unwrap_or_default();
        assert!(
            warning.contains("process list") && !warning.contains("pw@"),
            "{warning}"
        );
        assert_eq!(
            database_flag_warning(&choice("postgres://u:pw@db/s", Origin::Env, None)),
            None
        );
        assert_eq!(
            database_flag_warning(&choice("postgres://u:pw@db/s", Origin::File, None)),
            None
        );
        assert_eq!(
            database_flag_warning(&choice("postgres://u:pw@db/s", Origin::Flag, Some("/run/url"))),
            None,
            "a URL file keeps the password out of the process list"
        );
        assert_eq!(
            database_flag_warning(&choice("postgres://u@db/s", Origin::Flag, None)),
            None
        );
        assert!(database_flag_warning(&choice("postgres://u@db/s?password=pw", Origin::Flag, None)).is_some());
    }

    #[test]
    fn files_others_can_write_are_recognised() {
        let file = |uid, gid, mode| DirFacts { uid, gid, mode };
        assert_eq!(writable_by_others(file(990, 990, 0o100600), 990, 990), None);
        assert_eq!(writable_by_others(file(0, 0, 0o100644), 990, 990), None, "root's file");
        assert_eq!(
            writable_by_others(file(990, 990, 0o100664), 990, 990),
            None,
            "a user private group"
        );
        assert!(
            writable_by_others(file(990, 50, 0o100664), 990, 990).is_some(),
            "a shared group"
        );
        assert!(writable_by_others(file(990, 990, 0o100666), 990, 990).is_some());
        assert!(writable_by_others(file(2000, 2000, 0o100600), 990, 990).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_configuration_file_others_can_change_is_warned_about() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().context("dir")?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod dir")?;
        let path = dir.path().join("sekret.yaml");
        std::fs::write(&path, "server:\n  public_url: https://x\n").context("write")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
        assert_eq!(config_writers(&path), None);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
        let warning = config_writers(&path).context("a world-writable file")?;
        assert!(warning.contains("every user") && warning.contains("admin"), "{warning}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).context("chmod dir")?;
        assert!(config_writers(&path).is_some(), "anyone could replace it");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod dir")?;

        let mut flags = args(&["--public-url", "https://x"])?;
        flags.store.config = Some(path.clone());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
        let resolved = resolve(&flags, FileConfig::default())?;
        assert!(
            resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("configuration file")),
            "{:?}",
            resolved.report.warnings
        );
        Ok(())
    }

    /// Sources where every named variable is in the environment and nothing is a flag.
    fn all_from_env() -> Sources {
        Sources {
            argv: vec!["sekret".into(), "server".into()],
            env: Box::new(|name| name.starts_with("SEKRET_")),
        }
    }

    #[test]
    fn every_setting_overridden_by_the_environment_is_warned_about() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let secret = dir.path().join("oidc-secret");
        std::fs::write(&secret, "s\n").context("secret")?;
        let p = |name: &str| dir.path().join(name).display().to_string();
        let file = parse(&format!(
            "server:\n  public_url: https://file\n  unix_socket: {}\n  unix_socket_mode: \"0600\"\n\
             database:\n  url: postgres://u:filepass@db/file\n\
             oidc:\n  issuer: https://file-issuer\n  client_secret_file: {}\n\
             seal:\n  remember_file: {}\n\
             setup:\n  code_file: {}\n  admin_token_file: {}\n",
            p("file.sock"),
            secret.display(),
            p("file-remember"),
            p("file-code"),
            p("file-token"),
        ))?;
        let mut flags = args(&[])?;
        flags.public_url = Some("https://env".into());
        flags.unix_socket = Some(dir.path().join("env.sock"));
        flags.unix_socket_mode = Some("0660".into());
        flags.store.database_url = Some("postgres://u:envpass@db/env".into());
        flags.oidc_issuer = Some("https://env-issuer".into());
        flags.oidc_client_secret_file = Some(secret.clone());
        flags.store.remember_file = Some(dir.path().join("env-remember"));
        flags.setup_code_file = Some(dir.path().join("env-code"));
        flags.setup_admin_token_file = Some(dir.path().join("env-token"));
        let resolved = resolve_with(&flags, file, &EnvSecrets::default(), &all_from_env())?;
        let warnings = resolved.report.warnings.join("\n");
        for name in [
            "server.public_url",
            "server.unix_socket",
            "server.unix_socket_mode",
            "database.url",
            "oidc.issuer",
            "oidc.client_secret_file",
            "seal.remember_file",
            "setup.code_file",
            "setup.admin_token_file",
        ] {
            assert!(
                warnings.contains(&format!("{name} in the configuration file is overridden")),
                "{name} missing from {warnings}"
            );
            let reported = resolved
                .report
                .settings
                .iter()
                .find(|s| s.name == name)
                .with_context(|| format!("{name} not reported"))?;
            assert_eq!(reported.origin, Origin::Env, "{name}");
        }
        let shown = format!("{:?}", resolved.report);
        assert!(!shown.contains("envpass") && !shown.contains("filepass"), "{shown}");
        assert!(shown.contains("postgres://u:***@db/env"), "{shown}");
        Ok(())
    }

    #[test]
    fn secrets_follow_flag_then_environment_then_file() {
        let names = &REMEMBER_SECRET_NAMES;
        let flag = Path::new("/flag");
        let yaml = Path::new("/yaml");
        let chosen = choose_secret(names, Some((flag, Origin::Flag)), Some(yaml), true);
        assert_eq!(chosen.from, Some(SecretFrom::File(flag.into())));
        assert_eq!(chosen.origin, Origin::Flag);
        assert_eq!(chosen.ignored.len(), 2, "{:?}", chosen.ignored);
        let chosen = choose_secret(names, Some((flag, Origin::Env)), Some(yaml), true);
        assert_eq!(chosen.from, Some(SecretFrom::File(flag.into())));
        assert!(chosen.ignored.iter().any(|w| w.starts_with(REMEMBER_SECRET_ENV)));
        let chosen = choose_secret(names, None, Some(yaml), true);
        assert_eq!(chosen.from, Some(SecretFrom::Env), "the environment beats the file");
        assert_eq!(chosen.origin, Origin::Env);
        assert!(
            chosen
                .ignored
                .iter()
                .any(|w| w.starts_with("seal.remember_secret_file"))
        );
        let chosen = choose_secret(names, None, Some(yaml), false);
        assert_eq!(
            (chosen.from, chosen.origin),
            (Some(SecretFrom::File(yaml.into())), Origin::File)
        );
        assert_eq!(choose_secret(names, None, None, false).from, None);
    }

    #[test]
    fn the_unlock_passphrase_in_the_environment_beats_the_file_setting() -> anyhow::Result<()> {
        let file = parse("seal:\n  passphrase_file: /etc/sekret/unlock\n")?;
        let env = EnvSecrets {
            unlock_passphrase: Some(Zeroizing::new("from the environment".into())),
            ..EnvSecrets::default()
        };
        let resolved = resolve_with(&args(&["--public-url", "https://x"])?, file, &env, &Sources::none())?;
        assert_eq!(
            resolved.setup.unlock_passphrase_file, None,
            "the environment value is used"
        );
        assert!(
            resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("seal.passphrase_file is set but ignored")),
            "{:?}",
            resolved.report.warnings
        );
        let flagged = Sources {
            argv: vec!["sekret".into(), "--unlock-passphrase-file=/run/flag".into()],
            env: Box::new(|_| false),
        };
        let mut flags = args(&["--public-url", "https://x"])?;
        flags.unlock_passphrase_file = Some(PathBuf::from("/run/flag"));
        let resolved = resolve_with(&flags, FileConfig::default(), &env, &flagged)?;
        assert_eq!(resolved.setup.unlock_passphrase_file, Some(PathBuf::from("/run/flag")));
        assert!(
            resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("SEKRET_UNLOCK_PASSPHRASE is set but ignored")),
            "{:?}",
            resolved.report.warnings
        );
        Ok(())
    }

    #[test]
    fn written_files_may_not_be_an_epoch_mark_or_the_lock_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let db = dir.path().join("sekret.db");
        let url = format!("sqlite://{}?mode=rwc", db.display());
        let remember = dir.path().join("remember.key").display().to_string();
        let key = dir.path().join("root.key").display().to_string();
        for clash in [
            format!("{}.epoch", db.display()),
            format!("{}.lock", db.display()),
            format!("{remember}.epoch"),
            format!("{key}.epoch"),
        ] {
            let flags = args(&[
                "--public-url",
                "https://x",
                "--database-url",
                &url,
                "--remember-file",
                &remember,
                "--root-key-file",
                &key,
                "--setup-code-file",
                &clash,
            ])?;
            let error = resolve(&flags, FileConfig::default()).err().context(clash.clone())?;
            assert!(error.to_string().contains("same file"), "{clash}: {error}");
        }
        Ok(())
    }

    #[test]
    fn the_database_url_can_come_from_a_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let url_file = dir.path().join("db-url");
        std::fs::write(&url_file, "postgres://sekret:hunter2@db/sekret\n").context("write")?;
        let file = parse(&format!("database:\n  url_file: {}\n", url_file.display()))?;
        let resolved = resolve(&args(&["--public-url", "https://x"])?, file)?;
        assert_eq!(resolved.config.database_url, "postgres://sekret:hunter2@db/sekret");
        let reported = format!("{:?}", resolved.report);
        assert!(!reported.contains("hunter2"), "{reported}");
        let both = parse(&format!(
            "database:\n  url: sqlite://x.db\n  url_file: {}\n",
            url_file.display()
        ))?;
        let error = resolve(&args(&["--public-url", "https://x"])?, both)
            .err()
            .context("refused")?;
        assert!(error.to_string().contains("both set"), "{error}");
        let flags = args(&["--public-url", "https://x", "--database-url", "sqlite://flag.db"])?;
        let file = parse(&format!("database:\n  url_file: {}\n", url_file.display()))?;
        let flagged = Sources {
            argv: vec!["sekret".into(), "--database-url".into(), "sqlite://flag.db".into()],
            env: Box::new(|_| false),
        };
        let resolved = resolve_with(&flags, file, &EnvSecrets::default(), &flagged)?;
        assert_eq!(resolved.config.database_url, "sqlite://flag.db");
        assert!(
            resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("database.url_file from the file is ignored")),
            "{:?}",
            resolved.report.warnings
        );
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
        std::fs::write(
            &path,
            "database:\n  url: sqlite://x.db\nseal:\n  root_key_file: /k\n  remember_file: /r\n",
        )
        .context("write")?;
        let mut store = StoreArgs {
            config: Some(path),
            database_url: None,
            database_url_file: None,
            root_key_file: None,
            remember_file: None,
            epoch_file: None,
        };
        let located = store.locate(&Sources::none())?;
        assert_eq!(located.database_url, "sqlite://x.db");
        assert_eq!(located.root_key_file, Some(PathBuf::from("/k")));
        assert_eq!(located.remember_file, Some(PathBuf::from("/r")));
        // The flag or environment variable wins, as for the server, so its epoch mark is found.
        store.remember_file = Some(PathBuf::from("/flag"));
        assert_eq!(
            store.locate(&Sources::none())?.remember_file,
            Some(PathBuf::from("/flag"))
        );
        assert!(
            store
                .locate(&Sources::none())?
                .epoch_files()
                .contains(&PathBuf::from("/flag.epoch"))
        );
        Ok(())
    }

    fn warnings_of(flags: &[&str], yaml: &str) -> anyhow::Result<String> {
        Ok(resolve(&args(flags)?, parse(yaml)?)?.report.warnings.join("\n"))
    }

    #[test]
    fn a_root_key_file_with_passphrase_mode_is_refused() -> anyhow::Result<()> {
        let refusals = [
            (vec!["--seal-mode", "passphrase", "--root-key-file", "/k"], ""),
            (vec!["--seal-mode", "passphrase"], "seal:\n  root_key_file: /k\n"),
            (vec!["--root-key-file", "/k"], "seal:\n  mode: passphrase\n"),
            (vec![], "seal:\n  mode: passphrase\n  root_key_file: /k\n"),
        ];
        for (flags, yaml) in refusals {
            let mut all = vec!["--public-url", "https://x"];
            all.extend(flags.iter().copied());
            let error = resolve(&args(&all)?, parse(yaml)?)
                .err()
                .with_context(|| format!("{flags:?} {yaml:?} should be refused"))?;
            assert!(
                error
                    .to_string()
                    .contains("seal.mode is passphrase but seal.root_key_file is set"),
                "{error}"
            );
        }
        // The flag beats the file, so key-file mode or no mode at all keeps the key file usable.
        let flags = args(&["--public-url", "https://x", "--seal-mode", "key-file"])?;
        let resolved = resolve(&flags, parse("seal:\n  mode: passphrase\n  root_key_file: /k\n")?)?;
        assert_eq!(resolved.config.seal.mode, Some(SealMode::KeyFile));
        let resolved = resolve(
            &args(&["--public-url", "https://x", "--root-key-file", "/k"])?,
            FileConfig::default(),
        )?;
        assert_eq!(resolved.config.seal.mode, None);
        Ok(())
    }

    #[test]
    fn client_auth_without_a_client_ca_is_warned_about() -> anyhow::Result<()> {
        const WARNING: &str = "tls.client_auth is set but tls.client_ca_file is not";
        let base = ["--public-url", "https://x", "--listen", "127.0.0.1:8080"];
        let flag = [&base[..], &["--tls-client-auth", "required"]].concat();
        assert!(warnings_of(&flag, "")?.contains(WARNING));
        assert!(warnings_of(&base, "tls:\n  client_auth: optional\n")?.contains(WARNING));
        assert!(!warnings_of(&base, "")?.contains(WARNING));
        let dir = tempfile::tempdir().context("dir")?;
        let ca = dir.path().join("ca.pem");
        let (cert, key) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        for path in [&ca, &cert, &key] {
            std::fs::write(path, "pem").context("write")?;
        }
        let with_ca = format!(
            "tls:\n  client_auth: required\n  client_ca_file: {}\n  cert_file: {}\n  key_file: {}\n",
            ca.display(),
            cert.display(),
            key.display()
        );
        assert!(!warnings_of(&base, &with_ca)?.contains(WARNING));
        Ok(())
    }

    #[test]
    fn plain_http_on_all_interfaces_behind_an_https_url_is_warned_about() -> anyhow::Result<()> {
        const WARNING: &str = "speaks plain http on";
        assert!(warnings_of(&["--public-url", "https://x", "--listen", "0.0.0.0:8080"], "")?.contains(WARNING));
        assert!(
            warnings_of(&["--public-url", "https://x"], "")?.contains(WARNING),
            "the default listen"
        );
        assert!(warnings_of(&["--public-url", "https://x"], "server:\n  listen: \"[::]:8080\"\n")?.contains(WARNING));
        assert!(!warnings_of(&["--public-url", "https://x", "--listen", "127.0.0.1:8080"], "")?.contains(WARNING));
        assert!(
            !warnings_of(
                &["--public-url", "https://x", "--listen", "127.0.0.1:8080"],
                "server:\n  listen: 0.0.0.0:1\n"
            )?
            .contains(WARNING),
            "the flag wins"
        );
        let plain = warnings_of(&["--public-url", "http://x", "--listen", "0.0.0.0:8080"], "")?;
        assert!(!plain.contains(WARNING), "an http URL has its own warning: {plain}");
        Ok(())
    }

    #[test]
    fn database_passwords_are_spotted_in_urls() {
        assert!(has_password("postgres://sekret:hunter2@db/sekret"));
        assert!(has_password("postgresql://db/sekret?user=s&password=hunter2"));
        assert!(!has_password("postgres://sekret@db/sekret"));
        assert!(!has_password("sqlite://sekret.db?mode=rwc"));
        assert!(!has_password("not a url"));
    }

    #[cfg(unix)]
    #[test]
    fn database_url_files_and_configs_holding_passwords_get_permission_checks() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().context("dir")?;
        let open = std::fs::Permissions::from_mode(0o644);
        let url_file = dir.path().join("db-url");
        std::fs::write(&url_file, "postgres://sekret:hunter2@db/sekret\n").context("write")?;
        std::fs::set_permissions(&url_file, open.clone()).context("chmod")?;
        let config = dir.path().join("sekret.yaml");
        std::fs::write(&config, "").context("write")?;
        std::fs::set_permissions(&config, open.clone()).context("chmod")?;
        let mut flags = args(&["--public-url", "https://x"])?;
        flags.store.config = Some(config.clone());
        let file = parse(&format!("database:\n  url_file: {}\n", url_file.display()))?;
        let warnings = resolve(&flags, file)?.report.warnings.join("\n");
        assert!(warnings.contains("the database URL file"), "{warnings}");
        assert!(
            !warnings.contains("configuration file"),
            "no password in the file itself: {warnings}"
        );

        let file = parse("database:\n  url: postgres://sekret:hunter2@db/sekret\n")?;
        let warnings = resolve(&flags, file)?.report.warnings.join("\n");
        assert!(warnings.contains("the configuration file"), "{warnings}");
        assert!(!warnings.contains("hunter2"), "{warnings}");

        std::fs::write(&url_file, "sqlite://x.db\n").context("write")?;
        let file = parse(&format!("database:\n  url_file: {}\n", url_file.display()))?;
        let warnings = resolve(&flags, file)?.report.warnings.join("\n");
        assert!(
            !warnings.contains("database URL file"),
            "no password to protect: {warnings}"
        );

        std::fs::write(&url_file, "postgres://sekret:hunter2@db/sekret\n").context("write")?;
        std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
        let file = parse(&format!("database:\n  url_file: {}\n", url_file.display()))?;
        let warnings = resolve(&flags, file)?.report.warnings.join("\n");
        assert!(!warnings.contains("database URL file"), "{warnings}");
        Ok(())
    }

    #[test]
    fn directories_others_can_write_to_let_them_replace_files() {
        let dir = |uid, gid, mode| DirFacts { uid, gid, mode };
        assert_eq!(replaceable_in(dir(1000, 1000, 0o40700), 1000, 1000), None);
        assert_eq!(replaceable_in(dir(0, 0, 0o40755), 1000, 1000), None, "root's /etc");
        assert_eq!(
            replaceable_in(dir(1000, 1000, 0o40775), 1000, 1000),
            None,
            "a user private group"
        );
        assert_eq!(
            replaceable_in(dir(0, 0, 0o41777), 1000, 1000),
            None,
            "sticky, like a Kubernetes secret mount"
        );
        assert!(
            replaceable_in(dir(1000, 50, 0o40775), 1000, 1000).is_some(),
            "a shared group"
        );
        assert!(
            replaceable_in(dir(0, 50, 0o40770), 1000, 50).is_some(),
            "my shared group"
        );
        assert!(replaceable_in(dir(1000, 1000, 0o40777), 1000, 1000).is_some());
        assert!(
            replaceable_in(dir(2000, 2000, 0o41700), 1000, 1000).is_some(),
            "another user's directory, sticky or not"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_in_open_directories_are_exposed() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().context("dir")?;
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).context("mkdir")?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        let file = shared.join("pass");
        std::fs::write(&file, "x").context("write")?;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
        let why = secret_file_exposure(&file).context("exposed")?;
        assert!(why.contains("writable by every user"), "{why}");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        assert_eq!(secret_file_exposure(&file), None);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).context("symlink")?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        assert!(
            secret_file_exposure(&link).is_some(),
            "the target's directory counts too"
        );
        Ok(())
    }
}
