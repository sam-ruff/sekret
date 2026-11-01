pub mod config;
pub mod format;
pub mod login;
pub mod shell;
pub mod sys;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use sekret_api::{
    BatchResult, BatchWrite, Charset, GenerateSecret, Generator, PolicyOverride, SecretPolicy, SecretUpsert,
};
use sekret_client::{ClientOptions, HttpClient, Location, SekretApi};

use self::config::{Credentials, Overrides, Resolved, StoredToken};
use self::format::{ExportFormat, flatten, line_diff, parse_dotenv, render, table};
use self::login::{GithubActionsTokenSource, IdTokenSource, MachineCredential};
use crate::prompt::Prompter;

#[derive(Debug, Clone, Args)]
pub struct ClientArgs {
    /// Server URL, e.g. https://sekret.example.com.
    #[arg(long, global = true, env = "SEKRET_URL")]
    pub server: Option<String>,
    /// Access token; defaults to the one saved by `sekret login`. As a flag it is visible to
    /// other users in the process list; prefer SEKRET_TOKEN.
    #[arg(long, global = true, env = "SEKRET_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
    /// Project slug. Defaults to SEKRET_PROJECT, then the project file.
    #[arg(long, short = 'p', global = true)]
    pub project: Option<String>,
    /// Environment slug. Defaults to SEKRET_ENVIRONMENT, then the project file.
    #[arg(long = "env", short = 'e', global = true)]
    pub environment: Option<String>,
    /// Folder path within the environment.
    #[arg(long, global = true, env = "SEKRET_PATH")]
    pub path: Option<String>,
    /// Extra PEM CA bundle to trust, such as a private root.
    #[arg(long, global = true, env = "SEKRET_CA_FILE")]
    pub ca_file: Option<PathBuf>,
    /// PEM client certificate, for servers or proxies that require mutual TLS.
    #[arg(long, global = true, env = "SEKRET_CLIENT_CERT", requires = "client_key")]
    pub client_cert: Option<PathBuf>,
    /// PEM private key for --client-cert.
    #[arg(long, global = true, env = "SEKRET_CLIENT_KEY", requires = "client_cert")]
    pub client_key: Option<PathBuf>,
    /// Allow a plain http:// server that is not on this machine. Tokens then travel unencrypted.
    #[arg(long, global = true, env = "SEKRET_CLIENT_ALLOW_INSECURE_HTTP", num_args = 0..=1,
        default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    pub allow_insecure_http: Option<bool>,
}

#[derive(Debug, Clone, Args)]
pub struct LoginArgs {
    /// Machine identity id, for OIDC and Kubernetes logins.
    #[arg(long, env = "SEKRET_IDENTITY_ID")]
    pub identity_id: Option<String>,
    /// Read an OIDC token from this file.
    #[arg(long, conflicts_with_all = ["oidc_token_env", "github_actions", "kubernetes", "client_id"])]
    pub oidc_token_file: Option<PathBuf>,
    /// Read an OIDC token from this environment variable.
    #[arg(long, conflicts_with_all = ["github_actions", "kubernetes", "client_id"])]
    pub oidc_token_env: Option<String>,
    /// Use the GitHub Actions OIDC token (needs `permissions: id-token: write`).
    #[arg(long, conflicts_with_all = ["kubernetes", "client_id"])]
    pub github_actions: bool,
    /// Audience to request from GitHub Actions.
    #[arg(long, default_value = "sekret")]
    pub audience: String,
    /// Log in with this pod's Kubernetes service account token.
    #[arg(long, conflicts_with = "client_id")]
    pub kubernetes: bool,
    #[arg(long, default_value = login::DEFAULT_SA_TOKEN)]
    pub kubernetes_token_file: PathBuf,
    /// Universal auth client id (the identity id).
    #[arg(long, env = "SEKRET_CLIENT_ID")]
    pub client_id: Option<String>,
    /// File holding the universal auth client secret; SEKRET_CLIENT_SECRET also works.
    #[arg(long)]
    pub client_secret_file: Option<PathBuf>,
    /// Print the token instead of saving it, e.g. `export SEKRET_TOKEN=$(sekret login ... --print-token)`.
    #[arg(long)]
    pub print_token: bool,
    /// Do not try to open a browser.
    #[arg(long)]
    pub no_browser: bool,
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// List secrets in a folder.
    List {
        #[arg(long)]
        recursive: bool,
        /// Show values as well as keys.
        #[arg(long)]
        values: bool,
    },
    /// Print one secret's value.
    Get {
        key: String,
        #[arg(long)]
        json: bool,
        /// Print the value even to a terminal when it holds control characters or escape
        /// sequences, which could rewrite the screen or the clipboard. Pipes always get it as is.
        #[arg(long)]
        raw: bool,
    },
    /// Set secrets: `KEY=value`, or `KEY=-` to read the value from stdin.
    Set {
        pairs: Vec<String>,
        /// Import every entry from a .env file.
        #[arg(long)]
        from_dotenv: Option<PathBuf>,
        #[arg(long, default_value = "")]
        comment: String,
    },
    /// Delete secrets.
    Delete {
        #[arg(required = true)]
        keys: Vec<String>,
    },
    /// Show a secret's versions.
    History {
        key: String,
        #[arg(long)]
        values: bool,
        /// Show a line diff between two versions instead of the list.
        #[arg(long, num_args = 2, value_names = ["FROM", "TO"])]
        diff: Option<Vec<i64>>,
    },
    /// Restore an earlier version as a new version.
    Rollback { key: String, version: i64 },
    /// Fill a secret with a generated value, creating it if needed. The value is not printed.
    Generate {
        key: String,
        /// Length; defaults to the secret's policy, else 32.
        #[arg(long)]
        length: Option<u32>,
        #[arg(long, value_enum)]
        charset: Option<CharsetArg>,
        #[arg(long, default_value = "")]
        comment: String,
    },
    /// Show a secret's generation and rotation policy, or change it with the flags.
    Policy {
        key: String,
        /// Follow the project default again.
        #[arg(long, conflicts_with_all = ["off", "rotate_days", "length", "charset"])]
        inherit: bool,
        #[command(flatten)]
        policy: PolicyFlags,
    },
}

#[derive(Debug, Subcommand)]
pub enum SnapshotsCommand {
    /// List snapshots of an environment.
    List,
    /// Restore a snapshot, limited to --path and below.
    Restore { id: String },
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    #[arg(long, value_enum, default_value = "dotenv")]
    pub format: ExportFormat,
    #[arg(long)]
    pub recursive: bool,
    /// Load this blocked name anyway, for dotenv and shell output. Repeatable.
    #[arg(long = "allow", value_name = "NAME")]
    pub allow: Vec<String>,
    /// Print to a terminal even when values hold control characters or escape sequences, which
    /// could rewrite the screen or the clipboard. Pipes and files always get them as they are.
    #[arg(long)]
    pub raw: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CharsetArg {
    Alphanumeric,
    Symbols,
    Hex,
    Base64url,
    Numeric,
}

impl From<CharsetArg> for Charset {
    fn from(value: CharsetArg) -> Self {
        match value {
            CharsetArg::Alphanumeric => Charset::Alphanumeric,
            CharsetArg::Symbols => Charset::Symbols,
            CharsetArg::Hex => Charset::Hex,
            CharsetArg::Base64url => Charset::Base64url,
            CharsetArg::Numeric => Charset::Numeric,
        }
    }
}

/// Flags describing a generation and rotation policy; none of them means "just show it".
#[derive(Debug, Clone, Default, Args)]
pub struct PolicyFlags {
    /// Turn generation settings and rotation off.
    #[arg(long, conflicts_with_all = ["rotate_days", "length", "charset"])]
    pub off: bool,
    /// Rotate generated values this many days after they were set.
    #[arg(long)]
    pub rotate_days: Option<u32>,
    #[arg(long)]
    pub length: Option<u32>,
    #[arg(long, value_enum)]
    pub charset: Option<CharsetArg>,
}

impl PolicyFlags {
    fn is_empty(&self) -> bool {
        !self.off && self.rotate_days.is_none() && self.length.is_none() && self.charset.is_none()
    }

    /// The policy the flags describe, starting from `current` so unspecified parts are kept.
    pub fn apply(&self, current: SecretPolicy) -> SecretPolicy {
        if self.off {
            return SecretPolicy::default();
        }
        let generator = match (self.length, self.charset, current.generator) {
            (None, None, existing) => existing,
            (length, charset, existing) => {
                let base = existing.unwrap_or_default();
                Some(Generator {
                    length: length.unwrap_or(base.length),
                    charset: charset.map(Charset::from).unwrap_or(base.charset),
                })
            }
        };
        SecretPolicy {
            generator,
            rotation_days: self.rotate_days.or(current.rotation_days),
        }
    }
}

pub fn describe_policy(policy: &SecretPolicy) -> String {
    let generator = policy.generator_or_default();
    let rotation = match policy.rotation_days {
        Some(days) => format!("every {days} days (generated values only)"),
        None => "off".into(),
    };
    format!(
        "generator: {} {:?} characters\nrotation:  {rotation}\n",
        generator.length, generator.charset
    )
}

#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// Print shell code that swaps this shell's secrets for an environment's:
    /// `eval "$(sekret env use prod)"`, or `sekret-env prod` after `sekret shell-init`.
    Use {
        /// Environment to load; defaults to SEKRET_ENVIRONMENT or .sekret.toml.
        environment: Option<String>,
        #[arg(long, value_enum, default_value = "bash")]
        shell: shell::Shell,
        #[arg(long)]
        recursive: bool,
        /// Load this blocked name anyway. Repeatable.
        #[arg(long = "allow", value_name = "NAME")]
        allow: Vec<String>,
    },
    /// Print shell code that removes what `env use` loaded.
    Unload {
        #[arg(long, value_enum, default_value = "bash")]
        shell: shell::Shell,
    },
    /// Show which project and environment this shell has loaded, and the key names.
    Status,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long)]
    pub recursive: bool,
    /// Load this blocked name anyway. Repeatable.
    #[arg(long = "allow", value_name = "NAME")]
    pub allow: Vec<String>,
    /// Command to run with the secrets in its environment.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// The saved logins, printing any warning about the file's permissions.
fn read_credentials(path: &std::path::Path) -> anyhow::Result<Credentials> {
    let mut warnings = Vec::new();
    let credentials = config::load_credentials(path, &mut warnings)?;
    for warning in warnings {
        eprintln!("sekret: {warning}");
    }
    Ok(credentials)
}

/// A token given as `--token` sits in the process list, which every local user can read.
pub fn token_flag_warning(argv: &[String]) -> Option<&'static str> {
    argv.iter()
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--token" || arg.starts_with("--token="))
        .then_some(
            "--token is visible to other users on this machine in the process list; set SEKRET_TOKEN or run \
             `sekret login` instead",
        )
}

pub fn resolve(args: &ClientArgs) -> anyhow::Result<Resolved> {
    let cwd = std::env::current_dir()?;
    let mut warnings = Vec::new();
    let argv: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if let Some(warning) = token_flag_warning(&argv) {
        warnings.push(warning.to_string());
    }
    let (file, _) = config::load_project_file(&cwd, &mut warnings)?;
    for warning in warnings {
        eprintln!("sekret: {warning}");
    }
    let credentials = read_credentials(&config::credentials_path()?)?;
    let var = |name: &str| std::env::var(name).ok();
    config::resolve(
        Overrides {
            server: args.server.clone(),
            token: args.token.clone(),
            project: args.project.clone(),
            environment: args.environment.clone(),
            env_project: var("SEKRET_PROJECT").filter(|v| !v.is_empty()),
            env_environment: var("SEKRET_ENVIRONMENT").filter(|v| !v.is_empty()),
            loaded_file: var(config::LOADED_FILE_VAR),
            path: args.path.clone(),
        },
        file,
        &credentials,
        now(),
    )
}

pub fn client(args: &ClientArgs, resolved: &Resolved, token: Option<String>) -> anyhow::Result<HttpClient> {
    config::check_transport(&resolved.server, args.allow_insecure_http.unwrap_or(false))?;
    let ca_pem = args
        .ca_file
        .as_deref()
        .map(config::read_text)
        .transpose()
        .context("reading CA file")?
        .map(String::into_bytes);
    if let Some(key) = &args.client_key {
        crate::prompt::warn_if_exposed(key);
    }
    let identity_pem = sekret_client::identity_from_files(args.client_cert.as_deref(), args.client_key.as_deref())?;
    Ok(HttpClient::new(
        &resolved.server,
        token,
        ClientOptions {
            ca_pem,
            identity_pem,
            timeout: None,
        },
    )?)
}

/// A client for the server's host socket that uses the one connection `socket_check` approved.
#[cfg(unix)]
pub async fn host_socket_client(path: &std::path::Path, owner: Option<&str>) -> anyhow::Result<HttpClient> {
    let expected = owner
        .map(crate::socket_check::user_id)
        .transpose()
        .context("--socket-owner")?;
    let stream = crate::socket_check::connect(path, expected).await?;
    Ok(HttpClient::over_unix_stream(stream, None).await?)
}

#[cfg(not(unix))]
pub async fn host_socket_client(_path: &std::path::Path, _owner: Option<&str>) -> anyhow::Result<HttpClient> {
    bail!("host sockets need a Unix host")
}

pub fn location(resolved: &Resolved) -> anyhow::Result<Location> {
    let (project, environment) = resolved.require_project()?;
    Ok(Location {
        project,
        environment,
        path: resolved.path.clone(),
    })
}

fn read_trimmed(path: &std::path::Path) -> anyhow::Result<String> {
    Ok(config::read_text(path)?.trim().to_string())
}

/// Works out which machine credential the flags describe, or `None` for an interactive login.
pub async fn machine_credential(
    args: &LoginArgs,
    github: &dyn Fn() -> anyhow::Result<Box<dyn IdTokenSource>>,
) -> anyhow::Result<Option<MachineCredential>> {
    let identity = || {
        args.identity_id
            .clone()
            .context("--identity-id is required for this login method")
    };
    if let Some(client_id) = &args.client_id {
        let secret = match &args.client_secret_file {
            Some(path) => {
                crate::prompt::warn_if_exposed(path);
                read_trimmed(path)?
            }
            None => std::env::var("SEKRET_CLIENT_SECRET")
                .context("pass --client-secret-file or set SEKRET_CLIENT_SECRET")?,
        };
        return Ok(Some(MachineCredential::Universal {
            client_id: client_id.clone(),
            client_secret: secret,
        }));
    }
    if args.kubernetes {
        let token = read_trimmed(&args.kubernetes_token_file)?;
        return Ok(Some(MachineCredential::Kubernetes {
            identity_id: identity()?,
            token,
        }));
    }
    let token = if let Some(path) = &args.oidc_token_file {
        Some(read_trimmed(path)?)
    } else if let Some(var) = &args.oidc_token_env {
        Some(std::env::var(var).with_context(|| format!("{var} is not set"))?)
    } else if args.github_actions {
        Some(github()?.fetch(&args.audience).await?)
    } else {
        None
    };
    let Some(token) = token else {
        return Ok(None);
    };
    Ok(Some(MachineCredential::Oidc {
        identity_id: identity()?,
        token,
    }))
}

fn unconfirmed(server: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{} comes only from {}, so no credential is sent to it; pass --server or set SEKRET_URL to confirm the server",
        format::one_line(server),
        config::PROJECT_FILE
    )
}

/// Passphrases, setup codes and tokens only go to a server named by a flag or `SEKRET_URL`, or
/// one the person confirmed at `sekret login`, never to one that only a project file names.
pub fn require_confirmed_server(resolved: &Resolved) -> anyhow::Result<()> {
    if resolved.server_confirmed() {
        return Ok(());
    }
    Err(unconfirmed(&resolved.server))
}

/// Credentials from flags or the environment only go to a server named the same way: a saved
/// login does not vouch for a server to anything but its own token.
pub fn require_explicit_server(resolved: &Resolved) -> anyhow::Result<()> {
    if resolved.source == config::ServerSource::Explicit {
        return Ok(());
    }
    Err(unconfirmed(&resolved.server))
}

/// The client for `sekret sys` over the network, once the server is confirmed.
pub fn sys_client(args: &ClientArgs) -> anyhow::Result<HttpClient> {
    let resolved = resolve(args)?;
    require_confirmed_server(&resolved)?;
    client(args, &resolved, resolved.token.clone())
}

/// A browser login to a server only the project file names saves a token that confirms it from
/// then on, so the person must agree to it at a terminal first, seeing exactly where it goes.
pub fn confirm_login_server(resolved: &Resolved, prompter: &dyn Prompter, interactive: bool) -> anyhow::Result<()> {
    if resolved.source != config::ServerSource::ProjectFile {
        return Ok(());
    }
    if !interactive {
        return Err(unconfirmed(&resolved.server));
    }
    let shown = format::one_line(&resolved.server);
    let host = url::Url::parse(&resolved.server)
        .ok()
        .and_then(|url| url.host_str().map(String::from))
        .unwrap_or_else(|| shown.clone());
    let answer = prompter.line(&format!(
        "Only {} names this server:\n\n    {shown}\n    host: {host}\n\nLog in to it and trust it from now on? [y/N] ",
        config::PROJECT_FILE
    ))?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }
    bail!("not logging in to {shown}")
}

pub async fn run_login(client_args: &ClientArgs, args: LoginArgs) -> anyhow::Result<()> {
    let resolved = resolve(client_args)?;
    let api = client(client_args, &resolved, None)?;
    let github = || -> anyhow::Result<Box<dyn IdTokenSource>> { Ok(Box::new(GithubActionsTokenSource::from_env()?)) };
    let mut stderr = std::io::stderr();
    let token = match machine_credential(&args, &github).await? {
        Some(credential) => {
            require_explicit_server(&resolved)?;
            login::machine_login(&api, credential).await?
        }
        None => {
            let interactive =
                std::io::IsTerminal::is_terminal(&std::io::stdin()) && std::io::IsTerminal::is_terminal(&stderr);
            confirm_login_server(&resolved, &crate::prompt::Terminal, interactive)?;
            let opener = |url: &str| !args.no_browser && login::open_in_browser(url);
            login::device_login(&api, &resolved.server, &mut stderr, &opener, Duration::from_secs(10)).await?
        }
    };
    if args.print_token {
        println!("{}", token.access_token);
        return Ok(());
    }
    let path = config::credentials_path()?;
    let mut credentials = read_credentials(&path)?;
    credentials.servers.insert(
        resolved.server.clone(),
        StoredToken {
            token: token.access_token,
            expires_at: now() + token.expires_in,
        },
    );
    config::save_credentials(&path, &credentials)?;
    writeln!(stderr, "Logged in to {}", format::one_line(&resolved.server))?;
    Ok(())
}

pub async fn run_logout(client_args: &ClientArgs) -> anyhow::Result<()> {
    let resolved = resolve(client_args)?;
    if let Some(token) = resolved.token.clone() {
        let api = client(client_args, &resolved, Some(token))?;
        if let Err(error) = api.revoke().await {
            eprintln!("could not revoke the token on the server: {error}");
        }
    }
    let path = config::credentials_path()?;
    let mut credentials = read_credentials(&path)?;
    if credentials.servers.remove(&resolved.server).is_some() {
        config::save_credentials(&path, &credentials)?;
    }
    eprintln!("Logged out of {}", format::one_line(&resolved.server));
    Ok(())
}

fn summarise(result: &BatchResult) -> String {
    let mut parts = Vec::new();
    for (label, keys) in [
        ("created", &result.created),
        ("updated", &result.updated),
        ("deleted", &result.deleted),
        ("unchanged", &result.unchanged),
    ] {
        if !keys.is_empty() {
            parts.push(format!("{label}: {}", format::one_line(&keys.join(", "))));
        }
    }
    if parts.is_empty() {
        "nothing to do".into()
    } else {
        parts.join("; ")
    }
}

/// A reminder, for someone typing at a terminal, that values on the command line end up in the
/// shell's history and the process list.
pub fn shell_history_warning(pairs: &[String], interactive: bool) -> Option<String> {
    if !interactive {
        return None;
    }
    let keys: Vec<&str> = pairs
        .iter()
        .filter_map(|pair| pair.split_once('='))
        .filter(|(_, value)| *value != "-")
        .map(|(key, _)| key)
        .collect();
    if keys.is_empty() {
        return None;
    }
    Some(format!(
        "sekret: the value of {} is now in your shell history; next time use `{}=-` and type it on standard input",
        keys.join(", "),
        keys[0]
    ))
}

/// Turns `KEY=value` arguments (and an optional .env file) into upserts.
pub fn collect_upserts(
    pairs: &[String],
    dotenv: Option<&str>,
    comment: &str,
    stdin: &mut dyn Read,
) -> anyhow::Result<Vec<SecretUpsert>> {
    let mut entries = match dotenv {
        Some(text) => parse_dotenv(text)?,
        None => Vec::new(),
    };
    let mut stdin_used = false;
    for pair in pairs {
        let Some((key, value)) = pair.split_once('=') else {
            bail!("{pair} is not KEY=value");
        };
        let value = if value == "-" {
            if stdin_used {
                bail!("only one value can be read from stdin");
            }
            stdin_used = true;
            let mut buffer = String::new();
            stdin.read_to_string(&mut buffer)?;
            buffer.strip_suffix('\n').unwrap_or(&buffer).to_string()
        } else {
            value.to_string()
        };
        entries.push((key.to_string(), value));
    }
    if entries.is_empty() {
        bail!("nothing to set; pass KEY=value pairs or --from-dotenv");
    }
    Ok(entries
        .into_iter()
        .map(|(key, value)| SecretUpsert {
            key,
            value,
            comment: comment.to_string(),
            tags: None,
        })
        .collect())
}

pub async fn secrets(
    api: &dyn SekretApi,
    at: Location,
    command: SecretsCommand,
    out: &mut dyn Write,
    stdin: &mut dyn Read,
) -> anyhow::Result<()> {
    match command {
        SecretsCommand::List { recursive, values } => {
            let list = api.list_secrets(at, recursive, values).await?;
            let rows: Vec<Vec<String>> = list
                .secrets
                .iter()
                .map(|s| {
                    let mut row = vec![
                        format!(
                            "{}{}",
                            if s.path == "/" {
                                String::new()
                            } else {
                                format!("{}/", s.path)
                            },
                            s.key
                        ),
                        s.version.to_string(),
                        s.updated_by.clone(),
                    ];
                    if values {
                        row.push(if s.value_hidden {
                            "(hidden)".into()
                        } else {
                            s.value.clone().unwrap_or_default()
                        });
                    }
                    row
                })
                .collect();
            let headers: &[&str] = if values {
                &["KEY", "VERSION", "UPDATED BY", "VALUE"]
            } else {
                &["KEY", "VERSION", "UPDATED BY"]
            };
            write!(out, "{}", table(headers, &rows))?;
            for folder in list.folders {
                writeln!(out, "{}/", format::one_line(&folder))?;
            }
        }
        SecretsCommand::Get { key, json, raw } => {
            let secret = api.get_secret(at, key.clone()).await?;
            if json {
                // JSON escapes C0 controls but not C1 controls or bidi overrides.
                let text = serde_json::to_string_pretty(&secret)?;
                if !raw && sekret_client::terminal_safe(&text) != text {
                    bail!(
                        "{} holds characters that could change what this terminal shows; pipe it to a file or \
                         pass --raw to print it anyway",
                        format::one_line(&key)
                    );
                }
                writeln!(out, "{text}")?;
                return Ok(());
            }
            let Some(value) = secret.value else {
                bail!("you can see {key} but are not allowed to read its value");
            };
            if !raw && sekret_client::terminal_safe(&value) != value {
                bail!(
                    "the value of {} holds control characters that could change what this terminal shows; \
                     pipe it to a file or pass --raw to print it anyway",
                    format::one_line(&key)
                );
            }
            writeln!(out, "{value}")?;
        }
        SecretsCommand::Set {
            pairs,
            from_dotenv,
            comment,
        } => {
            if let Some(warning) = shell_history_warning(&pairs, std::io::IsTerminal::is_terminal(&std::io::stdin())) {
                eprintln!("{warning}");
            }
            let dotenv = from_dotenv
                .as_deref()
                .map(config::read_text)
                .transpose()
                .context("reading .env file")?;
            let upserts = collect_upserts(&pairs, dotenv.as_deref(), &comment, stdin)?;
            let result = api
                .write(
                    at,
                    BatchWrite {
                        path: String::new(),
                        upserts,
                        deletes: vec![],
                    },
                )
                .await?;
            writeln!(out, "{}", summarise(&result))?;
        }
        SecretsCommand::Delete { keys } => {
            let result = api
                .write(
                    at,
                    BatchWrite {
                        path: String::new(),
                        upserts: vec![],
                        deletes: keys,
                    },
                )
                .await?;
            writeln!(out, "{}", summarise(&result))?;
        }
        SecretsCommand::History {
            key, diff: Some(pair), ..
        } => {
            let versions = api.versions(at, key, true).await?;
            let value_of = |number: i64| -> anyhow::Result<String> {
                let version = versions
                    .iter()
                    .find(|v| v.version == number)
                    .ok_or_else(|| anyhow::anyhow!("there is no version {number}"))?;
                if version.deleted {
                    return Ok(String::new());
                }
                version
                    .value
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("you cannot read the value of version {number}"))
            };
            let (from, to) = match pair.as_slice() {
                [from, to] => (*from, *to),
                _ => anyhow::bail!("--diff takes two version numbers"),
            };
            write!(
                out,
                "--- version {from}\n+++ version {to}\n{}",
                sekret_client::terminal_safe(&line_diff(&value_of(from)?, &value_of(to)?))
            )?;
        }
        SecretsCommand::History { key, values, .. } => {
            let versions = api.versions(at, key, values).await?;
            let rows: Vec<Vec<String>> = versions
                .iter()
                .map(|v| {
                    let state = if v.deleted {
                        "deleted".to_string()
                    } else if values {
                        v.value.clone().unwrap_or_else(|| "(hidden)".into())
                    } else {
                        String::new()
                    };
                    vec![
                        v.version.to_string(),
                        v.actor.clone(),
                        v.created_at.to_string(),
                        v.comment.clone(),
                        state,
                    ]
                })
                .collect();
            write!(
                out,
                "{}",
                table(
                    &["VERSION", "BY", "AT", "COMMENT", if values { "VALUE" } else { "" }],
                    &rows
                )
            )?;
        }
        SecretsCommand::Rollback { key, version } => {
            let result = api.rollback(at, key, version).await?;
            writeln!(out, "{}", summarise(&result))?;
        }
        SecretsCommand::Generate {
            key,
            length,
            charset,
            comment,
        } => {
            let generator = (length.is_some() || charset.is_some()).then(|| {
                let base = Generator::default();
                Generator {
                    length: length.unwrap_or(base.length),
                    charset: charset.map(Charset::from).unwrap_or(base.charset),
                }
            });
            let result = api.generate(at, key, GenerateSecret { generator, comment }).await?;
            writeln!(out, "{}", summarise(&result))?;
        }
        SecretsCommand::Policy { key, inherit, policy } => {
            let view = if inherit {
                api.set_secret_policy(at, key, PolicyOverride::Inherit).await?
            } else if policy.is_empty() {
                api.secret_policy(at, key).await?
            } else {
                let current = api.secret_policy(at.clone(), key.clone()).await?;
                let next = policy.apply(current.effective);
                api.set_secret_policy(at, key, PolicyOverride::Custom(next)).await?
            };
            let source = match view.setting {
                PolicyOverride::Inherit => "project default",
                PolicyOverride::Custom(_) => "this secret",
            };
            writeln!(out, "{}set by:    {source}", describe_policy(&view.effective))?;
            match view.next_rotation_at {
                Some(at) => writeln!(out, "next rotation: {}", format::timestamp(at))?,
                None if view.effective.rotation_days.is_some() && !view.generated => writeln!(
                    out,
                    "not rotating: the current value was not generated by sekret; run `sekret secrets generate` once"
                )?,
                None => {}
            }
        }
    }
    Ok(())
}

pub async fn snapshots(
    api: &dyn SekretApi,
    at: Location,
    command: SnapshotsCommand,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    match command {
        SnapshotsCommand::List => {
            let snapshots = api.snapshots(at.project, at.environment).await?;
            let rows: Vec<Vec<String>> = snapshots
                .iter()
                .map(|s| {
                    vec![
                        s.id.clone(),
                        s.created_at.to_string(),
                        s.actor.clone(),
                        s.secret_count.to_string(),
                        s.reason.clone(),
                    ]
                })
                .collect();
            write!(out, "{}", table(&["ID", "AT", "BY", "SECRETS", "REASON"], &rows))?;
        }
        SnapshotsCommand::Restore { id } => {
            let result = api.restore(at, id).await?;
            writeln!(out, "{}", summarise(&result))?;
        }
    }
    Ok(())
}

/// The names `run`, `env use` and export may load: `--allow` flags plus the project file's
/// confirmed `allow`.
pub fn load_policy(resolved: &Resolved, flags: &[String]) -> anyhow::Result<shell::LoadPolicy> {
    shell::LoadPolicy::new(flags.iter().chain(&resolved.allow).cloned())
}

/// Whether to honour a project file's `allow` list that has not been confirmed: asked at a
/// terminal, and otherwise left out with a note saying how to confirm it.
pub fn ask_project_allow(
    scope: &config::AllowScope,
    names: &[String],
    prompter: &dyn Prompter,
    interactive: bool,
    notes: &mut dyn Write,
) -> anyhow::Result<bool> {
    let shown = format::one_line(&scope.file.display().to_string());
    let target = scope.describe();
    let listed = names.iter().map(|n| format::one_line(n)).collect::<Vec<_>>().join(", ");
    if !interactive {
        writeln!(
            notes,
            "sekret: not loading {listed} from {target} although {shown} allows them; run this once at a terminal \
             to confirm, or pass --allow NAME"
        )?;
        return Ok(false);
    }
    let answer = prompter.line(&format!(
        "{shown} asks to load these blocked names from {target}:\n\n    {listed}\n\nThey can change what programs \
         run or where they connect, so only say yes if you trust everyone who can write secrets there. Load them \
         from now on, while this list and this place are unchanged? [y/N] "
    ))?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// Like [`load_policy`], first asking about an unconfirmed project file `allow` list and saving
/// a yes beside the stored logins.
pub fn load_policy_confirming(resolved: &Resolved, flags: &[String]) -> anyhow::Result<shell::LoadPolicy> {
    let mut stderr = std::io::stderr();
    if let Some(note) = file_choice_note(resolved) {
        writeln!(stderr, "{note}")?;
    }
    let Some((scope, names)) = &resolved.unconfirmed_allow else {
        return load_policy(resolved, flags);
    };
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin()) && std::io::IsTerminal::is_terminal(&stderr);
    if !ask_project_allow(scope, names, &crate::prompt::Terminal, interactive, &mut stderr)? {
        return load_policy(resolved, flags);
    }
    let path = config::credentials_path()?;
    let mut credentials = read_credentials(&path)?;
    credentials.confirm_allow(scope, names);
    config::save_credentials(&path, &credentials)?;
    shell::LoadPolicy::new(flags.iter().chain(&resolved.allow).chain(names).cloned())
}

/// Names the project file when it, not the person, picked the project or environment.
pub fn file_choice_note(resolved: &Resolved) -> Option<String> {
    let file = resolved.chosen_by_file.as_ref()?;
    Some(format!(
        "sekret: using {}/{} as set in {}",
        format::one_line(resolved.project.as_deref().unwrap_or("?")),
        format::one_line(resolved.environment.as_deref().unwrap_or("?")),
        format::one_line(&file.display().to_string())
    ))
}

/// Formats that get sourced into a shell leave out keys that are unsafe as variables, like `run`.
pub async fn export(
    api: &dyn SekretApi,
    at: Location,
    args: &ExportArgs,
    policy: &shell::LoadPolicy,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> anyhow::Result<()> {
    let raw = api.raw(at, args.recursive).await?;
    let vars = flatten(&raw.secrets)?;
    let vars = match args.format {
        ExportFormat::Dotenv | ExportFormat::Shell => {
            let (kept, skipped) = policy.split(vars);
            note_skipped(notes, &skipped)?;
            kept
        }
        ExportFormat::Json | ExportFormat::Yaml => vars,
    };
    let text = render(&vars, args.format)?;
    if !args.raw && sekret_client::terminal_safe(&text) != text {
        let key = vars
            .iter()
            .find(|(k, v)| sekret_client::terminal_safe(k) != **k || sekret_client::terminal_safe(v) != **v)
            .map_or_else(|| "a secret".into(), |(k, _)| format::one_line(k));
        bail!(
            "the value of {key} holds control characters that could change what this terminal shows; \
             redirect the output to a file or pass --raw to print it anyway"
        );
    }
    write!(out, "{text}")?;
    Ok(())
}

/// Shows the project's default policy, changing it first when flags are given.
pub async fn project_policy(api: &dyn SekretApi, project: String, flags: &PolicyFlags) -> anyhow::Result<String> {
    let current = api.project_policy(project.clone()).await?;
    let policy = if flags.is_empty() {
        current
    } else {
        api.set_project_policy(project, flags.apply(current)).await?
    };
    Ok(format!(
        "{}applies to every secret that does not set its own policy\n",
        describe_policy(&policy)
    ))
}

/// How `env use` builds its shell code.
pub struct EnvUse<'a> {
    pub shell: shell::Shell,
    pub recursive: bool,
    pub policy: &'a shell::LoadPolicy,
    /// Keys the previous switch loaded, to unset first.
    pub previous: &'a [String],
    /// The project file in force, recorded so another folder's file is not overridden.
    pub project_file: Option<&'a std::path::Path>,
}

/// Writes shell code that switches to `at`, and a summary for the person or agent on `notes`.
pub async fn env_use(
    api: &dyn SekretApi,
    at: Location,
    options: EnvUse<'_>,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> anyhow::Result<()> {
    let raw = api.raw(at.clone(), options.recursive).await?;
    let origin = shell::Origin {
        project: at.project,
        environment: at.environment,
        path: at.path,
        project_file: options
            .project_file
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    };
    let switch = shell::switch_script(
        options.shell,
        options.previous,
        flatten(&raw.secrets)?,
        options.policy,
        &origin,
    );
    write!(out, "{}", switch.script)?;
    writeln!(
        notes,
        "sekret: loaded {} secrets from {}/{}{}",
        switch.loaded.len(),
        origin.project,
        origin.environment,
        if origin.path == "/" {
            String::new()
        } else {
            origin.path.clone()
        }
    )?;
    note_skipped(notes, &switch.skipped)
}

/// Describes what this shell has loaded, without values.
pub fn env_status(project: Option<&str>, environment: Option<&str>, loaded: &[String]) -> String {
    let Some(environment) = environment.filter(|_| !loaded.is_empty()) else {
        return "nothing loaded; run `sekret-env <environment>` or `eval \"$(sekret env use <environment>)\"`\n".into();
    };
    format!("{}/{environment}: {}\n", project.unwrap_or("?"), loaded.join(" "))
}

/// Fetches secrets and runs the command with them in its environment, returning its exit code.
pub async fn run_command(
    api: &dyn SekretApi,
    at: Location,
    args: &RunArgs,
    policy: &shell::LoadPolicy,
    notes: &mut dyn Write,
) -> anyhow::Result<i32> {
    let Some((program, rest)) = args.command.split_first() else {
        bail!("no command given");
    };
    let raw = api.raw(at, args.recursive).await?;
    let (vars, skipped) = policy.split(flatten(&raw.secrets)?);
    note_skipped(notes, &skipped)?;
    let mut command = tokio::process::Command::new(program);
    command.args(rest);
    // The child gets the secrets, never the credentials that fetched them.
    for name in shell::CREDENTIAL_VARS {
        command.env_remove(name);
    }
    let status = command
        .envs(&vars)
        .status()
        .await
        .with_context(|| format!("running {program}"))?;
    Ok(status.code().unwrap_or(1))
}

fn note_skipped(notes: &mut dyn Write, skipped: &[shell::Skipped]) -> anyhow::Result<()> {
    for line in shell::describe_skipped(skipped) {
        writeln!(notes, "{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use sekret_api::{RawSecret, RawSecrets, Secret, SecretList};
    use sekret_client::MockSekretApi;

    fn at() -> Location {
        Location {
            project: "app".into(),
            environment: "dev".into(),
            path: "/".into(),
        }
    }

    fn result() -> BatchResult {
        BatchResult {
            created: vec!["A".into()],
            updated: vec![],
            deleted: vec![],
            unchanged: vec!["B".into()],
            snapshot_id: None,
        }
    }

    fn secret(value: Option<&str>, hidden: bool) -> Secret {
        Secret {
            id: "s".into(),
            environment: "dev".into(),
            path: "/".into(),
            key: "A".into(),
            value: value.map(String::from),
            value_hidden: hidden,
            version: 3,
            comment: String::new(),
            tags: vec![],
            updated_at: 0,
            updated_by: "user:sam".into(),
            generated: false,
            next_rotation_at: None,
        }
    }

    #[test]
    fn upserts_from_pairs_stdin_and_dotenv() -> anyhow::Result<()> {
        let mut stdin = "from-stdin\n".as_bytes();
        let upserts = collect_upserts(
            &["A=1".into(), "B=-".into(), "C=x=y".into()],
            Some("D=4\n"),
            "c",
            &mut stdin,
        )
        .context("collect")?;
        let pairs: Vec<(&str, &str)> = upserts.iter().map(|u| (u.key.as_str(), u.value.as_str())).collect();
        assert_eq!(pairs, [("D", "4"), ("A", "1"), ("B", "from-stdin"), ("C", "x=y")]);
        assert!(collect_upserts(&["A=-".into(), "B=-".into()], None, "", &mut "x".as_bytes()).is_err());
        assert!(collect_upserts(&["NOEQUALS".into()], None, "", &mut "".as_bytes()).is_err());
        assert!(collect_upserts(&[], None, "", &mut "".as_bytes()).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn get_prints_value_or_explains_hidden() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_get_secret()
            .times(1)
            .returning(|_, _| Ok(secret(Some("v"), false)));
        api.expect_get_secret()
            .times(1)
            .returning(|_, _| Ok(secret(None, true)));
        let mut out = Vec::new();
        secrets(
            &api,
            at(),
            SecretsCommand::Get {
                key: "A".into(),
                json: false,
                raw: false,
            },
            &mut out,
            &mut "".as_bytes(),
        )
        .await
        .context("get")?;
        assert_eq!(out, b"v\n");
        let Err(hidden) = secrets(
            &api,
            at(),
            SecretsCommand::Get {
                key: "A".into(),
                json: false,
                raw: false,
            },
            &mut Vec::new(),
            &mut "".as_bytes(),
        )
        .await
        else {
            anyhow::bail!("getting a hidden value should fail");
        };
        assert!(hidden.to_string().contains("not allowed"));
        Ok(())
    }

    #[tokio::test]
    async fn get_refuses_escape_sequences_for_a_terminal_unless_raw() -> anyhow::Result<()> {
        const HOSTILE: &str = "x\u{1b}]52;c;cm0gLXJmIH4=\u{7}\u{1b}[2J";
        let mut api = MockSekretApi::new();
        api.expect_get_secret()
            .returning(|_, _| Ok(secret(Some(HOSTILE), false)));
        let get = |raw| SecretsCommand::Get {
            key: "A".into(),
            json: false,
            raw,
        };
        let mut out = Vec::new();
        let refused = secrets(&api, at(), get(false), &mut out, &mut "".as_bytes())
            .await
            .err()
            .context("expected a refusal")?;
        assert!(refused.to_string().contains("--raw"), "{refused}");
        assert!(out.is_empty(), "nothing reaches the terminal");

        // C1 controls and bidi overrides survive JSON escaping, so --json is checked too.
        for hostile in ["a\u{9b}2J", "a\u{202e}gnp.exe"] {
            let mut api = MockSekretApi::new();
            api.expect_get_secret()
                .returning(move |_, _| Ok(secret(Some(hostile), false)));
            let json = |raw| SecretsCommand::Get {
                key: "A".into(),
                json: true,
                raw,
            };
            let mut out = Vec::new();
            let refused = secrets(&api, at(), json(false), &mut out, &mut "".as_bytes())
                .await
                .err()
                .context("expected a JSON refusal")?;
            assert!(refused.to_string().contains("--raw"), "{refused}");
            assert!(out.is_empty());
            secrets(&api, at(), json(true), &mut out, &mut "".as_bytes())
                .await
                .context("raw JSON")?;
            assert!(String::from_utf8(out).context("utf8")?.contains(hostile));
        }
        let mut plain = MockSekretApi::new();
        plain
            .expect_get_secret()
            .returning(|_, _| Ok(secret(Some("ok\u{1b}[2J"), false)));
        let mut out = Vec::new();
        secrets(
            &plain,
            at(),
            SecretsCommand::Get {
                key: "A".into(),
                json: true,
                raw: false,
            },
            &mut out,
            &mut "".as_bytes(),
        )
        .await
        .context("JSON escapes ESC itself")?;
        assert!(String::from_utf8(out).context("utf8")?.contains("\\u001b"));

        let mut out = Vec::new();
        secrets(&api, at(), get(true), &mut out, &mut "".as_bytes())
            .await
            .context("raw")?;
        assert_eq!(out, format!("{HOSTILE}\n").as_bytes());
        let mut multi = MockSekretApi::new();
        multi
            .expect_get_secret()
            .returning(|_, _| Ok(secret(Some("line one\nline\ttwo"), false)));
        let mut out = Vec::new();
        secrets(&multi, at(), get(false), &mut out, &mut "".as_bytes())
            .await
            .context("multi-line")?;
        assert_eq!(out, b"line one\nline\ttwo\n", "newlines and tabs are fine");
        Ok(())
    }

    #[tokio::test]
    async fn set_and_delete_send_batches() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_write()
            .withf(|at, b| {
                at.project == "app" && b.upserts.len() == 1 && b.upserts[0].key == "A" && b.deletes.is_empty()
            })
            .times(1)
            .returning(|_, _| Ok(result()));
        api.expect_write()
            .withf(|_, b| b.deletes == vec!["OLD".to_string()])
            .times(1)
            .returning(|_, _| Ok(result()));
        let mut out = Vec::new();
        let set = SecretsCommand::Set {
            pairs: vec!["A=1".into()],
            from_dotenv: None,
            comment: String::new(),
        };
        secrets(&api, at(), set, &mut out, &mut "".as_bytes())
            .await
            .context("set")?;
        secrets(
            &api,
            at(),
            SecretsCommand::Delete {
                keys: vec!["OLD".into()],
            },
            &mut out,
            &mut "".as_bytes(),
        )
        .await
        .context("delete")?;
        assert!(
            String::from_utf8(out)
                .context("utf8")?
                .contains("created: A; unchanged: B")
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_shows_hidden_values_and_folders() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_list_secrets().returning(|_, _, _| {
            Ok(SecretList {
                secrets: vec![secret(None, true)],
                folders: vec!["db".into()],
            })
        });
        let mut out = Vec::new();
        secrets(
            &api,
            at(),
            SecretsCommand::List {
                recursive: false,
                values: true,
            },
            &mut out,
            &mut "".as_bytes(),
        )
        .await
        .context("list")?;
        let text = String::from_utf8(out).context("utf8")?;
        assert!(text.contains("(hidden)") && text.contains("db/") && text.contains("user:sam"));
        Ok(())
    }

    #[tokio::test]
    async fn export_and_run_use_raw_values() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_raw().returning(|_, _| {
            Ok(RawSecrets {
                project: "app".into(),
                environment: "dev".into(),
                secrets: vec![RawSecret {
                    path: "/".into(),
                    key: "APP_GREETING".into(),
                    value: "hello world".into(),
                }],
            })
        });
        let mut out = Vec::new();
        export(
            &api,
            at(),
            &export_args(ExportFormat::Dotenv),
            &strict(),
            &mut out,
            &mut Vec::new(),
        )
        .await
        .context("export")?;
        assert_eq!(out, b"APP_GREETING=\"hello world\"\n");

        let args = run_args("test \"$APP_GREETING\" = 'hello world' && exit 7");
        assert_eq!(
            run_command(&api, at(), &args, &strict(), &mut Vec::new())
                .await
                .context("run")?,
            7
        );
        Ok(())
    }

    fn strict() -> shell::LoadPolicy {
        shell::LoadPolicy::default()
    }

    fn export_args(format: ExportFormat) -> ExportArgs {
        ExportArgs {
            format,
            recursive: false,
            allow: vec![],
            raw: false,
        }
    }

    #[tokio::test]
    async fn export_refuses_escape_sequences_for_a_terminal_unless_raw() -> anyhow::Result<()> {
        const HOSTILE: &str = "x\u{1b}]52;c;cm0gLXJmIH4=\u{7}\u{1b}[2J";
        let mut api = MockSekretApi::new();
        api.expect_raw().returning(|_, _| {
            Ok(RawSecrets {
                project: "app".into(),
                environment: "dev".into(),
                secrets: vec![
                    RawSecret {
                        path: "/".into(),
                        key: "PLAIN_VALUE".into(),
                        value: "fine".into(),
                    },
                    RawSecret {
                        path: "/".into(),
                        key: "TRAP_VALUE".into(),
                        value: HOSTILE.into(),
                    },
                    RawSecret {
                        path: "/".into(),
                        key: "BIDI_VALUE".into(),
                        value: "a\u{202e}b".into(),
                    },
                ],
            })
        });
        for format in [
            ExportFormat::Dotenv,
            ExportFormat::Shell,
            ExportFormat::Json,
            ExportFormat::Yaml,
        ] {
            let mut out = Vec::new();
            let refused = export(&api, at(), &export_args(format), &strict(), &mut out, &mut Vec::new())
                .await
                .err()
                .context("expected a refusal")?;
            assert!(refused.to_string().contains("--raw"), "{format:?}: {refused}");
            assert!(!refused.to_string().contains('\u{1b}'), "{format:?}");
            assert!(out.is_empty(), "{format:?}: nothing reaches the terminal");

            let raw = ExportArgs {
                raw: true,
                ..export_args(format)
            };
            let mut out = Vec::new();
            export(&api, at(), &raw, &strict(), &mut out, &mut Vec::new())
                .await
                .context("raw")?;
            // JSON and YAML escape ESC themselves, but not bidi overrides.
            let out = String::from_utf8(out)?;
            assert!(out.contains('\u{202e}'), "{format:?}");
            if matches!(format, ExportFormat::Dotenv | ExportFormat::Shell) {
                assert!(out.contains("\u{1b}]52"), "{format:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn a_token_flag_is_warned_about_but_not_the_variable_or_a_childs_flag() {
        let argv = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert!(token_flag_warning(&argv(&["sekret", "--token", "skt_x", "whoami"])).is_some());
        assert!(token_flag_warning(&argv(&["sekret", "whoami", "--token=skt_x"])).is_some());
        assert_eq!(token_flag_warning(&argv(&["sekret", "whoami"])), None);
        assert_eq!(
            token_flag_warning(&argv(&["sekret", "run", "--", "tool", "--token", "x"])),
            None,
            "the command's own arguments are not sekret's"
        );
        let warning = token_flag_warning(&argv(&["sekret", "--token", "skt_secret"])).unwrap_or_default();
        assert!(warning.contains("SEKRET_TOKEN") && !warning.contains("skt_secret"));
    }

    #[test]
    fn a_duplicate_key_is_named_without_its_escape_sequences() -> anyhow::Result<()> {
        let secret = |path: &str| RawSecret {
            path: path.into(),
            key: "K\u{1b}[2J".into(),
            value: "v".into(),
        };
        let error = flatten(&[secret("/"), secret("/a")])
            .err()
            .context("expected a clash")?;
        assert!(!error.to_string().contains('\u{1b}'), "{error}");
        Ok(())
    }

    fn run_args(script: &str) -> RunArgs {
        RunArgs {
            recursive: false,
            allow: vec![],
            command: vec!["sh".into(), "-c".into(), script.into()],
        }
    }

    fn hostile_raw() -> RawSecrets {
        let secret = |key: &str, value: &str| RawSecret {
            path: "/".into(),
            key: key.into(),
            value: value.into(),
        };
        RawSecrets {
            project: "app".into(),
            environment: "dev".into(),
            secrets: vec![
                secret("APP_GREETING", "hi"),
                secret("SEKRET_URL", "https://evil.test"),
                secret("HTTPS_PROXY", "http://evil.test:3128"),
                secret("GIT_ASKPASS", "/tmp/evil"),
                secret("bad.key", "x"),
            ],
        }
    }

    #[tokio::test]
    async fn run_and_dotenv_export_leave_out_unsafe_and_sekret_keys() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_raw().returning(|_, _| Ok(hostile_raw()));
        let args = run_args(
            "test \"$APP_GREETING\" = hi && test \"${HTTPS_PROXY-}\" != http://evil.test:3128 \
             && test \"${GIT_ASKPASS-}\" != /tmp/evil \
             && test \"${SEKRET_URL-unset}\" != https://evil.test && exit 7",
        );
        let mut notes = Vec::new();
        assert_eq!(
            run_command(&api, at(), &args, &strict(), &mut notes)
                .await
                .context("run")?,
            7
        );
        let notes = String::from_utf8(notes).context("utf8")?;
        assert!(notes.contains("HTTPS_PROXY") && notes.contains("SEKRET_URL") && notes.contains("bad.key"));
        assert!(!notes.contains("evil.test"), "values never reach the notes");

        for format in [ExportFormat::Dotenv, ExportFormat::Shell] {
            let (mut out, mut notes) = (Vec::new(), Vec::new());
            export(&api, at(), &export_args(format), &strict(), &mut out, &mut notes)
                .await
                .context("export")?;
            let out = String::from_utf8(out).context("utf8")?;
            assert!(out.contains("APP_GREETING"), "{format:?}");
            for hidden in ["SEKRET_URL", "HTTPS_PROXY", "GIT_ASKPASS", "bad.key"] {
                assert!(!out.contains(hidden), "{format:?}: {hidden} in {out}");
            }
            assert!(String::from_utf8(notes).context("utf8")?.contains("HTTPS_PROXY"));
        }
        let mut json = Vec::new();
        export(
            &api,
            at(),
            &export_args(ExportFormat::Json),
            &strict(),
            &mut json,
            &mut Vec::new(),
        )
        .await
        .context("json")?;
        assert!(
            String::from_utf8(json).context("utf8")?.contains("HTTPS_PROXY"),
            "JSON is data, not sourced, so it keeps every key"
        );
        Ok(())
    }

    #[tokio::test]
    async fn allowed_names_are_loaded_but_sekret_settings_never_are() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_raw().returning(|_, _| Ok(hostile_raw()));
        let mut resolved = resolved(config::ServerSource::Explicit);
        resolved.allow = vec!["HTTPS_PROXY".into()];
        let policy = load_policy(&resolved, &["GIT_ASKPASS".into()])?;
        let args = run_args(
            "test \"$HTTPS_PROXY\" = http://evil.test:3128 && test \"$GIT_ASKPASS\" = /tmp/evil \
             && test \"${SEKRET_URL-unset}\" != https://evil.test && exit 7",
        );
        let mut notes = Vec::new();
        assert_eq!(run_command(&api, at(), &args, &policy, &mut notes).await?, 7);
        let notes = String::from_utf8(notes)?;
        assert!(
            notes.contains("SEKRET_URL") && !notes.contains("HTTPS_PROXY"),
            "{notes}"
        );
        let mut out = Vec::new();
        export(
            &api,
            at(),
            &export_args(ExportFormat::Shell),
            &policy,
            &mut out,
            &mut Vec::new(),
        )
        .await?;
        let out = String::from_utf8(out)?;
        assert!(
            out.contains("export HTTPS_PROXY=") && out.contains("export GIT_ASKPASS="),
            "{out}"
        );
        assert!(load_policy(&resolved, &["SEKRET_TOKEN".into()]).is_err());
        Ok(())
    }

    #[test]
    fn typed_values_on_a_terminal_warn_about_shell_history() {
        let pairs = vec!["DB_PASSWORD=hunter2".to_string(), "TOKEN=-".to_string()];
        let warning = shell_history_warning(&pairs, true).unwrap_or_default();
        assert!(
            warning.contains("DB_PASSWORD") && warning.contains("DB_PASSWORD=-"),
            "{warning}"
        );
        assert!(!warning.contains("TOKEN,"), "values from stdin are not in the history");
        assert!(!warning.contains("hunter2"), "the warning never repeats the value");
        assert_eq!(shell_history_warning(&pairs, false), None, "scripts are not nagged");
        assert_eq!(shell_history_warning(&["A=-".into()], true), None);
    }

    fn resolved(source: config::ServerSource) -> Resolved {
        Resolved {
            server: "https://evil.test".into(),
            token: None,
            project: None,
            environment: None,
            path: "/".into(),
            source,
            allow: vec![],
            unconfirmed_allow: None,
            chosen_by_file: None,
            project_file: None,
            stale_shell: None,
        }
    }

    struct Answer(&'static str);

    impl Prompter for Answer {
        fn secret(&self, _: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
            anyhow::bail!("no secrets asked")
        }

        fn line(&self, _: &str) -> anyhow::Result<String> {
            Ok(self.0.into())
        }
    }

    fn scope() -> config::AllowScope {
        config::AllowScope {
            file: "/repo/.sekret.toml".into(),
            server: "https://s.test".into(),
            project: "payments".into(),
            environment: "prod\u{1b}[2J".into(),
            path: "/".into(),
        }
    }

    /// Records what a prompt asked, so tests can check what the person was shown.
    struct Recorded(std::cell::RefCell<String>);

    impl Prompter for Recorded {
        fn secret(&self, _: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
            anyhow::bail!("no secrets asked")
        }

        fn line(&self, prompt: &str) -> anyhow::Result<String> {
            self.0.borrow_mut().push_str(prompt);
            Ok("y".into())
        }
    }

    #[test]
    fn a_project_file_allow_list_needs_a_yes_at_a_terminal() -> anyhow::Result<()> {
        let scope = scope();
        let names = vec!["LD_PRELOAD".to_string()];
        let mut notes = Vec::new();
        assert!(!ask_project_allow(&scope, &names, &Answer("y"), false, &mut notes)?);
        let note = String::from_utf8(notes)?;
        assert!(
            note.contains("LD_PRELOAD") && note.contains("/repo/.sekret.toml") && note.contains("payments/prod"),
            "{note}"
        );
        assert!(!note.contains('\u{1b}'), "{note}");
        assert!(!ask_project_allow(&scope, &names, &Answer(""), true, &mut Vec::new())?);
        assert!(!ask_project_allow(&scope, &names, &Answer("n"), true, &mut Vec::new())?);
        assert!(ask_project_allow(
            &scope,
            &names,
            &Answer("yes"),
            true,
            &mut Vec::new()
        )?);

        let recorded = Recorded(std::cell::RefCell::new(String::new()));
        assert!(ask_project_allow(&scope, &names, &recorded, true, &mut Vec::new())?);
        let asked = recorded.0.into_inner();
        assert!(
            asked.contains("payments/prod") && asked.contains("https://s.test") && asked.contains("LD_PRELOAD"),
            "the prompt says where the names would load from: {asked}"
        );
        assert!(!asked.contains('\u{1b}'), "{asked}");
        Ok(())
    }

    #[test]
    fn an_unconfirmed_allow_list_unblocks_nothing() -> anyhow::Result<()> {
        let mut resolved = resolved(config::ServerSource::Explicit);
        resolved.unconfirmed_allow = Some((scope(), vec!["LD_PRELOAD".into()]));
        let policy = load_policy(&resolved, &[])?;
        assert_eq!(policy.check("LD_PRELOAD"), Err(shell::SkipReason::Blocked));
        let flagged = load_policy(&resolved, &["LD_PRELOAD".into()])?;
        assert_eq!(flagged.check("LD_PRELOAD"), Ok(()), "a flag is the person's own choice");
        Ok(())
    }

    #[test]
    fn a_project_and_environment_from_the_file_are_named() {
        let mut resolved = resolved(config::ServerSource::Explicit);
        assert_eq!(file_choice_note(&resolved), None);
        resolved.project = Some("payments".into());
        resolved.environment = Some("prod".into());
        resolved.chosen_by_file = Some("/repo/.sekret.toml".into());
        let note = file_choice_note(&resolved).unwrap_or_default();
        assert!(
            note.contains("payments/prod") && note.contains("/repo/.sekret.toml"),
            "{note}"
        );
    }

    #[test]
    fn secrets_need_a_confirmed_server_and_machine_credentials_an_explicit_one() {
        use config::ServerSource::{Explicit, LoggedIn, ProjectFile};
        assert!(require_confirmed_server(&resolved(ProjectFile)).is_err());
        assert!(require_confirmed_server(&resolved(LoggedIn)).is_ok());
        assert!(require_confirmed_server(&resolved(Explicit)).is_ok());
        assert!(require_explicit_server(&resolved(ProjectFile)).is_err());
        assert!(
            require_explicit_server(&resolved(LoggedIn)).is_err(),
            "a saved login does not vouch for a client secret"
        );
        assert!(require_explicit_server(&resolved(Explicit)).is_ok());
    }

    #[test]
    fn a_login_to_a_server_only_the_project_file_names_needs_a_yes_at_a_terminal() -> anyhow::Result<()> {
        use crate::prompt::tests::Scripted;
        use config::ServerSource::{Explicit, LoggedIn, ProjectFile};
        let mut hostile = resolved(ProjectFile);
        // A Cyrillic letter that looks Latin, plus an escape sequence to hide the rest.
        hostile.server = "https://s\u{0435}kret.example/\u{1b}[8m".into();
        let refused = confirm_login_server(&hostile, &Scripted::new(&[]), false);
        assert!(refused.is_err_and(|e| e.to_string().contains("no credential is sent")));
        let declined = confirm_login_server(&hostile, &Scripted::new(&[""]), true);
        assert!(declined.is_err_and(|e| e.to_string().contains("not logging in")));
        let answers = Scripted::new(&["yes"]);
        confirm_login_server(&hostile, &answers, true)?;
        let asked = answers.asked().join("\n");
        assert!(
            asked.contains("host: xn--"),
            "the look-alike host is shown as punycode: {asked}"
        );
        assert!(!asked.contains('\u{1b}'), "{asked:?}");
        for source in [Explicit, LoggedIn] {
            let nothing_asked = Scripted::new(&[]);
            confirm_login_server(&resolved(source), &nothing_asked, false)?;
            assert!(nothing_asked.asked().is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn machine_credentials_from_flags() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "jwt-from-file\n").context("write")?;
        let base = LoginArgs {
            identity_id: Some("id".into()),
            oidc_token_file: None,
            oidc_token_env: None,
            github_actions: false,
            audience: "sekret".into(),
            kubernetes: false,
            kubernetes_token_file: token_file.clone(),
            client_id: None,
            client_secret_file: None,
            print_token: false,
            no_browser: true,
        };
        let no_github = || -> anyhow::Result<Box<dyn IdTokenSource>> { anyhow::bail!("not in GitHub Actions") };
        assert!(machine_credential(&base, &no_github).await.context("none")?.is_none());

        let k8s = LoginArgs {
            kubernetes: true,
            ..base.clone()
        };
        assert!(
            matches!(machine_credential(&k8s, &no_github).await.context("k8s")?, Some(MachineCredential::Kubernetes { token, .. }) if token == "jwt-from-file")
        );

        let oidc = LoginArgs {
            oidc_token_file: Some(token_file.clone()),
            ..base.clone()
        };
        assert!(matches!(
            machine_credential(&oidc, &no_github).await.context("oidc")?,
            Some(MachineCredential::Oidc { .. })
        ));

        let missing_identity = LoginArgs {
            identity_id: None,
            oidc_token_file: Some(token_file),
            ..base.clone()
        };
        assert!(machine_credential(&missing_identity, &no_github).await.is_err());

        let github = LoginArgs {
            github_actions: true,
            ..base.clone()
        };
        let fake_github = || -> anyhow::Result<Box<dyn IdTokenSource>> {
            let mut source = login::MockIdTokenSource::new();
            source.expect_fetch().returning(|_| Ok("gh-jwt".into()));
            Ok(Box::new(source))
        };
        assert!(
            matches!(machine_credential(&github, &fake_github).await.context("gh")?, Some(MachineCredential::Oidc { token, .. }) if token == "gh-jwt")
        );
        assert!(machine_credential(&github, &no_github).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn env_use_writes_values_to_the_script_and_only_names_to_notes() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_raw()
            .withf(|at, recursive| at.environment == "prod" && !recursive)
            .returning(|_, _| {
                Ok(RawSecrets {
                    project: "app".into(),
                    environment: "prod".into(),
                    secrets: vec![
                        RawSecret {
                            path: "/".into(),
                            key: "DB_PASSWORD".into(),
                            value: "hunter2".into(),
                        },
                        RawSecret {
                            path: "/".into(),
                            key: "bad.key".into(),
                            value: "x".into(),
                        },
                    ],
                })
            });
        let mut prod = at();
        prod.environment = "prod".into();
        let (mut out, mut notes) = (Vec::new(), Vec::new());
        let options = EnvUse {
            shell: shell::Shell::Bash,
            recursive: false,
            policy: &strict(),
            previous: &["OLD".into()],
            project_file: Some(std::path::Path::new("/repo/.sekret.toml")),
        };
        env_use(&api, prod, options, &mut out, &mut notes)
            .await
            .context("env use")?;
        let script = String::from_utf8(out).context("utf8")?;
        let notes = String::from_utf8(notes).context("utf8")?;
        assert!(script.starts_with("unset OLD\n"));
        assert!(script.contains("export DB_PASSWORD='hunter2'"));
        assert!(script.contains("export SEKRET_ENVIRONMENT='prod'"));
        assert!(script.contains("export SEKRET_LOADED_FILE='/repo/.sekret.toml'"));
        assert!(notes.contains("loaded 1 secrets from app/prod"));
        assert!(notes.contains("bad.key"));
        assert!(!notes.contains("hunter2"), "values never reach the notes");
        Ok(())
    }

    #[tokio::test]
    async fn env_use_reports_fetch_errors() {
        let mut api = MockSekretApi::new();
        api.expect_raw().returning(|_, _| {
            Err(sekret_client::ClientError::Api {
                status: 403,
                code: "forbidden".into(),
                message: "no".into(),
                retry_after: None,
            })
        });
        let (mut out, mut notes) = (Vec::new(), Vec::new());
        let options = EnvUse {
            shell: shell::Shell::Bash,
            recursive: false,
            policy: &strict(),
            previous: &[],
            project_file: None,
        };
        let result = env_use(&api, at(), options, &mut out, &mut notes).await;
        assert!(result.is_err());
        assert!(out.is_empty(), "nothing to eval on failure");
    }

    #[test]
    fn policy_flags_change_only_what_they_name() {
        let current = SecretPolicy {
            generator: Some(Generator {
                length: 40,
                charset: Charset::Hex,
            }),
            rotation_days: Some(30),
        };
        let rotate = PolicyFlags {
            rotate_days: Some(7),
            ..Default::default()
        };
        assert_eq!(
            rotate.apply(current),
            SecretPolicy {
                rotation_days: Some(7),
                ..current
            }
        );
        let shorter = PolicyFlags {
            length: Some(16),
            ..Default::default()
        };
        assert_eq!(
            shorter.apply(current).generator,
            Some(Generator {
                length: 16,
                charset: Charset::Hex
            })
        );
        let from_nothing = PolicyFlags {
            charset: Some(CharsetArg::Numeric),
            ..Default::default()
        };
        assert_eq!(
            from_nothing.apply(SecretPolicy::default()).generator,
            Some(Generator {
                length: 32,
                charset: Charset::Numeric
            })
        );
        let off = PolicyFlags {
            off: true,
            ..Default::default()
        };
        assert_eq!(off.apply(current), SecretPolicy::default());
        assert!(PolicyFlags::default().is_empty());
        assert!(describe_policy(&current).contains("every 30 days"));
    }

    #[test]
    fn env_status_shows_names_only() {
        assert_eq!(
            env_status(Some("app"), Some("prod"), &["A".into(), "B".into()]),
            "app/prod: A B\n"
        );
        assert!(env_status(Some("app"), Some("prod"), &[]).starts_with("nothing loaded"));
    }
}
