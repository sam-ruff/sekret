pub mod config;
pub mod format;
pub mod login;
pub mod shell;

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

#[derive(Debug, Clone, Args)]
pub struct ClientArgs {
    /// Server URL, e.g. https://sekret.example.com.
    #[arg(long, global = true, env = "SEKRET_URL")]
    pub server: Option<String>,
    /// Access token; defaults to the one saved by `sekret login`.
    #[arg(long, global = true, env = "SEKRET_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
    #[arg(long, short = 'p', global = true, env = "SEKRET_PROJECT")]
    pub project: Option<String>,
    #[arg(long = "env", short = 'e', global = true, env = "SEKRET_ENVIRONMENT")]
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

pub fn resolve(args: &ClientArgs) -> anyhow::Result<Resolved> {
    let cwd = std::env::current_dir()?;
    let file = config::load_project_file(&cwd)?;
    let credentials = config::load_credentials(&config::credentials_path()?)?;
    config::resolve(
        Overrides {
            server: args.server.clone(),
            token: args.token.clone(),
            project: args.project.clone(),
            environment: args.environment.clone(),
            path: args.path.clone(),
        },
        file,
        &credentials,
        now(),
    )
}

pub fn client(args: &ClientArgs, resolved: &Resolved, token: Option<String>) -> anyhow::Result<HttpClient> {
    let ca_pem = args
        .ca_file
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("reading CA file")?;
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

pub fn location(resolved: &Resolved) -> anyhow::Result<Location> {
    let (project, environment) = resolved.require_project()?;
    Ok(Location {
        project,
        environment,
        path: resolved.path.clone(),
    })
}

fn read_trimmed(path: &std::path::Path) -> anyhow::Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .to_string())
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
            Some(path) => read_trimmed(path)?,
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

pub async fn run_login(client_args: &ClientArgs, args: LoginArgs) -> anyhow::Result<()> {
    let resolved = resolve(client_args)?;
    let api = client(client_args, &resolved, None)?;
    let github = || -> anyhow::Result<Box<dyn IdTokenSource>> { Ok(Box::new(GithubActionsTokenSource::from_env()?)) };
    let mut stderr = std::io::stderr();
    let token = match machine_credential(&args, &github).await? {
        Some(credential) => login::machine_login(&api, credential).await?,
        None => {
            let opener = |url: &str| !args.no_browser && login::open_in_browser(url);
            login::device_login(&api, &mut stderr, &opener, Duration::from_secs(10)).await?
        }
    };
    if args.print_token {
        println!("{}", token.access_token);
        return Ok(());
    }
    let path = config::credentials_path()?;
    let mut credentials = config::load_credentials(&path)?;
    credentials.servers.insert(
        resolved.server.clone(),
        StoredToken {
            token: token.access_token,
            expires_at: now() + token.expires_in,
        },
    );
    config::save_credentials(&path, &credentials)?;
    writeln!(stderr, "Logged in to {}", resolved.server)?;
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
    let mut credentials: Credentials = config::load_credentials(&path)?;
    if credentials.servers.remove(&resolved.server).is_some() {
        config::save_credentials(&path, &credentials)?;
    }
    eprintln!("Logged out of {}", resolved.server);
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
            parts.push(format!("{label}: {}", keys.join(", ")));
        }
    }
    if parts.is_empty() {
        "nothing to do".into()
    } else {
        parts.join("; ")
    }
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
                writeln!(out, "{folder}/")?;
            }
        }
        SecretsCommand::Get { key, json } => {
            let secret = api.get_secret(at, key.clone()).await?;
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&secret)?)?;
                return Ok(());
            }
            let Some(value) = secret.value else {
                bail!("you can see {key} but are not allowed to read its value");
            };
            writeln!(out, "{value}")?;
        }
        SecretsCommand::Set {
            pairs,
            from_dotenv,
            comment,
        } => {
            let dotenv = from_dotenv
                .map(std::fs::read_to_string)
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
                line_diff(&value_of(from)?, &value_of(to)?)
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

pub async fn export(api: &dyn SekretApi, at: Location, args: &ExportArgs, out: &mut dyn Write) -> anyhow::Result<()> {
    let raw = api.raw(at, args.recursive).await?;
    write!(out, "{}", render(&flatten(&raw.secrets)?, args.format)?)?;
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

/// Writes shell code that switches to `at`, and a summary for the person or agent on `notes`.
pub async fn env_use(
    api: &dyn SekretApi,
    at: Location,
    shell: shell::Shell,
    recursive: bool,
    previous: &[String],
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> anyhow::Result<()> {
    let raw = api.raw(at.clone(), recursive).await?;
    let origin = shell::Origin {
        project: at.project,
        environment: at.environment,
        path: at.path,
    };
    let switch = shell::switch_script(shell, previous, &flatten(&raw.secrets)?, &origin);
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
    if !switch.skipped.is_empty() {
        writeln!(
            notes,
            "sekret: skipped keys that are not valid variable names or start with SEKRET_: {}",
            switch.skipped.join(", ")
        )?;
    }
    Ok(())
}

/// Describes what this shell has loaded, without values.
pub fn env_status(project: Option<&str>, environment: Option<&str>, loaded: &[String]) -> String {
    let Some(environment) = environment.filter(|_| !loaded.is_empty()) else {
        return "nothing loaded; run `sekret-env <environment>` or `eval \"$(sekret env use <environment>)\"`\n".into();
    };
    format!("{}/{environment}: {}\n", project.unwrap_or("?"), loaded.join(" "))
}

/// Fetches secrets and runs the command with them in its environment, returning its exit code.
pub async fn run_command(api: &dyn SekretApi, at: Location, args: &RunArgs) -> anyhow::Result<i32> {
    let raw = api.raw(at, args.recursive).await?;
    let mut vars = flatten(&raw.secrets)?;
    let unsafe_names: Vec<String> = vars.keys().filter(|k| shell::is_unsafe_name(k)).cloned().collect();
    if !unsafe_names.is_empty() {
        eprintln!(
            "sekret: not passing {} because they change how programs are loaded or run",
            unsafe_names.join(", ")
        );
        vars.retain(|k, _| !shell::is_unsafe_name(k));
    }
    let Some((program, rest)) = args.command.split_first() else {
        bail!("no command given");
    };
    let status = tokio::process::Command::new(program)
        .args(rest)
        .envs(&vars)
        .status()
        .await
        .with_context(|| format!("running {program}"))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn upserts_from_pairs_stdin_and_dotenv() {
        let mut stdin = "from-stdin\n".as_bytes();
        let upserts = collect_upserts(
            &["A=1".into(), "B=-".into(), "C=x=y".into()],
            Some("D=4\n"),
            "c",
            &mut stdin,
        )
        .expect("collect");
        let pairs: Vec<(&str, &str)> = upserts.iter().map(|u| (u.key.as_str(), u.value.as_str())).collect();
        assert_eq!(pairs, [("D", "4"), ("A", "1"), ("B", "from-stdin"), ("C", "x=y")]);
        assert!(collect_upserts(&["A=-".into(), "B=-".into()], None, "", &mut "x".as_bytes()).is_err());
        assert!(collect_upserts(&["NOEQUALS".into()], None, "", &mut "".as_bytes()).is_err());
        assert!(collect_upserts(&[], None, "", &mut "".as_bytes()).is_err());
    }

    #[tokio::test]
    async fn get_prints_value_or_explains_hidden() {
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
            },
            &mut out,
            &mut "".as_bytes(),
        )
        .await
        .expect("get");
        assert_eq!(out, b"v\n");
        let hidden = secrets(
            &api,
            at(),
            SecretsCommand::Get {
                key: "A".into(),
                json: false,
            },
            &mut Vec::new(),
            &mut "".as_bytes(),
        )
        .await;
        assert!(hidden.unwrap_err().to_string().contains("not allowed"));
    }

    #[tokio::test]
    async fn set_and_delete_send_batches() {
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
            .expect("set");
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
        .expect("delete");
        assert!(
            String::from_utf8(out)
                .expect("utf8")
                .contains("created: A; unchanged: B")
        );
    }

    #[tokio::test]
    async fn list_shows_hidden_values_and_folders() {
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
        .expect("list");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("(hidden)") && text.contains("db/") && text.contains("user:sam"));
    }

    #[tokio::test]
    async fn export_and_run_use_raw_values() {
        let mut api = MockSekretApi::new();
        api.expect_raw().returning(|_, _| {
            Ok(RawSecrets {
                project: "app".into(),
                environment: "dev".into(),
                secrets: vec![RawSecret {
                    path: "/".into(),
                    key: "GREETING".into(),
                    value: "hello world".into(),
                }],
            })
        });
        let mut out = Vec::new();
        export(
            &api,
            at(),
            &ExportArgs {
                format: ExportFormat::Dotenv,
                recursive: false,
            },
            &mut out,
        )
        .await
        .expect("export");
        assert_eq!(out, b"GREETING=\"hello world\"\n");

        let args = RunArgs {
            recursive: false,
            command: vec![
                "sh".into(),
                "-c".into(),
                "test \"$GREETING\" = 'hello world' && exit 7".into(),
            ],
        };
        assert_eq!(run_command(&api, at(), &args).await.expect("run"), 7);
    }

    #[tokio::test]
    async fn machine_credentials_from_flags() {
        let dir = tempfile::tempdir().expect("dir");
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "jwt-from-file\n").expect("write");
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
        assert!(machine_credential(&base, &no_github).await.expect("none").is_none());

        let k8s = LoginArgs {
            kubernetes: true,
            ..base.clone()
        };
        assert!(
            matches!(machine_credential(&k8s, &no_github).await.expect("k8s"), Some(MachineCredential::Kubernetes { token, .. }) if token == "jwt-from-file")
        );

        let oidc = LoginArgs {
            oidc_token_file: Some(token_file.clone()),
            ..base.clone()
        };
        assert!(matches!(
            machine_credential(&oidc, &no_github).await.expect("oidc"),
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
            matches!(machine_credential(&github, &fake_github).await.expect("gh"), Some(MachineCredential::Oidc { token, .. }) if token == "gh-jwt")
        );
        assert!(machine_credential(&github, &no_github).await.is_err());
    }

    #[tokio::test]
    async fn env_use_writes_values_to_the_script_and_only_names_to_notes() {
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
        env_use(
            &api,
            prod,
            shell::Shell::Bash,
            false,
            &["OLD".into()],
            &mut out,
            &mut notes,
        )
        .await
        .expect("env use");
        let script = String::from_utf8(out).expect("utf8");
        let notes = String::from_utf8(notes).expect("utf8");
        assert!(script.starts_with("unset OLD\n"));
        assert!(script.contains("export DB_PASSWORD='hunter2'"));
        assert!(script.contains("export SEKRET_ENVIRONMENT='prod'"));
        assert!(notes.contains("loaded 1 secrets from app/prod"));
        assert!(notes.contains("bad.key"));
        assert!(!notes.contains("hunter2"), "values never reach the notes");
    }

    #[tokio::test]
    async fn env_use_reports_fetch_errors() {
        let mut api = MockSekretApi::new();
        api.expect_raw().returning(|_, _| {
            Err(sekret_client::ClientError::Api {
                status: 403,
                code: "forbidden".into(),
                message: "no".into(),
            })
        });
        let (mut out, mut notes) = (Vec::new(), Vec::new());
        let result = env_use(&api, at(), shell::Shell::Bash, false, &[], &mut out, &mut notes).await;
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
