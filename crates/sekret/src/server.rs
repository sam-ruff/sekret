use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use sekret_core::crypto::RootKey;
use sekret_server::clock::SystemClock;
use sekret_server::config::{HumanOidcConfig, ServerConfig, TlsSettings};
use sekret_server::net::{ReqwestOidcHttp, ReqwestTokenReviewer};
use sekret_server::state::{AppState, Dependencies, build_state};
use sekret_store::SqlStore;
use zeroize::Zeroizing;

#[derive(Debug, Args)]
pub struct StoreArgs {
    /// `sqlite://path?mode=rwc` or `postgres://user:pass@host/db`.
    #[arg(long, env = "SEKRET_DATABASE_URL", default_value = "sqlite://sekret.db?mode=rwc")]
    pub database_url: String,
    /// File holding the 32-byte root key (raw, base64 or hex).
    #[arg(long, env = "SEKRET_ROOT_KEY_FILE")]
    pub root_key_file: PathBuf,
}

#[derive(Debug, Args)]
pub struct ServerArgs {
    #[command(flatten)]
    pub store: StoreArgs,
    #[arg(long, env = "SEKRET_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,
    /// External URL people and machines use, e.g. https://sekret.example.com.
    #[arg(long, env = "SEKRET_PUBLIC_URL")]
    pub public_url: String,
    #[arg(long, env = "SEKRET_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,
    #[arg(long, env = "SEKRET_OIDC_CLIENT_ID", default_value = "sekret")]
    pub oidc_client_id: String,
    #[arg(long, env = "SEKRET_OIDC_CLIENT_SECRET_FILE")]
    pub oidc_client_secret_file: Option<PathBuf>,
    #[arg(
        long,
        env = "SEKRET_OIDC_SCOPES",
        default_value = "openid profile email",
        value_delimiter = ' '
    )]
    pub oidc_scopes: Vec<String>,
    /// Token claims whose values become the user's groups.
    #[arg(
        long,
        env = "SEKRET_OIDC_GROUP_CLAIMS",
        default_value = "roles,groups",
        value_delimiter = ','
    )]
    pub oidc_group_claims: Vec<String>,
    /// Groups that make someone an organisation admin.
    #[arg(
        long,
        env = "SEKRET_OIDC_ADMIN_GROUPS",
        default_value = "sekret-admin",
        value_delimiter = ','
    )]
    pub oidc_admin_groups: Vec<String>,
    /// When set, only users in one of these groups may sign in.
    #[arg(long, env = "SEKRET_OIDC_REQUIRED_GROUPS", value_delimiter = ',')]
    pub oidc_required_groups: Vec<String>,
    /// Organisation role every signed-in person receives; empty for none.
    #[arg(long, env = "SEKRET_DEFAULT_ORG_ROLE", default_value = "org-member")]
    pub default_org_role: String,
    #[arg(long, env = "SEKRET_SESSION_TTL", default_value_t = 12 * 3600)]
    pub session_ttl: i64,
    #[arg(long, env = "SEKRET_CLI_TOKEN_TTL", default_value_t = 24 * 3600)]
    pub cli_token_ttl: i64,
    /// Reverse proxies allowed to set X-Forwarded-For, as CIDRs.
    #[arg(long, env = "SEKRET_TRUSTED_PROXIES", value_delimiter = ',')]
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Allow http:// OIDC issuers and Kubernetes hosts. Development only.
    #[arg(long, env = "SEKRET_ALLOW_INSECURE_HTTP")]
    pub allow_insecure_http: bool,
    #[arg(long, env = "SEKRET_SNAPSHOTS_TO_KEEP", default_value_t = 200)]
    pub snapshots_to_keep: i64,
    #[arg(long, env = "SEKRET_LOGIN_RATE_PER_MINUTE", default_value_t = 30)]
    pub login_rate_per_minute: u32,
    /// PEM certificate chain to serve HTTPS directly instead of plain HTTP.
    #[arg(long, env = "SEKRET_TLS_CERT_FILE", requires = "tls_key_file")]
    pub tls_cert_file: Option<PathBuf>,
    /// PEM private key for --tls-cert-file.
    #[arg(long, env = "SEKRET_TLS_KEY_FILE", requires = "tls_cert_file")]
    pub tls_key_file: Option<PathBuf>,
    /// PEM CA certificates that client certificates must chain to; turns on mutual TLS.
    #[arg(long, env = "SEKRET_TLS_CLIENT_CA_FILE", requires = "tls_cert_file")]
    pub tls_client_ca_file: Option<PathBuf>,
    /// With a client CA: `required` refuses connections without a certificate, `optional`
    /// only checks certificates that are offered.
    #[arg(long, env = "SEKRET_TLS_CLIENT_AUTH", value_enum, default_value = "required")]
    pub tls_client_auth: ClientAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ClientAuth {
    Required,
    Optional,
}

fn tls_settings(args: &ServerArgs) -> anyhow::Result<Option<TlsSettings>> {
    let (Some(cert), Some(key)) = (&args.tls_cert_file, &args.tls_key_file) else {
        return Ok(None);
    };
    let read = |path: &PathBuf| std::fs::read(path).with_context(|| format!("reading {}", path.display()));
    Ok(Some(TlsSettings {
        cert_pem: read(cert)?,
        key_pem: Zeroizing::new(read(key)?),
        client_ca_pem: args.tls_client_ca_file.as_ref().map(read).transpose()?,
        client_auth_required: args.tls_client_auth == ClientAuth::Required,
    }))
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Print a short-lived organisation admin token for first-time setup or recovery.
    Bootstrap {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long, default_value_t = 3600)]
        ttl: i64,
    },
    /// Print a new random root key, base64 encoded.
    GenerateRootKey,
    /// Re-wrap every project key under a new root key. Stop the server first.
    RotateRootKey {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        new_root_key_file: PathBuf,
    },
    /// Exit non-zero unless this binary embeds the web interface.
    WebCheck,
}

pub fn read_root_key(path: &Path) -> anyhow::Result<RootKey> {
    let material = Zeroizing::new(std::fs::read(path).with_context(|| format!("reading root key {}", path.display()))?);
    RootKey::parse(&material).context("parsing root key")
}

fn read_secret_file(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text.trim().to_string())
}

pub fn server_config(args: &ServerArgs) -> anyhow::Result<ServerConfig> {
    let oidc = match &args.oidc_issuer {
        Some(issuer) => {
            let secret_file = args
                .oidc_client_secret_file
                .as_deref()
                .context("--oidc-client-secret-file is required with --oidc-issuer")?;
            Some(HumanOidcConfig {
                issuer: issuer.trim_end_matches('/').to_string(),
                client_id: args.oidc_client_id.clone(),
                client_secret: read_secret_file(secret_file)?,
                scopes: args.oidc_scopes.clone(),
                group_claims: args.oidc_group_claims.clone(),
                admin_groups: args.oidc_admin_groups.clone(),
                required_groups: args.oidc_required_groups.clone(),
            })
        }
        None => None,
    };
    if !args.public_url.starts_with("http://") && !args.public_url.starts_with("https://") {
        bail!("--public-url must start with http:// or https://");
    }
    Ok(ServerConfig {
        listen: args.listen,
        public_url: args.public_url.trim_end_matches('/').to_string(),
        database_url: args.store.database_url.clone(),
        oidc,
        default_org_role: args.default_org_role.clone(),
        session_ttl: args.session_ttl,
        cli_token_ttl: args.cli_token_ttl,
        trusted_proxies: args.trusted_proxies.clone(),
        allow_insecure_http: args.allow_insecure_http,
        snapshots_to_keep: args.snapshots_to_keep.max(1),
        login_rate_per_minute: args.login_rate_per_minute,
        tls: tls_settings(args)?,
    })
}

async fn state(config: ServerConfig, root_key: RootKey) -> anyhow::Result<AppState> {
    let store = SqlStore::connect(&config.database_url)
        .await
        .context("opening database")?;
    let allow_http = config.allow_insecure_http;
    Ok(build_state(Dependencies {
        store: Arc::new(store),
        root_key,
        config,
        clock: Arc::new(SystemClock),
        http: Arc::new(ReqwestOidcHttp::new(allow_http)?),
        token_reviewer: Arc::new(ReqwestTokenReviewer::new(allow_http)),
    }))
}

pub async fn run_server(args: ServerArgs) -> anyhow::Result<()> {
    let config = server_config(&args)?;
    let root_key = read_root_key(&args.store.root_key_file)?;
    sekret_server::serve(state(config, root_key).await?).await?;
    Ok(())
}

fn admin_config(store: &StoreArgs) -> ServerConfig {
    let mut config = ServerConfig::for_tests(&store.database_url);
    config.allow_insecure_http = false;
    config
}

pub async fn run_admin(command: AdminCommand) -> anyhow::Result<()> {
    match command {
        AdminCommand::GenerateRootKey => {
            println!("{}", RootKey::generate()?.to_base64().as_str());
        }
        AdminCommand::WebCheck => {
            if !sekret_server::web_embedded() {
                anyhow::bail!("no web interface embedded");
            }
            println!("web interface embedded");
        }
        AdminCommand::Bootstrap { store, ttl } => {
            let root_key = read_root_key(&store.root_key_file)?;
            let fingerprint = root_key.fingerprint();
            let state = state(admin_config(&store), root_key).await?;
            sekret_server::check_root_key(state.store.as_ref(), &fingerprint).await?;
            let token = sekret_server::admin::bootstrap_admin(&state, ttl)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            println!("{token}");
        }
        AdminCommand::RotateRootKey {
            store,
            new_root_key_file,
        } => {
            let old = read_root_key(&store.root_key_file)?;
            let new = read_root_key(&new_root_key_file)?;
            let sql = SqlStore::connect(&store.database_url).await?;
            sekret_server::check_root_key(&sql, &old.fingerprint()).await?;
            let count = sekret_server::admin::rotate_root_key(&sql, &old, &new)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            eprintln!("re-wrapped {count} project keys; start the server with the new root key");
        }
    }
    Ok(())
}
