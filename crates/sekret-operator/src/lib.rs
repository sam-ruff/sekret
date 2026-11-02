//! Kubernetes operator that syncs sekret secrets into native Secrets.

mod content;
mod controller;
mod crd;
mod interval;
mod kube_api;
mod reconcile;
mod sekret;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use sekret_client::ClientOptions;

pub use controller::{Context, WatchScope, run_controller, run_controllers};
pub use crd::{AuthSpec, Condition, SekretSecret, SekretSecretSpec, SekretSecretStatus, TargetSpec, crd_yaml};
pub use interval::parse_interval;
pub use kube_api::{KubeApi, KubeClient, KubeError};
pub use reconcile::{
    ALLOW_ANNOTATION, MANAGED_BY_LABEL, MANAGED_BY_VALUE, SyncError, SyncOutcome, WriteKind, reconcile,
};
pub use sekret::{HttpSekretFactory, SekretApiFactory};

/// Settings for `sekret operator`.
#[derive(Debug, Clone, clap::Args)]
pub struct OperatorArgs {
    /// Base URL of the sekret server.
    #[arg(long = "server-url", env = "SEKRET_URL")]
    pub server_url: String,
    /// PEM CA bundle to trust when talking to the sekret server.
    #[arg(long = "ca-file", env = "SEKRET_CA_FILE")]
    pub ca_file: Option<PathBuf>,
    /// PEM client certificate, for a sekret server that requires mutual TLS.
    #[arg(long = "client-cert", env = "SEKRET_CLIENT_CERT", requires = "client_key")]
    pub client_cert: Option<PathBuf>,
    /// PEM private key for --client-cert.
    #[arg(long = "client-key", env = "SEKRET_CLIENT_KEY", requires = "client_cert")]
    pub client_key: Option<PathBuf>,
    /// Namespaces to watch, comma separated. Either this or --all-namespaces is required.
    #[arg(long = "namespace", env = "SEKRET_OPERATOR_NAMESPACE", value_delimiter = ',')]
    pub namespaces: Vec<String>,
    /// Watch every namespace. The operator then needs cluster-wide rights to Secrets and tokens.
    #[arg(long, env = "SEKRET_OPERATOR_ALL_NAMESPACES", num_args = 0..=1,
        default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    pub all_namespaces: Option<bool>,
    /// Allow a plain http:// sekret server that is not on loopback. Tokens and secrets then
    /// travel unencrypted.
    #[arg(long, env = "SEKRET_OPERATOR_ALLOW_INSECURE_HTTP", num_args = 0..=1,
        default_missing_value = "true", value_parser = clap::builder::BoolishValueParser::new())]
    pub allow_insecure_http: Option<bool>,
    /// How many resources to reconcile at once.
    #[arg(long, env = "SEKRET_OPERATOR_CONCURRENCY", default_value_t = 4)]
    pub concurrency: u16,
    /// Timeout in seconds for each request to the sekret server.
    #[arg(
        long = "request-timeout",
        env = "SEKRET_OPERATOR_REQUEST_TIMEOUT",
        default_value_t = 30
    )]
    pub request_timeout: u64,
}

impl OperatorArgs {
    /// Cluster-wide watching has to be asked for, never implied by a missing namespace.
    pub fn scope(&self) -> anyhow::Result<WatchScope> {
        let namespaces: Vec<String> = self
            .namespaces
            .iter()
            .map(|ns| ns.trim().to_string())
            .filter(|ns| !ns.is_empty())
            .collect();
        let all = self.all_namespaces.unwrap_or(false);
        match (all, namespaces.is_empty()) {
            (true, true) => Ok(WatchScope::AllNamespaces),
            (true, false) => bail!("--namespace and --all-namespaces cannot be used together"),
            (false, false) => Ok(WatchScope::Namespaces(namespaces)),
            (false, true) => bail!(
                "no namespace to watch; pass --namespace (or SEKRET_OPERATOR_NAMESPACE) with a comma-separated \
                 list, or --all-namespaces to watch the whole cluster"
            ),
        }
    }
}

/// What to do about the server URL's transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Secure,
    /// Plain http to another host, allowed explicitly; worth a warning.
    InsecureAllowed,
}

/// Plain `http://` is refused unless it stays on loopback or is explicitly allowed, because
/// service account tokens and secret values would cross the network unencrypted.
pub fn check_transport(server: &str, allow_insecure_http: bool) -> anyhow::Result<Transport> {
    let url = url::Url::parse(server).with_context(|| format!("the server URL {server} is not valid"))?;
    if url.scheme() != "http" || sekret_client::is_loopback(&url) {
        return Ok(Transport::Secure);
    }
    if allow_insecure_http {
        return Ok(Transport::InsecureAllowed);
    }
    bail!(
        "{server} is plain http; use https, or pass --allow-insecure-http (SEKRET_OPERATOR_ALLOW_INSECURE_HTTP) if \
         you accept sending tokens and secrets unencrypted"
    )
}

/// Runs the operator against the in-cluster or local kubeconfig until shutdown.
///
/// Expects a rustls crypto provider to be installed already.
pub async fn run(args: OperatorArgs) -> anyhow::Result<()> {
    let scope = args.scope()?;
    if check_transport(&args.server_url, args.allow_insecure_http.unwrap_or(false))? == Transport::InsecureAllowed {
        tracing::warn!(
            server = %args.server_url,
            "talking to sekret over plain http; tokens and secret values are not encrypted in transit"
        );
    }
    let ca_pem = match &args.ca_file {
        Some(path) => Some(
            tokio::fs::read(path)
                .await
                .with_context(|| format!("reading CA bundle {}", path.display()))?,
        ),
        None => None,
    };
    let identity_pem = sekret_client::identity_from_files(args.client_cert.as_deref(), args.client_key.as_deref())
        .context("reading the client certificate")?;
    let options = ClientOptions {
        ca_pem,
        identity_pem,
        timeout: Some(Duration::from_secs(args.request_timeout)),
    };
    let sekret = HttpSekretFactory::new(args.server_url.clone(), options).context("configuring the sekret client")?;
    let client = kube::Client::try_default().await.context("connecting to Kubernetes")?;
    let ctx = Arc::new(Context::new(
        Arc::new(KubeClient::new(client.clone())),
        Arc::new(sekret),
    ));
    run_controllers(client, ctx, &scope, args.concurrency.max(1)).await
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        operator: OperatorArgs,
    }

    const SERVER: &str = "https://sekret.example.com";

    fn parse(args: &[&str]) -> Result<OperatorArgs, clap::Error> {
        let mut argv = vec!["sekret", "--server-url", SERVER];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).map(|cli| cli.operator)
    }

    /// Clap reads the process environment, so tests that set variables take this lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<T>(vars: &[(&str, &str)], body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (name, value) in vars {
            // SAFETY: every test that touches the environment holds ENV_LOCK.
            unsafe { std::env::set_var(name, value) };
        }
        let result = body();
        for (name, _) in vars {
            // SAFETY: as above.
            unsafe { std::env::remove_var(name) };
        }
        result
    }

    #[test]
    fn args_parse_with_defaults() -> anyhow::Result<()> {
        let args = with_env(&[], || parse(&["--namespace", "web"]))?;
        assert_eq!(args.server_url, SERVER);
        assert_eq!(args.concurrency, 4);
        assert_eq!(args.allow_insecure_http, None);
        Ok(())
    }

    #[test]
    fn a_namespace_or_all_namespaces_is_required() -> anyhow::Result<()> {
        let args = with_env(&[], || parse(&[]))?;
        let error = args.scope().err().context("expected no scope")?;
        assert!(error.to_string().contains("--all-namespaces"), "{error}");
        let blank = with_env(&[], || parse(&["--namespace", " , "]))?;
        assert!(blank.scope().is_err(), "blank names are not namespaces");
        let off = with_env(&[], || parse(&["--all-namespaces=false"]))?;
        assert!(off.scope().is_err(), "an explicit false is not cluster-wide");
        Ok(())
    }

    #[test]
    fn namespaces_come_from_a_flag_or_the_environment_as_a_list() -> anyhow::Result<()> {
        let flag = with_env(&[], || parse(&["--namespace", "web,api", "--namespace", "jobs"]))?;
        assert_eq!(
            flag.scope()?,
            WatchScope::Namespaces(vec!["web".into(), "api".into(), "jobs".into()])
        );
        let env = with_env(&[("SEKRET_OPERATOR_NAMESPACE", "web, api")], || parse(&[]))?;
        assert_eq!(env.scope()?, WatchScope::Namespaces(vec!["web".into(), "api".into()]));
        let both = with_env(&[("SEKRET_OPERATOR_NAMESPACE", "from-env")], || {
            parse(&["--namespace", "from-flag"])
        })?;
        assert_eq!(
            both.scope()?,
            WatchScope::Namespaces(vec!["from-flag".into()]),
            "the flag wins over the environment"
        );
        Ok(())
    }

    #[test]
    fn all_namespaces_comes_from_a_flag_or_the_environment() -> anyhow::Result<()> {
        let flag = with_env(&[], || parse(&["--all-namespaces"]))?;
        assert_eq!(flag.scope()?, WatchScope::AllNamespaces);
        for value in ["true", "1", "yes"] {
            let env = with_env(&[("SEKRET_OPERATOR_ALL_NAMESPACES", value)], || parse(&[]))?;
            assert_eq!(env.scope()?, WatchScope::AllNamespaces, "{value}");
        }
        let env_off = with_env(&[("SEKRET_OPERATOR_ALL_NAMESPACES", "false")], || {
            parse(&["--namespace", "web"])
        })?;
        assert_eq!(env_off.scope()?, WatchScope::Namespaces(vec!["web".into()]));
        let flag_beats_env = with_env(&[("SEKRET_OPERATOR_ALL_NAMESPACES", "true")], || {
            parse(&["--all-namespaces=false", "--namespace", "web"])
        })?;
        assert_eq!(flag_beats_env.scope()?, WatchScope::Namespaces(vec!["web".into()]));
        Ok(())
    }

    #[test]
    fn namespaces_and_all_namespaces_conflict() -> anyhow::Result<()> {
        let flags = with_env(&[], || parse(&["--namespace", "web", "--all-namespaces"]))?;
        let error = flags.scope().err().context("expected both flags to be refused")?;
        assert!(error.to_string().contains("cannot be used together"), "{error}");
        let mixed = with_env(&[("SEKRET_OPERATOR_ALL_NAMESPACES", "true")], || {
            parse(&["--namespace", "web"])
        })?;
        assert!(
            mixed.scope().is_err(),
            "a namespace with cluster-wide from the environment"
        );
        let env_both = with_env(
            &[
                ("SEKRET_OPERATOR_ALL_NAMESPACES", "true"),
                ("SEKRET_OPERATOR_NAMESPACE", "web"),
            ],
            || parse(&[]),
        )?;
        assert!(env_both.scope().is_err(), "both from the environment");
        Ok(())
    }

    #[test]
    fn plain_http_needs_loopback_or_an_explicit_allow() -> anyhow::Result<()> {
        for secure in [
            "https://sekret.example.com",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert_eq!(check_transport(secure, false)?, Transport::Secure, "{secure}");
        }
        for insecure in [
            "http://sekret.example.com",
            "http://sekret.sekret.svc:8080",
            "http://10.0.0.5",
        ] {
            let error = check_transport(insecure, false)
                .err()
                .with_context(|| format!("expected {insecure} to be refused"))?;
            assert!(error.to_string().contains("--allow-insecure-http"), "{error}");
            assert_eq!(
                check_transport(insecure, true)?,
                Transport::InsecureAllowed,
                "{insecure}"
            );
        }
        assert!(check_transport("not a url", true).is_err());
        Ok(())
    }

    #[test]
    fn allow_insecure_http_comes_from_a_flag_or_the_environment() -> anyhow::Result<()> {
        let insecure =
            |args: &OperatorArgs| check_transport("http://sekret.lan", args.allow_insecure_http.unwrap_or(false));
        let default = with_env(&[], || parse(&["--namespace", "web"]))?;
        assert!(insecure(&default).is_err());
        let flag = with_env(&[], || parse(&["--namespace", "web", "--allow-insecure-http"]))?;
        assert_eq!(insecure(&flag)?, Transport::InsecureAllowed);
        let env = with_env(&[("SEKRET_OPERATOR_ALLOW_INSECURE_HTTP", "true")], || {
            parse(&["--namespace", "web"])
        })?;
        assert_eq!(insecure(&env)?, Transport::InsecureAllowed);
        let flag_beats_env = with_env(&[("SEKRET_OPERATOR_ALLOW_INSECURE_HTTP", "true")], || {
            parse(&["--namespace", "web", "--allow-insecure-http=false"])
        })?;
        assert!(insecure(&flag_beats_env).is_err());
        Ok(())
    }
}
