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

use anyhow::Context as _;
use sekret_client::ClientOptions;

pub use controller::{Context, run_controller};
pub use crd::{AuthSpec, Condition, SekretSecret, SekretSecretSpec, SekretSecretStatus, TargetSpec, crd_yaml};
pub use interval::parse_interval;
pub use kube_api::{KubeApi, KubeClient, KubeError};
pub use reconcile::{MANAGED_BY_LABEL, MANAGED_BY_VALUE, SyncError, SyncOutcome, WriteKind, reconcile};
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
    /// Only watch this namespace; all namespaces when absent.
    #[arg(long, env = "SEKRET_OPERATOR_NAMESPACE")]
    pub namespace: Option<String>,
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

/// Runs the operator against the in-cluster or local kubeconfig until shutdown.
///
/// Expects a rustls crypto provider to be installed already.
pub async fn run(args: OperatorArgs) -> anyhow::Result<()> {
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
    run_controller(client, ctx, args.namespace.as_deref(), args.concurrency.max(1)).await
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

    #[test]
    fn args_parse_with_defaults() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["sekret", "--server-url", "https://sekret.example.com"])?;
        assert_eq!(cli.operator.server_url, "https://sekret.example.com");
        assert_eq!(cli.operator.namespace, None);
        assert_eq!(cli.operator.concurrency, 4);
        Ok(())
    }
}
