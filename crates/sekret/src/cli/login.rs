use std::io::Write;
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use sekret_api::TokenResponse;
use sekret_client::SekretApi;

pub const DEFAULT_SA_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Fetches a workload identity token, e.g. from GitHub Actions.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait IdTokenSource: Send + Sync {
    async fn fetch(&self, audience: &str) -> anyhow::Result<String>;
}

/// GitHub Actions OIDC, available when a job has `permissions: id-token: write`.
pub struct GithubActionsTokenSource {
    client: reqwest::Client,
    request_url: String,
    request_token: String,
}

impl GithubActionsTokenSource {
    pub fn from_env() -> anyhow::Result<Self> {
        let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
            .context("ACTIONS_ID_TOKEN_REQUEST_URL is not set; does the job have `permissions: id-token: write`?")?;
        let request_token =
            std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").context("ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set")?;
        let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build()?;
        Ok(Self {
            client,
            request_url,
            request_token,
        })
    }
}

#[async_trait]
impl IdTokenSource for GithubActionsTokenSource {
    async fn fetch(&self, audience: &str) -> anyhow::Result<String> {
        let response = self
            .client
            .get(&self.request_url)
            .query(&[("audience", audience)])
            .bearer_auth(&self.request_token)
            .send()
            .await?
            .error_for_status()?;
        let body: serde_json::Value = response.json().await?;
        body["value"]
            .as_str()
            .map(String::from)
            .context("GitHub did not return a token")
    }
}

pub enum MachineCredential {
    Oidc { identity_id: String, token: String },
    Kubernetes { identity_id: String, token: String },
    Universal { client_id: String, client_secret: String },
}

pub async fn machine_login(api: &dyn SekretApi, credential: MachineCredential) -> anyhow::Result<TokenResponse> {
    let response = match credential {
        MachineCredential::Oidc { identity_id, token } => api.oidc_login(identity_id, token).await,
        MachineCredential::Kubernetes { identity_id, token } => api.kubernetes_login(identity_id, token).await,
        MachineCredential::Universal {
            client_id,
            client_secret,
        } => api.universal_login(client_id, client_secret).await,
    };
    response.context("login failed")
}

/// Browser-approved login: show a code, wait for approval in the web interface.
pub async fn device_login(
    api: &dyn SekretApi,
    out: &mut dyn Write,
    open_browser: &dyn Fn(&str) -> bool,
    max_interval: Duration,
) -> anyhow::Result<TokenResponse> {
    let start = api.cli_start().await.context("starting login")?;
    writeln!(out, "Confirm this code in your browser: {}", start.user_code)?;
    if !open_browser(&start.verification_url) {
        writeln!(out, "Open {} to continue.", start.verification_url)?;
    }
    let interval = Duration::from_secs(start.interval.max(1) as u64).min(max_interval);
    let attempts = (start.expires_in / start.interval.max(1)).max(1);
    for _ in 0..attempts {
        match api.cli_poll(start.device_code.clone()).await {
            Ok(token) => return Ok(token),
            Err(error) if error.code() == Some("authorization_pending") => tokio::time::sleep(interval).await,
            Err(error) if error.code() == Some("expired_token") => {
                bail!("the login code expired; run `sekret login` again")
            }
            Err(error) => return Err(error).context("waiting for approval"),
        }
    }
    bail!("timed out waiting for approval")
}

pub fn open_in_browser(url: &str) -> bool {
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use sekret_api::CliStartResponse;
    use sekret_client::{ClientError, MockSekretApi};

    fn start() -> CliStartResponse {
        CliStartResponse {
            device_code: "skd_x".into(),
            user_code: "ABCD-EFGH".into(),
            verification_url: "https://sekret.example.com/cli-login?code=ABCD-EFGH".into(),
            expires_in: 600,
            interval: 2,
        }
    }

    fn pending() -> ClientError {
        ClientError::Api {
            status: 400,
            code: "authorization_pending".into(),
            message: "waiting".into(),
        }
    }

    fn token() -> TokenResponse {
        TokenResponse {
            access_token: "skt_t".into(),
            token_type: "Bearer".into(),
            expires_in: 60,
        }
    }

    #[tokio::test]
    async fn device_login_polls_until_approved() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_cli_start().returning(|| Ok(start()));
        let mut seq = mockall::Sequence::new();
        api.expect_cli_poll()
            .times(2)
            .in_sequence(&mut seq)
            .returning(|_| Err(pending()));
        api.expect_cli_poll()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(token()));
        let mut out = Vec::new();
        let result = device_login(&api, &mut out, &|_| false, Duration::ZERO)
            .await
            .context("login")?;
        assert_eq!(result.access_token, "skt_t");
        let printed = String::from_utf8(out).context("utf8")?;
        assert!(printed.contains("ABCD-EFGH") && printed.contains("Open https://sekret.example.com/cli-login"));
        Ok(())
    }

    #[tokio::test]
    async fn device_login_stops_on_expiry_and_errors() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_cli_start().returning(|| Ok(start()));
        api.expect_cli_poll().returning(|_| {
            Err(ClientError::Api {
                status: 400,
                code: "expired_token".into(),
                message: String::new(),
            })
        });
        let Err(err) = device_login(&api, &mut Vec::new(), &|_| true, Duration::ZERO).await else {
            anyhow::bail!("expired device code should fail the login");
        };
        assert!(err.to_string().contains("expired"));

        let mut api = MockSekretApi::new();
        api.expect_cli_start()
            .returning(|| Err(ClientError::Network("down".into())));
        assert!(
            device_login(&api, &mut Vec::new(), &|_| true, Duration::ZERO)
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn machine_logins_route_to_the_right_endpoint() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_oidc_login()
            .withf(|id, t| id == "i" && t == "jwt")
            .times(1)
            .returning(|_, _| Ok(token()));
        api.expect_kubernetes_login().times(1).returning(|_, _| Ok(token()));
        api.expect_universal_login()
            .withf(|c, s| c == "c" && s == "s")
            .times(1)
            .returning(|_, _| Ok(token()));
        machine_login(
            &api,
            MachineCredential::Oidc {
                identity_id: "i".into(),
                token: "jwt".into(),
            },
        )
        .await
        .context("oidc")?;
        machine_login(
            &api,
            MachineCredential::Kubernetes {
                identity_id: "i".into(),
                token: "sa".into(),
            },
        )
        .await
        .context("k8s")?;
        machine_login(
            &api,
            MachineCredential::Universal {
                client_id: "c".into(),
                client_secret: "s".into(),
            },
        )
        .await
        .context("universal")?;
        Ok(())
    }

    #[tokio::test]
    async fn id_token_source_is_injectable() -> anyhow::Result<()> {
        let mut source = MockIdTokenSource::new();
        source
            .expect_fetch()
            .withf(|aud| aud == "sekret")
            .returning(|_| Ok("jwt".into()));
        assert_eq!(source.fetch("sekret").await.context("fetch")?, "jwt");
        Ok(())
    }
}
