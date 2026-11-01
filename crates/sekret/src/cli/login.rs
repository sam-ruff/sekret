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
    server: &str,
    out: &mut dyn Write,
    open_browser: &dyn Fn(&str) -> bool,
    max_interval: Duration,
) -> anyhow::Result<TokenResponse> {
    let start = api.cli_start().await.context("starting login")?;
    let shown_url = super::format::one_line(&start.verification_url);
    // A link elsewhere would send the person to approve on a site the server does not control.
    if !super::config::same_origin(server, &start.verification_url) {
        bail!("the server sent an approval link for another site ({shown_url}); not opening it");
    }
    writeln!(
        out,
        "Confirm this code in your browser: {}",
        super::format::one_line(&start.user_code)
    )?;
    if !open_browser(&start.verification_url) {
        writeln!(out, "Open {shown_url} to continue.")?;
    }
    let mut interval = Duration::from_secs(start.interval.max(1) as u64).min(max_interval);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(start.expires_in.max(1) as u64);
    loop {
        let wait = match api.cli_poll(start.device_code.clone()).await {
            Ok(token) => return Ok(token),
            Err(error) if error.code() == Some("authorization_pending") => interval,
            // RFC 8628: slow down by five seconds for this and every later poll.
            Err(error) if error.code() == Some("slow_down") => {
                interval += SLOW_DOWN_STEP;
                error.retry_after().map_or(interval, |asked| asked.max(interval))
            }
            Err(error) if error.code() == Some("expired_token") => {
                bail!("the login code expired; run `sekret login` again")
            }
            Err(error) => return Err(error).context("waiting for approval"),
        };
        if tokio::time::Instant::now() + wait >= deadline {
            bail!("timed out waiting for approval")
        }
        tokio::time::sleep(wait).await;
    }
}

/// How much longer to wait between polls each time the server answers `slow_down`.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

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

    const SERVER: &str = "https://sekret.example.com";

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
            retry_after: None,
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
        let result = device_login(&api, SERVER, &mut out, &|_| false, Duration::ZERO)
            .await
            .context("login")?;
        assert_eq!(result.access_token, "skt_t");
        let printed = String::from_utf8(out).context("utf8")?;
        assert!(printed.contains("ABCD-EFGH") && printed.contains("Open https://sekret.example.com/cli-login"));
        Ok(())
    }

    fn slow_down(retry_after: Option<u64>) -> ClientError {
        ClientError::Api {
            status: 429,
            code: "slow_down".into(),
            message: "too many polls".into(),
            retry_after,
        }
    }

    /// Records how long after the start each poll arrived, in whole seconds of paused time.
    fn timed_polls(
        api: &mut MockSekretApi,
        answers: Vec<Result<TokenResponse, ClientError>>,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<u64>>> {
        let begun = tokio::time::Instant::now();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = seen.clone();
        let answers = std::sync::Mutex::new(answers.into_iter());
        api.expect_cli_poll().returning(move |_| {
            if let Ok(mut seen) = record.lock() {
                seen.push(begun.elapsed().as_secs());
            }
            answers
                .lock()
                .ok()
                .and_then(|mut answers| answers.next())
                .unwrap_or_else(|| Err(slow_down(None)))
        });
        seen
    }

    fn polled_at(seen: &std::sync::Arc<std::sync::Mutex<Vec<u64>>>) -> Vec<u64> {
        seen.lock().map(|seen| seen.clone()).unwrap_or_default()
    }

    #[tokio::test(start_paused = true)]
    async fn slow_down_adds_five_seconds_to_every_later_poll() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_cli_start().returning(|| Ok(start()));
        let seen = timed_polls(
            &mut api,
            vec![Err(pending()), Err(slow_down(None)), Err(pending()), Ok(token())],
        );
        let result = device_login(&api, SERVER, &mut Vec::new(), &|_| false, Duration::from_secs(10))
            .await
            .context("a slow_down is not fatal")?;
        assert_eq!(result.access_token, "skt_t");
        // Two seconds, then seven from the slow_down on.
        assert_eq!(polled_at(&seen), [0, 2, 9, 16]);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn retry_after_is_honoured_when_longer() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_cli_start().returning(|| Ok(start()));
        let seen = timed_polls(
            &mut api,
            vec![Err(slow_down(Some(30))), Err(slow_down(Some(1))), Ok(token())],
        );
        device_login(&api, SERVER, &mut Vec::new(), &|_| false, Duration::from_secs(10))
            .await
            .context("login")?;
        // Thirty seconds as asked, then the interval of 12 beats the shorter Retry-After.
        assert_eq!(polled_at(&seen), [0, 30, 42]);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn slowing_down_never_outlasts_the_login_code() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_cli_start().returning(|| {
            Ok(CliStartResponse {
                expires_in: 40,
                ..start()
            })
        });
        let seen = timed_polls(&mut api, Vec::new());
        let Err(error) = device_login(&api, SERVER, &mut Vec::new(), &|_| false, Duration::from_secs(10)).await else {
            anyhow::bail!("endless slow_down answers must end the login");
        };
        assert!(error.to_string().contains("timed out"), "{error}");
        // 0, then +7, +12, +17 would reach 36; the next wait of 22 would pass 40.
        assert_eq!(polled_at(&seen), [0, 7, 19, 36]);
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
                retry_after: None,
            })
        });
        let Err(err) = device_login(&api, SERVER, &mut Vec::new(), &|_| true, Duration::ZERO).await else {
            anyhow::bail!("expired device code should fail the login");
        };
        assert!(err.to_string().contains("expired"));

        let mut api = MockSekretApi::new();
        api.expect_cli_start()
            .returning(|| Err(ClientError::Network("down".into())));
        assert!(
            device_login(&api, SERVER, &mut Vec::new(), &|_| true, Duration::ZERO)
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_approval_link_on_another_site_is_refused() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_cli_start().returning(|| {
            Ok(CliStartResponse {
                verification_url: "https://evil.test/cli-login?code=ABCD-EFGH".into(),
                ..start()
            })
        });
        api.expect_cli_poll().times(0);
        let opened = std::cell::Cell::new(false);
        let opener = |_: &str| {
            opened.set(true);
            true
        };
        let mut out = Vec::new();
        let Err(error) = device_login(&api, SERVER, &mut out, &opener, Duration::ZERO).await else {
            anyhow::bail!("a foreign approval link must fail the login");
        };
        assert!(error.to_string().contains("another site"), "{error}");
        assert!(!opened.get(), "the browser is never opened on the foreign link");
        assert!(out.is_empty(), "no code is shown for a foreign link");
        Ok(())
    }

    #[tokio::test]
    async fn the_code_and_link_cannot_drive_the_terminal() -> anyhow::Result<()> {
        let mut api = MockSekretApi::new();
        api.expect_cli_start().returning(|| {
            Ok(CliStartResponse {
                user_code: "\u{1b}[2J\u{1b}]0;pwned\u{7}ABCD\r\n-EFGH".into(),
                verification_url: "https://sekret.example.com/cli-login?code=\u{1b}[8mHIDDEN\u{1b}[0m".into(),
                ..start()
            })
        });
        api.expect_cli_poll().returning(|_| Ok(token()));
        let mut out = Vec::new();
        device_login(&api, SERVER, &mut out, &|_| false, Duration::ZERO)
            .await
            .context("login")?;
        let printed = String::from_utf8(out).context("utf8")?;
        assert!(!printed.contains('\u{1b}') && !printed.contains('\r'), "{printed:?}");
        assert!(
            printed.contains("ABCD -EFGH") && printed.contains("code=HIDDEN"),
            "{printed:?}"
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
