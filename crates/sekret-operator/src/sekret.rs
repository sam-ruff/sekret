use sekret_client::{ClientError, ClientOptions, HttpClient, SekretApi};

/// Builds sekret API clients, unauthenticated for login and token-scoped afterwards.
#[cfg_attr(test, mockall::automock)]
pub trait SekretApiFactory: Send + Sync {
    fn client(&self, token: Option<String>) -> Result<Box<dyn SekretApi>, ClientError>;
}

pub struct HttpSekretFactory {
    base_url: String,
    options: ClientOptions,
}

impl HttpSekretFactory {
    /// Validates the URL and CA bundle up front so misconfiguration fails at startup.
    pub fn new(base_url: String, options: ClientOptions) -> Result<Self, ClientError> {
        HttpClient::new(&base_url, None, options.clone())?;
        Ok(Self { base_url, options })
    }
}

impl SekretApiFactory for HttpSekretFactory {
    fn client(&self, token: Option<String>) -> Result<Box<dyn SekretApi>, ClientError> {
        Ok(Box::new(HttpClient::new(&self.base_url, token, self.options.clone())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CHILD: &str = "SEKRET_OPERATOR_PROXY_TEST_CHILD";
    const TEST: &str = "sekret::tests::plain_http_and_loopback_skip_the_proxy";

    /// Accepts connections and reports how many arrived, answering each with a 401.
    async fn listener() -> anyhow::Result<(String, tokio::sync::mpsc::UnboundedReceiver<String>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.context("bind")?;
        let addr = listener.local_addr().context("addr")?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if tx.send(String::from_utf8_lossy(&buf[..n]).into_owned()).is_err() {
                    return;
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
            }
        });
        Ok((format!("http://{addr}"), rx))
    }

    /// Proxy variables are read from the process environment, so the check runs in a child
    /// process that has them set rather than changing this one's environment.
    #[tokio::test(flavor = "multi_thread")]
    async fn plain_http_and_loopback_skip_the_proxy() -> anyhow::Result<()> {
        if let Ok(proxy) = std::env::var(CHILD) {
            return child(&proxy).await;
        }
        let (proxy, mut proxied) = listener().await?;
        let exe = std::env::current_exe().context("test binary")?;
        let mut command = std::process::Command::new(exe);
        command.args(["--exact", TEST, "--nocapture"]).env(CHILD, &proxy);
        for name in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ALL_PROXY"] {
            command.env(name, &proxy);
        }
        command.env_remove("NO_PROXY").env_remove("no_proxy");
        let status = tokio::task::spawn_blocking(move || command.status())
            .await
            .context("join")?
            .context("child")?;
        assert!(status.success(), "the child check failed");
        assert!(proxied.try_recv().is_err(), "the proxy received a request");
        Ok(())
    }

    async fn child(proxy: &str) -> anyhow::Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server, mut direct) = listener().await?;
        let port = server.rsplit(':').next().context("port")?;
        for base in [server.clone(), format!("http://localhost:{port}")] {
            let factory = HttpSekretFactory::new(base.clone(), ClientOptions::default()).context("factory")?;
            let api = factory.client(Some("skt_operator_canary".into())).context("client")?;
            assert!(api.me().await.is_err(), "the stand-in answers 401");
            let request = direct.try_recv().context("the server was reached directly")?;
            assert!(request.contains("skt_operator_canary"), "{base}: {request}");
        }
        assert!(!proxy.is_empty());
        Ok(())
    }
}
