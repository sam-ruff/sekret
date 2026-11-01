//! Slow, idle and too many clients are cut off by the accept loop, over plain HTTP and TLS.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::routing::get;
use sekret_server::config::TlsSettings;
use sekret_server::serve::{ConnectionLimits, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

fn app() -> Router {
    Router::new().route("/fast", get(|| async { "ok" })).route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(900)).await;
            "done"
        }),
    )
}

struct Running {
    addr: SocketAddr,
    _stop: oneshot::Sender<()>,
}

async fn run(limits: ConnectionLimits, tls: Option<Arc<rustls::ServerConfig>>) -> anyhow::Result<Running> {
    let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
    let addr = listener.local_addr().context("addr")?;
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(serve(listener, app(), tls, limits, async move {
        let _ = stopped.await;
    }));
    Ok(Running { addr, _stop: stop })
}

fn limits(header: u64, idle: u64, max: usize) -> ConnectionLimits {
    ConnectionLimits {
        header_read_timeout: Duration::from_millis(header),
        idle_timeout: Duration::from_millis(idle),
        max_connections: max,
        ..ConnectionLimits::new(max)
    }
}

/// Reads until the server closes the connection, or `within` passes.
async fn closed_within(stream: &mut (impl AsyncReadExt + Unpin), within: Duration) -> bool {
    let mut buf = [0u8; 1024];
    let read_all = async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(within, read_all).await.is_ok()
}

async fn request(stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin), path: &str) -> anyhow::Result<String> {
    let head = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    stream.write_all(head.as_bytes()).await.context("write")?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .context("response timed out")?
        .context("read")?;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[tokio::test]
async fn headers_that_trickle_in_are_cut_off() -> anyhow::Result<()> {
    let server = run(limits(300, 5_000, 16), None).await?;
    let mut stream = TcpStream::connect(server.addr).await.context("connect")?;
    stream.write_all(b"GET /fast HTTP/1.1\r\n").await.context("write")?;
    // One header byte at a time keeps the connection busy, but never finishes the headers.
    let trickle = async {
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if stream.write_all(b"X").await.is_err() {
                return true;
            }
        }
        false
    };
    let cut = trickle.await || closed_within(&mut stream, Duration::from_millis(500)).await;
    assert!(cut, "a slow header must not hold the connection for three seconds");
    Ok(())
}

#[tokio::test]
async fn idle_connections_are_closed_but_long_requests_are_not() -> anyhow::Result<()> {
    let server = run(limits(5_000, 300, 16), None).await?;
    let mut silent = TcpStream::connect(server.addr).await.context("connect")?;
    assert!(
        closed_within(&mut silent, Duration::from_secs(3)).await,
        "a connection that never sends anything is closed"
    );

    let mut kept_alive = TcpStream::connect(server.addr).await.context("connect")?;
    let response = request(&mut kept_alive, "/fast").await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        closed_within(&mut kept_alive, Duration::from_secs(3)).await,
        "an idle keep-alive connection is closed"
    );

    let mut slow = TcpStream::connect(server.addr).await.context("connect")?;
    let response = request(&mut slow, "/slow").await?;
    assert!(
        response.starts_with("HTTP/1.1 200") && response.ends_with("done"),
        "a request running longer than the idle timeout still finishes: {response}"
    );
    Ok(())
}

#[tokio::test]
async fn connections_beyond_the_cap_wait_for_a_free_slot() -> anyhow::Result<()> {
    let server = run(limits(5_000, 5_000, 2), None).await?;
    let first = TcpStream::connect(server.addr).await.context("connect")?;
    let _second = TcpStream::connect(server.addr).await.context("connect")?;
    let mut third = TcpStream::connect(server.addr).await.context("connect")?;
    third
        .write_all(b"GET /fast HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .context("write")?;
    let mut buf = [0u8; 256];
    let waited = tokio::time::timeout(Duration::from_millis(500), third.read(&mut buf)).await;
    assert!(waited.is_err(), "the third connection is not served while two are open");
    drop(first);
    let n = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf))
        .await
        .context("served once a slot frees")?
        .context("read")?;
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    Ok(())
}

#[tokio::test]
async fn one_client_cannot_hold_every_connection() -> anyhow::Result<()> {
    let capped = ConnectionLimits {
        max_per_client: 2,
        exempt: Arc::from([]),
        ..limits(5_000, 5_000, 16)
    };
    let server = run(capped, None).await?;
    let first = TcpStream::connect(server.addr).await.context("connect")?;
    let _second = TcpStream::connect(server.addr).await.context("connect")?;
    let mut third = TcpStream::connect(server.addr).await.context("connect")?;
    assert!(
        closed_within(&mut third, Duration::from_secs(2)).await,
        "a third connection from the same client is closed"
    );
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut fourth = TcpStream::connect(server.addr).await.context("connect")?;
    assert!(request(&mut fourth, "/fast").await?.starts_with("HTTP/1.1 200"));

    let exempt = ConnectionLimits {
        max_per_client: 1,
        ..limits(5_000, 5_000, 16)
    };
    let server = run(exempt, None).await?;
    let _held = TcpStream::connect(server.addr).await.context("connect")?;
    let mut other = TcpStream::connect(server.addr).await.context("connect")?;
    assert!(
        request(&mut other, "/fast").await?.starts_with("HTTP/1.1 200"),
        "loopback, where a local proxy runs, is exempt by default"
    );
    Ok(())
}

#[test]
fn trusted_proxies_are_exempt_from_the_per_client_cap() -> anyhow::Result<()> {
    let proxy: ipnet::IpNet = "10.0.0.0/24".parse().context("net")?;
    let limits = ConnectionLimits::new(512).exempting(&[proxy]);
    assert_eq!(limits.max_per_client, sekret_server::serve::MAX_PER_CLIENT);
    assert!(limits.exempt.contains(&proxy));
    let local: std::net::IpAddr = "127.0.0.1".parse().context("ip")?;
    assert!(limits.exempt.iter().any(|n| n.contains(&local)));
    Ok(())
}

/// The host's unlock socket gets the same header timeout and a connection cap of its own.
#[cfg(unix)]
#[tokio::test]
async fn the_local_socket_has_header_and_connection_limits() -> anyhow::Result<()> {
    use tokio::net::UnixStream;
    let dir = tempfile::tempdir().context("dir")?;
    let socket = |name: &str, limits: ConnectionLimits| -> anyhow::Result<std::path::PathBuf> {
        let path = dir.path().join(name);
        let listener = tokio::net::UnixListener::bind(&path).context("bind")?;
        tokio::spawn(sekret_server::serve::serve_local(listener, app(), limits));
        Ok(path)
    };

    let path = socket("strict.sock", limits(300, 5_000, 16))?;
    let mut slow = UnixStream::connect(&path).await.context("connect")?;
    slow.write_all(b"GET /fast HTTP/1.1\r\n").await.context("write")?;
    assert!(
        closed_within(&mut slow, Duration::from_secs(3)).await,
        "headers that never finish are cut off"
    );

    let path = socket("capped.sock", limits(5_000, 5_000, 2))?;
    let first = UnixStream::connect(&path).await.context("connect")?;
    let mut second = UnixStream::connect(&path).await.context("connect")?;
    assert!(request(&mut second, "/fast").await?.starts_with("HTTP/1.1 200"));
    let mut third = UnixStream::connect(&path).await.context("connect")?;
    third
        .write_all(b"GET /fast HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .context("write")?;
    let mut buf = [0u8; 256];
    let waited = tokio::time::timeout(Duration::from_millis(500), third.read(&mut buf)).await;
    assert!(waited.is_err(), "a third connection waits while two are open");
    drop(first);
    let n = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf))
        .await
        .context("served once a slot frees")?
        .context("read")?;
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    Ok(())
}

fn tls_config() -> anyhow::Result<(Arc<rustls::ServerConfig>, Vec<u8>)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate().context("key")?;
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .context("params")?
        .self_signed(&key)
        .context("cert")?;
    let settings = TlsSettings {
        cert_pem: cert.pem().into_bytes(),
        key_pem: zeroize::Zeroizing::new(key.serialize_pem().into_bytes()),
        client_ca_pem: None,
        client_auth_required: false,
    };
    let config = sekret_server::tls::server_config(&settings).context("tls config")?;
    Ok((Arc::new(config), settings.cert_pem))
}

#[tokio::test]
async fn the_same_limits_apply_over_tls() -> anyhow::Result<()> {
    let (config, cert_pem) = tls_config()?;
    let server = run(limits(300, 5_000, 16), Some(config)).await?;
    let mut stalled = TcpStream::connect(server.addr).await.context("connect")?;
    assert!(
        closed_within(&mut stalled, Duration::from_secs(3)).await,
        "a client that never finishes the handshake is closed"
    );

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&cert_pem).context("ca")?)
        .build()
        .context("client")?;
    let response = client
        .get(format!("https://localhost:{}/fast", server.addr.port()))
        .send()
        .await
        .context("request")?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.context("body")?, "ok");
    Ok(())
}
