//! Accepts connections with a cap on how many are open at once, and closes clients that are slow
//! to send their headers or sit idle, over plain HTTP and TLS alike.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long open connections get to finish once the server is stopping.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HTTP2_STREAMS: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// For a request's headers, and for the TLS handshake before them.
    pub header_read_timeout: Duration,
    /// With no request running and nothing sent either way for this long, the connection is closed.
    pub idle_timeout: Duration,
    /// Connections served at once; further ones wait in the listen backlog.
    pub max_connections: usize,
}

impl ConnectionLimits {
    pub fn new(max_connections: usize) -> Self {
        Self {
            header_read_timeout: HEADER_READ_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            max_connections: max_connections.max(1),
        }
    }
}

/// Serves `app` on `listener` until `shutdown` completes, then gives open connections a short
/// while to finish.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    limits: ConnectionLimits,
    shutdown: impl Future<Output = ()>,
) {
    let max = limits.max_connections.clamp(1, Semaphore::MAX_PERMITS);
    let permits = Arc::new(Semaphore::new(max));
    let (stop, stopping) = watch::channel(false);
    let acceptor = tls.map(TlsAcceptor::from);
    tokio::pin!(shutdown);
    loop {
        // Waiting for a free slot before accepting leaves extra clients in the kernel's backlog.
        let permit = tokio::select! {
            () = &mut shutdown => break,
            permit = permits.clone().acquire_owned() => permit,
        };
        let Ok(permit) = permit else {
            break;
        };
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    // Usually out of file descriptors; pausing lets some close.
                    tracing::warn!(%error, "accepting a connection failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let app = app.clone();
        let acceptor = acceptor.clone();
        let stopping = stopping.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_connection(stream, peer, app, acceptor, limits, stopping).await;
        });
    }
    let _ = stop.send(true);
    // Every open connection holds a permit until it ends.
    let all = u32::try_from(max).unwrap_or(u32::MAX);
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, permits.acquire_many(all)).await;
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    app: Router,
    acceptor: Option<TlsAcceptor>,
    limits: ConnectionLimits,
    stopping: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    let activity = Arc::new(Activity::new());
    let io = Tracked {
        inner: stream,
        activity: activity.clone(),
    };
    let Some(acceptor) = acceptor else {
        drive(io, peer, app, limits, activity, stopping).await;
        return;
    };
    match tokio::time::timeout(limits.header_read_timeout, acceptor.accept(io)).await {
        Ok(Ok(tls)) => drive(tls, peer, app, limits, activity, stopping).await,
        Ok(Err(error)) => tracing::debug!(%error, %peer, "TLS handshake failed"),
        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
    }
}

async fn drive<I>(
    io: I,
    peer: SocketAddr,
    app: Router,
    limits: ConnectionLimits,
    activity: Arc<Activity>,
    mut stopping: watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let requests = activity.clone();
    let service = hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
        request.extensions_mut().insert(ConnectInfo(peer));
        let running = InFlight::start(requests.clone());
        let response = app.clone().oneshot(request);
        async move {
            let response = response.await;
            drop(running);
            response
        }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(MAX_HTTP2_STREAMS);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(connection);
    let tick = (limits.idle_timeout / 4).clamp(Duration::from_millis(10), Duration::from_secs(1));
    let mut ticker = tokio::time::interval(tick);
    let mut closing = false;
    loop {
        tokio::select! {
            result = connection.as_mut() => {
                if let Err(error) = result {
                    tracing::debug!(%error, %peer, "connection ended with an error");
                }
                return;
            }
            _ = stopping.changed(), if !closing => {
                connection.as_mut().graceful_shutdown();
                closing = true;
            }
            _ = ticker.tick() => {
                if activity.idle_for() < limits.idle_timeout {
                    continue;
                }
                // A client that ignores the polite close is dropped after another idle spell.
                if closing {
                    return;
                }
                connection.as_mut().graceful_shutdown();
                closing = true;
                activity.touch();
            }
        }
    }
}

/// When a connection last moved bytes, and how many of its requests are running.
struct Activity {
    origin: Instant,
    last_millis: AtomicU64,
    in_flight: AtomicUsize,
}

impl Activity {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_millis: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
        }
    }

    fn touch(&self) {
        let millis = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis.store(millis, Ordering::Relaxed);
    }

    /// A running request never counts as idle, however long it takes.
    fn idle_for(&self) -> Duration {
        if self.in_flight.load(Ordering::Relaxed) > 0 {
            return Duration::ZERO;
        }
        let last = Duration::from_millis(self.last_millis.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(last)
    }
}

/// Counts a request as running until dropped.
struct InFlight(Arc<Activity>);

impl InFlight {
    fn start(activity: Arc<Activity>) -> Self {
        activity.in_flight.fetch_add(1, Ordering::Relaxed);
        Self(activity)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.0.touch();
    }
}

/// A stream that records when bytes last moved.
struct Tracked<T> {
    inner: T,
    activity: Arc<Activity>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Tracked<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.activity.touch();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Tracked<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        polled
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        polled
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
