//! The TCP peer of the request being handled, so audit entries can record it beside the client
//! address taken from `X-Forwarded-For`.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::Value;

tokio::task_local! {
    static PEER: Option<IpAddr>;
}

/// Runs `work` with `peer` as the current request's peer.
pub async fn scoped<F: Future>(peer: Option<IpAddr>, work: F) -> F::Output {
    PEER.scope(peer, work).await
}

/// The current request's TCP peer, if this runs inside one.
pub fn current() -> Option<IpAddr> {
    PEER.try_with(|peer| *peer).ok().flatten()
}

/// Adds `peer` to an audit entry's detail when the connection came from somewhere other than the
/// recorded client address, as through a reverse proxy.
pub fn annotate(detail: Value, client_ip: &str) -> Value {
    let Some(peer) = current() else {
        return detail;
    };
    let peer = peer.to_string();
    if peer == client_ip {
        return detail;
    }
    let Value::Object(mut fields) = detail else {
        return detail;
    };
    fields.insert("peer".into(), Value::String(peer));
    Value::Object(fields)
}

pub async fn record_peer(request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_canonical());
    scoped(peer, next.run(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn the_peer_is_added_only_when_it_differs() {
        let proxy = IpAddr::from([10, 0, 0, 2]);
        let (through_proxy, direct, outside) = scoped(Some(proxy), async {
            (
                annotate(json!({"a": 1}), "203.0.113.9"),
                annotate(json!({"a": 1}), "10.0.0.2"),
                annotate(json!("not an object"), "203.0.113.9"),
            )
        })
        .await;
        assert_eq!(through_proxy, json!({"a": 1, "peer": "10.0.0.2"}));
        assert_eq!(direct, json!({"a": 1}));
        assert_eq!(outside, json!("not an object"));
        assert_eq!(annotate(json!({}), "203.0.113.9"), json!({}), "no request, no peer");
    }
}
