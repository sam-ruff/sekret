use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode, header};
use ipnet::IpNet;
use sekret_core::crypto::{generate_token, hash_token};
use sekret_store::{AccessToken, PrincipalKind};
use zeroize::Zeroizing;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub const SESSION_COOKIE: &str = "sekret_session";
pub const CSRF_HEADER: &str = "x-sekret-csrf";
pub const TOKEN_PREFIX: &str = "skt_";
const TOUCH_INTERVAL: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Session,
    Cli,
    Machine,
    Admin,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Session => "session",
            TokenKind::Cli => "cli",
            TokenKind::Machine => "machine",
            TokenKind::Admin => "admin",
        }
    }
}

/// The authenticated caller of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub kind: PrincipalKind,
    pub id: String,
    pub name: String,
    pub email: String,
    pub groups: Vec<String>,
    pub token_id: String,
    pub token_kind: String,
}

impl Principal {
    /// How the caller is shown in history and the audit log.
    pub fn actor(&self) -> String {
        let label = if self.email.is_empty() { &self.name } else { &self.email };
        format!("{}:{}", self.kind.as_str(), label)
    }
}

pub struct ClientIp(pub IpAddr);

/// Resolves the client address, trusting `X-Forwarded-For` only from configured proxies.
///
/// Every header line counts, read right to left. Trusted proxies are skipped; the first
/// untrusted address is the client. An entry that does not parse stops the walk at the peer,
/// so a garbled value cannot be used to reach further left.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    let mut lines = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(text) = value.to_str() else {
            return peer;
        };
        lines.push(text);
    }
    let joined = lines.join(",");
    for part in joined.split(',').rev() {
        let Ok(ip) = part.trim().parse::<IpAddr>() else {
            return peer;
        };
        let ip = ip.to_canonical();
        if !is_trusted(&ip) {
            return ip;
        }
    }
    peer
}

/// Proxy ranges wide enough to let most of the internet set its own client address.
pub fn broad_proxy_ranges(trusted: &[IpNet]) -> Vec<IpNet> {
    trusted.iter().copied().filter(|net| net.prefix_len() < 8).collect()
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        Ok(ClientIp(client_ip(peer, &parts.headers, &state.config.trusted_proxies)))
    }
}

pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token.trim())
}

pub fn ip_allowed(cidrs: &[String], ip: IpAddr) -> bool {
    if cidrs.is_empty() {
        return true;
    }
    cidrs
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

pub async fn authenticate(state: &AppState, method: &Method, headers: &HeaderMap, ip: IpAddr) -> ApiResult<Principal> {
    let (token, from_cookie) = match (bearer(headers), cookie_value(headers, SESSION_COOKIE)) {
        (Some(token), _) => (token, false),
        (None, Some(token)) => (token, true),
        (None, None) => return Err(ApiError::unauthorised()),
    };
    // Browsers cannot add custom headers cross-site without a CORS preflight, which we never grant.
    let safe = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if from_cookie && !safe && headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some("1") {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "csrf", "missing CSRF header"));
    }
    if !token.starts_with(TOKEN_PREFIX) {
        return Err(ApiError::unauthorised());
    }
    let now = state.clock.now();
    let record = state
        .store
        .find_token(&hash_token(token))
        .await?
        .ok_or_else(ApiError::unauthorised)?;
    let kind_ok = (record.kind == TokenKind::Session.as_str()) == from_cookie;
    if record.revoked || record.expires_at <= now || !kind_ok {
        return Err(ApiError::unauthorised());
    }
    let principal = match record.principal_kind {
        PrincipalKind::User => {
            let user = state
                .store
                .get_user(&record.principal_id)
                .await?
                .ok_or_else(ApiError::unauthorised)?;
            if user.disabled {
                return Err(ApiError::unauthorised());
            }
            Principal {
                kind: PrincipalKind::User,
                id: user.id,
                name: user.name,
                email: user.email,
                groups: user.groups,
                token_id: record.id.clone(),
                token_kind: record.kind.clone(),
            }
        }
        PrincipalKind::Identity => {
            let identity = state
                .store
                .get_identity(&record.principal_id)
                .await?
                .ok_or_else(ApiError::unauthorised)?;
            if identity.disabled || !ip_allowed(&identity.trusted_cidrs, ip) {
                return Err(ApiError::unauthorised());
            }
            Principal {
                kind: PrincipalKind::Identity,
                id: identity.id,
                name: identity.name,
                email: String::new(),
                groups: Vec::new(),
                token_id: record.id.clone(),
                token_kind: record.kind.clone(),
            }
        }
        PrincipalKind::Group => return Err(ApiError::unauthorised()),
    };
    if record.last_used_at.is_none_or(|at| now - at > TOUCH_INTERVAL) {
        state.store.touch_token(&record.id, now).await?;
    }
    Ok(principal)
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let ClientIp(ip) = ClientIp::from_request_parts(parts, state).await?;
        authenticate(state, &parts.method, &parts.headers, ip).await
    }
}

pub struct MintedToken {
    pub token: Zeroizing<String>,
    pub record: AccessToken,
}

pub struct TokenRequest<'a> {
    pub kind: TokenKind,
    pub principal_kind: PrincipalKind,
    pub principal_id: &'a str,
    pub ttl: i64,
    pub max_ttl: i64,
    pub description: String,
    /// The credential the token comes from, so revoking that credential revokes the token.
    pub source: String,
    /// When the person last authenticated with the identity provider, for browser sessions.
    pub auth_time: Option<i64>,
}

pub async fn mint_token(state: &AppState, request: TokenRequest<'_>) -> ApiResult<MintedToken> {
    let now = state.clock.now();
    let token = generate_token(TOKEN_PREFIX)?;
    let max_expires_at = now + request.max_ttl.max(request.ttl);
    let record = AccessToken {
        id: uuid::Uuid::new_v4().to_string(),
        token_hash: hash_token(&token),
        kind: request.kind.as_str().to_string(),
        principal_kind: request.principal_kind,
        principal_id: request.principal_id.to_string(),
        description: request.description,
        source: request.source,
        created_at: now,
        expires_at: (now + request.ttl).min(max_expires_at),
        max_expires_at,
        revoked: false,
        last_used_at: None,
        auth_time: request.auth_time,
    };
    state.store.create_token(record.clone()).await?;
    Ok(MintedToken { token, record })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn headers(pairs: &[(&'static str, &str)]) -> anyhow::Result<HeaderMap> {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(*k, v.parse().context("header")?);
        }
        Ok(map)
    }

    #[test]
    fn forwarded_for_is_only_trusted_from_proxies() -> anyhow::Result<()> {
        let proxy: IpNet = "10.0.0.0/24".parse().context("net")?;
        let h = headers(&[("x-forwarded-for", "203.0.113.9, 10.0.0.5")])?;
        let peer: IpAddr = "10.0.0.2".parse().context("ip")?;
        assert_eq!(
            client_ip(peer, &h, &[proxy]),
            "203.0.113.9".parse::<IpAddr>().context("ip")?
        );
        let outsider: IpAddr = "198.51.100.1".parse().context("ip")?;
        assert_eq!(client_ip(outsider, &h, &[proxy]), outsider);
        assert_eq!(client_ip(peer, &HeaderMap::new(), &[proxy]), peer);
        Ok(())
    }

    #[test]
    fn every_forwarded_for_line_is_read_and_garbage_stops_the_walk() -> anyhow::Result<()> {
        let proxy: IpNet = "10.0.0.0/24".parse().context("net")?;
        let peer: IpAddr = "10.0.0.2".parse().context("ip")?;
        let ip = |s: &str| s.parse::<IpAddr>().context("ip");
        // The proxy appended the real client on a second line; the first came from the client.
        let two_lines = headers(&[("x-forwarded-for", "1.2.3.4"), ("x-forwarded-for", "203.0.113.9")])?;
        assert_eq!(client_ip(peer, &two_lines, &[proxy]), ip("203.0.113.9")?);
        // A spoofed address hiding behind a value that does not parse is never reached.
        let garbled = headers(&[("x-forwarded-for", "1.2.3.4, not-an-ip, 10.0.0.5")])?;
        assert_eq!(client_ip(peer, &garbled, &[proxy]), peer);
        let all_trusted = headers(&[("x-forwarded-for", "10.0.0.7, 10.0.0.5")])?;
        assert_eq!(client_ip(peer, &all_trusted, &[proxy]), peer);
        Ok(())
    }

    #[test]
    fn ipv4_mapped_addresses_match_ipv4_proxies() -> anyhow::Result<()> {
        let proxy: IpNet = "10.0.0.0/24".parse().context("net")?;
        let mapped_peer: IpAddr = "::ffff:10.0.0.2".parse().context("ip")?;
        let h = headers(&[("x-forwarded-for", "::ffff:203.0.113.9")])?;
        assert_eq!(
            client_ip(mapped_peer, &h, &[proxy]),
            "203.0.113.9".parse::<IpAddr>().context("ip")?
        );
        let spoof = headers(&[("x-forwarded-for", "203.0.113.9, ::ffff:10.0.0.9")])?;
        assert_eq!(
            client_ip(mapped_peer, &spoof, &[proxy]),
            "203.0.113.9".parse::<IpAddr>().context("ip")?
        );
        Ok(())
    }

    #[test]
    fn broad_proxy_ranges_are_flagged() -> anyhow::Result<()> {
        let nets: Vec<IpNet> = ["0.0.0.0/0", "10.0.0.0/8", "4.0.0.0/7", "::/0", "fd00::/8"]
            .iter()
            .map(|n| n.parse().context("net"))
            .collect::<anyhow::Result<_>>()?;
        let broad: Vec<String> = broad_proxy_ranges(&nets).iter().map(ToString::to_string).collect();
        assert_eq!(broad, vec!["0.0.0.0/0", "4.0.0.0/7", "::/0"]);
        Ok(())
    }

    #[test]
    fn cookie_and_bearer_parsing() -> anyhow::Result<()> {
        let h = headers(&[
            ("cookie", "a=1; sekret_session=skt_abc; b=2"),
            ("authorization", "Bearer skt_x"),
        ])?;
        assert_eq!(cookie_value(&h, SESSION_COOKIE), Some("skt_abc"));
        assert_eq!(bearer(&h), Some("skt_x"));
        assert_eq!(bearer(&headers(&[("authorization", "Basic abc")])?), None);
        Ok(())
    }

    #[test]
    fn cidr_allowlist() -> anyhow::Result<()> {
        let ip: IpAddr = "192.168.1.20".parse().context("ip")?;
        assert!(ip_allowed(&[], ip));
        assert!(ip_allowed(&["192.168.1.0/24".into()], ip));
        assert!(!ip_allowed(&["10.0.0.0/8".into()], ip));
        assert!(!ip_allowed(&["garbage".into()], ip));
        Ok(())
    }
}
