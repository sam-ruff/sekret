use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode, header};
use ipnet::IpNet;
use sekret_core::crypto::{generate_token, hash_token};
use sekret_store::{AccessToken, PrincipalKind};
use zeroize::Zeroizing;

use crate::admin::BOOTSTRAP_SUBJECT;
use crate::config::{HumanOidcConfig, ServerConfig};
use crate::error::{ApiError, ApiResult};
use crate::human::subject_allowed;
use crate::state::AppState;

pub const SESSION_COOKIE: &str = "sekret_session";
/// Used over HTTPS, where the prefix stops a sibling subdomain from planting or shadowing it.
pub const SECURE_SESSION_COOKIE: &str = "__Host-sekret_session";
pub const CSRF_HEADER: &str = "x-sekret-csrf";

pub fn session_cookie_name(config: &ServerConfig) -> &'static str {
    if config.secure_cookies() {
        SECURE_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    }
}

/// Whether a browser sent this request from another site or as a page navigation. Requests
/// without `Sec-Fetch-*` headers, such as from scripts and older browsers, pass.
pub fn browser_cross_site(headers: &HeaderMap) -> bool {
    let value = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let site_ok = value("sec-fetch-site").is_none_or(|site| site.eq_ignore_ascii_case("same-origin"));
    let navigation = value("sec-fetch-mode").is_some_and(|mode| mode.eq_ignore_ascii_case("navigate"));
    !site_ok || navigation
}
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
    /// Recorded as the actor for things with no signed-in caller, such as setup and unlocking.
    pub fn system(name: &str) -> Self {
        Self {
            kind: PrincipalKind::Identity,
            id: name.into(),
            name: name.into(),
            email: String::new(),
            groups: Vec::new(),
            token_id: String::new(),
            token_kind: "system".into(),
        }
    }

    /// How the caller is shown in history and the audit log.
    pub fn actor(&self) -> String {
        let label = if self.email.is_empty() { &self.name } else { &self.email };
        format!("{}:{}", self.kind.as_str(), label)
    }
}

pub struct ClientIp(pub IpAddr);

/// Stands in for a client whose forwarded address could not be read. No identity's trusted
/// CIDRs match it, and every such client shares one rate-limit bucket.
pub const UNKNOWN_CLIENT: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// One `X-Forwarded-For` entry: an address, optionally with a port as `ip:port` or `[v6]:port`.
fn forwarded_entry(bytes: &[u8]) -> Option<IpAddr> {
    if !bytes.is_ascii() {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(socket) = text.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    text.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

/// Resolves the client address, trusting `X-Forwarded-For` only from configured proxies.
///
/// Every header line counts, read right to left, which is the order the proxies appended them.
/// Trusted proxies are skipped; the first untrusted address is the client, so whatever the client
/// wrote further left cannot hide it. Only when an entry that is not an address comes before any
/// untrusted one is the client [`UNKNOWN_CLIENT`], never the trusted peer, so a garbled value
/// can neither borrow the proxy's address nor stand for a spoofed one.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    let lines: Vec<&[u8]> = headers
        .get_all("x-forwarded-for")
        .iter()
        .map(|value| value.as_bytes())
        .collect();
    for entry in lines.iter().rev().flat_map(|line| line.split(|b| *b == b',').rev()) {
        let Some(ip) = forwarded_entry(entry).map(|ip| ip.to_canonical()) else {
            return UNKNOWN_CLIENT;
        };
        if !is_trusted(&ip) {
            return ip;
        }
    }
    peer
}

/// Addresses in this range are private, loopback or link-local.
fn private_range(net: &IpNet) -> bool {
    let private: &[&str] = match net {
        IpNet::V4(_) => &[
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.64.0.0/10",
        ],
        IpNet::V6(_) => &["fc00::/7", "fe80::/10", "::1/128"],
    };
    private
        .iter()
        .filter_map(|p| p.parse::<IpNet>().ok())
        .any(|p| p.contains(net))
}

/// Warnings about proxy ranges that let too many hosts set their own client address: wider than
/// /16 for IPv4 or /32 for IPv6, outside private ranges, or more than a /8's worth in total.
pub fn proxy_range_warnings(trusted: &[IpNet]) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut total_v4: u128 = 0;
    let mut total_v6: u128 = 0;
    for net in trusted {
        let (threshold, bits) = match net {
            IpNet::V4(_) => (16, 32),
            IpNet::V6(_) => (32, 128),
        };
        let size = 1u128
            .checked_shl(bits - u32::from(net.prefix_len()))
            .unwrap_or(u128::MAX);
        match net {
            IpNet::V4(_) => total_v4 = total_v4.saturating_add(size),
            IpNet::V6(_) => total_v6 = total_v6.saturating_add(size),
        }
        if net.prefix_len() == 0 {
            warnings.push(format!(
                "trusted proxy range {net} is the whole internet; any client can set its own address with X-Forwarded-For"
            ));
        } else if net.prefix_len() < threshold {
            warnings.push(format!(
                "trusted proxy range {net} is wider than /{threshold}; any host in it can set its own address with \
                 X-Forwarded-For"
            ));
        } else if !private_range(net) {
            warnings.push(format!(
                "trusted proxy range {net} is not a private range; only list your own reverse proxies"
            ));
        }
    }
    if total_v4 > 1 << 24 || total_v6 > 1 << 120 {
        warnings.push(
            "the trusted proxy ranges together cover more than a /8; list only the addresses of your reverse proxies"
                .into(),
        );
    }
    warnings
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
    // An address that could not be read is never inside a restriction, even `::/0`.
    if ip == UNKNOWN_CLIENT {
        return false;
    }
    cidrs
        .iter()
        .filter_map(|c| c.parse::<IpNet>().ok())
        .any(|net| net.contains(&ip))
}

pub async fn authenticate(state: &AppState, method: &Method, headers: &HeaderMap, ip: IpAddr) -> ApiResult<Principal> {
    let cookie = cookie_value(headers, session_cookie_name(&state.config));
    let (token, from_cookie) = match (bearer(headers), cookie) {
        (Some(token), _) => (token, false),
        (None, Some(token)) => (token, true),
        (None, None) => return Err(ApiError::unauthorised()),
    };
    // A cross-site link or page must not spend the session, even on a read.
    if from_cookie && browser_cross_site(headers) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "cross_site",
            "this request came from another site or a page navigation; open sekret instead",
        ));
    }
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
            if user.disabled || !user_still_allowed(state.config.oidc.as_ref(), &user.subject, &user.groups) {
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

/// Whether a user still passes `oidc.allowed_subjects` and `oidc.required_groups`, judged from the
/// subject and groups stored at their last browser sign-in. The local break-glass admin is not an
/// OIDC user, so neither list applies to it.
pub fn user_still_allowed(config: Option<&HumanOidcConfig>, subject: &str, groups: &[String]) -> bool {
    let Some(config) = config else {
        return true;
    };
    if subject == BOOTSTRAP_SUBJECT {
        return true;
    }
    let groups_ok = config.required_groups.is_empty() || groups.iter().any(|g| config.required_groups.contains(g));
    groups_ok && subject_allowed(config, subject)
}

/// Revokes every session and token of users who no longer pass the sign-in lists, as after the
/// lists were narrowed. Returns how many users lost access.
pub async fn revoke_disallowed_users(state: &AppState) -> ApiResult<usize> {
    let Some(config) = state.config.oidc.as_ref() else {
        return Ok(0);
    };
    let mut revoked = 0;
    for user in state.store.list_users().await? {
        if user_still_allowed(Some(config), &user.subject, &user.groups) {
            continue;
        }
        let tokens = state.store.list_principal_tokens(PrincipalKind::User, &user.id).await?;
        if tokens.iter().all(|t| t.revoked) {
            continue;
        }
        state
            .store
            .revoke_principal_tokens(PrincipalKind::User, &user.id)
            .await?;
        tracing::warn!(user = %user.subject, "revoked the sessions and tokens of a user the sign-in lists no longer allow");
        revoked += 1;
    }
    Ok(revoked)
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        // The write gate authenticates before taking its lock; reuse that rather than repeat it.
        if let Some(principal) = parts.extensions.get::<Principal>() {
            return Ok(principal.clone());
        }
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
    use axum::http::HeaderValue;

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
        assert_eq!(client_ip(peer, &garbled, &[proxy]), UNKNOWN_CLIENT);
        let all_trusted = headers(&[("x-forwarded-for", "10.0.0.7, 10.0.0.5")])?;
        assert_eq!(client_ip(peer, &all_trusted, &[proxy]), peer);
        Ok(())
    }

    #[test]
    fn a_non_utf8_forwarded_for_never_becomes_the_proxy_address() -> anyhow::Result<()> {
        let proxy: IpNet = "10.0.0.0/24".parse().context("net")?;
        let peer: IpAddr = "10.0.0.2".parse().context("ip")?;
        let raw = |bytes: &[u8]| HeaderValue::from_bytes(bytes).context("header");
        // Garbage the client wrote to the left of what the proxy appended does not hide the client.
        let mut one_line = HeaderMap::new();
        one_line.append("x-forwarded-for", raw(b"\x80, 203.0.113.9")?);
        assert_eq!(
            client_ip(peer, &one_line, &[proxy]),
            "203.0.113.9".parse::<IpAddr>().context("ip")?
        );
        let mut leading = HeaderMap::new();
        leading.append("x-forwarded-for", raw(b"203.0.113.9, \x80")?);
        assert_eq!(client_ip(peer, &leading, &[proxy]), UNKNOWN_CLIENT);
        let mut two_lines = HeaderMap::new();
        two_lines.append("x-forwarded-for", raw(b"203.0.113.9")?);
        two_lines.append("x-forwarded-for", raw(b"\x80")?);
        assert_eq!(client_ip(peer, &two_lines, &[proxy]), UNKNOWN_CLIENT);
        // An identity limited to the proxy's network must not be reachable through it.
        let cidrs = ["10.0.0.0/24".to_string()];
        assert!(!ip_allowed(&cidrs, client_ip(peer, &two_lines, &[proxy])));
        assert!(!ip_allowed(&["::/0".into(), "0.0.0.0/0".into()], UNKNOWN_CLIENT));
        assert!(ip_allowed(&[], UNKNOWN_CLIENT), "no restriction means everyone");
        Ok(())
    }

    #[test]
    fn a_client_cannot_erase_its_address_with_garbage_or_ports() -> anyhow::Result<()> {
        let proxy: IpNet = "10.0.0.0/24".parse().context("net")?;
        let peer: IpAddr = "10.0.0.2".parse().context("ip")?;
        let ip = |s: &str| s.parse::<IpAddr>().context("ip");
        // The attack: the client sends garbage, and the proxy appends the real address after it.
        for sent in ["garbage", "", "1.2.3.4, ???", "unknown"] {
            let h = headers(&[("x-forwarded-for", &format!("{sent}, 203.0.113.9"))])?;
            assert_eq!(client_ip(peer, &h, &[proxy]), ip("203.0.113.9")?, "{sent:?}");
            let lines = headers(&[("x-forwarded-for", sent), ("x-forwarded-for", "203.0.113.9")])?;
            assert_eq!(client_ip(peer, &lines, &[proxy]), ip("203.0.113.9")?, "{sent:?}");
        }
        let ported = headers(&[("x-forwarded-for", "203.0.113.9:51234, 10.0.0.5:443")])?;
        assert_eq!(client_ip(peer, &ported, &[proxy]), ip("203.0.113.9")?);
        let v6 = headers(&[("x-forwarded-for", "[2001:db8::7]:443")])?;
        assert_eq!(client_ip(peer, &v6, &[proxy]), ip("2001:db8::7")?);
        let bracketed = headers(&[("x-forwarded-for", "[2001:db8::7]")])?;
        assert_eq!(client_ip(peer, &bracketed, &[proxy]), ip("2001:db8::7")?);
        // Garbage between the proxies and any client address still means unknown.
        let hidden = headers(&[("x-forwarded-for", "203.0.113.9, junk, 10.0.0.5")])?;
        assert_eq!(client_ip(peer, &hidden, &[proxy]), UNKNOWN_CLIENT);
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

    fn nets(list: &[&str]) -> anyhow::Result<Vec<IpNet>> {
        list.iter().map(|n| n.parse().context("net")).collect()
    }

    #[test]
    fn broad_and_public_proxy_ranges_are_flagged_per_family() -> anyhow::Result<()> {
        let quiet = nets(&["10.0.0.0/24", "192.168.1.10/32", "fd00:1::/48", "172.18.0.0/16"])?;
        assert_eq!(proxy_range_warnings(&quiet), Vec::<String>::new());
        let warned = |list: &[&str]| -> anyhow::Result<String> { Ok(proxy_range_warnings(&nets(list)?).join("\n")) };
        assert!(warned(&["0.0.0.0/0"])?.contains("whole internet"));
        assert!(warned(&["::/0"])?.contains("whole internet"));
        assert!(warned(&["10.0.0.0/15"])?.contains("wider than /16"));
        assert!(warned(&["fd00::/31"])?.contains("wider than /32"));
        assert!(warned(&["203.0.113.0/24"])?.contains("not a private range"));
        assert!(warned(&["2001:db8::/48"])?.contains("not a private range"));
        let many: Vec<String> = (0..300).map(|i| format!("10.{}.0.0/16", i % 256)).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(warned(&many)?.contains("more than a /8"));
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
    fn cross_site_and_navigation_requests_are_spotted() -> anyhow::Result<()> {
        let cases: &[(&[(&str, &str)], bool)] = &[
            (&[], false),
            (&[("sec-fetch-site", "same-origin"), ("sec-fetch-mode", "cors")], false),
            (
                &[("sec-fetch-site", "same-origin"), ("sec-fetch-mode", "no-cors")],
                false,
            ),
            (
                &[("sec-fetch-site", "same-origin"), ("sec-fetch-mode", "navigate")],
                true,
            ),
            (&[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "cors")], true),
            (
                &[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "navigate")],
                true,
            ),
            (&[("sec-fetch-site", "same-site"), ("sec-fetch-mode", "cors")], true),
            (&[("sec-fetch-site", "none"), ("sec-fetch-mode", "navigate")], true),
            (&[("sec-fetch-site", "cross-site")], true),
            (&[("sec-fetch-mode", "navigate")], true),
        ];
        for (list, expected) in cases {
            assert_eq!(browser_cross_site(&headers(list)?), *expected, "{list:?}");
        }
        Ok(())
    }

    #[test]
    fn https_servers_use_the_host_prefixed_cookie() {
        let mut config = ServerConfig::for_tests("sqlite::memory:");
        config.public_url = "http://localhost:8200".into();
        assert_eq!(session_cookie_name(&config), SESSION_COOKIE);
        config.public_url = "https://sekret.example".into();
        assert_eq!(session_cookie_name(&config), SECURE_SESSION_COOKIE);
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
