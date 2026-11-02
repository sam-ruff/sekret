use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sekret_api::{
    AuthConfig, CliApproveRequest, CliDenyRequest, CliPollRequest, CliStartResponse, LogoutResponse, PendingCliLogin,
    TokenResponse,
};
use sekret_core::crypto::{constant_time_eq, generate_token, hash_token, random_chars};
use sekret_store::{CliLogin, CliPoll, LoginState, PrincipalKind, UserLogin};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::{AuditTarget, audit};
use crate::auth::{ClientIp, Principal, TokenKind, TokenRequest, cookie_value, mint_token, session_cookie_name};
use crate::config::{HumanOidcConfig, ServerConfig};
use crate::error::{ApiError, ApiResult};
use crate::jwt::{Expectations, KeySource};
use crate::state::AppState;

const LOGIN_STATE_TTL: i64 = 600;
/// Short, so a code sent to someone else goes stale quickly.
const CLI_CODE_TTL: i64 = 300;
const MAX_USER_AGENT_CHARS: usize = 200;
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";

/// Only same-site relative paths are allowed as post-login destinations.
pub fn safe_return_to(value: Option<&str>) -> String {
    value.and_then(same_origin_path).unwrap_or_else(|| "/".to_string())
}

/// The path normalised as a browser would resolve it, matching the web client's check.
fn same_origin_path(path: &str) -> Option<String> {
    // Browsers drop tabs and newlines, so `/\t/evil.test` would otherwise become `//evil.test`.
    let plain = !path.chars().any(|c| c == '\\' || c.is_whitespace() || c.is_control());
    if !plain || !path.starts_with('/') || path.starts_with("//") {
        return None;
    }
    let base = url::Url::parse("http://sekret.invalid").ok()?;
    let resolved = base.join(path).ok()?;
    if resolved.origin() != base.origin() {
        return None;
    }
    // "/..//x" normalises to "//x", which a browser reads as another host.
    let normalised = resolved.path();
    if normalised.starts_with("//") || normalised.starts_with("/\\") {
        return None;
    }
    let mut out = normalised.to_string();
    if let Some(query) = resolved.query() {
        out.push('?');
        out.push_str(query);
    }
    if let Some(fragment) = resolved.fragment() {
        out.push('#');
        out.push_str(fragment);
    }
    Some(out)
}

/// Ties a login attempt to the browser that started it, so a callback URL cannot be replayed into another browser.
pub const LOGIN_STATE_COOKIE: &str = "sekret_login";
/// Used over HTTPS, where the prefix stops a sibling subdomain from planting it to force a login.
pub const SECURE_LOGIN_STATE_COOKIE: &str = "__Host-sekret_login";

pub fn login_state_cookie_name(config: &ServerConfig) -> &'static str {
    if config.secure_cookies() {
        SECURE_LOGIN_STATE_COOKIE
    } else {
        LOGIN_STATE_COOKIE
    }
}

/// `__Host-` cookies must be `Secure` with `Path=/`; the plain one stays on `/auth`.
fn login_state_cookie(config: &ServerConfig, value: &str, max_age: i64) -> ApiResult<HeaderValue> {
    let name = login_state_cookie_name(config);
    let scope = if config.secure_cookies() {
        "Path=/; Secure"
    } else {
        "Path=/auth"
    };
    HeaderValue::from_str(&format!(
        "{name}={value}; {scope}; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    ))
    .map_err(|e| ApiError::internal("cookie", e))
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Groups from the configured claims; names starting with `/` are JSON pointers.
pub fn extract_groups(claims: &Value, group_claims: &[String]) -> Vec<String> {
    let mut groups: Vec<String> = group_claims
        .iter()
        .filter_map(|name| {
            if name.starts_with('/') {
                claims.pointer(name)
            } else {
                claims.get(name)
            }
        })
        .flat_map(|value| match value {
            Value::String(s) => vec![s.clone()],
            Value::Array(items) => items.iter().filter_map(|i| i.as_str().map(String::from)).collect(),
            _ => vec![],
        })
        .collect();
    groups.sort();
    groups.dedup();
    groups
}

pub fn user_code() -> ApiResult<String> {
    let chars = random_chars(USER_CODE_ALPHABET, 8)?;
    Ok(format!("{}-{}", &chars[..4], &chars[4..]))
}

fn oidc(state: &AppState) -> ApiResult<&HumanOidcConfig> {
    state
        .config
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::not_found("OIDC sign-in"))
}

fn session_cookie(state: &AppState, value: &str, max_age: i64) -> ApiResult<HeaderValue> {
    let secure = if state.config.secure_cookies() { "; Secure" } else { "" };
    let name = session_cookie_name(&state.config);
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
    .map_err(|e| ApiError::internal("cookie", e))
}

#[utoipa::path(get, path = "/api/v1/auth/config", tag = "auth", responses((status = 200, body = AuthConfig)))]
pub async fn auth_config(State(state): State<AppState>) -> Json<AuthConfig> {
    Json(AuthConfig {
        oidc_enabled: state.config.oidc.is_some(),
        login_url: "/auth/login".into(),
    })
}

#[derive(Deserialize)]
pub struct LoginQuery {
    return_to: Option<String>,
    /// Ask the provider to authenticate the person again, for approving a CLI login.
    #[serde(default)]
    reauth: Option<String>,
}

/// When the browser's current session last authenticated with the provider, if it has one.
async fn session_auth_time(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<i64>> {
    let Some(token) = cookie_value(headers, session_cookie_name(&state.config)) else {
        return Ok(None);
    };
    Ok(crate::auth::find_token(state, token)
        .await?
        .and_then(|record| record.auth_time))
}

/// Whether an authentication at `auth_time` is recent enough under `max_age`, allowing a minute
/// of clock difference with the provider.
pub fn fresh_enough(auth_time: Option<i64>, max_age: i64, now: i64) -> bool {
    auth_time.is_some_and(|at| at <= now + 60 && now - at <= max_age + 60)
}

/// The sign-in URL that asks the provider for a fresh authentication, then returns to `return_to`.
pub fn reauth_url(return_to: &str) -> String {
    format!(
        "/auth/login?reauth=1&return_to={}",
        url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>()
    )
}

pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> ApiResult<Response> {
    let config = oidc(&state)?;
    if !state.login_limiter.allow_ip(ip) {
        return Err(ApiError::too_many_requests());
    }
    let max_age = state.config.cli_login_max_auth_age.filter(|_| query.reauth.is_some());
    let prompt_login = match max_age {
        Some(max_age) => !fresh_enough(session_auth_time(&state, &headers).await?, max_age, state.clock.now()),
        None => false,
    };
    let discovery = state
        .jwt
        .discover(&config.issuer)
        .await
        .map_err(|e| ApiError::internal("OIDC discovery", e))?;
    let endpoint = discovery["authorization_endpoint"]
        .as_str()
        .ok_or_else(|| ApiError::internal("OIDC discovery", "no authorization_endpoint"))?;
    let login_state = generate_token("")?;
    let nonce = generate_token("")?;
    let verifier = generate_token("")?;
    state
        .store
        .put_login_state(LoginState {
            state: login_state.to_string(),
            nonce: nonce.to_string(),
            pkce_verifier: verifier.to_string(),
            return_to: safe_return_to(query.return_to.as_deref()),
            created_at: state.clock.now(),
            max_age,
        })
        .await?;
    let mut url = url::Url::parse(endpoint).map_err(|e| ApiError::internal("authorization endpoint", e))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &state.config.redirect_uri())
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", &login_state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &pkce_challenge(&verifier))
        .append_pair("code_challenge_method", "S256");
    if let Some(max_age) = max_age {
        url.query_pairs_mut().append_pair("max_age", &max_age.to_string());
    }
    if prompt_login {
        url.query_pairs_mut().append_pair("prompt", "login");
    }
    let mut response = Redirect::to(url.as_str()).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        login_state_cookie(&state.config, &login_state, LOGIN_STATE_TTL)?,
    );
    Ok(response)
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Why a browser sign-in failed. Only the fixed code reaches the URL; the login page owns the wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginError {
    ProviderRefused,
    IncompleteResponse,
    OtherBrowser,
    Expired,
    ReauthNotPerformed,
    NotAllowed,
    AccountDisabled,
}

impl LoginError {
    fn code(self) -> &'static str {
        match self {
            Self::ProviderRefused => "provider_refused",
            Self::IncompleteResponse => "incomplete_response",
            Self::OtherBrowser => "other_browser",
            Self::Expired => "expired",
            Self::ReauthNotPerformed => "reauth_not_performed",
            Self::NotAllowed => "not_allowed",
            Self::AccountDisabled => "account_disabled",
        }
    }
}

/// The email and display name to store for a user. The email is kept only when the provider
/// says it verified it, since it labels the user in audit entries and member lists.
fn user_labels(claims: &serde_json::Value, subject: &str) -> (String, String) {
    let verified = match &claims["email_verified"] {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    };
    let email = claims["email"]
        .as_str()
        .filter(|e| verified && !e.is_empty())
        .unwrap_or_default()
        .to_string();
    let name = ["name", "preferred_username"]
        .iter()
        .find_map(|k| claims[*k].as_str().filter(|n| !n.is_empty()))
        .or(Some(email.as_str()).filter(|e| !e.is_empty()))
        .unwrap_or(subject)
        .to_string();
    (email.clone(), unspoofable(name, &email))
}

/// The name labels a user with no verified email, so it must not pass for someone's email.
fn unspoofable(name: String, email: &str) -> String {
    if !email.is_empty() || !name.contains('@') {
        return name;
    }
    format!("{name} (unverified)")
}

/// OIDC Core 3.1.3.7: a token for several audiences must name this client as `azp`, and any
/// `azp` given must be this client.
fn issued_to(claims: &serde_json::Value, client_id: &str) -> bool {
    let several = claims["aud"].as_array().is_some_and(|a| a.len() > 1);
    match claims.get("azp") {
        Some(azp) => azp.as_str() == Some(client_id),
        None => !several,
    }
}

/// Caller-supplied text cut short for a log line; log it with `?` so control characters are escaped.
fn loggable(value: &str) -> String {
    value.chars().take(64).collect()
}

fn login_error(error: LoginError) -> Response {
    Redirect::to(&format!("/login?error={}", error.code())).into_response()
}

pub async fn callback(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> ApiResult<Response> {
    if !state.login_limiter.allow_ip(ip) {
        return Err(ApiError::too_many_requests());
    }
    let mut response = finish_login(&state, ip, &headers, query).await?;
    response
        .headers_mut()
        .append(header::SET_COOKIE, login_state_cookie(&state.config, "", 0)?);
    Ok(response)
}

/// Why an ID token with `subject` and `groups` may not sign in, or `None` when it may.
pub fn login_refusal(config: &HumanOidcConfig, subject: &str, groups: &[String]) -> Option<&'static str> {
    if !config.allowed_subjects.is_empty() && !config.allowed_subjects.iter().any(|s| s == subject) {
        return Some("subject not in oidc.allowed_subjects");
    }
    if !config.required_groups.is_empty() && !groups.iter().any(|g| config.required_groups.contains(g)) {
        return Some("not in any of oidc.required_groups");
    }
    None
}

async fn audit_refused(state: &AppState, ip: std::net::IpAddr, subject: &str, reason: &str) {
    crate::seal::audit_system(
        state.store.as_ref(),
        state.clock.now(),
        &ip.to_string(),
        "auth.login.refused",
        json!({"subject": subject, "reason": reason}),
    )
    .await;
}

/// Whether the user stored as `issuer|sub` is still in `oidc.allowed_subjects`.
pub(crate) fn subject_allowed(config: &HumanOidcConfig, stored_subject: &str) -> bool {
    if config.allowed_subjects.is_empty() {
        return true;
    }
    let Some(sub) = stored_subject.strip_prefix(&format!("{}|", config.issuer)) else {
        return false;
    };
    config.allowed_subjects.iter().any(|s| s == sub)
}

async fn finish_login(
    state: &AppState,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
    query: CallbackQuery,
) -> ApiResult<Response> {
    let config = oidc(state)?;
    if let Some(error) = query.error {
        tracing::warn!(error = ?loggable(&error), "identity provider returned an error");
        return Ok(login_error(LoginError::ProviderRefused));
    }
    let (Some(code), Some(state_param)) = (query.code, query.state) else {
        return Ok(login_error(LoginError::IncompleteResponse));
    };
    let same_browser = cookie_value(headers, login_state_cookie_name(&state.config))
        .is_some_and(|cookie| constant_time_eq(cookie.as_bytes(), state_param.as_bytes()));
    if !same_browser {
        return Ok(login_error(LoginError::OtherBrowser));
    }
    let now = state.clock.now();
    let Some(saved) = state
        .store
        .take_login_state(&state_param)
        .await?
        .filter(|s| now - s.created_at < LOGIN_STATE_TTL)
    else {
        return Ok(login_error(LoginError::Expired));
    };
    let discovery = state
        .jwt
        .discover(&config.issuer)
        .await
        .map_err(|e| ApiError::internal("OIDC discovery", e))?;
    let token_endpoint = discovery["token_endpoint"]
        .as_str()
        .ok_or_else(|| ApiError::internal("OIDC discovery", "no token_endpoint"))?;
    let form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code),
        ("redirect_uri".to_string(), state.config.redirect_uri()),
        ("client_id".to_string(), config.client_id.clone()),
        ("client_secret".to_string(), config.client_secret.clone()),
        ("code_verifier".to_string(), saved.pkce_verifier.clone()),
    ];
    let tokens = state.http.post_form(token_endpoint, form).await.map_err(|e| {
        tracing::warn!(error = %e, "code exchange failed");
        ApiError::login_failed()
    })?;
    let id_token = tokens["id_token"].as_str().ok_or_else(ApiError::login_failed)?;
    let expect = Expectations {
        issuer: Some(&config.issuer),
        audience: Some(&config.client_id),
    };
    let claims = state
        .jwt
        .verify(id_token, &KeySource::Issuer, &expect)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "id token rejected");
            ApiError::login_failed()
        })?;
    if claims["nonce"].as_str() != Some(saved.nonce.as_str()) {
        return Err(ApiError::login_failed());
    }
    if !issued_to(&claims, &config.client_id) {
        tracing::warn!("id token was issued to another client");
        return Err(ApiError::login_failed());
    }
    let auth_time = claims["auth_time"].as_i64();
    if let Some(max_age) = saved.max_age
        && !fresh_enough(auth_time, max_age, now)
    {
        tracing::warn!("the identity provider did not authenticate the person again as asked");
        return Ok(login_error(LoginError::ReauthNotPerformed));
    }
    let subject = claims["sub"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(ApiError::login_failed)?;
    let groups = extract_groups(&claims, &config.group_claims);
    if let Some(reason) = login_refusal(config, subject, &groups) {
        audit_refused(state, ip, subject, reason).await;
        return Ok(login_error(LoginError::NotAllowed));
    }
    let (email, name) = user_labels(&claims, subject);
    let user = state
        .store
        .upsert_user(UserLogin {
            subject: format!("{}|{subject}", config.issuer),
            email,
            name,
            groups,
            now,
        })
        .await?;
    if user.disabled {
        return Ok(login_error(LoginError::AccountDisabled));
    }
    let minted = mint_token(
        state,
        TokenRequest {
            kind: TokenKind::Session,
            principal_kind: PrincipalKind::User,
            principal_id: &user.id,
            ttl: state.config.session_ttl,
            max_ttl: state.config.session_ttl,
            description: "browser session".into(),
            source: String::new(),
            auth_time,
        },
    )
    .await?;
    let principal = Principal {
        kind: PrincipalKind::User,
        id: user.id.clone(),
        name: user.name.clone(),
        email: user.email.clone(),
        groups: user.groups.clone(),
        token_id: minted.record.id.clone(),
        token_kind: minted.record.kind.clone(),
    };
    audit(state, &principal, ip, "auth.login", AuditTarget::default(), json!({})).await;
    let mut response = Redirect::to(&saved.return_to).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(state, &minted.token, state.config.session_ttl)?,
    );
    Ok(response)
}

/// Ends the browser session and clears its cookie.
#[utoipa::path(post, path = "/auth/logout", tag = "auth", responses((status = 200, body = LogoutResponse)),
    security(("bearer" = [])))]
pub async fn logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if cookie_value(&headers, session_cookie_name(&state.config)).is_some() {
        state.store.revoke_token(&principal.token_id).await?;
    }
    audit(&state, &principal, ip, "auth.logout", AuditTarget::default(), json!({})).await;
    let logout_url = match &state.config.oidc {
        Some(config) => state
            .jwt
            .discover(&config.issuer)
            .await
            .ok()
            .and_then(|d| d["end_session_endpoint"].as_str().map(String::from))
            .and_then(|endpoint| {
                let mut url = url::Url::parse(&endpoint).ok()?;
                url.query_pairs_mut()
                    .append_pair("client_id", &config.client_id)
                    .append_pair("post_logout_redirect_uri", &state.config.public_url);
                Some(url.to_string())
            }),
        None => None,
    };
    let mut response = Json(LogoutResponse { logout_url }).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&state, "", 0)?);
    Ok(response)
}

/// The user agent, cut to a length the approval page can show. A value that is not plain ASCII
/// is dropped whole, so lookalike letters cannot imitate a familiar one.
fn shown_user_agent(headers: &HeaderMap) -> String {
    let raw = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    shown_text(raw, MAX_USER_AGENT_CHARS)
}

/// Requester-supplied text with control and invisible format characters removed, so it cannot
/// be reordered with bidi overrides or hide characters on the approval page.
fn shown_text(raw: &str, max_chars: usize) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && !is_format_character(*c))
        .take(max_chars)
        .collect()
}

/// Unicode format (Cf) characters and other invisible ones: bidi controls, zero-width
/// characters, joiners, the byte order mark, interlinear annotations and tag characters.
fn is_format_character(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{0600}'..='\u{0605}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Codes are shown grouped and read back by people, so case, spaces and dashes are ignored.
fn normalise_user_code(code: &str) -> String {
    let plain: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    match plain.len() {
        8 => format!("{}-{}", &plain[..4], &plain[4..]),
        _ => plain,
    }
}

#[utoipa::path(post, path = "/api/v1/auth/cli/start", tag = "auth", responses((status = 200, body = CliStartResponse)))]
pub async fn cli_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> ApiResult<Json<CliStartResponse>> {
    if !state.cli_login_limiter.allow_ip(ip) {
        return Err(ApiError::too_many_requests());
    }
    let now = state.clock.now();
    let device_code = generate_token("skd_")?;
    let code = user_code()?;
    state
        .store
        .create_cli_login(CliLogin {
            device_code_hash: hash_token(&device_code),
            user_code: code.clone(),
            created_at: now,
            expires_at: now + CLI_CODE_TTL,
            approved_user_id: None,
            consumed: false,
            requested_from_ip: ip.to_string(),
            user_agent: shown_user_agent(&headers),
        })
        .await?;
    Ok(Json(CliStartResponse {
        device_code: device_code.to_string(),
        verification_url: format!(
            "{}/cli-login?code={code}",
            state.config.public_url.trim_end_matches('/')
        ),
        user_code: code,
        expires_in: CLI_CODE_TTL,
        interval: 2,
    }))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct PendingQuery {
    /// The code from the terminal, or from the link the CLI printed.
    code: String,
}

/// Only a browser session may look at or approve CLI logins.
fn require_browser_session(principal: &Principal) -> ApiResult<()> {
    if principal.kind != PrincipalKind::User || principal.token_kind != TokenKind::Session.as_str() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

/// A browser session within its own allowance for looking at and answering CLI logins.
fn require_cli_reviewer(state: &AppState, principal: &Principal) -> ApiResult<()> {
    require_browser_session(principal)?;
    if !state.cli_review_limiter.allow(&principal.id) {
        return Err(ApiError::too_many_requests());
    }
    Ok(())
}

#[utoipa::path(get, path = "/api/v1/auth/cli/pending", tag = "auth", params(PendingQuery),
    description = "Where and when a CLI login was started, so the person can check it was them before approving.",
    responses((status = 200, body = PendingCliLogin), (status = 403, body = sekret_api::ErrorBody),
        (status = 404, body = sekret_api::ErrorBody), (status = 429, body = sekret_api::ErrorBody)),
    security(("bearer" = [])))]
pub async fn cli_pending(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Query(query): Query<PendingQuery>,
) -> ApiResult<Json<PendingCliLogin>> {
    require_cli_reviewer(&state, &principal)?;
    let login = state
        .store
        .get_cli_login(&normalise_user_code(&query.code), state.clock.now())
        .await?
        .filter(|login| login.approved_user_id.is_none())
        .ok_or_else(|| ApiError::not_found("login code"))?;
    Ok(Json(PendingCliLogin {
        code_hint: None,
        same_address: login.requested_from_ip == ip.to_string(),
        requested_from_ip: login.requested_from_ip,
        user_agent: login.user_agent,
        created_at: login.created_at,
        expires_at: login.expires_at,
    }))
}

#[utoipa::path(post, path = "/api/v1/auth/cli/deny", tag = "auth", request_body = CliDenyRequest,
    description = "Refuses a pending CLI login. The terminal that started it is told the login has ended.",
    responses((status = 204), (status = 403, body = sekret_api::ErrorBody), (status = 404, body = sekret_api::ErrorBody),
        (status = 429, body = sekret_api::ErrorBody)),
    security(("bearer" = [])))]
pub async fn cli_deny(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Json(request): Json<CliDenyRequest>,
) -> ApiResult<StatusCode> {
    require_cli_reviewer(&state, &principal)?;
    let code = normalise_user_code(&request.code);
    let now = state.clock.now();
    let Some(login) = state.store.get_cli_login(&code, now).await? else {
        return Err(ApiError::not_found("login code"));
    };
    if !state.store.deny_cli_login(&code, now).await? {
        return Err(ApiError::not_found("login code"));
    }
    audit(
        &state,
        &principal,
        ip,
        "auth.cli-deny",
        AuditTarget::default(),
        requester_details(&login),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Where a CLI login came from, for its audit entries.
fn requester_details(login: &CliLogin) -> Value {
    json!({
        "requested_from_ip": login.requested_from_ip,
        "user_agent": login.user_agent,
        "requested_at": login.created_at,
    })
}

#[utoipa::path(post, path = "/api/v1/auth/cli/approve", tag = "auth", request_body = CliApproveRequest,
    description = "`code` must be typed by the person from the terminal that started the login.",
    responses((status = 204), (status = 403, body = sekret_api::ErrorBody), (status = 404, body = sekret_api::ErrorBody),
        (status = 429, body = sekret_api::ErrorBody)),
    security(("bearer" = [])))]
pub async fn cli_approve(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    principal: Principal,
    Json(request): Json<CliApproveRequest>,
) -> ApiResult<StatusCode> {
    require_cli_reviewer(&state, &principal)?;
    let code = normalise_user_code(&request.code);
    // A session from before the subject list changed must not mint a CLI token.
    if let Some(config) = &state.config.oidc
        && !config.allowed_subjects.is_empty()
    {
        let user = state.store.get_user(&principal.id).await?;
        let stored = user.as_ref().map(|u| u.subject.as_str()).unwrap_or_default();
        if !subject_allowed(config, stored) {
            audit_refused(&state, ip, stored, "subject not in oidc.allowed_subjects").await;
            return Err(ApiError::forbidden());
        }
    }
    if let Some(max_age) = state.config.cli_login_max_auth_age {
        let auth_time = state
            .store
            .list_principal_tokens(PrincipalKind::User, &principal.id)
            .await?
            .into_iter()
            .find(|t| t.id == principal.token_id)
            .and_then(|t| t.auth_time);
        if !fresh_enough(auth_time, max_age, state.clock.now()) {
            let encoded = url::form_urlencoded::byte_serialize(code.as_bytes()).collect::<String>();
            return Err(ApiError::reauthentication_required(&reauth_url(&format!(
                "/cli-login?code={encoded}"
            ))));
        }
    }
    let now = state.clock.now();
    let Some(login) = state.store.get_cli_login(&code, now).await? else {
        return Err(ApiError::not_found("login code"));
    };
    let key = state.keyring.integrity(state.store.as_ref()).await?;
    let mac = crate::auth::cli_approval_mac(&key, &login.device_code_hash, &principal.id)?;
    if !state.store.approve_cli_login(&code, &principal.id, now, &mac).await? {
        return Err(ApiError::not_found("login code"));
    }
    audit(
        &state,
        &principal,
        ip,
        "auth.cli-approve",
        AuditTarget::default(),
        requester_details(&login),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// How long a CLI token may be renewed to. With re-authentication on, or when the user's access
/// may come from identity provider groups, which only refresh at the next browser sign-in, it
/// cannot be renewed past its first TTL.
pub(crate) fn cli_max_ttl(state: &AppState, groups: &[String]) -> i64 {
    let fixed = state.config.cli_login_max_auth_age.is_some() || !groups.is_empty();
    renewal_limit(state.config.cli_token_ttl, fixed)
}

fn renewal_limit(ttl: i64, fixed: bool) -> i64 {
    if fixed {
        return ttl;
    }
    ttl.saturating_mul(7)
}

#[utoipa::path(post, path = "/api/v1/auth/cli/poll", tag = "auth", request_body = CliPollRequest,
    responses((status = 200, body = TokenResponse), (status = 400, body = sekret_api::ErrorBody),
        (status = 429, body = sekret_api::ErrorBody)))]
pub async fn cli_poll(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(request): Json<CliPollRequest>,
) -> ApiResult<Json<TokenResponse>> {
    if !state.poll_limiter.allow_ip(ip) {
        // The device flow's own answer for polling too fast (RFC 8628).
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "slow_down",
            "polling too fast; wait before asking again",
        ));
    }
    let now = state.clock.now();
    let device_code_hash = hash_token(&request.device_code);
    match state.store.poll_cli_login(&device_code_hash, now).await? {
        CliPoll::Pending => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "waiting for approval",
        )),
        CliPoll::Gone => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "login code expired or already used",
        )),
        CliPoll::Approved { user_id, mac } => {
            let key = state.keyring.integrity(state.store.as_ref()).await?;
            if !crate::auth::cli_approval_verified(&key, &device_code_hash, &user_id, mac.as_deref()) {
                tracing::error!("a CLI login approval fails its integrity check; it was not given through sekret");
                return Err(ApiError::login_failed());
            }
            let user = state
                .store
                .get_user(&user_id)
                .await?
                .filter(|u| !u.disabled)
                .ok_or_else(ApiError::login_failed)?;
            let minted = mint_token(
                &state,
                TokenRequest {
                    kind: TokenKind::Cli,
                    principal_kind: PrincipalKind::User,
                    principal_id: &user.id,
                    ttl: state.config.cli_token_ttl,
                    max_ttl: cli_max_ttl(&state, &user.groups),
                    description: "CLI login".into(),
                    source: String::new(),
                    auth_time: None,
                },
            )
            .await?;
            let principal = Principal {
                kind: PrincipalKind::User,
                id: user.id.clone(),
                name: user.name.clone(),
                email: user.email.clone(),
                groups: user.groups.clone(),
                token_id: minted.record.id.clone(),
                token_kind: minted.record.kind.clone(),
            };
            audit(
                &state,
                &principal,
                ip,
                "auth.cli-login",
                AuditTarget::default(),
                json!({}),
            )
            .await;
            Ok(Json(TokenResponse {
                access_token: minted.token.to_string(),
                token_type: "Bearer".into(),
                expires_in: minted.record.expires_at - now,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_is_restricted_to_local_paths() {
        assert_eq!(safe_return_to(Some("/projects/app")), "/projects/app");
        assert_eq!(safe_return_to(Some("//evil.test")), "/");
        assert_eq!(safe_return_to(Some("https://evil.test")), "/");
        assert_eq!(safe_return_to(Some("/\\evil.test")), "/");
        assert_eq!(safe_return_to(Some("/\t/evil.test")), "/");
        assert_eq!(safe_return_to(Some("/\n/evil.test")), "/");
        assert_eq!(safe_return_to(Some("/ /evil.test")), "/");
        assert_eq!(safe_return_to(None), "/");
    }

    #[test]
    fn return_to_rejects_paths_that_normalise_to_another_host() {
        for attack in [
            "/..//evil.test",
            "/../..//evil.test/x",
            "/./..//evil.test",
            "/%2e%2e//evil.test",
            "/%2E%2E//evil.test",
            "/a/../..//evil.test",
        ] {
            assert_eq!(safe_return_to(Some(attack)), "/", "{attack}");
        }
        assert_eq!(safe_return_to(Some("/a/../projects?x=1#y")), "/projects?x=1#y");
        assert_eq!(
            safe_return_to(Some("/cli-login?code=AB%2DCD")),
            "/cli-login?code=AB%2DCD"
        );
    }

    fn oidc_config(required_groups: &[&str], allowed_subjects: &[&str]) -> HumanOidcConfig {
        let strings = |values: &[&str]| values.iter().map(|v| v.to_string()).collect();
        HumanOidcConfig {
            issuer: "https://id.example".into(),
            client_id: "sekret".into(),
            client_secret: String::new(),
            scopes: vec![],
            group_claims: vec![],
            admin_groups: vec![],
            required_groups: strings(required_groups),
            allowed_subjects: strings(allowed_subjects),
        }
    }

    #[test]
    fn id_tokens_must_be_issued_to_this_client() {
        assert!(issued_to(&json!({"aud": "sekret"}), "sekret"));
        assert!(issued_to(&json!({"aud": "sekret", "azp": "sekret"}), "sekret"));
        assert!(issued_to(
            &json!({"aud": ["sekret", "other"], "azp": "sekret"}),
            "sekret"
        ));
        assert!(!issued_to(&json!({"aud": "sekret", "azp": "other"}), "sekret"));
        assert!(!issued_to(&json!({"aud": ["sekret", "other"]}), "sekret"));
        assert!(!issued_to(&json!({"aud": "sekret", "azp": 7}), "sekret"));
    }

    #[test]
    fn allowed_subjects_are_checked_before_groups() {
        let users = vec!["sekret-users".to_string()];
        let open = oidc_config(&[], &[]);
        assert_eq!(login_refusal(&open, "anyone", &[]), None, "empty means everyone");
        let grouped = oidc_config(&["sekret-users"], &[]);
        assert_eq!(login_refusal(&grouped, "anyone", &users), None);
        assert!(login_refusal(&grouped, "anyone", &[]).is_some());
        let pinned = oidc_config(&["sekret-users"], &["owner"]);
        assert_eq!(login_refusal(&pinned, "owner", &users), None);
        assert_eq!(
            login_refusal(&pinned, "intruder", &users),
            Some("subject not in oidc.allowed_subjects"),
            "the right groups are not enough"
        );
        assert!(login_refusal(&pinned, "owner", &[]).is_some(), "groups still apply");
    }

    #[test]
    fn stored_subjects_are_matched_under_the_issuer() {
        let pinned = oidc_config(&[], &["owner"]);
        assert!(subject_allowed(&pinned, "https://id.example|owner"));
        assert!(!subject_allowed(&pinned, "https://id.example|intruder"));
        assert!(!subject_allowed(&pinned, "https://other.example|owner"));
        assert!(subject_allowed(&oidc_config(&[], &[]), "anything"));
    }

    #[test]
    fn recent_enough_sign_ins_allow_a_minute_of_skew() {
        assert!(fresh_enough(Some(1000), 900, 1000));
        assert!(fresh_enough(Some(1000), 900, 1960));
        assert!(!fresh_enough(Some(1000), 900, 1961));
        assert!(!fresh_enough(None, 900, 1000));
        assert!(
            !fresh_enough(Some(5000), 900, 1000),
            "a time far in the future is not trusted"
        );
        assert_eq!(
            reauth_url("/cli-login?code=AB-CD"),
            "/auth/login?reauth=1&return_to=%2Fcli-login%3Fcode%3DAB-CD"
        );
    }

    #[test]
    fn only_a_verified_email_labels_the_user() {
        let cases = [
            (
                json!({"email": "a@x", "email_verified": true, "name": "Ann"}),
                "a@x",
                "Ann",
            ),
            (json!({"email": "a@x", "email_verified": "true"}), "a@x", "a@x"),
            (json!({"email": "cfo@x", "name": "Mallory"}), "", "Mallory"),
            (json!({"email": "cfo@x", "email_verified": false}), "", "sub-1"),
            (
                json!({"email": "cfo@x", "email_verified": "no", "preferred_username": "mal"}),
                "",
                "mal",
            ),
            (json!({"email": "", "email_verified": true, "name": ""}), "", "sub-1"),
            (
                json!({"email": "m@x", "name": "cfo@example.com"}),
                "",
                "cfo@example.com (unverified)",
            ),
            (
                json!({"preferred_username": "cfo@example.com"}),
                "",
                "cfo@example.com (unverified)",
            ),
            (
                json!({"email": "a@x", "email_verified": true, "name": "a@y"}),
                "a@x",
                "a@y",
            ),
        ];
        for (claims, email, name) in cases {
            assert_eq!(
                user_labels(&claims, "sub-1"),
                (email.to_string(), name.to_string()),
                "{claims}"
            );
        }
    }

    #[test]
    fn provider_errors_cannot_forge_log_lines() {
        let forged = format!(
            "x\n2026-01-01T00:00:00Z  INFO sekret_server: unsealed{}",
            "y".repeat(500)
        );
        let logged = format!("{:?}", loggable(&forged));
        assert!(!logged.contains('\n'));
        assert!(logged.chars().count() <= 64 + 4, "{logged}");
    }

    #[test]
    fn login_errors_redirect_with_fixed_codes_only() {
        let all = [
            (LoginError::ProviderRefused, "provider_refused"),
            (LoginError::IncompleteResponse, "incomplete_response"),
            (LoginError::OtherBrowser, "other_browser"),
            (LoginError::Expired, "expired"),
            (LoginError::ReauthNotPerformed, "reauth_not_performed"),
            (LoginError::NotAllowed, "not_allowed"),
            (LoginError::AccountDisabled, "account_disabled"),
        ];
        let mut seen = std::collections::HashSet::new();
        for (error, code) in all {
            assert_eq!(error.code(), code);
            assert!(seen.insert(code), "{code} is used twice");
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{code} needs no escaping and carries no prose"
            );
            let response = login_error(error);
            let location = response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok());
            assert_eq!(location, Some(format!("/login?error={code}").as_str()));
        }
    }

    #[test]
    fn the_login_state_cookie_is_host_only_over_https() -> anyhow::Result<()> {
        let mut config = ServerConfig::for_tests("sqlite::memory:");
        config.public_url = "https://sekret.example".into();
        let cookie = login_state_cookie(&config, "abc", 600).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let cookie = cookie.to_str()?;
        assert!(cookie.starts_with("__Host-sekret_login=abc;"), "{cookie}");
        assert!(cookie.contains("Path=/;") && cookie.contains("Secure"), "{cookie}");
        assert!(!cookie.contains("Domain"), "{cookie}");
        assert_eq!(login_state_cookie_name(&config), SECURE_LOGIN_STATE_COOKIE);

        config.public_url = "http://localhost:8200".into();
        let cookie = login_state_cookie(&config, "abc", 600).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let cookie = cookie.to_str()?;
        assert!(cookie.starts_with("sekret_login=abc;"), "{cookie}");
        assert!(cookie.contains("Path=/auth") && !cookie.contains("Secure"), "{cookie}");
        Ok(())
    }

    #[test]
    fn requester_text_loses_bidi_and_invisible_characters() -> anyhow::Result<()> {
        let spoofed = "sekret/1.0 \u{202E}xunil\u{202C} \u{2066}x\u{2069}\u{200B}\u{FEFF}\u{E0041}\u{061C}(Linux)";
        assert_eq!(shown_text(spoofed, 200), "sekret/1.0 xunil x(Linux)");
        assert_eq!(shown_text("a\u{0}b\nc\u{7F}", 200), "abc");
        assert_eq!(shown_text(&"y".repeat(500), 200).len(), 200);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_bytes("curl \u{202E}1.8".as_bytes())?,
        );
        assert_eq!(shown_user_agent(&headers), "", "a non-ASCII agent is not shown at all");
        headers.insert(header::USER_AGENT, HeaderValue::from_static("sekret/1.0 (linux)"));
        assert_eq!(shown_user_agent(&headers), "sekret/1.0 (linux)");
        Ok(())
    }

    #[test]
    fn cli_renewal_limits_cannot_overflow() {
        assert_eq!(renewal_limit(3600, false), 7 * 3600);
        assert_eq!(renewal_limit(3600, true), 3600);
        assert_eq!(renewal_limit(i64::MAX / 2, false), i64::MAX);
        assert_eq!(renewal_limit(i64::MAX, true), i64::MAX);
    }

    #[test]
    fn pkce_matches_rfc_7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn groups_from_flat_and_nested_claims() {
        let claims =
            json!({"roles": ["sekret-admin", "guest-x"], "groups": "/devs", "realm_access": {"roles": ["offline"]}});
        let groups = extract_groups(
            &claims,
            &[
                "roles".into(),
                "groups".into(),
                "/realm_access/roles".into(),
                "missing".into(),
            ],
        );
        assert_eq!(groups, vec!["/devs", "guest-x", "offline", "sekret-admin"]);
    }

    #[test]
    fn user_codes_are_readable() -> anyhow::Result<()> {
        let code = user_code().map_err(|e| anyhow::anyhow!("code: {e:?}"))?;
        assert_eq!(code.len(), 9);
        assert_eq!(&code[4..5], "-");
        assert!(
            code.chars()
                .filter(|c| *c != '-')
                .all(|c| USER_CODE_ALPHABET.contains(&(c as u8)))
        );
        Ok(())
    }
}
