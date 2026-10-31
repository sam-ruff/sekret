mod common;

use std::collections::HashMap;

use anyhow::Context;
use base64::Engine;
use common::{Harness, Options, start};
use reqwest::{Method, StatusCode};
use sekret_server::config::HumanOidcConfig;
use sekret_server::testkit::TestIssuer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn issuer() -> (MockServer, TestIssuer) {
    let server = MockServer::start().await;
    let issuer = TestIssuer::new(&server.uri());
    mount_keys(&server, &issuer).await;
    (server, issuer)
}

async fn mount_keys(server: &MockServer, issuer: &TestIssuer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issuer.discovery()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issuer.jwks()))
        .mount(server)
        .await;
}

fn oidc_config(issuer: &TestIssuer) -> HumanOidcConfig {
    HumanOidcConfig {
        issuer: issuer.url.clone(),
        client_id: "sekret".into(),
        client_secret: "client-secret".into(),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        group_claims: vec!["roles".into()],
        admin_groups: vec!["sekret-admin".into()],
        required_groups: vec![],
        allowed_subjects: vec![],
    }
}

fn query(location: &str) -> anyhow::Result<HashMap<String, String>> {
    Ok(url::Url::parse(location)
        .context("url")?
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect())
}

/// Runs the browser sign-in; the inner result is the session cookie value or why the server refused it.
async fn browser_login(
    h: &Harness,
    server: &MockServer,
    issuer: &TestIssuer,
    roles: &[&str],
    nonce_override: Option<&str>,
) -> anyhow::Result<Result<String, String>> {
    let response = h
        .client
        .get(format!("{}/auth/login?return_to=/projects", h.base))
        .send()
        .await
        .context("login")?;
    assert!(response.status().is_redirection());
    let location = response.headers()["location"].to_str().context("location")?.to_string();
    let params = query(&location)?;
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["redirect_uri"], format!("{}/auth/callback", h.base));
    let nonce = nonce_override.unwrap_or(&params["nonce"]).to_string();
    let id_token = issuer.sign(json!({"aud": "sekret", "sub": "alice", "email": "alice@example.com", "name": "Alice", "nonce": nonce, "roles": roles}))?;
    server.reset().await;
    mount_keys(server, issuer).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id_token": id_token, "access_token": "x", "token_type": "Bearer"})),
        )
        .mount(server)
        .await;
    let login_cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("sekret_login="))
        .and_then(|c| c.split(';').next())
        .context("login state cookie")?
        .to_string();
    let callback_url = format!("{}/auth/callback?code=the-code&state={}", h.base, params["state"]);
    let elsewhere = h.client.get(&callback_url).send().await.context("callback")?;
    assert!(
        elsewhere.headers()["location"]
            .to_str()
            .is_ok_and(|l| l.starts_with("/login?error=")),
        "a callback from a browser without the login cookie is refused"
    );
    let callback = h
        .client
        .get(&callback_url)
        .header("cookie", login_cookie)
        .send()
        .await
        .context("callback")?;

    let requests = server.received_requests().await.unwrap_or_default();
    if let Some(exchange) = requests.iter().find(|r| r.url.path() == "/token") {
        let form: HashMap<String, String> = url::form_urlencoded::parse(&exchange.body).into_owned().collect();
        let challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes()));
        assert_eq!(
            challenge, params["code_challenge"],
            "PKCE verifier must match the challenge"
        );
        assert_eq!(form["code"], "the-code");
    }

    let target = callback
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let Some(cookie) = callback
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("sekret_session="))
        .map(String::from)
    else {
        return Ok(Err(format!("{} {target}", callback.status())));
    };
    assert_eq!(target, "/projects");
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"));
    let value = cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .context("cookie")?;
    Ok(Ok(value))
}

async fn with_cookie(
    h: &Harness,
    method: Method,
    path: &str,
    session: &str,
    csrf: bool,
    body: Option<Value>,
) -> anyhow::Result<(StatusCode, Value)> {
    let mut request = h
        .client
        .request(method, format!("{}{path}", h.base))
        .header("cookie", format!("sekret_session={session}"));
    if csrf {
        request = request.header("x-sekret-csrf", "1");
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.context("request")?;
    let status = response.status();
    Ok((status, response.json().await.unwrap_or(Value::Null)))
}

#[tokio::test]
async fn browser_login_sessions_csrf_and_cli_flow() -> anyhow::Result<()> {
    let (server, issuer) = issuer().await;
    let h = start(Options {
        oidc: Some(oidc_config(&issuer)),
        ..Default::default()
    })
    .await?;

    let (_, config) = h.call(Method::GET, "/api/v1/auth/config", None, None).await?;
    assert_eq!(config["oidc_enabled"], true);

    let session = browser_login(&h, &server, &issuer, &["sekret-admin"], None)
        .await?
        .map_err(anyhow::Error::msg)
        .context("login")?;
    let (status, me) = with_cookie(&h, Method::GET, "/api/v1/me", &session, false, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["email"], "alice@example.com");
    assert!(
        me["org_rules"]
            .as_array()
            .is_some_and(|r| r.iter().any(|rule| rule["subject"] == "identities")),
        "sekret-admin maps to org admin"
    );

    let create = json!({"slug": "web", "name": "Web"});
    let (status, body) = with_cookie(
        &h,
        Method::POST,
        "/api/v1/projects",
        &session,
        false,
        Some(create.clone()),
    )
    .await?;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("csrf")));
    let (status, _) = with_cookie(&h, Method::POST, "/api/v1/projects", &session, true, Some(create)).await?;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = h.get("/api/v1/me", &session).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "session tokens are not bearer tokens");

    // CLI device login, started by a client the person can recognise.
    let response = h
        .client
        .post(format!("{}/api/v1/auth/cli/start", h.base))
        .header("user-agent", "sekret-cli/9.9 (test)")
        .send()
        .await
        .context("start")?;
    assert_eq!(response.status(), StatusCode::OK);
    let start_body: Value = response.json().await.context("start body")?;
    assert!(start_body["expires_in"].as_i64().is_some_and(|ttl| ttl <= 600));
    let poll = json!({"device_code": start_body["device_code"]});
    let (status, pending) = h
        .call(Method::POST, "/api/v1/auth/cli/poll", None, Some(poll.clone()))
        .await?;
    assert_eq!(
        (status, pending["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("authorization_pending"))
    );
    let code = start_body["user_code"].as_str().context("user code")?;
    let pending_path = format!("/api/v1/auth/cli/pending?code={code}");
    let (status, shown) = with_cookie(&h, Method::GET, &pending_path, &session, false, None).await?;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(shown["requested_from_ip"], "127.0.0.1");
    assert_eq!(shown["user_agent"], "sekret-cli/9.9 (test)");
    assert!(shown["created_at"].as_i64().is_some() && shown["expires_at"].as_i64().is_some());
    assert!(shown.get("code_hint").is_none(), "the code is never handed back");
    let (status, _) = h.get(&pending_path, &h.admin).await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "only browser sessions see pending logins"
    );

    let approve = json!({"code": code.to_lowercase().replace('-', " ")});
    let (status, _) = h.post("/api/v1/auth/cli/approve", &h.admin, approve.clone()).await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "only browser sessions may approve CLI logins"
    );
    // A link carrying the code is not approval; the body must hold a code typed by the person.
    let (status, _) = with_cookie(
        &h,
        Method::POST,
        "/api/v1/auth/cli/approve",
        &session,
        true,
        Some(json!({"user_code": code})),
    )
    .await?;
    assert!(status.is_client_error() && status != StatusCode::NO_CONTENT);
    let (status, _) = with_cookie(
        &h,
        Method::POST,
        "/api/v1/auth/cli/approve",
        &session,
        true,
        Some(json!({"code": "BCDF-GHJK"})),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "a wrong code approves nothing");
    let (status, _) = with_cookie(
        &h,
        Method::POST,
        "/api/v1/auth/cli/approve",
        &session,
        true,
        Some(approve),
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, token) = h
        .call(Method::POST, "/api/v1/auth/cli/poll", None, Some(poll.clone()))
        .await?;
    assert_eq!(status, StatusCode::OK);
    let cli_token = token["access_token"].as_str().context("token")?;
    let (_, me) = h.get("/api/v1/me", cli_token).await?;
    assert_eq!(me["email"], "alice@example.com");
    let record = h
        .state
        .store
        .find_token(&sekret_core::crypto::hash_token(cli_token))
        .await?
        .context("cli token")?;
    assert_eq!(
        record.max_expires_at - record.created_at,
        h.state.config.cli_token_ttl,
        "access from groups cannot be renewed past the first TTL"
    );
    let (_, gone) = h.call(Method::POST, "/api/v1/auth/cli/poll", None, Some(poll)).await?;
    assert_eq!(gone["error"], "expired_token");

    let (status, logout) = with_cookie(&h, Method::POST, "/auth/logout", &session, true, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        logout["logout_url"]
            .as_str()
            .is_some_and(|u| u.starts_with(&issuer.url))
    );
    let (status, _) = with_cookie(&h, Method::GET, "/api/v1/me", &session, false, None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, audit) = h.get("/api/v1/audit?action=auth.logout", &h.admin).await?;
    assert_eq!(audit["entries"].as_array().map(Vec::len), Some(1), "{audit}");
    Ok(())
}

/// A session for a user stored with `subject` and `groups`, as a sign-in would leave it.
async fn stored_session(h: &Harness, subject: &str, groups: &[&str]) -> anyhow::Result<(String, String)> {
    let now = h.state.clock.now();
    let user = h
        .state
        .store
        .upsert_user(sekret_store::UserLogin {
            subject: subject.into(),
            email: format!("{}@example.com", uuid::Uuid::new_v4()),
            name: subject.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            now,
        })
        .await?;
    let token = format!("skt_{}", uuid::Uuid::new_v4().simple());
    h.state
        .store
        .create_token(sekret_store::AccessToken {
            id: uuid::Uuid::new_v4().to_string(),
            token_hash: sekret_core::crypto::hash_token(&token),
            kind: "session".into(),
            principal_kind: sekret_store::PrincipalKind::User,
            principal_id: user.id.clone(),
            description: "browser session".into(),
            source: String::new(),
            created_at: now,
            expires_at: now + 3600,
            max_expires_at: now + 3600,
            revoked: false,
            last_used_at: None,
            auth_time: Some(now),
        })
        .await?;
    Ok((user.id, token))
}

async fn start_cli_login(h: &Harness) -> anyhow::Result<(String, Value)> {
    let request = h
        .client
        .post(format!("{}/api/v1/auth/cli/start", h.base))
        .header("user-agent", "sekret-cli/9.9 (test)");
    let body: Value = request
        .send()
        .await
        .context("start")?
        .json()
        .await
        .context("start body")?;
    let code = body["user_code"].as_str().context("user code")?.to_string();
    Ok((code, json!({"device_code": body["device_code"]})))
}

async fn cli_requests_can_be_denied_and_are_audited_with_their_origin(database_url: String) -> anyhow::Result<()> {
    let (_server, issuer) = issuer().await;
    let h = start(Options {
        oidc: Some(oidc_config(&issuer)),
        ..common::options(database_url)
    })
    .await?;
    let (_, session) = stored_session(&h, &format!("{}|alice", issuer.url), &["sekret-admin"]).await?;

    let (code, poll) = start_cli_login(&h).await?;
    let pending_path = format!("/api/v1/auth/cli/pending?code={code}");
    let (status, shown) = with_cookie(&h, Method::GET, &pending_path, &session, false, None).await?;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(shown["same_address"], true, "{shown}");

    let deny = |code: &str| Some(json!({"code": code.to_lowercase()}));
    let (status, _) = h.post("/api/v1/auth/cli/deny", &h.admin, json!({"code": code})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "only browser sessions may deny");
    let (status, _) = with_cookie(&h, Method::POST, "/api/v1/auth/cli/deny", &session, false, deny(&code)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "denying needs the CSRF header");
    let (status, _) = with_cookie(&h, Method::POST, "/api/v1/auth/cli/deny", &session, true, deny(&code)).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, gone) = h.call(Method::POST, "/api/v1/auth/cli/poll", None, Some(poll)).await?;
    assert_eq!(gone["error"], "expired_token", "the terminal is told at once");
    let (status, _) = with_cookie(&h, Method::GET, &pending_path, &session, false, None).await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "a denied request is consumed");
    let (status, _) = with_cookie(
        &h,
        Method::POST,
        "/api/v1/auth/cli/approve",
        &session,
        true,
        Some(json!({"code": code})),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "a denied request cannot be approved");
    let (status, _) = with_cookie(&h, Method::POST, "/api/v1/auth/cli/deny", &session, true, deny(&code)).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Approval records where the request came from.
    let (code, _) = start_cli_login(&h).await?;
    let (status, _) = with_cookie(
        &h,
        Method::POST,
        "/api/v1/auth/cli/approve",
        &session,
        true,
        Some(json!({"code": code})),
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, denied) = h.get("/api/v1/audit?action=auth.cli-deny", &h.admin).await?;
    let (_, approved) = h.get("/api/v1/audit?action=auth.cli-approve", &h.admin).await?;
    for (audit, label) in [(denied, "deny"), (approved, "approve")] {
        let entry = audit["entries"].get(0).context("entry")?;
        assert_eq!(entry["detail"]["requested_from_ip"], "127.0.0.1", "{label}: {entry}");
        assert_eq!(entry["detail"]["user_agent"], "sekret-cli/9.9 (test)", "{label}");
        assert!(entry["detail"]["requested_at"].as_i64().is_some(), "{label}");
    }
    Ok(())
}

on_both_backends!(cli_requests_can_be_denied_and_are_audited_with_their_origin);

/// Narrowing the sign-in lists takes effect at once, not at each person's next sign-in.
#[tokio::test]
async fn sessions_from_before_the_sign_in_lists_narrowed_stop_working() -> anyhow::Result<()> {
    let (_server, issuer) = issuer().await;
    let mut config = oidc_config(&issuer);
    config.required_groups = vec!["sekret-users".into()];
    config.allowed_subjects = vec!["alice".into(), "bob".into()];
    let h = start(Options {
        oidc: Some(config),
        ..Default::default()
    })
    .await?;
    let stored = |sub: &str| format!("{}|{sub}", issuer.url);
    let (_, allowed) = stored_session(&h, &stored("alice"), &["sekret-users"]).await?;
    let (_, outsider) = stored_session(&h, &stored("mallory"), &["sekret-users"]).await?;
    let (_, ungrouped) = stored_session(&h, &stored("bob"), &["guests"]).await?;
    let me = |session: &str| {
        let session = session.to_string();
        let h = &h;
        async move { with_cookie(h, Method::GET, "/api/v1/me", &session, false, None).await }
    };
    assert_eq!(me(&allowed).await?.0, StatusCode::OK);
    assert_eq!(me(&outsider).await?.0, StatusCode::UNAUTHORIZED);
    assert_eq!(me(&ungrouped).await?.0, StatusCode::UNAUTHORIZED);
    let (status, _) = h.get("/api/v1/me", &h.admin).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the local break-glass admin is not an OIDC user"
    );

    let revoked = sekret_server::auth::revoke_disallowed_users(&h.state)
        .await
        .map_err(common::api_error("revoke"))?;
    assert_eq!(revoked, 2);
    let record = h
        .state
        .store
        .find_token(&sekret_core::crypto::hash_token(&outsider))
        .await?
        .context("token")?;
    assert!(record.revoked, "revoked at start, not just refused");
    assert_eq!(me(&allowed).await?.0, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn browser_login_rejects_bad_nonce_replay_and_missing_groups() -> anyhow::Result<()> {
    let (server, issuer) = issuer().await;
    let mut config = oidc_config(&issuer);
    config.required_groups = vec!["sekret-users".into()];
    let h = start(Options {
        oidc: Some(config),
        ..Default::default()
    })
    .await?;

    let wrong_nonce = browser_login(&h, &server, &issuer, &["sekret-users"], Some("attacker")).await?;
    assert!(wrong_nonce.err().context("wrong nonce is refused")?.starts_with("401"));

    let not_allowed = browser_login(&h, &server, &issuer, &["guest-x"], None).await?;
    assert!(
        not_allowed
            .err()
            .context("missing group is refused")?
            .contains("/login?error=")
    );

    let ok = browser_login(&h, &server, &issuer, &["sekret-users"], None).await?;
    assert!(ok.is_ok());

    let response = h
        .client
        .get(format!("{}/auth/callback?code=x&state=unknown", h.base))
        .send()
        .await
        .context("callback")?;
    assert!(
        response.headers()["location"]
            .to_str()
            .context("location")?
            .starts_with("/login?error=")
    );
    let response = h
        .client
        .get(format!("{}/auth/login?return_to=//evil.test", h.base))
        .send()
        .await
        .context("login")?;
    assert!(response.status().is_redirection());
    Ok(())
}

async fn identity_with(h: &Harness, method_kind: &str, config: Value) -> anyhow::Result<String> {
    let name = format!("{method_kind}-{}", uuid::Uuid::new_v4());
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": name})).await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    let (status, body) = h
        .put(&format!("/api/v1/identities/{id}/auth/{method_kind}"), &h.admin, config)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = h
        .post(
            "/api/v1/projects/app/members",
            &h.admin,
            json!({"principal_kind": "identity", "principal_id": id, "role": "viewer"}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Ok(id)
}

async fn jwt_login(h: &Harness, kind: &str, id: &str, token: &str) -> anyhow::Result<(StatusCode, Value)> {
    h.call(
        Method::POST,
        &format!("/api/v1/auth/{kind}/login"),
        None,
        Some(json!({"identity_id": id, "token": token})),
    )
    .await
}

#[tokio::test]
async fn machine_oidc_login_for_ci() -> anyhow::Result<()> {
    let (_server, issuer) = issuer().await;
    let h = start(Options::default()).await?;
    h.create_project("app").await?;
    h.set_secrets("app", "prod", "/", &[("DEPLOY_KEY", "k")]).await?;
    let id = identity_with(&h, "oidc", json!({
        "kind": "oidc",
        "issuer": issuer.url,
        "bindings": {"audiences": ["sekret"], "subjects": ["repo:sam-ruff/*:ref:refs/heads/main"], "claims": {"repository_owner": ["sam-ruff"]}}
    }))
    .await?;

    let good = issuer.sign(
        json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"}),
    )?;
    let (status, token) = jwt_login(&h, "oidc", &id, &good).await?;
    assert_eq!(status, StatusCode::OK, "{token}");
    let (_, raw) = h
        .get(
            "/api/v1/secrets/raw?project=app&environment=prod",
            token["access_token"].as_str().context("token")?,
        )
        .await?;
    assert_eq!(raw["secrets"][0]["value"], "k");

    for bad in [
        issuer.sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/feature", "repository_owner": "sam-ruff"}))?,
        issuer.sign(json!({"aud": "other", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"}))?,
        issuer.sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff", "exp": issuer.now - 600}))?,
        TestIssuer::with_key(&issuer.url, 2).sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"}))?,
    ] {
        let (status, body) = jwt_login(&h, "oidc", &id, &bad).await?;
        assert_eq!((status, body["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("login_failed")));
    }
    let (status, _) = jwt_login(&h, "kubernetes", &id, &good).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "methods that are not configured are refused"
    );
    let (status, _) = jwt_login(&h, "oidc", "no-such-identity", &good).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn kubernetes_login_with_jwks_and_token_review() -> anyhow::Result<()> {
    let (server, issuer) = issuer().await;
    let h = start(Options::default()).await?;
    h.create_project("app").await?;

    let jwks_id = identity_with(
        &h,
        "kubernetes",
        json!({
            "kind": "kubernetes", "mode": "jwks", "issuer": issuer.url, "jwks_url": issuer.jwks_url(),
            "namespaces": ["apps"], "service_accounts": ["web"], "audiences": ["sekret"]
        }),
    )
    .await?;
    let sa_token = issuer.sign(json!({"aud": ["sekret"], "sub": "system:serviceaccount:apps:web"}))?;
    let (status, body) = jwt_login(&h, "kubernetes", &jwks_id, &sa_token).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let other_ns = issuer.sign(json!({"aud": ["sekret"], "sub": "system:serviceaccount:kube-system:web"}))?;
    assert_eq!(
        jwt_login(&h, "kubernetes", &jwks_id, &other_ns).await?.0,
        StatusCode::UNAUTHORIZED
    );

    Mock::given(method("POST"))
        .and(path("/apis/authentication.k8s.io/v1/tokenreviews"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "status": {"authenticated": true, "user": {"username": "system:serviceaccount:apps:worker"}, "audiences": ["sekret"]}
        })))
        .mount(&server)
        .await;
    let review_id = identity_with(
        &h,
        "kubernetes",
        json!({
            "kind": "kubernetes", "mode": "token-review", "host": server.uri(),
            "namespaces": ["apps"], "service_accounts": ["worker"], "audiences": ["sekret"]
        }),
    )
    .await?;
    // The lifetime cap always applies, so a token whose lifetime cannot be read is refused even
    // though the API server accepts it.
    let (status, _) = jwt_login(&h, "kubernetes", &review_id, "opaque-sa-token").await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let worker_token = issuer.sign(json!({"sub": "system:serviceaccount:apps:worker"}))?;
    let (status, body) = jwt_login(&h, "kubernetes", &review_id, &worker_token).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let review = server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .rfind(|r| r.url.path().ends_with("tokenreviews"))
        .context("token review sent")?;
    assert_eq!(
        review.headers["authorization"],
        format!("Bearer {worker_token}").as_str()
    );
    let sent: Value = serde_json::from_slice(&review.body).context("json")?;
    assert_eq!(sent["spec"]["audiences"], json!(["sekret"]));
    Ok(())
}

#[tokio::test]
async fn auth_method_configs_are_validated() -> anyhow::Result<()> {
    let h = start(Options::default()).await?;
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "x"})).await?;
    let id = identity["id"].as_str().context("id")?;
    let unbounded = json!({"kind": "oidc", "issuer": "https://token.actions.githubusercontent.com", "bindings": {"audiences": ["sekret"]}});
    let (status, _) = h
        .put(&format!("/api/v1/identities/{id}/auth/oidc"), &h.admin, unbounded)
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mismatched = json!({"kind": "universal"});
    let (status, _) = h
        .put(&format!("/api/v1/identities/{id}/auth/oidc"), &h.admin, mismatched)
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}
