mod common;

use std::collections::HashMap;

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
    }
}

fn query(location: &str) -> HashMap<String, String> {
    url::Url::parse(location)
        .expect("url")
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Runs the browser sign-in and returns the session cookie value.
async fn browser_login(
    h: &Harness,
    server: &MockServer,
    issuer: &TestIssuer,
    roles: &[&str],
    nonce_override: Option<&str>,
) -> Result<String, String> {
    let response = h
        .client
        .get(format!("{}/auth/login?return_to=/projects", h.base))
        .send()
        .await
        .expect("login");
    assert!(response.status().is_redirection());
    let location = response.headers()["location"].to_str().expect("location").to_string();
    let params = query(&location);
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["redirect_uri"], format!("{}/auth/callback", h.base));
    let nonce = nonce_override.unwrap_or(&params["nonce"]).to_string();
    let id_token = issuer.sign(json!({"aud": "sekret", "sub": "alice", "email": "alice@example.com", "name": "Alice", "nonce": nonce, "roles": roles}));
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
        .expect("login state cookie")
        .to_string();
    let callback_url = format!("{}/auth/callback?code=the-code&state={}", h.base, params["state"]);
    let elsewhere = h.client.get(&callback_url).send().await.expect("callback");
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
        .expect("callback");

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
        return Err(format!("{} {target}", callback.status()));
    };
    assert_eq!(target, "/projects");
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"));
    let value = cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .expect("cookie");
    Ok(value)
}

async fn with_cookie(
    h: &Harness,
    method: Method,
    path: &str,
    session: &str,
    csrf: bool,
    body: Option<Value>,
) -> (StatusCode, Value) {
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
    let response = request.send().await.expect("request");
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn browser_login_sessions_csrf_and_cli_flow() {
    let (server, issuer) = issuer().await;
    let h = start(Options {
        oidc: Some(oidc_config(&issuer)),
        ..Default::default()
    })
    .await;

    let (_, config) = h.call(Method::GET, "/api/v1/auth/config", None, None).await;
    assert_eq!(config["oidc_enabled"], true);

    let session = browser_login(&h, &server, &issuer, &["sekret-admin"], None)
        .await
        .expect("login");
    let (status, me) = with_cookie(&h, Method::GET, "/api/v1/me", &session, false, None).await;
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
    .await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("csrf")));
    let (status, _) = with_cookie(&h, Method::POST, "/api/v1/projects", &session, true, Some(create)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = h.get("/api/v1/me", &session).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "session tokens are not bearer tokens");

    // CLI device login.
    let (status, start_body) = h.call(Method::POST, "/api/v1/auth/cli/start", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let poll = json!({"device_code": start_body["device_code"]});
    let (status, pending) = h
        .call(Method::POST, "/api/v1/auth/cli/poll", None, Some(poll.clone()))
        .await;
    assert_eq!(
        (status, pending["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("authorization_pending"))
    );
    let approve = json!({"user_code": start_body["user_code"]});
    let (status, _) = h.post("/api/v1/auth/cli/approve", &h.admin, approve.clone()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "only browser sessions may approve CLI logins"
    );
    let (status, _) = with_cookie(
        &h,
        Method::POST,
        "/api/v1/auth/cli/approve",
        &session,
        true,
        Some(approve),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, token) = h
        .call(Method::POST, "/api/v1/auth/cli/poll", None, Some(poll.clone()))
        .await;
    assert_eq!(status, StatusCode::OK);
    let cli_token = token["access_token"].as_str().expect("token");
    let (_, me) = h.get("/api/v1/me", cli_token).await;
    assert_eq!(me["email"], "alice@example.com");
    let (_, gone) = h.call(Method::POST, "/api/v1/auth/cli/poll", None, Some(poll)).await;
    assert_eq!(gone["error"], "expired_token");

    let (status, logout) = with_cookie(&h, Method::POST, "/auth/logout", &session, true, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        logout["logout_url"]
            .as_str()
            .is_some_and(|u| u.starts_with(&issuer.url))
    );
    let (status, _) = with_cookie(&h, Method::GET, "/api/v1/me", &session, false, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn browser_login_rejects_bad_nonce_replay_and_missing_groups() {
    let (server, issuer) = issuer().await;
    let mut config = oidc_config(&issuer);
    config.required_groups = vec!["sekret-users".into()];
    let h = start(Options {
        oidc: Some(config),
        ..Default::default()
    })
    .await;

    let wrong_nonce = browser_login(&h, &server, &issuer, &["sekret-users"], Some("attacker")).await;
    assert!(wrong_nonce.unwrap_err().starts_with("401"));

    let not_allowed = browser_login(&h, &server, &issuer, &["guest-x"], None).await;
    assert!(not_allowed.unwrap_err().contains("/login?error="));

    let ok = browser_login(&h, &server, &issuer, &["sekret-users"], None).await;
    assert!(ok.is_ok());

    let response = h
        .client
        .get(format!("{}/auth/callback?code=x&state=unknown", h.base))
        .send()
        .await
        .expect("callback");
    assert!(
        response.headers()["location"]
            .to_str()
            .expect("location")
            .starts_with("/login?error=")
    );
    let response = h
        .client
        .get(format!("{}/auth/login?return_to=//evil.test", h.base))
        .send()
        .await
        .expect("login");
    assert!(response.status().is_redirection());
}

async fn identity_with(h: &Harness, method_kind: &str, config: Value) -> String {
    let name = format!("{method_kind}-{}", uuid::Uuid::new_v4());
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": name})).await;
    let id = identity["id"].as_str().expect("id").to_string();
    let (status, body) = h
        .put(&format!("/api/v1/identities/{id}/auth/{method_kind}"), &h.admin, config)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = h
        .post(
            "/api/v1/projects/app/members",
            &h.admin,
            json!({"principal_kind": "identity", "principal_id": id, "role": "viewer"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    id
}

async fn jwt_login(h: &Harness, kind: &str, id: &str, token: &str) -> (StatusCode, Value) {
    h.call(
        Method::POST,
        &format!("/api/v1/auth/{kind}/login"),
        None,
        Some(json!({"identity_id": id, "token": token})),
    )
    .await
}

#[tokio::test]
async fn machine_oidc_login_for_ci() {
    let (_server, issuer) = issuer().await;
    let h = start(Options::default()).await;
    h.create_project("app").await;
    h.set_secrets("app", "prod", "/", &[("DEPLOY_KEY", "k")]).await;
    let id = identity_with(&h, "oidc", json!({
        "kind": "oidc",
        "issuer": issuer.url,
        "bindings": {"audiences": ["sekret"], "subjects": ["repo:sam-ruff/*:ref:refs/heads/main"], "claims": {"repository_owner": ["sam-ruff"]}}
    }))
    .await;

    let good = issuer
        .sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"}));
    let (status, token) = jwt_login(&h, "oidc", &id, &good).await;
    assert_eq!(status, StatusCode::OK, "{token}");
    let (_, raw) = h
        .get(
            "/api/v1/secrets/raw?project=app&environment=prod",
            token["access_token"].as_str().expect("token"),
        )
        .await;
    assert_eq!(raw["secrets"][0]["value"], "k");

    for bad in [
        issuer.sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/feature", "repository_owner": "sam-ruff"})),
        issuer.sign(json!({"aud": "other", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"})),
        issuer.sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff", "exp": issuer.now - 600})),
        TestIssuer::with_key(&issuer.url, 2).sign(json!({"aud": "sekret", "sub": "repo:sam-ruff/app:ref:refs/heads/main", "repository_owner": "sam-ruff"})),
    ] {
        let (status, body) = jwt_login(&h, "oidc", &id, &bad).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("login_failed")));
    }
    let (status, _) = jwt_login(&h, "kubernetes", &id, &good).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "methods that are not configured are refused"
    );
    let (status, _) = jwt_login(&h, "oidc", "no-such-identity", &good).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn kubernetes_login_with_jwks_and_token_review() {
    let (server, issuer) = issuer().await;
    let h = start(Options::default()).await;
    h.create_project("app").await;

    let jwks_id = identity_with(
        &h,
        "kubernetes",
        json!({
            "kind": "kubernetes", "mode": "jwks", "issuer": issuer.url, "jwks_url": issuer.jwks_url(),
            "namespaces": ["apps"], "service_accounts": ["web"], "audiences": ["sekret"]
        }),
    )
    .await;
    let sa_token = issuer.sign(json!({"aud": ["sekret"], "sub": "system:serviceaccount:apps:web"}));
    let (status, body) = jwt_login(&h, "kubernetes", &jwks_id, &sa_token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let other_ns = issuer.sign(json!({"aud": ["sekret"], "sub": "system:serviceaccount:kube-system:web"}));
    assert_eq!(
        jwt_login(&h, "kubernetes", &jwks_id, &other_ns).await.0,
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
    .await;
    let (status, body) = jwt_login(&h, "kubernetes", &review_id, "opaque-sa-token").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let review = server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|r| r.url.path().ends_with("tokenreviews"))
        .expect("token review sent");
    assert_eq!(review.headers["authorization"], "Bearer opaque-sa-token");
    let sent: Value = serde_json::from_slice(&review.body).expect("json");
    assert_eq!(sent["spec"]["audiences"], json!(["sekret"]));
}

#[tokio::test]
async fn auth_method_configs_are_validated() {
    let h = start(Options::default()).await;
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "x"})).await;
    let id = identity["id"].as_str().expect("id");
    let unbounded = json!({"kind": "oidc", "issuer": "https://token.actions.githubusercontent.com", "bindings": {"audiences": ["sekret"]}});
    let (status, _) = h
        .put(&format!("/api/v1/identities/{id}/auth/oidc"), &h.admin, unbounded)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mismatched = json!({"kind": "universal"});
    let (status, _) = h
        .put(&format!("/api/v1/identities/{id}/auth/oidc"), &h.admin, mismatched)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
