//! Regressions for the fifth security audit's server findings: costly logos, the sign-in state
//! cookie, environment denies, snapshot and history metadata, CLI polling, lifetimes and the
//! host socket's client address.

mod common;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Context;
use common::{Harness, Options, options, start};
use reqwest::StatusCode;
use sekret_server::testkit::TestIssuer;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRETS: &str = "/api/v1/projects/app/environments";

fn png() -> anyhow::Result<Vec<u8>> {
    let image = image::RgbaImage::from_pixel(8, 8, image::Rgba([30, 44, 67, 255]));
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut out, image::ImageFormat::Png)
        .context("png")?;
    Ok(out.into_inner())
}

async fn upload(h: &Harness, token: &str, body: Vec<u8>) -> anyhow::Result<(StatusCode, Value)> {
    let response = h
        .client
        .put(format!("{}/api/v1/projects/app/logo", h.base))
        .bearer_auth(token)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .context("upload")?;
    let status = response.status();
    Ok((status, response.json().await.unwrap_or_default()))
}

async fn costly_logos_are_refused_quickly_and_uploads_are_rate_limited(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let morphology = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><filter id="f"><feMorphology radius="50"/></filter><rect width="100" height="100" filter="url(#f)"/></svg>"##;
    let mut nested_masks = String::from(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><mask id="m0"><rect width="100" height="100" fill="white"/></mask>"#,
    );
    for level in 1..18 {
        nested_masks.push_str(&format!(
            r##"<mask id="m{level}"><rect width="100" height="100" mask="url(#m{0})"/><rect width="100" height="100" mask="url(#m{0})"/></mask>"##,
            level - 1
        ));
    }
    nested_masks.push_str(r##"<rect width="100" height="100" mask="url(#m17)"/></svg>"##);
    for attack in [morphology.to_vec(), nested_masks.into_bytes()] {
        let started = Instant::now();
        let (status, body) = upload(&h, &h.admin, attack).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "refused in {:?}",
            started.elapsed()
        );
    }

    let png = png()?;
    for _ in 2..sekret_server::api::logo::LOGO_UPLOADS_PER_MINUTE {
        let (status, body) = upload(&h, &h.admin, png.clone()).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, _) = upload(&h, &h.admin, png.clone()).await?;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "refused uploads count towards the limit too"
    );
    let (_, designer) = h.machine("designer", "app", "admin").await?;
    let (status, body) = upload(&h, &designer, png).await?;
    assert_eq!(status, StatusCode::OK, "the limit is per caller: {body}");
    Ok(())
}

fn query(location: &str) -> anyhow::Result<HashMap<String, String>> {
    Ok(url::Url::parse(location)
        .context("url")?
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect())
}

fn set_cookies(response: &reqwest::Response) -> Vec<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect()
}

async fn a_planted_login_cookie_is_ignored_over_https(db: String) -> anyhow::Result<()> {
    let server = MockServer::start().await;
    let issuer = TestIssuer::new(&server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issuer.discovery()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issuer.jwks()))
        .mount(&server)
        .await;
    let h = start(Options {
        oidc: Some(sekret_server::config::HumanOidcConfig {
            issuer: issuer.url.clone(),
            client_id: "sekret".into(),
            client_secret: "client-secret".into(),
            scopes: vec!["openid".into()],
            group_claims: vec![],
            admin_groups: vec![],
            required_groups: vec![],
            allowed_subjects: vec![],
        }),
        public_url: Some("https://sekret.example".into()),
        ..options(db)
    })
    .await?;

    let login = h
        .client
        .get(format!("{}/auth/login", h.base))
        .send()
        .await
        .context("login")?;
    let cookies = set_cookies(&login);
    let state_cookie = cookies
        .iter()
        .find(|c| c.starts_with("__Host-sekret_login="))
        .context("prefixed login cookie")?;
    assert!(
        state_cookie.contains("Path=/;") && state_cookie.contains("Secure") && !state_cookie.contains("Domain"),
        "{state_cookie}"
    );
    assert!(!cookies.iter().any(|c| c.starts_with("sekret_login=")), "{cookies:?}");
    let location = login.headers()["location"].to_str().context("location")?.to_string();
    let params = query(&location)?;
    let state = &params["state"];

    let id_token = issuer.sign(json!({"aud": "sekret", "sub": "alice", "nonce": params["nonce"]}))?;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id_token": id_token, "token_type": "Bearer"})))
        .mount(&server)
        .await;
    let callback = format!("{}/auth/callback?code=the-code&state={state}", h.base);
    // What a sibling subdomain could set for the whole parent domain.
    let planted = h
        .client
        .get(&callback)
        .header("cookie", format!("sekret_login={state}"))
        .send()
        .await
        .context("planted callback")?;
    assert_eq!(
        planted.headers()["location"],
        "/login?error=other_browser",
        "an unprefixed cookie does not bind the login over HTTPS"
    );
    assert!(!set_cookies(&planted).iter().any(|c| c.contains("sekret_session=")));

    let genuine = h
        .client
        .get(&callback)
        .header("cookie", format!("__Host-sekret_login={state}"))
        .send()
        .await
        .context("callback")?;
    assert_eq!(genuine.headers()["location"], "/");
    let cookies = set_cookies(&genuine);
    assert!(
        cookies.iter().any(|c| c.starts_with("__Host-sekret_session=")),
        "{cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("__Host-sekret_login=;") && c.contains("Max-Age=0")),
        "the state cookie is cleared under the same name: {cookies:?}"
    );
    Ok(())
}

async fn put_role(h: &Harness, slug: &str, rules: Value) -> anyhow::Result<()> {
    let (status, body) = h
        .put(
            &format!("/api/v1/projects/app/roles/{slug}"),
            &h.admin,
            json!({"name": slug, "rules": rules}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

async fn an_environment_deny_hides_its_secrets_folders_and_snapshots(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    h.set_secrets("app", "dev", "/", &[("DB_URL", "dev-db")]).await?;
    h.set_secrets("app", "prod", "/team", &[("DB_URL", "prod-db")]).await?;
    put_role(
        &h,
        "no-prod",
        json!([
            {"effect": "allow", "subject": "secrets", "actions": ["read", "read-value", "create", "edit", "delete"]},
            {"effect": "allow", "subject": "secret-versions", "actions": ["read", "read-value"]},
            {"effect": "allow", "subject": "snapshots", "actions": ["read", "edit"]},
            {"effect": "allow", "subject": "folders", "actions": ["read", "create", "delete"]},
            {"effect": "allow", "subject": "environments", "actions": ["read", "edit", "delete"]},
            {"effect": "deny", "subject": "environments", "actions": ["read"], "conditions": {"environments": ["prod"]}}
        ]),
    )
    .await?;
    let (_, token) = h.machine("no-prod", "app", "no-prod").await?;

    let (_, snapshots) = h.get(&format!("{SECRETS}/prod/snapshots"), &h.admin).await?;
    let snapshot = snapshots[0]["id"].as_str().context("snapshot")?.to_string();
    let hidden_reads = [
        "/api/v1/secrets/raw?project=app&environment=prod&recursive=true".to_string(),
        format!("{SECRETS}/prod/secrets?recursive=true&values=true"),
        format!("{SECRETS}/prod/secrets/DB_URL?path=/team"),
        format!("{SECRETS}/prod/secrets/DB_URL/versions?path=/team&values=true"),
        format!("{SECRETS}/prod/snapshots"),
        format!("{SECRETS}/prod/snapshots/{snapshot}"),
        format!("{SECRETS}/prod/folders"),
    ];
    for read in &hidden_reads {
        let (status, body) = h.get(read, &token).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{read}: {body}");
    }
    let (status, _) = h
        .put(
            &format!("{SECRETS}/prod/secrets/NEW?path=/team"),
            &token,
            json!({"value": "x"}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "writes are refused the same way");
    let (status, _) = h
        .post(&format!("{SECRETS}/prod/folders"), &token, json!({"path": "/other"}))
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .patch(
            &format!("{SECRETS}/prod"),
            &token,
            json!({"name": "Renamed", "position": 0}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, raw) = h.get("/api/v1/secrets/raw?project=app&environment=dev", &token).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(raw["secrets"][0]["value"], "dev-db");
    let (_, environments) = h.get("/api/v1/projects/app/environments", &token).await?;
    assert!(!environments.to_string().contains("\"prod\""), "{environments}");
    let (_, overview) = h.get("/api/v1/projects/app/overview?path=/team", &token).await?;
    assert!(!overview.to_string().contains("prod"), "{overview}");

    // Secrets rules alone still reach secrets: lacking an allow on environments is not a deny.
    put_role(
        &h,
        "secrets-only",
        json!([{"effect": "allow", "subject": "secrets", "actions": ["read", "read-value"]}]),
    )
    .await?;
    let (_, plain) = h.machine("secrets-only", "app", "secrets-only").await?;
    let (status, raw) = h
        .get(
            "/api/v1/secrets/raw?project=app&environment=prod&recursive=true",
            &plain,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(raw["secrets"][0]["value"], "prod-db");
    Ok(())
}

async fn snapshots_and_history_leave_out_what_the_reader_cannot_read(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    h.set_secrets("app", "dev", "/", &[("PUBLIC", "1")]).await?;
    h.set_secrets("app", "dev", "/hidden", &[("A", "a"), ("B", "b"), ("C", "c")])
        .await?;
    put_role(
        &h,
        "partial",
        json!([
            {"effect": "allow", "subject": "secrets", "actions": ["read", "read-value"]},
            {"effect": "allow", "subject": "snapshots", "actions": ["read"]},
            {"effect": "allow", "subject": "folders", "actions": ["read"]},
            {"effect": "allow", "subject": "environments", "actions": ["read"]},
            {"effect": "deny", "subject": "secrets", "actions": ["read"], "conditions": {"paths": ["/hidden/**"]}},
            {"effect": "deny", "subject": "folders", "actions": ["read"], "conditions": {"paths": ["/hidden/**"]}}
        ]),
    )
    .await?;
    let (_, token) = h.machine("partial", "app", "partial").await?;

    let (_, full) = h.get(&format!("{SECRETS}/dev/snapshots"), &h.admin).await?;
    let hidden_batch = full
        .as_array()
        .context("snapshots")?
        .iter()
        .find(|s| s["reason"] == "3 created, 0 updated, 0 deleted in /hidden")
        .context("the hidden batch")?;
    assert_eq!(hidden_batch["secret_count"], 4, "{full}");
    let id = hidden_batch["id"].as_str().context("id")?;

    let (_, partial) = h.get(&format!("{SECRETS}/dev/snapshots"), &token).await?;
    let seen = partial
        .as_array()
        .context("snapshots")?
        .iter()
        .find(|s| s["id"] == id)
        .context("the same snapshot")?;
    assert_eq!(seen["reason"], "secrets changed", "{partial}");
    assert_eq!(seen["secret_count"], 1, "only PUBLIC is readable");
    assert!(
        partial
            .as_array()
            .context("snapshots")?
            .iter()
            .any(|s| s["reason"] == "secrets changed in /"),
        "a visible folder stays, without counts: {partial}"
    );
    let (_, detail) = h.get(&format!("{SECRETS}/dev/snapshots/{id}"), &token).await?;
    assert_eq!(detail["snapshot"]["secret_count"], 1, "{detail}");

    // A version whose own tags hide it keeps its number but not its comment, tags or author.
    let batch = format!("{SECRETS}/dev/secrets/batch");
    h.post(
        &batch,
        &h.admin,
        json!({"upserts": [{"key": "VAULT", "value": "v1", "comment": "rotated after the breach", "tags": ["restricted"]}]}),
    )
    .await?;
    h.post(
        &batch,
        &h.admin,
        json!({"upserts": [{"key": "VAULT", "value": "v2", "comment": "routine", "tags": []}]}),
    )
    .await?;
    put_role(
        &h,
        "historian",
        json!([
            {"effect": "allow", "subject": "secrets", "actions": ["read"]},
            {"effect": "allow", "subject": "secret-versions", "actions": ["read"]},
            {"effect": "deny", "subject": "secrets", "actions": ["read"], "conditions": {"tags": ["restricted"]}}
        ]),
    )
    .await?;
    let (_, historian) = h.machine("historian", "app", "historian").await?;
    let (status, versions) = h
        .get(&format!("{SECRETS}/dev/secrets/VAULT/versions"), &historian)
        .await?;
    assert_eq!(status, StatusCode::OK, "{versions}");
    let by_number = |n: i64| {
        versions
            .as_array()
            .and_then(|v| v.iter().find(|x| x["version"] == n).cloned())
    };
    let old = by_number(1).context("version 1")?;
    let new = by_number(2).context("version 2")?;
    assert_eq!(new["comment"], "routine");
    assert_eq!(
        (old["comment"].clone(), old["tags"].clone(), old["actor"].clone()),
        (json!(""), json!([]), json!(""))
    );
    assert!(!versions.to_string().contains("breach"), "{versions}");
    let (_, admin_view) = h
        .get(&format!("{SECRETS}/dev/secrets/VAULT/versions"), &h.admin)
        .await?;
    assert!(admin_view.to_string().contains("breach"), "a full reader still sees it");
    Ok(())
}

async fn cli_polls_are_rate_limited_per_address(db: String) -> anyhow::Result<()> {
    let h = start(Options {
        trusted_proxies: vec!["127.0.0.0/8".parse().context("net")?],
        ..options(db)
    })
    .await?;
    let poll = |from: &'static str| {
        let request = h
            .client
            .post(format!("{}/api/v1/auth/cli/poll", h.base))
            .header("x-forwarded-for", from)
            .json(&json!({"device_code": "skd_not-a-real-code"}));
        async move {
            let response = request.send().await.context("poll")?;
            let status = response.status();
            anyhow::Ok((status, response.json::<Value>().await.unwrap_or_default()))
        }
    };
    for _ in 0..sekret_server::state::CLI_POLLS_PER_MINUTE {
        let (status, body) = poll("203.0.113.7").await?;
        assert_eq!(
            (status, body["error"].clone()),
            (StatusCode::BAD_REQUEST, json!("expired_token"))
        );
    }
    let (status, body) = poll("203.0.113.7").await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::TOO_MANY_REQUESTS, json!("slow_down"))
    );
    let (status, _) = poll("198.51.100.4").await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "other addresses are unaffected");
    Ok(())
}

async fn client_secret_and_token_lifetimes_are_bounded(db: String) -> anyhow::Result<()> {
    use sekret_api::{MAX_CLIENT_SECRET_USES, MAX_LIFETIME};
    let h = start(options(db)).await?;
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "ci"})).await?;
    let id = identity["id"].as_str().context("id")?;
    let secrets = format!("/api/v1/identities/{id}/client-secrets");
    for request in [
        json!({"ttl": 100_000_000_000_000_i64}),
        json!({"ttl": i64::MAX}),
        json!({"ttl": MAX_LIFETIME + 1}),
        json!({"ttl": 0}),
        json!({"max_uses": MAX_CLIENT_SECRET_USES + 1}),
        json!({"max_uses": i64::MAX}),
    ] {
        let (status, body) = h.post(&secrets, &h.admin, request.clone()).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{request}: {body}");
    }
    let (status, created) = h
        .post(
            &secrets,
            &h.admin,
            json!({"ttl": MAX_LIFETIME, "max_uses": MAX_CLIENT_SECRET_USES}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let secret = &created["secret"];
    assert_eq!(
        secret["expires_at"].as_i64().context("expires_at")? - secret["created_at"].as_i64().context("created_at")?,
        MAX_LIFETIME
    );
    let (_, listed) = h.get(&secrets, &h.admin).await?;
    assert!(
        listed
            .to_string()
            .contains(&created["secret"]["id"].as_str().context("id")?.to_string()),
        "{listed}"
    );

    let kubernetes = |lifetime: i64| {
        json!({
            "kind": "kubernetes", "mode": "token-review", "host": "https://k8s.example.com:6443",
            "namespaces": ["apps"], "service_accounts": ["web"], "max_token_lifetime": lifetime,
        })
    };
    let path = format!("/api/v1/identities/{id}/auth/kubernetes");
    let (status, _) = h.put(&path, &h.admin, kubernetes(MAX_LIFETIME + 1)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = h.put(&path, &h.admin, kubernetes(MAX_LIFETIME)).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    Ok(())
}

on_both_backends!(
    costly_logos_are_refused_quickly_and_uploads_are_rate_limited,
    a_planted_login_cookie_is_ignored_over_https,
    an_environment_deny_hides_its_secrets_folders_and_snapshots,
    snapshots_and_history_leave_out_what_the_reader_cannot_read,
    cli_polls_are_rate_limited_per_address,
    client_secret_and_token_lifetimes_are_bounded,
);

#[tokio::test]
async fn host_socket_requests_ignore_forwarded_addresses() -> anyhow::Result<()> {
    use axum::extract::Extension;
    use sekret_server::api::HostSocket;
    use sekret_server::auth::ClientIp;
    use tower::ServiceExt;

    let h = start(Options {
        trusted_proxies: vec!["127.0.0.0/8".parse().context("net")?],
        ..Options::default()
    })
    .await?;
    async fn echo(ClientIp(ip): ClientIp) -> String {
        ip.to_string()
    }
    let request = || {
        axum::http::Request::builder()
            .uri("/ip")
            .header("x-forwarded-for", "203.0.113.9")
            .body(axum::body::Body::empty())
    };
    let address = |router: axum::Router, request: axum::http::Request<axum::body::Body>| async move {
        let response = router.oneshot(request).await.context("request")?;
        let body = axum::body::to_bytes(response.into_body(), 1024).await.context("body")?;
        anyhow::Ok(String::from_utf8_lossy(&body).to_string())
    };
    let network = axum::Router::new()
        .route("/ip", axum::routing::get(echo))
        .with_state(h.state.clone());
    assert_eq!(
        address(network, request()?).await?,
        "203.0.113.9",
        "a trusted loopback proxy is believed on the network"
    );
    let socket = axum::Router::new()
        .route("/ip", axum::routing::get(echo))
        .layer(Extension(HostSocket))
        .with_state(h.state.clone());
    assert_eq!(
        address(socket, request()?).await?,
        "127.0.0.1",
        "but never on the host socket"
    );
    Ok(())
}
