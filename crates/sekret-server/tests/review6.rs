//! Regressions for the sixth security audit's server findings: project deletion past denies,
//! write body budgets, token lifetimes, OIDC token lifetimes, metadata addresses and separate
//! login limits.

mod common;

use anyhow::Context;
use common::{Harness, options, start};
use reqwest::{Method, StatusCode};
use sekret_server::testkit::TestIssuer;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LOCALHOST: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

async fn put_role(h: &Harness, slug: &str, rules: Value) -> anyhow::Result<()> {
    let (status, body) = h
        .put(
            &format!("/api/v1/projects/app/roles/{slug}"),
            &h.admin,
            json!({"name": slug, "rules": rules}),
        )
        .await?;
    assert!(status.is_success(), "{status} {body}");
    Ok(())
}

async fn deleting_a_project_respects_denies_on_what_it_holds(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    h.set_secrets("app", "prod", "/", &[("PCI_KEY", "k")]).await?;
    let everything = ["read", "read-value", "create", "edit", "delete"];
    let allow_all: Vec<Value> = [
        "secrets",
        "secret-versions",
        "snapshots",
        "folders",
        "environments",
        "settings",
    ]
    .iter()
    .map(|s| json!({"effect": "allow", "subject": s, "actions": everything}))
    .collect();
    let mut ops = allow_all.clone();
    ops.push(
        json!({"effect": "deny", "subject": "secrets", "actions": ["delete", "edit"],
        "conditions": {"environments": ["prod"]}}),
    );
    put_role(&h, "ops", Value::Array(ops)).await?;
    put_role(&h, "owner", Value::Array(allow_all)).await?;

    let (_, ops) = h.machine("ops", "app", "ops").await?;
    let (status, body) = h
        .delete("/api/v1/projects/app/environments/prod/secrets/PCI_KEY", &ops)
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "one prod secret is out of reach: {body}");
    let (status, body) = h.delete("/api/v1/projects/app", &ops).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "so is the whole project: {body}");
    let (status, _) = h.get("/api/v1/projects/app", &h.admin).await?;
    assert_eq!(status, StatusCode::OK, "nothing was removed");

    let (_, owner) = h.machine("owner", "app", "owner").await?;
    let (status, body) = h.delete("/api/v1/projects/app", &owner).await?;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "unrestricted access still deletes: {body}"
    );
    Ok(())
}

async fn raw_write(h: &Harness, method: Method, path: &str, token: &str, body: Vec<u8>) -> anyhow::Result<StatusCode> {
    let response = h
        .client
        .request(method, format!("{}{path}", h.base))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .context("write")?;
    Ok(response.status())
}

async fn each_write_reads_only_what_its_route_needs(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let (_, viewer) = h.machine("viewer", "app", "viewer").await?;
    // Well-formed JSON past the default limit, so only the size refuses it.
    let padded = |bytes: usize| {
        format!(
            r#"{{"name": "x", "slug": "x", "description": "{}"}}"#,
            "a".repeat(bytes)
        )
        .into_bytes()
    };
    let big = padded(sekret_server::body::DEFAULT_BODY + 1);
    for token in [&viewer, &h.admin] {
        let status = raw_write(&h, Method::POST, "/api/v1/projects", token, big.clone()).await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }
    let status = raw_write(
        &h,
        Method::PUT,
        "/api/v1/projects/app/logo",
        &viewer,
        vec![0; 600 * 1024],
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "the logo limit applies before the body is held"
    );

    // A batch still takes megabytes.
    let value = "v".repeat(60 * 1024);
    let upserts: Vec<Value> = (0..30)
        .map(|i| json!({"key": format!("K{i}"), "value": value}))
        .collect();
    let batch = serde_json::to_vec(&json!({"path": "/", "upserts": upserts})).context("batch")?;
    assert!(batch.len() > sekret_server::body::LARGE_BODY);
    let status = raw_write(
        &h,
        Method::POST,
        "/api/v1/projects/app/environments/prod/secrets/batch",
        &h.admin,
        batch,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    // And a single secret its largest value.
    let one = serde_json::to_vec(&json!({"value": "\u{1}".repeat(64 * 1024)})).context("one")?;
    assert!(
        one.len() > sekret_server::body::DEFAULT_BODY,
        "escaping makes it larger"
    );
    let status = raw_write(
        &h,
        Method::PUT,
        "/api/v1/projects/app/environments/prod/secrets/BINARY",
        &h.admin,
        one,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

async fn identity_with_secret(h: &Harness, name: &str, secret: Value) -> anyhow::Result<(String, String)> {
    let (status, identity) = h
        .post(
            "/api/v1/identities",
            &h.admin,
            json!({"name": name, "token_max_ttl": 86_400 * 30}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{identity}");
    let id = identity["id"].as_str().context("id")?.to_string();
    let (status, body) = h
        .put(
            &format!("/api/v1/identities/{id}/auth/universal"),
            &h.admin,
            json!({"kind": "universal"}),
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, created) = h
        .post(&format!("/api/v1/identities/{id}/client-secrets"), &h.admin, secret)
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let client_secret = created["client_secret"].as_str().context("secret")?.to_string();
    Ok((id, client_secret))
}

async fn universal_login(h: &Harness, id: &str, secret: &str) -> anyhow::Result<Value> {
    let (status, token) = h
        .call(
            Method::POST,
            "/api/v1/auth/universal/login",
            None,
            Some(json!({"client_id": id, "client_secret": secret})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{token}");
    Ok(token)
}

async fn renewed_for(h: &Harness, token: &str) -> anyhow::Result<i64> {
    let (status, renewed) = h.post("/api/v1/auth/token/renew", token, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{renewed}");
    renewed["expires_in"].as_i64().context("expires_in")
}

async fn machine_tokens_follow_their_secret_and_identity_lifetimes(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let (id, secret) = identity_with_secret(&h, "bootstrap", json!({"ttl": 300, "max_uses": 1})).await?;
    let token = universal_login(&h, &id, &secret).await?;
    assert!(token["expires_in"].as_i64().context("expires_in")? <= 300, "{token}");
    let access = token["access_token"].as_str().context("token")?.to_string();
    assert!(
        renewed_for(&h, &access).await? <= 300,
        "renewing never passes the secret's expiry"
    );

    let (id, secret) = identity_with_secret(&h, "long", json!({})).await?;
    let token = universal_login(&h, &id, &secret).await?;
    let access = token["access_token"].as_str().context("token")?.to_string();
    let (status, body) = h
        .patch(
            &format!("/api/v1/identities/{id}"),
            &h.admin,
            json!({"name": "long", "token_ttl": 60, "token_max_ttl": 120}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        renewed_for(&h, &access).await? <= 120,
        "lowering the identity's maximum shortens tokens already issued"
    );
    Ok(())
}

async fn jwks_issuer() -> (MockServer, TestIssuer) {
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
    (server, issuer)
}

async fn oidc_machine_logins_refuse_long_lived_tokens(db: String) -> anyhow::Result<()> {
    let (_server, issuer) = jwks_issuer().await;
    let h = start(options(db)).await?;
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "ci"})).await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    let method_path = format!("/api/v1/identities/{id}/auth/oidc");
    let config = |lifetime: Option<i64>| {
        let mut config =
            json!({"kind": "oidc", "issuer": issuer.url, "bindings": {"audiences": ["sekret"], "subjects": ["ci"]}});
        if let Some(lifetime) = lifetime {
            config["max_token_lifetime"] = json!(lifetime);
        }
        config
    };
    let (status, body) = h.put(&method_path, &h.admin, config(None)).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, stored) = h.get(&format!("/api/v1/identities/{id}/auth"), &h.admin).await?;
    assert!(stored.to_string().contains("\"max_token_lifetime\":3600"), "{stored}");

    let login = |token: String| {
        let h = &h;
        let id = id.clone();
        async move {
            h.call(
                Method::POST,
                "/api/v1/auth/oidc/login",
                None,
                Some(json!({"identity_id": id, "token": token})),
            )
            .await
        }
    };
    let short = issuer.sign(json!({"aud": "sekret", "sub": "ci"}))?;
    let day = issuer.sign(json!({"aud": "sekret", "sub": "ci", "exp": issuer.now + 86_400}))?;
    let no_iat = issuer.sign(json!({"aud": "sekret", "sub": "ci", "iat": null}))?;
    assert_eq!(login(short).await?.0, StatusCode::OK);
    assert_eq!(
        login(day.clone()).await?.0,
        StatusCode::UNAUTHORIZED,
        "over the default hour"
    );
    assert_eq!(login(no_iat).await?.0, StatusCode::UNAUTHORIZED, "no iat");

    let (status, body) = h.put(&method_path, &h.admin, config(Some(2 * 86_400))).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(login(day).await?.0, StatusCode::OK, "the setting raises the limit");
    for bad in [0, 315_360_001] {
        let (status, _) = h.put(&method_path, &h.admin, config(Some(bad))).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    Ok(())
}

async fn auth_methods_cannot_point_at_cloud_metadata(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "ssrf"})).await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    let bindings = json!({"audiences": ["sekret"], "subjects": ["*"]});
    for (kind, config) in [
        (
            "oidc",
            json!({"kind": "oidc", "issuer": "http://169.254.169.254/latest", "bindings": bindings}),
        ),
        (
            "oidc",
            json!({"kind": "oidc", "issuer": "https://issuer.example", "jwks_url": "http://[fd00:ec2::254]/", "bindings": bindings}),
        ),
        (
            "kubernetes",
            json!({"kind": "kubernetes", "mode": "token-review", "host": "http://169.254.169.254",
            "namespaces": ["*"], "service_accounts": ["*"]}),
        ),
    ] {
        let (status, body) = h
            .put(&format!("/api/v1/identities/{id}/auth/{kind}"), &h.admin, config)
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{kind}: {body}");
    }
    Ok(())
}

/// Limits live in memory, so one backend is enough.
#[tokio::test]
async fn machine_logins_and_people_have_separate_limits() -> anyhow::Result<()> {
    let h = start(options(common::SQLITE.into())).await?;
    while h.state.machine_login_limiter.allow_ip(LOCALHOST) {}
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/auth/universal/login",
            None,
            Some(json!({"client_id": "x", "client_secret": "y"})),
        )
        .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(
        cli_start_on(&h).await?,
        StatusCode::OK,
        "machine logins cannot lock out the CLI flow"
    );
    assert!(h.state.login_limiter.allow_ip(LOCALHOST), "or browser sign-in");

    let h = start(options(common::SQLITE.into())).await?;
    h.create_project("app").await?;
    while h.state.login_limiter.allow_ip(LOCALHOST) {}
    while h.state.cli_login_limiter.allow_ip(LOCALHOST) {}
    assert_eq!(cli_start_on(&h).await?, StatusCode::TOO_MANY_REQUESTS);
    // Sign-in and the CLI flow exhausted, a machine still logs in.
    h.machine("deployer", "app", "viewer").await?;
    Ok(())
}

/// Anyone who can reach the host socket used to guess passphrases without limit. A few typos
/// still cost nothing, then the socket backs off, but never for more than half a minute.
#[cfg(unix)]
#[tokio::test]
async fn host_socket_guesses_back_off_briefly() -> anyhow::Result<()> {
    use sekret_server::config::SealSettings;
    use sekret_server::ratelimit::{HOST_FREE_FAILURES, HOST_MAX_DELAY};
    use sekret_server::seal::StartupSecrets;
    const PASSPHRASE: &str = "violet tractor sings beneath";

    let db = common::persistent(common::SQLITE)?;
    let first = start(common::opened(
        &db.url,
        SealSettings::default(),
        StartupSecrets::default(),
    ))
    .await?;
    let code = first.state.keyring.setup_code().context("setup code")?;
    let (status, body) = first
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": PASSPHRASE})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    let clock = std::sync::Arc::new(sekret_server::clock::FixedClock::new(1_000_000));
    let h = start(common::Options {
        clock: Some(clock.clone()),
        ..common::opened(&db.url, SealSettings::default(), StartupSecrets::default())
    })
    .await?;
    let socket = db.dir.path().join("sekret.sock");
    let listener = tokio::net::UnixListener::bind(&socket).context("bind")?;
    let router = sekret_server::api::host_router(h.state.clone());
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router).await {
            eprintln!("socket stopped: {error}");
        }
    });
    let local = reqwest::Client::builder()
        .unix_socket(socket.as_path())
        .build()
        .context("client")?;
    let unseal = |passphrase: &'static str| {
        let local = local.clone();
        async move {
            let response = local
                .post("http://localhost/api/v1/sys/unseal")
                .json(&json!({"passphrase": passphrase}))
                .send()
                .await
                .context("unseal")?;
            let status = response.status();
            let body: Value = response.json().await.unwrap_or_default();
            anyhow::Ok((status, body))
        }
    };

    for _ in 0..=HOST_FREE_FAILURES {
        assert_eq!(unseal("wrong guess entirely").await?.0, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = unseal(PASSPHRASE).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "passphrase_backoff");
    assert_eq!(h.state.keyring.state(), sekret_core::seal::SealState::Sealed);

    clock.advance(HOST_MAX_DELAY);
    assert_eq!(
        unseal(PASSPHRASE).await?.0,
        StatusCode::OK,
        "the owner gets back in shortly"
    );
    assert_eq!(h.state.host_backoff.failures(), 0, "a success starts again");
    Ok(())
}

async fn cli_start_on(h: &Harness) -> anyhow::Result<StatusCode> {
    Ok(h.call(Method::POST, "/api/v1/auth/cli/start", None, None).await?.0)
}

on_both_backends!(
    deleting_a_project_respects_denies_on_what_it_holds,
    each_write_reads_only_what_its_route_needs,
    machine_tokens_follow_their_secret_and_identity_lifetimes,
    oidc_machine_logins_refuse_long_lived_tokens,
    auth_methods_cannot_point_at_cloud_metadata,
);
