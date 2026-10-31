//! Runs against a live stack: real Keycloak, Postgres and a `sekret server` process.
//! Started by `scripts/system-test.sh`, which exports the variables read here.
#![cfg(feature = "system-tests")]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use anyhow::Context;
use serde_json::{Value, json};

/// The binary under test: the release build the script exports, or this crate's own build.
fn bin() -> String {
    std::env::var("SEKRET_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_sekret").to_string())
}

struct Stack {
    url: String,
    keycloak: String,
    admin: String,
}

fn stack() -> anyhow::Result<Stack> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let var =
        |name: &str| std::env::var(name).with_context(|| format!("{name} must be set; run scripts/system-test.sh"));
    Ok(Stack {
        url: var("SEKRET_E2E_URL")?,
        keycloak: var("SEKRET_E2E_KEYCLOAK")?,
        admin: var("SEKRET_E2E_ADMIN_TOKEN")?,
    })
}

fn browser() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder().cookie_store(true).build().context("client")
}

fn decode_html(text: &str) -> String {
    text.replace("&amp;", "&")
}

/// Signs in through the real Keycloak login page and returns a cookie-holding client.
async fn sign_in(stack: &Stack, username: &str, password: &str) -> anyhow::Result<reqwest::Client> {
    let client = browser()?;
    let page = client
        .get(format!("{}/auth/login?return_to=/", stack.url))
        .send()
        .await
        .context("login")?
        .text()
        .await
        .context("page")?;
    let action = page
        .split("id=\"kc-form-login\"")
        .nth(1)
        .and_then(|rest| rest.split("action=\"").nth(1))
        .and_then(|rest| rest.split('"').next())
        .map(decode_html)
        .context("Keycloak login form")?;
    let response = client
        .post(action)
        .form(&[("username", username), ("password", password), ("credentialId", "")])
        .send()
        .await
        .context("submit")?;
    let landed = response.url();
    assert!(
        landed.as_str().starts_with(&stack.url) && !landed.path().starts_with("/login"),
        "expected to return to sekret signed in, got {landed}"
    );
    Ok(client)
}

async fn session_call(
    stack: &Stack,
    client: &reqwest::Client,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> anyhow::Result<(u16, Value)> {
    let mut request = client
        .request(method, format!("{}{path}", stack.url))
        .header("x-sekret-csrf", "1");
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.context("request")?;
    let status = response.status().as_u16();
    Ok((status, response.json().await.unwrap_or(Value::Null)))
}

async fn admin_call(stack: &Stack, method: reqwest::Method, path: &str, body: Value) -> anyhow::Result<Value> {
    let response = reqwest::Client::new()
        .request(method, format!("{}{path}", stack.url))
        .bearer_auth(&stack.admin)
        .json(&body)
        .send()
        .await
        .context("request")?;
    assert!(response.status().is_success(), "{path}: {}", response.status());
    Ok(response.json().await.unwrap_or(Value::Null))
}

fn cli(args: &[&str], env: &[(&str, &str)]) -> anyhow::Result<std::process::Output> {
    let home = tempfile::tempdir().context("home")?;
    let mut command = Command::new(bin());
    command
        .args(args)
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("SEKRET_TOKEN");
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().context("cli")
}

#[tokio::test]
async fn keycloak_users_sign_in_with_mapped_roles() -> anyhow::Result<()> {
    let stack = stack()?;
    let alice = sign_in(&stack, "alice", "alice-password").await?;
    let (status, me) = session_call(&stack, &alice, reqwest::Method::GET, "/api/v1/me", None).await?;
    assert_eq!(status, 200);
    assert_eq!(me["email"], "alice@example.com");
    assert!(
        me["groups"]
            .as_array()
            .is_some_and(|g| g.iter().any(|r| r == "sekret-admin"))
    );
    let slug = format!("sys-{}", std::process::id());
    let (status, _) = session_call(
        &stack,
        &alice,
        reqwest::Method::POST,
        "/api/v1/projects",
        Some(json!({"slug": slug, "name": "System"})),
    )
    .await?;
    assert_eq!(status, 201);

    let bob = sign_in(&stack, "bob", "bob-password").await?;
    let (status, _) = session_call(
        &stack,
        &bob,
        reqwest::Method::GET,
        &format!("/api/v1/projects/{slug}"),
        None,
    )
    .await?;
    assert_eq!(status, 404, "bob is not a member and must not see the project");
    let (status, _) = session_call(
        &stack,
        &bob,
        reqwest::Method::POST,
        "/api/v1/identities",
        Some(json!({"name": "nope"})),
    )
    .await?;
    assert_eq!(status, 403);

    let (status, _) = session_call(&stack, &alice, reqwest::Method::POST, "/auth/logout", None).await?;
    assert_eq!(status, 200);
    let (status, _) = session_call(&stack, &alice, reqwest::Method::GET, "/api/v1/me", None).await?;
    assert_eq!(status, 401);
    Ok(())
}

/// Seals the server, checks sign-in is refused, then unseals it through the CLI.
async fn sealed_then_unsealed(stack: &Stack, passphrase: &str, earlier: &reqwest::Client) -> anyhow::Result<()> {
    let sealed = admin_call(stack, reqwest::Method::POST, "/api/v1/sys/seal", json!({})).await?;
    assert_eq!(sealed["state"], "sealed");
    let response = browser()?
        .get(format!("{}/auth/login?return_to=/", stack.url))
        .send()
        .await
        .context("login while sealed")?;
    assert_eq!(response.status().as_u16(), 503, "no sign-in while sealed");
    let body: Value = response.json().await.context("json")?;
    assert_eq!(body["error"], "sealed");
    let (status, _) = session_call(stack, earlier, reqwest::Method::GET, "/api/v1/me", None).await?;
    assert_eq!(status, 503, "an existing session is refused too");

    let file = tempfile::NamedTempFile::new().context("passphrase file")?;
    std::fs::write(file.path(), format!("{passphrase}\n")).context("write")?;
    let path = file.path().display().to_string();
    let unsealed = cli(
        &["sys", "unseal", "--passphrase-file", &path],
        &[("SEKRET_URL", &stack.url)],
    )?;
    assert!(
        unsealed.status.success(),
        "{}",
        String::from_utf8_lossy(&unsealed.stderr)
    );
    Ok(())
}

/// Only in the passphrase-mode stage of scripts/system-test.sh, which exports the passphrase.
#[tokio::test]
async fn keycloak_sign_in_is_refused_while_sealed() -> anyhow::Result<()> {
    let stack = stack()?;
    let Ok(passphrase) = std::env::var("SEKRET_E2E_PASSPHRASE") else {
        eprintln!("skipping: this stage runs the server in key-file mode");
        return Ok(());
    };
    let earlier = sign_in(&stack, "alice", "alice-password").await?;
    let outcome = sealed_then_unsealed(&stack, &passphrase, &earlier).await;
    if outcome.is_err() {
        // Leave the shared server usable for the rest of the suite.
        let _ = reqwest::Client::new()
            .post(format!("{}/api/v1/sys/unseal", stack.url))
            .json(&json!({"passphrase": passphrase}))
            .send()
            .await;
    }
    outcome?;

    let status: Value = reqwest::get(format!("{}/api/v1/sys/status", stack.url))
        .await
        .context("status")?
        .json()
        .await
        .context("json")?;
    assert_eq!(status["state"], "unsealed");
    let (status, me) = session_call(&stack, &earlier, reqwest::Method::GET, "/api/v1/me", None).await?;
    assert_eq!(status, 200, "the session from before the seal works again");
    assert_eq!(me["email"], "alice@example.com");
    let again = sign_in(&stack, "alice", "alice-password").await?;
    let (status, _) = session_call(&stack, &again, reqwest::Method::GET, "/api/v1/me", None).await?;
    assert_eq!(status, 200, "sign-in works after unlocking");
    Ok(())
}

#[tokio::test]
async fn keycloak_service_account_logs_in_as_machine_identity() -> anyhow::Result<()> {
    let stack = stack()?;
    let slug = format!("ci-{}", std::process::id());
    admin_call(
        &stack,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": slug, "name": "CI"}),
    )
    .await?;
    admin_call(
        &stack,
        reqwest::Method::POST,
        &format!("/api/v1/projects/{slug}/environments/prod/secrets/batch"),
        json!({"upserts": [{"key": "DEPLOY_TOKEN", "value": "from-sekret"}]}),
    )
    .await?;
    let identity = admin_call(
        &stack,
        reqwest::Method::POST,
        "/api/v1/identities",
        json!({"name": format!("keycloak-ci-{}", std::process::id())}),
    )
    .await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    admin_call(
        &stack,
        reqwest::Method::PUT,
        &format!("/api/v1/identities/{id}/auth/oidc"),
        json!({"kind": "oidc", "issuer": stack.keycloak, "bindings": {"audiences": ["sekret"], "claims": {"azp": ["ci-runner"]}}}),
    )
    .await?;
    admin_call(
        &stack,
        reqwest::Method::POST,
        &format!("/api/v1/projects/{slug}/members"),
        json!({"principal_kind": "identity", "principal_id": id, "role": "viewer"}),
    )
    .await?;

    let token: Value = reqwest::Client::new()
        .post(format!("{}/protocol/openid-connect/token", stack.keycloak))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "ci-runner"),
            ("client_secret", "ci-runner-secret"),
        ])
        .send()
        .await
        .context("token")?
        .json()
        .await
        .context("json")?;
    let jwt = token["access_token"].as_str().context("access token")?;

    let login = cli(
        &[
            "login",
            "--identity-id",
            &id,
            "--oidc-token-env",
            "KC_TOKEN",
            "--print-token",
        ],
        &[("SEKRET_URL", &stack.url), ("KC_TOKEN", jwt)],
    )?;
    assert!(login.status.success(), "{}", String::from_utf8_lossy(&login.stderr));
    let sekret_token = String::from_utf8(login.stdout).context("utf8")?.trim().to_string();

    let env = [
        ("SEKRET_URL", stack.url.as_str()),
        ("SEKRET_TOKEN", sekret_token.as_str()),
        ("SEKRET_PROJECT", slug.as_str()),
        ("SEKRET_ENVIRONMENT", "prod"),
    ];
    let exported = cli(&["export", "--format", "dotenv"], &env)?;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&exported.stdout),
        "DEPLOY_TOKEN=\"from-sekret\"\n"
    );

    let admin_env = [
        ("SEKRET_URL", stack.url.as_str()),
        ("SEKRET_TOKEN", stack.admin.as_str()),
        ("SEKRET_PROJECT", slug.as_str()),
        ("SEKRET_ENVIRONMENT", "prod"),
    ];
    let set = cli(&["secrets", "set", "DEPLOY_TOKEN=rotated"], &admin_env)?;
    assert!(set.status.success(), "{}", String::from_utf8_lossy(&set.stderr));
    let check = |expected: &str| -> anyhow::Result<bool> {
        Ok(cli(
            &["run", "--", "sh", "-c", &format!("test \"$DEPLOY_TOKEN\" = {expected}")],
            &env,
        )?
        .status
        .success())
    };
    assert!(check("rotated")?, "run injects the current value");
    let rollback = cli(&["secrets", "rollback", "DEPLOY_TOKEN", "1"], &admin_env)?;
    assert!(
        rollback.status.success(),
        "{}",
        String::from_utf8_lossy(&rollback.stderr)
    );
    assert!(check("from-sekret")?, "rollback restores the first value");

    let tampered = format!("{}x", &jwt[..jwt.len() - 1]);
    let refused = cli(
        &[
            "login",
            "--identity-id",
            &id,
            "--oidc-token-env",
            "KC_TOKEN",
            "--print-token",
        ],
        &[("SEKRET_URL", &stack.url), ("KC_TOKEN", &tampered)],
    )?;
    assert!(!refused.status.success());
    Ok(())
}

#[tokio::test]
async fn cli_device_login_is_approved_in_the_browser() -> anyhow::Result<()> {
    let stack = stack()?;
    let alice = sign_in(&stack, "alice", "alice-password").await?;
    let home = tempfile::tempdir().context("home")?;
    let mut child = Command::new(bin())
        .args(["login", "--no-browser"])
        .env("SEKRET_URL", &stack.url)
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("SEKRET_TOKEN")
        .stderr(Stdio::piped())
        .spawn()
        .context("login")?;
    let stderr = child.stderr.take().context("stderr")?;
    let mut lines = BufReader::new(stderr).lines();
    let prompt = lines
        .by_ref()
        .map_while(Result::ok)
        .find(|l| l.contains("Confirm this code"))
        .context("code prompt")?;
    let code = prompt.rsplit(' ').next().context("code")?.to_string();
    let (status, _) = session_call(
        &stack,
        &alice,
        reqwest::Method::POST,
        "/api/v1/auth/cli/approve",
        Some(json!({"code": code})),
    )
    .await?;
    assert_eq!(status, 204);
    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    assert!(child.wait().context("wait")?.success(), "{rest:?}");

    let whoami = Command::new(bin())
        .args(["whoami"])
        .env("SEKRET_URL", &stack.url)
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("SEKRET_TOKEN")
        .output()
        .context("whoami")?;
    assert!(String::from_utf8_lossy(&whoami.stdout).contains("alice@example.com"));
    Ok(())
}
