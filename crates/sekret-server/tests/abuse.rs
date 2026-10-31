//! Regressions for the third security audit's server findings: unlock floods, forwarded
//! addresses, what refusals put in the audit log, request bodies, backups and token renewal.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use common::{Harness, Options, opened, options, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_server::config::SealSettings;
use sekret_server::seal::StartupSecrets;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSPHRASE: &str = "violet tractor sings beneath";
const WRONG: &str = "copper lantern drifts westward";

fn loopback_proxy() -> anyhow::Result<Vec<ipnet::IpNet>> {
    Ok(vec!["127.0.0.0/8".parse().context("net")?])
}

/// A passphrase-mode server set up through the API, that believes `X-Forwarded-For` from
/// loopback so a test can speak from many addresses, and its admin token.
async fn initialised(url: &str) -> anyhow::Result<(Harness, String)> {
    let h = start(Options {
        trusted_proxies: loopback_proxy()?,
        ..opened(url, SealSettings::default(), StartupSecrets::default())
    })
    .await?;
    let code = h.state.keyring.setup_code().context("setup code")?;
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": PASSPHRASE})),
        )
        .await?;
    anyhow::ensure!(status == StatusCode::OK, "init {status}: {body}");
    let admin = body["admin_token"].as_str().context("token")?.to_string();
    Ok((h, admin))
}

/// [`initialised`], then sealed.
async fn sealed_behind_proxy(url: &str) -> anyhow::Result<Harness> {
    let (h, admin) = initialised(url).await?;
    let (status, body) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    anyhow::ensure!(status == StatusCode::OK, "seal {status}: {body}");
    Ok(h)
}

async fn unseal_from(h: &Harness, ip: &str, passphrase: &str) -> anyhow::Result<(StatusCode, Value)> {
    let response = h
        .client
        .post(format!("{}/api/v1/sys/unseal", h.base))
        .header("x-forwarded-for", ip)
        .json(&json!({"passphrase": passphrase}))
        .send()
        .await
        .context("unseal")?;
    let status = response.status();
    Ok((status, response.json().await.unwrap_or(Value::Null)))
}

/// An unlock waiting for the keyring gate must not hold the derivation permit meanwhile: the gate
/// holder may need the permit, as re-wrapping after an unlock does, and the two would deadlock.
async fn the_gate_is_taken_before_the_derivation_permit(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = Arc::new(sealed_behind_proxy(&db.url).await?);
    let gate = h.state.keyring.lock().await;
    let waiting = {
        let h = h.clone();
        tokio::spawn(async move { unseal_from(&h, "192.0.2.10", PASSPHRASE).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let permit = h.state.keyring.kdf_permit();
    assert!(permit.is_ok(), "the waiting unlock holds the permit");
    drop(permit);
    drop(gate);
    let (status, body) = waiting.await.context("join")??;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// The attack: several addresses guess over and over. Before the fix the owner, who had never
/// failed, was turned away with `kdf_busy` or the server-wide pause for as long as it lasted.
async fn a_flood_from_many_sources_cannot_lock_the_owner_out(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = Arc::new(sealed_behind_proxy(&db.url).await?);
    let stop = Arc::new(AtomicBool::new(false));
    let mut flood = Vec::new();
    for source in 0..6u8 {
        let (h, stop) = (h.clone(), stop.clone());
        flood.push(tokio::spawn(async move {
            let ip = format!("10.{source}.0.1");
            while !stop.load(Ordering::Relaxed) {
                if unseal_from(&h, &ip, WRONG).await.is_err() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }));
    }
    // Long enough for every flooding source to have failed and the server-wide pause to start.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut outcome = (StatusCode::IM_A_TEAPOT, Value::Null);
    for _ in 0..3 {
        outcome = unseal_from(&h, "192.0.2.10", PASSPHRASE).await?;
        if outcome.0 == StatusCode::OK {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    stop.store(true, Ordering::Relaxed);
    for task in flood {
        let _ = task.await;
    }
    assert_eq!(outcome.0, StatusCode::OK, "the owner waits in line: {}", outcome.1);
    assert_eq!(outcome.1["state"], "unsealed");
    Ok(())
}

/// Sources that have failed are turned away while the derivation is busy rather than queueing,
/// and attempts are also counted per network, not just per address.
async fn failed_sources_do_not_queue_and_networks_are_counted(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = sealed_behind_proxy(&db.url).await?;
    let (status, _) = unseal_from(&h, "10.9.0.1", WRONG).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let gate = h.state.keyring.lock().await;
    let (status, body) = unseal_from(&h, "10.9.0.1", WRONG).await?;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("kdf_busy")),
        "a source that has failed is not queued"
    );
    drop(gate);
    let (status, body) = unseal_from(&h, "10.9.0.2", PASSPHRASE).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// The attack: the client sends garbage in `X-Forwarded-For` and the proxy appends the real
/// address after it. Before the fix the whole header was thrown away and the client recorded as
/// unknown. The TCP peer is now recorded beside the client address.
async fn a_client_cannot_erase_its_forwarded_address(db: String) -> anyhow::Result<()> {
    let h = start(Options {
        trusted_proxies: loopback_proxy()?,
        ..options(db)
    })
    .await?;
    let response = h
        .client
        .post(format!("{}/api/v1/auth/universal/login", h.base))
        .header("x-forwarded-for", "garbage, 198.51.100.7")
        .json(&json!({"client_id": uuid::Uuid::new_v4().to_string(), "client_secret": "sks_wrong"}))
        .send()
        .await
        .context("login")?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (_, audit) = h
        .get("/api/v1/audit?action=auth.machine-login.failed", &h.admin)
        .await?;
    let entry = audit["entries"].get(0).context("entry")?;
    assert_eq!(entry["ip"], "198.51.100.7", "{entry}");
    assert_eq!(entry["detail"]["peer"], "127.0.0.1", "{entry}");
    Ok(())
}

/// The attack: the client id and secret swapped round, which put the `sks_` secret in the audit
/// log as the identity id.
async fn a_swapped_client_secret_never_reaches_the_audit_log(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "ci"})).await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    h.put(
        &format!("/api/v1/identities/{id}/auth/universal"),
        &h.admin,
        json!({"kind": "universal"}),
    )
    .await?;
    let (_, secret) = h
        .post(&format!("/api/v1/identities/{id}/client-secrets"), &h.admin, json!({}))
        .await?;
    let secret = secret["client_secret"].as_str().context("secret")?.to_string();
    let swapped = json!({"client_id": secret, "client_secret": id});
    let (status, _) = h
        .call(Method::POST, "/api/v1/auth/universal/login", None, Some(swapped))
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, audit) = h.get("/api/v1/audit?limit=500", &h.admin).await?;
    let text = audit.to_string();
    assert!(!text.contains(&secret), "the secret is in the audit log: {text}");
    let failed = audit["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .find(|e| e["action"] == "auth.machine-login.failed")
        .context("the failure is still audited")?;
    let recorded = failed["detail"]["identity_id"].as_str().context("identity id")?;
    assert!(recorded.starts_with("hash:"), "{recorded}");
    Ok(())
}

async fn audit_count(h: &Harness, action: &str) -> anyhow::Result<usize> {
    let (_, audit) = h
        .get(&format!("/api/v1/audit?action={action}&limit=500"), &h.admin)
        .await?;
    Ok(audit["entries"].as_array().map_or(0, Vec::len))
}

/// A flood of refusals from one caller and source is one audit entry a minute, not one each.
async fn refusal_floods_are_folded_in_the_audit_log(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let (_, viewer) = h.machine("viewer", "app", "viewer").await?;
    for _ in 0..30 {
        let (status, _) = h.get("/api/v1/sys/status/detail", &viewer).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert_eq!(audit_count(&h, "sys.forbidden").await?, 1);
    let unknown = uuid::Uuid::new_v4().to_string();
    for _ in 0..30 {
        let login = json!({"client_id": unknown, "client_secret": "sks_wrong"});
        h.call(Method::POST, "/api/v1/auth/universal/login", None, Some(login))
            .await?;
    }
    assert_eq!(audit_count(&h, "auth.machine-login.failed").await?, 1);
    let other = json!({"client_id": uuid::Uuid::new_v4().to_string(), "client_secret": "sks_wrong"});
    h.call(Method::POST, "/api/v1/auth/universal/login", None, Some(other))
        .await?;
    assert_eq!(
        audit_count(&h, "auth.machine-login.failed").await?,
        2,
        "another identity is another key"
    );
    Ok(())
}

/// An anonymous write is refused from its headers, before the server reads any of the body.
async fn anonymous_bodies_are_not_buffered(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let address = h.base.trim_start_matches("http://").to_string();
    let mut stream = tokio::net::TcpStream::connect(&address).await.context("connect")?;
    let head = "POST /api/v1/projects HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
                Content-Length: 3000000\r\n\r\n{\"slug\":";
    stream.write_all(head.as_bytes()).await.context("write")?;
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .context("refused without waiting for the body")?
        .context("read")?;
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");

    let padding = "x".repeat(sekret_server::api::AUTH_BODY_LIMIT + 1);
    let big = json!({"client_id": "x", "client_secret": padding});
    let (status, _) = h
        .call(Method::POST, "/api/v1/auth/universal/login", None, Some(big))
        .await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "sign-in bodies are small");
    Ok(())
}

/// The attack: start a backup, hang up, start another. Before the fix hanging up released the
/// one-backup lock while the first carried on.
async fn hanging_up_does_not_free_the_backup_lock(db: String) -> anyhow::Result<()> {
    if db.starts_with("postgres") {
        return Ok(());
    }
    let db = persistent(&db)?;
    let (h, admin) = initialised(&db.url).await?;
    let backup = |timeout: Duration| {
        h.client
            .post(format!("{}/api/v1/sys/backup", h.base))
            .bearer_auth(&admin)
            .timeout(timeout)
            .send()
    };
    // Holding the keyring gate keeps the first backup waiting partway through.
    let gate = h.state.keyring.lock().await;
    assert!(
        backup(Duration::from_millis(300)).await.is_err(),
        "the first backup is waiting"
    );
    let second = backup(Duration::from_secs(3))
        .await
        .context("the second is answered at once")?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    drop(gate);
    for _ in 0..50 {
        if h.state.backup_lock.try_lock().is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (_, audit) = h.get("/api/v1/audit?action=sys.backup", &admin).await?;
    assert_eq!(
        audit["entries"].as_array().map(Vec::len),
        Some(1),
        "the abandoned backup finished on its own"
    );
    let finished = backup(Duration::from_secs(10)).await.context("backup")?;
    assert_eq!(finished.status(), StatusCode::OK);
    Ok(())
}

/// The renewal cap comes from the user's groups now, not when the token was minted.
async fn cli_renewals_follow_the_current_groups(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let now = h.state.clock.now();
    let ttl = h.state.config.cli_token_ttl;
    // The user signed in with no groups, so the token could be renewed for a week, and has
    // since gained a group from the identity provider.
    let user = h
        .state
        .store
        .upsert_user(sekret_store::UserLogin {
            subject: "issuer|grouped".into(),
            email: "grouped@example.com".into(),
            name: "Grouped".into(),
            groups: vec!["devs".into()],
            now,
        })
        .await?;
    let token = format!("skt_{}", uuid::Uuid::new_v4().simple());
    let created_at = now - ttl + 3600;
    h.state
        .store
        .create_token(sekret_store::AccessToken {
            id: uuid::Uuid::new_v4().to_string(),
            token_hash: sekret_core::crypto::hash_token(&token),
            kind: "cli".into(),
            principal_kind: sekret_store::PrincipalKind::User,
            principal_id: user.id.clone(),
            description: "CLI login".into(),
            source: String::new(),
            created_at,
            expires_at: now + 3600,
            max_expires_at: created_at + ttl * 7,
            revoked: false,
            last_used_at: None,
            auth_time: None,
        })
        .await?;
    let (status, renewed) = h.post("/api/v1/auth/token/renew", &token, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{renewed}");
    let expires_in = renewed["expires_in"].as_i64().context("expires_in")?;
    assert!(expires_in <= 3600, "renewed past the first TTL: {expires_in}");
    Ok(())
}

on_both_backends!(
    the_gate_is_taken_before_the_derivation_permit,
    a_flood_from_many_sources_cannot_lock_the_owner_out,
    failed_sources_do_not_queue_and_networks_are_counted,
    a_client_cannot_erase_its_forwarded_address,
    a_swapped_client_secret_never_reaches_the_audit_log,
    refusal_floods_are_folded_in_the_audit_log,
    anonymous_bodies_are_not_buffered,
    hanging_up_does_not_free_the_backup_lock,
    cli_renewals_follow_the_current_groups,
);
