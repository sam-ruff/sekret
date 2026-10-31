//! Regressions for the second security audit: write-ahead log residue, rotation and sealing
//! races, slow requests, setup ordering, the host socket and audit coverage.

mod common;

use std::time::Duration;

use anyhow::Context;
use common::{Harness, api_error, opened, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_core::seal::{SealState, UnlockPolicy, decrypt_backup, parse_backup};
use sekret_server::config::SealSettings;
use sekret_server::seal::StartupSecrets;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

const PASSPHRASE: &str = "violet tractor sings beneath";
const NEW_PASSPHRASE: &str = "copper lantern drifts at dawn";

async fn fresh(url: &str, settings: SealSettings) -> anyhow::Result<Harness> {
    start(opened(url, settings, StartupSecrets::default())).await
}

async fn init_with(h: &Harness, request: Value) -> anyhow::Result<(StatusCode, Value)> {
    h.call(Method::POST, "/api/v1/sys/init", None, Some(request)).await
}

async fn init(h: &Harness) -> anyhow::Result<String> {
    let code = h.state.keyring.setup_code().context("setup code")?;
    let (status, body) = init_with(
        h,
        json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": PASSPHRASE}),
    )
    .await?;
    anyhow::ensure!(status == StatusCode::OK, "init {status}: {body}");
    Ok(body["admin_token"].as_str().context("token")?.to_string())
}

async fn audit_actions(h: &Harness, admin: &str) -> anyhow::Result<Vec<String>> {
    let (code, audit) = h.get("/api/v1/audit?limit=200", admin).await?;
    anyhow::ensure!(code == StatusCode::OK, "audit {code}: {audit}");
    Ok(audit["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .filter_map(|e| e["action"].as_str().map(String::from))
        .collect())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The demonstrated attack: after a passphrase change the old wrap and values were still in the
/// `-wal` file, so the old passphrase decrypted current data.
#[tokio::test]
async fn a_passphrase_change_leaves_nothing_old_in_the_write_ahead_log() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let file = db.dir.path().join("sekret.db");
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h).await?;
    h.create_project_as("app", &admin).await?;
    h.set_secrets_as("app", "dev", "/", &[("A", "first"), ("B", "second")], &admin)
        .await?;
    let old_wrap = h
        .state
        .store
        .get_seal_config()
        .await?
        .and_then(|c| c.wrapped)
        .context("wrap")?;
    let project = h.state.store.get_project("app").await?.context("project")?;
    let old_values = h.state.store.list_encrypted_values(&project.id).await?;

    let (code, body) = h
        .post(
            "/api/v1/sys/passphrase",
            &admin,
            json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE}),
        )
        .await?;
    assert_eq!(code, StatusCode::NO_CONTENT, "{body}");

    let wal = std::fs::read(db.dir.path().join("sekret.db-wal")).unwrap_or_default();
    let main = std::fs::read(&file).context("database")?;
    for (name, bytes) in [("write-ahead log", &wal), ("database", &main)] {
        assert!(!contains(bytes, &old_wrap.ciphertext), "the old wrap is in the {name}");
        for value in &old_values {
            assert!(!contains(bytes, &value.value), "an old ciphertext is in the {name}");
        }
    }
    Ok(())
}

/// The demonstrated attack: sealing while a passphrase change waited put the new key back.
async fn sealing_during_a_passphrase_change_stays_sealed(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h).await?;
    let gate = h.state.keyring.lock().await;
    let changing = {
        let (client, base, admin) = (h.client.clone(), h.base.clone(), admin.clone());
        tokio::spawn(async move {
            client
                .post(format!("{base}/api/v1/sys/passphrase"))
                .bearer_auth(admin)
                .json(&json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE}))
                .send()
                .await
                .map(|r| r.status())
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sealing = {
        let (client, base, admin) = (h.client.clone(), h.base.clone(), admin.clone());
        tokio::spawn(async move {
            client
                .post(format!("{base}/api/v1/sys/seal"))
                .bearer_auth(admin)
                .json(&json!({}))
                .send()
                .await
                .map(|r| r.status())
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(gate);
    let changed = changing.await.context("join")?.context("change")?;
    let sealed = sealing.await.context("join")?.context("seal")?;
    assert_eq!((changed, sealed), (StatusCode::NO_CONTENT, StatusCode::OK));
    assert_eq!(h.state.keyring.state(), SealState::Sealed, "the seal wins");
    let (code, _) = h
        .call(
            Method::POST,
            "/api/v1/sys/unseal",
            None,
            Some(json!({"passphrase": NEW_PASSPHRASE})),
        )
        .await?;
    assert_eq!(code, StatusCode::OK);
    Ok(())
}

/// A body that arrives slowly, or never, must not hold up replacing the root key.
#[tokio::test]
async fn a_slow_body_does_not_hold_up_a_rotation() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h).await?;
    let address = h.base.trim_start_matches("http://").to_string();
    let mut stalled = tokio::net::TcpStream::connect(&address).await.context("connect")?;
    let head = format!(
        "POST /api/v1/projects HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {admin}\r\n\
         Content-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{\"slug\":"
    );
    stalled.write_all(head.as_bytes()).await.context("write")?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let change = tokio::time::timeout(
        Duration::from_secs(20),
        h.post(
            "/api/v1/sys/passphrase",
            &admin,
            json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE}),
        ),
    )
    .await
    .context("the rotation waited on the stalled request")??;
    assert_eq!(change.0, StatusCode::NO_CONTENT, "{}", change.1);
    drop(stalled);
    Ok(())
}

/// The demonstrated attack: an admin command rotated the key under a running server, which then
/// wrote under the old key. The server now refuses to write once the key is not its own.
async fn writes_stop_when_the_database_has_another_root_key(db: String) -> anyhow::Result<()> {
    let h = start(common::options(db)).await?;
    h.create_project("app").await?;
    h.state
        .store
        .set_meta(sekret_server::ROOT_KEY_META, "0000000000000000")
        .await?;
    let (code, body) = h
        .post("/api/v1/projects", &h.admin, json!({"slug": "web", "name": "Web"}))
        .await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("root_key_changed"))
    );
    let (code, _) = h.get("/api/v1/projects", &h.admin).await?;
    assert_eq!(code, StatusCode::OK, "reading still works");
    Ok(())
}

async fn a_wrong_setup_code_never_takes_the_derivation_permit(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let permit = h.state.keyring.kdf_permit().map_err(api_error("permit"))?;
    let (code, body) = init_with(
        &h,
        json!({"setup_code": "AAAA-AAAA-AAAA", "mode": "passphrase", "passphrase": PASSPHRASE}),
    )
    .await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::UNAUTHORIZED, json!("invalid_setup_code"))
    );
    drop(permit);
    Ok(())
}

async fn setup_stores_the_policy_in_force(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = SealSettings {
        unlock: Some(UnlockPolicy::Manual),
        remember_file: Some(db.dir.path().join("unlock.key")),
        ..SealSettings::default()
    };
    let h = fresh(&db.url, settings).await?;
    let code = h.state.keyring.setup_code().context("setup code")?;
    let (status, body) = init_with(
        &h,
        json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": PASSPHRASE,
            "unlock_policy": "remember"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stored = h.state.store.get_seal_config().await?.context("config")?;
    assert_eq!(
        stored.unlock_policy,
        UnlockPolicy::Manual,
        "configuration wins over the request"
    );
    assert!(!db.dir.path().join("unlock.key").exists());
    Ok(())
}

async fn refused_machine_logins_are_audited(db: String) -> anyhow::Result<()> {
    let h = start(common::options(db)).await?;
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "ci"})).await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    for (client_id, secret) in [(id.as_str(), "sks_wrong"), ("no-such-identity", "sks_x")] {
        let (code, _) = h
            .call(
                Method::POST,
                "/api/v1/auth/universal/login",
                None,
                Some(json!({"client_id": client_id, "client_secret": secret})),
            )
            .await?;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }
    let failures = audit_actions(&h, &h.admin)
        .await?
        .iter()
        .filter(|a| *a == "auth.machine-login.failed")
        .count();
    assert_eq!(failures, 2);
    Ok(())
}

/// Backups taken while the root key is replaced still decrypt to a database of the same key.
#[tokio::test]
async fn a_backup_never_mixes_two_root_keys() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h).await?;
    h.create_project_as("app", &admin).await?;
    let pairs: Vec<(String, String)> = (0..200).map(|i| (format!("K{i}"), format!("value-{i}"))).collect();
    let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    h.set_secrets_as("app", "dev", "/", &pairs, &admin).await?;
    let change = {
        let (client, base, admin) = (h.client.clone(), h.base.clone(), admin.clone());
        tokio::spawn(async move {
            client
                .post(format!("{base}/api/v1/sys/passphrase"))
                .bearer_auth(admin)
                .json(&json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE}))
                .send()
                .await
                .map(|r| r.status())
        })
    };
    for _ in 0..10 {
        let response = h
            .client
            .post(format!("{}/api/v1/sys/backup", h.base))
            .bearer_auth(&admin)
            .send()
            .await
            .context("backup")?;
        if response.status() != StatusCode::OK {
            continue;
        }
        let bytes = response.bytes().await.context("bytes")?;
        let parsed = parse_backup(&bytes).context("parse")?;
        let wrapped = parsed.header.wrapped()?.context("wrap")?;
        let root = sekret_core::seal::unwrap_root_key(&wrapped, PASSPHRASE)
            .or_else(|_| sekret_core::seal::unwrap_root_key(&wrapped, NEW_PASSPHRASE))
            .context("the header's wrap opens")?;
        assert_eq!(root.fingerprint(), parsed.header.root_fingerprint);
        let snapshot = decrypt_backup(&root, &parsed).context("decrypt")?;
        let fingerprint = root.fingerprint();
        assert!(
            contains(&snapshot, fingerprint.as_bytes()),
            "the snapshot belongs to the header's key"
        );
    }
    assert_eq!(change.await.context("join")?.context("change")?, StatusCode::NO_CONTENT);
    Ok(())
}

/// The host socket unseals without the network's back-off, and serves nothing else.
#[cfg(unix)]
#[tokio::test]
async fn the_host_socket_unseals_past_the_network_back_off() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let first = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&first).await?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    for _ in 0..6 {
        let (code, _) = h
            .call(
                Method::POST,
                "/api/v1/sys/unseal",
                None,
                Some(json!({"passphrase": NEW_PASSPHRASE})),
            )
            .await?;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }
    let (code, _) = h
        .call(
            Method::POST,
            "/api/v1/sys/unseal",
            None,
            Some(json!({"passphrase": PASSPHRASE})),
        )
        .await?;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS, "the network is backed off");

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
    let response = local
        .post("http://localhost/api/v1/sys/unseal")
        .json(&json!({"passphrase": PASSPHRASE}))
        .send()
        .await
        .context("unseal")?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(h.state.keyring.state(), SealState::Unsealed);
    let other = local
        .get("http://localhost/api/v1/projects")
        .bearer_auth(&admin)
        .send()
        .await
        .context("projects")?;
    assert_eq!(
        other.status(),
        StatusCode::NOT_FOUND,
        "only status and unseal are served"
    );
    let unseals = h
        .state
        .store
        .list_audit(sekret_store::AuditQuery {
            action: Some("sys.unseal".into()),
            limit: 50,
            ..Default::default()
        })
        .await?;
    assert!(
        unseals
            .iter()
            .any(|e| e.action == "sys.unseal" && e.detail["via"] == "host-socket")
    );
    Ok(())
}

on_both_backends!(
    sealing_during_a_passphrase_change_stays_sealed,
    writes_stop_when_the_database_has_another_root_key,
    a_wrong_setup_code_never_takes_the_derivation_permit,
    setup_stores_the_policy_in_force,
    refused_machine_logins_are_audited,
);
