//! Regressions for the first security audit: seal configuration signing, passphrase changes,
//! unlock-policy confirmation, key derivation limits, rate limits, backups and CLI re-approval.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use common::{Harness, api_error, opened, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_core::crypto::RootKey;
use sekret_core::seal::{KdfParams, UnlockPolicy, unwrap_root_key, wrap_root_key_with};
use sekret_server::clock::{Clock, FixedClock};
use sekret_server::config::{SealSettings, ServerConfig};
use sekret_server::net::{ReqwestOidcHttp, ReqwestTokenReviewer};
use sekret_server::seal::{AutoInit, Keyring, Signature, StartupSecrets, check_signature, open_keyring, signed};
use sekret_server::state::{Dependencies, build_state};
use sekret_store::{AccessToken, Identity, PrincipalKind, SqlStore, Store, UserLogin};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "violet tractor sings beneath";
const NEW_PASSPHRASE: &str = "copper lantern drifts at dawn";
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn remembering(dir: &Path) -> SealSettings {
    SealSettings {
        remember_file: Some(dir.join("unlock.key")),
        ..SealSettings::default()
    }
}

async fn fresh(url: &str, settings: SealSettings) -> anyhow::Result<Harness> {
    start(opened(url, settings, StartupSecrets::default())).await
}

async fn status(h: &Harness) -> anyhow::Result<Value> {
    let (code, body) = h.call(Method::GET, "/api/v1/sys/status", None, None).await?;
    anyhow::ensure!(code == StatusCode::OK, "status {code}: {body}");
    Ok(body)
}

/// Every status field, as organisation admins see them.
fn detail(h: &Harness) -> anyhow::Result<Value> {
    serde_json::to_value(sekret_server::seal::status(&h.state.config.seal, &h.state.keyring)).context("status")
}

async fn init(h: &Harness, policy: &str) -> anyhow::Result<Value> {
    let code = h.state.keyring.setup_code().context("setup code")?;
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(
                json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": PASSPHRASE,
                "unlock_policy": policy}),
            ),
        )
        .await?;
    anyhow::ensure!(status == StatusCode::OK, "init {status}: {body}");
    Ok(body)
}

fn token(body: &Value) -> anyhow::Result<String> {
    Ok(body["admin_token"].as_str().context("token")?.to_string())
}

async fn unseal(h: &Harness, passphrase: &str) -> anyhow::Result<(StatusCode, Value)> {
    h.call(
        Method::POST,
        "/api/v1/sys/unseal",
        None,
        Some(json!({"passphrase": passphrase})),
    )
    .await
}

async fn audit_actions(h: &Harness, admin: &str) -> anyhow::Result<Vec<String>> {
    let (code, audit) = h.get("/api/v1/audit?limit=200&order=asc", admin).await?;
    anyhow::ensure!(code == StatusCode::OK, "audit {code}: {audit}");
    Ok(audit["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .filter_map(|e| e["action"].as_str().map(String::from))
        .collect())
}

/// A harness on a configuration the test adjusts, for options the shared harness does not expose.
async fn start_with(
    database_url: &str,
    clock: Arc<FixedClock>,
    tweak: impl FnOnce(&mut ServerConfig),
) -> anyhow::Result<Harness> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let store = Arc::new(SqlStore::connect(database_url).await.context("store")?);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.context("bind")?;
    let addr = listener.local_addr().context("addr")?;
    let mut config = ServerConfig::for_tests(database_url);
    config.public_url = format!("http://{addr}");
    tweak(&mut config);
    let root = RootKey::generate().context("root")?;
    sekret_server::check_root_key(store.as_ref(), &root.fingerprint())
        .await
        .context("root check")?;
    let state = build_state(Dependencies {
        store,
        keyring: Keyring::unsealed(root, sekret_core::seal::SealMode::KeyFile),
        config,
        clock,
        http: Arc::new(ReqwestOidcHttp::new(true).context("http")?),
        token_reviewer: Arc::new(ReqwestTokenReviewer::new(true)),
    });
    let app = sekret_server::app(state.clone());
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
            eprintln!("test server stopped: {error}");
        }
    });
    let admin = sekret_server::admin::bootstrap_admin(&state, 3600)
        .await
        .map_err(api_error("bootstrap"))?;
    Ok(Harness {
        base: format!("http://{addr}"),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("client")?,
        state,
        admin,
    })
}

async fn a_flipped_unlock_policy_is_caught_and_never_remembered(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = remembering(db.dir.path());
    let file = db.dir.path().join("unlock.key");
    let first = fresh(&db.url, settings.clone()).await?;
    let admin = token(&init(&first, "manual").await?)?;

    // A database writer turns on remember without the root key.
    let mut config = first.state.store.get_seal_config().await?.context("config")?;
    config.unlock_policy = UnlockPolicy::Remember;
    first.state.store.update_seal_config(config).await?;

    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    let (code, body) = unseal(&h, PASSPHRASE).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(
        detail(&h)?["unlock_policy"],
        "manual",
        "the flipped policy is not trusted"
    );
    assert!(!file.exists(), "no remember file is written for a tampered policy");
    assert!(
        audit_actions(&h, &admin)
            .await?
            .contains(&"sys.seal_config.tampered".to_string())
    );
    let stored = h.state.store.get_seal_config().await?.context("config")?;
    let root = h.state.keyring.root().map_err(api_error("root"))?;
    assert_eq!(check_signature(&root, &stored), Signature::Valid, "re-signed as manual");
    assert_eq!(stored.unlock_policy, UnlockPolicy::Manual);

    let again = fresh(&db.url, settings).await?;
    assert_eq!(status(&again).await?["state"], "sealed");
    Ok(())
}

async fn a_tampered_configuration_never_unlocks_at_start(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = remembering(db.dir.path());
    let first = fresh(&db.url, settings.clone()).await?;
    init(&first, "remember").await?;
    assert!(db.dir.path().join("unlock.key").exists());
    let mut config = first.state.store.get_seal_config().await?.context("config")?;
    config.epoch += 7;
    first.state.store.update_seal_config(config).await?;
    let h = fresh(&db.url, settings).await?;
    assert_eq!(
        status(&h).await?["state"],
        "sealed",
        "a bad signature stops the automatic unlock"
    );
    assert!(!db.dir.path().join("unlock.key").exists());
    // Nothing proved the stored wrap, so the tampered row is not signed; the passphrase repairs it.
    let config = h.state.store.get_seal_config().await?.context("config")?;
    assert_eq!(
        config.unlock_policy,
        UnlockPolicy::Remember,
        "left as the writer made it"
    );
    assert_eq!(unseal(&h, PASSPHRASE).await?.0, StatusCode::OK);
    let config = h.state.store.get_seal_config().await?.context("config")?;
    let root = h.state.keyring.root().map_err(api_error("root"))?;
    assert_eq!(check_signature(&root, &config), Signature::Valid);
    assert_eq!(config.unlock_policy, UnlockPolicy::Manual);
    assert_eq!(config.remembered, None);
    Ok(())
}

async fn unsigned_configurations_are_only_signed_when_they_grant_nothing(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = remembering(db.dir.path());
    let first = fresh(&db.url, settings.clone()).await?;
    let admin = token(&init(&first, "manual").await?)?;
    // As a database from before signing, which granted nothing: signed quietly.
    let mut config = first.state.store.get_seal_config().await?.context("config")?;
    config.mac = None;
    first.state.store.update_seal_config(config.clone()).await?;
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(unseal(&h, PASSPHRASE).await?.0, StatusCode::OK);
    let root = h.state.keyring.root().map_err(api_error("root"))?;
    let stored = h.state.store.get_seal_config().await?.context("config")?;
    assert_eq!(check_signature(&root, &stored), Signature::Valid);
    assert!(
        !audit_actions(&h, &admin)
            .await?
            .contains(&"sys.seal_config.tampered".to_string())
    );

    // Clearing the signature does not launder a policy or wrap a database writer put there.
    for policy in [UnlockPolicy::Remember, UnlockPolicy::PassphraseFile] {
        let current = h.state.store.get_seal_config().await?.context("config")?;
        h.state
            .store
            .update_seal_config(sekret_store::SealConfig {
                mac: None,
                unlock_policy: policy,
                ..current
            })
            .await?;
        let restarted = start(opened(
            &db.url,
            settings.clone(),
            StartupSecrets {
                unlock_passphrase: Some(Zeroizing::new(PASSPHRASE.to_string())),
                auto_init: None,
            },
        ))
        .await?;
        assert_eq!(
            status(&restarted).await?["state"],
            "sealed",
            "{policy:?}: an unsigned grant never unlocks at start"
        );
        assert_eq!(unseal(&restarted, PASSPHRASE).await?.0, StatusCode::OK);
        let stored = restarted.state.store.get_seal_config().await?.context("config")?;
        assert_eq!(stored.unlock_policy, UnlockPolicy::Manual, "{policy:?}");
        assert!(stored.mac.is_some());
    }
    let tampered = audit_actions(&h, &admin)
        .await?
        .iter()
        .filter(|a| *a == "sys.seal_config.tampered")
        .count();
    assert_eq!(tampered, 2);
    Ok(())
}

/// The demonstrated attack: no signature, junk in the remembered wrap and the remember policy.
async fn a_cleared_signature_with_a_planted_wrap_is_tampering(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = remembering(db.dir.path());
    let file = db.dir.path().join("unlock.key");
    let first = fresh(&db.url, settings.clone()).await?;
    let admin = token(&init(&first, "manual").await?)?;
    let current = first.state.store.get_seal_config().await?.context("config")?;
    first
        .state
        .store
        .update_seal_config(sekret_store::SealConfig {
            mac: None,
            unlock_policy: UnlockPolicy::Remember,
            remembered: Some(vec![0x41; 72]),
            ..current
        })
        .await?;
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    assert_eq!(unseal(&h, PASSPHRASE).await?.0, StatusCode::OK);
    let stored = h.state.store.get_seal_config().await?.context("config")?;
    assert_eq!(stored.unlock_policy, UnlockPolicy::Manual);
    assert_eq!(stored.remembered, None);
    assert!(!file.exists(), "the tampered policy is never acted on");
    assert!(
        audit_actions(&h, &admin)
            .await?
            .contains(&"sys.seal_config.tampered".to_string())
    );
    let again = fresh(&db.url, settings).await?;
    assert_eq!(status(&again).await?["state"], "sealed");
    Ok(())
}

/// A signed configuration from earlier, put back into the database, is caught by the epoch kept
/// beside the database.
async fn an_older_signed_configuration_is_a_rollback(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let marks = vec![db.dir.path().join("sekret.db.epoch")];
    let settings = SealSettings {
        epoch_files: marks.clone(),
        ..SealSettings::default()
    };
    let first = fresh(&db.url, settings.clone()).await?;
    let admin = token(&init(&first, "manual").await?)?;
    let (code, _) = first
        .put(
            "/api/v1/sys/unlock-policy",
            &admin,
            json!({"policy": "passphrase-file", "passphrase": PASSPHRASE}),
        )
        .await?;
    assert_eq!(code, StatusCode::OK);
    let granting = first.state.store.get_seal_config().await?.context("config")?;
    let (code, _) = first
        .put("/api/v1/sys/unlock-policy", &admin, json!({"policy": "manual"}))
        .await?;
    assert_eq!(code, StatusCode::OK);
    let mark = sekret_server::seal::high_water(&marks).highest.context("mark")?;
    assert!(mark > granting.epoch);

    // A database writer puts the old, validly signed passphrase-file configuration back.
    first.state.store.update_seal_config(granting).await?;
    let with_passphrase = || StartupSecrets {
        unlock_passphrase: Some(Zeroizing::new(PASSPHRASE.to_string())),
        auto_init: None,
    };
    let h = start(opened(&db.url, settings.clone(), with_passphrase())).await?;
    assert_eq!(status(&h).await?["state"], "sealed", "the rollback does not unlock");
    let stored = h.state.store.get_seal_config().await?.context("config")?;
    assert_eq!(stored.unlock_policy, UnlockPolicy::Manual);
    assert!(
        stored.epoch > mark,
        "reset past the mark, so it is not taken for a rollback again"
    );
    assert_eq!(unseal(&h, PASSPHRASE).await?.0, StatusCode::OK);
    assert!(
        audit_actions(&h, &admin)
            .await?
            .contains(&"sys.seal_config.rolled_back".to_string())
    );
    let again = start(opened(&db.url, settings, with_passphrase())).await?;
    assert_eq!(status(&again).await?["state"], "sealed");
    assert_eq!(unseal(&again, PASSPHRASE).await?.0, StatusCode::OK);
    let rollbacks = audit_actions(&again, &admin)
        .await?
        .iter()
        .filter(|a| *a == "sys.seal_config.rolled_back")
        .count();
    assert_eq!(rollbacks, 1, "the reset itself is accepted");
    Ok(())
}

async fn changing_the_passphrase_replaces_the_root_key(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = token(&init(&h, "manual").await?)?;
    h.create_project_as("app", &admin).await?;
    h.set_secrets_as("app", "dev", "/", &[("A", "before")], &admin).await?;
    h.set_secrets_as("app", "dev", "/", &[("A", "second")], &admin).await?;
    let old_config = h.state.store.get_seal_config().await?.context("config")?;
    let project = h.state.store.get_project("app").await?.context("project")?;
    let old_values = h.state.store.list_encrypted_values(&project.id).await?;
    assert_eq!(old_values.len(), 2);

    let (code, body) = h
        .post(
            "/api/v1/sys/passphrase",
            &admin,
            json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE}),
        )
        .await?;
    assert_eq!(code, StatusCode::NO_CONTENT, "{body}");

    // The old wrap, as an old backup or database copy holds it, opens a key that reads nothing now.
    let old_wrap = old_config.wrapped.clone().context("wrap")?;
    let old_root = unwrap_root_key(&old_wrap, PASSPHRASE).context("old root")?;
    let project = h.state.store.get_project("app").await?.context("project")?;
    assert!(sekret_server::secrets::data_key(&old_root, &project).is_err());
    let new_values = h.state.store.list_encrypted_values(&project.id).await?;
    assert_eq!(new_values.len(), 2);
    for (old, new) in old_values.iter().zip(&new_values) {
        assert_ne!(old.value, new.value, "every version, history included, is re-encrypted");
    }
    let new_root = h.state.keyring.root().map_err(api_error("root"))?;
    assert_ne!(new_root.fingerprint(), old_root.fingerprint());
    let config = h.state.store.get_seal_config().await?.context("config")?;
    assert!(config.epoch > old_config.epoch);
    assert_eq!(check_signature(&new_root, &config), Signature::Valid);
    let (code, body) = h.get("/api/v1/projects/app/environments/dev/secrets/A", &admin).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["value"], "second");

    let restarted = fresh(&db.url, SealSettings::default()).await?;
    assert_eq!(unseal(&restarted, PASSPHRASE).await?.0, StatusCode::UNAUTHORIZED);
    assert_eq!(unseal(&restarted, NEW_PASSPHRASE).await?.0, StatusCode::OK);
    let (code, body) = restarted
        .get("/api/v1/projects/app/environments/dev/secrets/A", &admin)
        .await?;
    assert_eq!((code, body["value"].clone()), (StatusCode::OK, json!("second")));
    Ok(())
}

async fn weakening_the_unlock_policy_needs_the_passphrase(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, remembering(db.dir.path())).await?;
    let admin = token(&init(&h, "manual").await?)?;
    for policy in ["remember", "passphrase-file"] {
        let (code, body) = h
            .put("/api/v1/sys/unlock-policy", &admin, json!({"policy": policy}))
            .await?;
        assert_eq!(
            (code, body["error"].clone()),
            (StatusCode::BAD_REQUEST, json!("passphrase_required"))
        );
        let (code, body) = h
            .put(
                "/api/v1/sys/unlock-policy",
                &admin,
                json!({"policy": policy, "passphrase": NEW_PASSPHRASE}),
            )
            .await?;
        assert_eq!(
            (code, body["error"].clone()),
            (StatusCode::UNAUTHORIZED, json!("invalid_passphrase"))
        );
        let (code, body) = h
            .put(
                "/api/v1/sys/unlock-policy",
                &admin,
                json!({"policy": policy, "passphrase": format!("{PASSPHRASE}\n")}),
            )
            .await?;
        assert_eq!(code, StatusCode::OK, "{policy}: {body}");
        assert_eq!(body["unlock_policy"], policy);
    }
    let (code, _) = h
        .put("/api/v1/sys/unlock-policy", &admin, json!({"policy": "manual"}))
        .await?;
    assert_eq!(code, StatusCode::OK, "making it stricter needs no passphrase");
    let actions = audit_actions(&h, &admin).await?;
    assert!(actions.contains(&"sys.passphrase.failed".to_string()), "{actions:?}");
    Ok(())
}

#[tokio::test]
async fn key_derivations_run_one_at_a_time_and_survive_cancellation() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let first = fresh(&db.url, SealSettings::default()).await?;
    let admin = token(&init(&first, "manual").await?)?;
    let h = fresh(&db.url, SealSettings::default()).await?;

    let permit = h.state.keyring.kdf_permit().map_err(api_error("permit"))?;
    let (code, body) = unseal(&h, PASSPHRASE).await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::TOO_MANY_REQUESTS, json!("kdf_busy"))
    );
    drop(permit);

    // A request abandoned mid-derivation keeps its permit until Argon2 itself finishes.
    let impatient = reqwest::Client::builder()
        .timeout(Duration::from_millis(40))
        .build()
        .context("client")?;
    let abandoned = impatient
        .post(format!("{}/api/v1/sys/unseal", h.base))
        .json(&json!({"passphrase": "not the passphrase at all"}))
        .send()
        .await;
    assert!(abandoned.is_err(), "the first request timed out");
    assert!(
        h.state.keyring.kdf_permit().is_err(),
        "the abandoned derivation is still running"
    );
    for _ in 0..50 {
        if h.state.keyring.kdf_permit().is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The abandoned attempt still counts against its source and is still audited.
    let mut counted = false;
    for _ in 0..50 {
        let failures = h.state.passphrase_backoff.failures(LOCALHOST);
        let audited = h
            .state
            .store
            .count_audit(sekret_store::AuditQuery {
                action: Some("sys.unseal.failed".into()),
                ..Default::default()
            })
            .await?;
        if failures == 1 && audited == 1 {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(counted, "the abandoned unseal was counted and audited");
    assert_eq!(unseal(&h, PASSPHRASE).await?.0, StatusCode::OK);
    assert!(!admin.is_empty());
    Ok(())
}

#[tokio::test]
async fn wrong_passphrases_back_off_their_source_without_saying_for_how_long() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let first = fresh(&db.url, SealSettings::default()).await?;
    let admin = token(&init(&first, "manual").await?)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    for _ in 0..6 {
        assert_eq!(unseal(&h, NEW_PASSPHRASE).await?.0, StatusCode::UNAUTHORIZED);
    }
    let response = h
        .client
        .post(format!("{}/api/v1/sys/unseal", h.base))
        .json(&json!({"passphrase": PASSPHRASE}))
        .send()
        .await
        .context("unseal")?;
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "even the right passphrase waits"
    );
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .context("retry-after")?;
    assert_eq!(retry_after % 5, 0, "rounded, so the exact back-off is not given away");
    let body: Value = response.json().await.context("body")?;
    assert_eq!(body["error"], "passphrase_backoff");
    assert!(
        !body["message"]
            .as_str()
            .unwrap_or_default()
            .chars()
            .any(|c| c.is_ascii_digit()),
        "{body}"
    );
    // Another source is not held back.
    assert!(
        h.state
            .passphrase_backoff
            .wait("198.51.100.20".parse().context("ip")?)
            .is_none()
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(unseal(&h, PASSPHRASE).await?.0, StatusCode::OK);
    let failed = audit_actions(&h, &admin)
        .await?
        .iter()
        .filter(|a| *a == "sys.unseal.failed")
        .count();
    assert_eq!(failed, 6);
    Ok(())
}

#[tokio::test]
async fn sign_in_and_unlock_have_separate_rate_limits() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let first = fresh(&db.url, SealSettings::default()).await?;
    init(&first, "manual").await?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    while h.state.login_limiter.allow_ip(LOCALHOST) {}
    assert_eq!(
        unseal(&h, PASSPHRASE).await?.0,
        StatusCode::OK,
        "an exhausted sign-in limit does not block unlocking"
    );
    while h.state.sys_limiter.allow_ip(LOCALHOST) {}
    let fresh_start = fresh(&db.url, SealSettings::default()).await?;
    while fresh_start.state.sys_limiter.allow_ip(LOCALHOST) {}
    let (code, _) = fresh_start
        .call(Method::POST, "/api/v1/auth/cli/start", None, None)
        .await?;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "sealed, but not rate limited");
    assert_eq!(unseal(&fresh_start, PASSPHRASE).await?.0, StatusCode::TOO_MANY_REQUESTS);
    let (code, _) = h.call(Method::POST, "/api/v1/auth/cli/start", None, None).await?;
    assert_eq!(code, StatusCode::OK, "an exhausted unlock limit does not block sign-in");
    Ok(())
}

#[tokio::test]
async fn system_requests_are_small() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let first = fresh(&db.url, SealSettings::default()).await?;
    init(&first, "manual").await?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let (code, _) = unseal(&h, &"a".repeat(20 * 1024)).await?;
    assert_eq!(code, StatusCode::PAYLOAD_TOO_LARGE);
    let (code, body) = unseal(&h, &"a".repeat(2000)).await?;
    assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
    Ok(())
}

async fn setup_codes_are_checked_and_audited(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let attempt = |code: String| {
        h.call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(json!({"setup_code": code, "mode": "passphrase", "passphrase": PASSPHRASE})),
        )
    };
    let (code, _) = attempt("A".repeat(100)).await?;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    let (code, body) = attempt("AAAA-AAAA-AAAA".into()).await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::UNAUTHORIZED, json!("invalid_setup_code"))
    );
    let (code, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(
                json!({"setup_code": h.state.keyring.setup_code().context("code")?.as_str(),
                "mode": "passphrase", "passphrase": "violet tractor\tsings beneath"}),
            ),
        )
        .await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::BAD_REQUEST, json!("weak_passphrase"))
    );
    let body = init(&h, "manual").await?;
    let now = h.state.clock.now();
    let expires = body["admin_token_expires_at"].as_i64().context("expiry")?;
    assert!(expires > now && expires <= now + 3600, "{expires}");
    let admin = token(&body)?;
    let actions = audit_actions(&h, &admin).await?;
    assert!(actions.contains(&"sys.init.failed".to_string()), "{actions:?}");
    assert!(actions.contains(&"sys.init".to_string()));
    Ok(())
}

async fn tokens_can_be_revoked_while_sealed(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = token(&init(&h, "manual").await?)?;
    let (code, _) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    assert_eq!(code, StatusCode::OK);
    let (code, body) = h.post("/api/v1/auth/token/revoke", &admin, json!({})).await?;
    assert!(code.is_success(), "{code}: {body}");
    assert_eq!(unseal(&h, PASSPHRASE).await?.0, StatusCode::OK);
    let (code, _) = h.get("/api/v1/me", &admin).await?;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn status_says_how_the_server_was_unlocked(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let configured = SealSettings {
        mode: Some(sekret_core::seal::SealMode::Passphrase),
        unlock: Some(UnlockPolicy::Manual),
        ..SealSettings::default()
    };
    let h = fresh(&db.url, configured).await?;
    let before = status(&h).await?;
    assert_eq!(
        (
            before["state"].clone(),
            before["seal_mode"].clone(),
            before["unlock_policy"].clone(),
            before["configured"].clone()
        ),
        (
            json!("uninitialised"),
            json!("passphrase"),
            json!("manual"),
            json!(true)
        ),
        "configured choices show before setup"
    );
    let admin = token(&init(&h, "manual").await?)?;
    assert_eq!(status(&h).await?["unsealed_by"], Value::Null, "only admins learn how");
    let (code, full) = h.get("/api/v1/sys/status/detail", &admin).await?;
    assert_eq!(code, StatusCode::OK, "{full}");
    assert_eq!(full["unsealed_by"], "passphrase");
    let (code, me) = h.get("/api/v1/me", &admin).await?;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(me["is_org_admin"], true);
    assert!(
        me["org_roles"]
            .as_array()
            .context("roles")?
            .contains(&json!("org-admin"))
    );
    let member = h.org_identity_as("reader", "backup-reader", &admin).await?;
    let (_, me) = h.get("/api/v1/me", &member).await?;
    assert_eq!(me["is_org_admin"], false);

    // A key file opens a passphrase-mode server, and status says so.
    let root = h.state.keyring.root().map_err(api_error("root"))?;
    let key = db.dir.path().join("root.key");
    std::fs::write(&key, root.to_base64().as_bytes()).context("key")?;
    let keyed = fresh(
        &db.url,
        SealSettings {
            root_key_file: Some(key),
            ..SealSettings::default()
        },
    )
    .await?;
    let body = detail(&keyed)?;
    assert_eq!(
        (body["seal_mode"].clone(), body["unsealed_by"].clone()),
        (json!("passphrase"), json!("key-file"))
    );
    let (_, starts) = keyed.get("/api/v1/audit?limit=200", &admin).await?;
    assert!(
        starts["entries"]
            .as_array()
            .context("entries")?
            .iter()
            .any(|e| e["action"] == "sys.unseal" && e["actor_id"] == "key-file"),
        "an unlock at start is audited with how it happened"
    );
    let sealed = fresh(&db.url, SealSettings::default()).await?;
    assert_eq!(detail(&sealed)?["unsealed_by"], Value::Null);
    Ok(())
}

async fn backups_are_one_at_a_time_and_staged_privately(db: String) -> anyhow::Result<()> {
    let postgres = db.starts_with("postgres");
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = token(&init(&h, "manual").await?)?;
    if postgres {
        let (code, _) = h.post("/api/v1/sys/backup", &admin, json!({})).await?;
        assert_eq!(code, StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let held = h.state.backup_lock.lock().await;
    let (code, body) = h.post("/api/v1/sys/backup", &admin, json!({})).await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::TOO_MANY_REQUESTS, json!("backup_in_progress"))
    );
    drop(held);
    let (code, _) = h.call(Method::GET, "/api/v1/sys/backup", Some(&admin), None).await?;
    assert_eq!(code, StatusCode::METHOD_NOT_ALLOWED, "backups are POST only");
    let (code, _) = h.post("/api/v1/sys/backup", &admin, json!({})).await?;
    assert_eq!(code, StatusCode::OK);
    let leftovers: Vec<_> = std::fs::read_dir(db.dir.path())
        .context("list")?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".sekret-backup-"))
        .collect();
    assert!(leftovers.is_empty(), "the staging directory is removed");
    Ok(())
}

async fn old_argon2_costs_are_upgraded_on_unseal(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    init(&h, "manual").await?;
    let root = h.state.keyring.root().map_err(api_error("root"))?;
    let old = KdfParams::new(65_536, 3, 1);
    let config = h.state.store.get_seal_config().await?.context("config")?;
    let downgraded = sekret_store::SealConfig {
        wrapped: Some(wrap_root_key_with(&root, PASSPHRASE, old).context("wrap")?),
        ..config
    };
    h.state.store.update_seal_config(signed(&root, downgraded, 0)?).await?;
    let restarted = fresh(&db.url, SealSettings::default()).await?;
    assert_eq!(unseal(&restarted, PASSPHRASE).await?.0, StatusCode::OK);
    let upgraded = restarted.state.store.get_seal_config().await?.context("config")?;
    assert_eq!(upgraded.wrapped.context("wrap")?.params, KdfParams::default());
    let again = fresh(&db.url, SealSettings::default()).await?;
    assert_eq!(unseal(&again, PASSPHRASE).await?.0, StatusCode::OK);
    Ok(())
}

/// A wrap from before the form marker opens through the fallbacks once, then is made again with
/// the marker, so later unlocks never pay for more than one derivation.
async fn unmarked_wraps_are_marked_on_unseal(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    init(&h, "manual").await?;
    let root = h.state.keyring.root().map_err(api_error("root"))?;
    let config = h.state.store.get_seal_config().await?.context("config")?;
    let mut wrapped = config.wrapped.clone().context("wrap")?;
    wrapped.params.normalised = false;
    let unmarked = sekret_store::SealConfig {
        wrapped: Some(wrapped),
        ..config
    };
    h.state.store.update_seal_config(signed(&root, unmarked, 0)?).await?;
    let restarted = fresh(&db.url, SealSettings::default()).await?;
    assert_eq!(unseal(&restarted, PASSPHRASE).await?.0, StatusCode::OK);
    let marked = restarted.state.store.get_seal_config().await?.context("config")?;
    assert!(marked.wrapped.context("wrap")?.params.normalised);
    let again = fresh(&db.url, SealSettings::default()).await?;
    assert_eq!(unseal(&again, PASSPHRASE).await?.0, StatusCode::OK);
    Ok(())
}

async fn auto_init_refuses_a_database_with_data(db: String) -> anyhow::Result<()> {
    let store = SqlStore::connect(&db).await.context("store")?;
    store
        .create_identity(Identity {
            id: "i1".into(),
            name: "left-over".into(),
            description: String::new(),
            token_ttl: 60,
            token_max_ttl: 60,
            trusted_cidrs: vec![],
            disabled: false,
            created_at: 1,
        })
        .await?;
    let secrets = StartupSecrets {
        unlock_passphrase: None,
        auto_init: Some(AutoInit {
            passphrase: Some(Zeroizing::new(PASSPHRASE.to_string())),
        }),
    };
    let result = open_keyring(&store, 1, &SealSettings::default(), secrets).await;
    assert!(result.is_err_and(|e| e.to_string().contains("already holds data")));
    assert!(store.get_seal_config().await?.is_none());
    Ok(())
}

/// The unlock passphrase only stands in for the setup passphrase under the policy that keeps it.
async fn auto_init_uses_the_unlock_passphrase_only_under_passphrase_file(db: String) -> anyhow::Result<()> {
    let only_unlock = || StartupSecrets {
        unlock_passphrase: Some(Zeroizing::new(PASSPHRASE.to_string())),
        auto_init: Some(AutoInit { passphrase: None }),
    };
    let manual = persistent(&db)?;
    let store = SqlStore::connect(&manual.url).await.context("store")?;
    let result = open_keyring(&store, 1, &SealSettings::default(), only_unlock()).await;
    assert!(
        result.is_err_and(|e| e.to_string().contains("setup.passphrase_file")),
        "manual needs a setup passphrase of its own"
    );
    assert!(store.get_seal_config().await?.is_none());

    let file_policy = persistent(&db)?;
    let settings = SealSettings {
        unlock: Some(UnlockPolicy::PassphraseFile),
        ..SealSettings::default()
    };
    let h = start(opened(&file_policy.url, settings, only_unlock())).await?;
    assert_eq!(status(&h).await?["state"], "unsealed");
    let stored = h.state.store.get_seal_config().await?.context("config")?;
    assert_eq!(stored.unlock_policy, UnlockPolicy::PassphraseFile);
    let opened = unwrap_root_key(&stored.wrapped.context("wrap")?, PASSPHRASE).context("unwrap")?;
    let root = h.state.keyring.root().map_err(api_error("root"))?;
    assert_eq!(opened.fingerprint(), root.fingerprint());
    Ok(())
}

on_both_backends!(
    a_flipped_unlock_policy_is_caught_and_never_remembered,
    a_tampered_configuration_never_unlocks_at_start,
    unsigned_configurations_are_only_signed_when_they_grant_nothing,
    a_cleared_signature_with_a_planted_wrap_is_tampering,
    an_older_signed_configuration_is_a_rollback,
    auto_init_uses_the_unlock_passphrase_only_under_passphrase_file,
    changing_the_passphrase_replaces_the_root_key,
    weakening_the_unlock_policy_needs_the_passphrase,
    setup_codes_are_checked_and_audited,
    tokens_can_be_revoked_while_sealed,
    status_says_how_the_server_was_unlocked,
    backups_are_one_at_a_time_and_staged_privately,
    old_argon2_costs_are_upgraded_on_unseal,
    unmarked_wraps_are_marked_on_unseal,
    auto_init_refuses_a_database_with_data,
);

/// A browser session for a new user, authenticated with the provider at `auth_time`.
async fn session(h: &Harness, auth_time: Option<i64>) -> anyhow::Result<String> {
    let now = h.state.clock.now();
    let user = h
        .state
        .store
        .upsert_user(UserLogin {
            subject: format!("issuer|{}", uuid::Uuid::new_v4()),
            email: "person@example.com".into(),
            name: "Person".into(),
            groups: vec![],
            now,
        })
        .await?;
    let token = format!("skt_{}", uuid::Uuid::new_v4().simple());
    h.state
        .store
        .create_token(AccessToken {
            id: uuid::Uuid::new_v4().to_string(),
            token_hash: sekret_core::crypto::hash_token(&token),
            kind: "session".into(),
            principal_kind: PrincipalKind::User,
            principal_id: user.id,
            description: "browser session".into(),
            source: String::new(),
            created_at: now,
            expires_at: now + 3600,
            max_expires_at: now + 3600,
            revoked: false,
            last_used_at: None,
            auth_time,
        })
        .await?;
    Ok(token)
}

async fn approve(h: &Harness, session: &str, user_code: &str) -> anyhow::Result<(StatusCode, Value)> {
    let response = h
        .client
        .post(format!("{}/api/v1/auth/cli/approve", h.base))
        .header("cookie", format!("sekret_session={session}"))
        .header("x-sekret-csrf", "1")
        .json(&json!({"code": user_code}))
        .send()
        .await
        .context("approve")?;
    let code = response.status();
    let text = response.text().await.context("body")?;
    Ok((code, serde_json::from_str(&text).unwrap_or(Value::String(text))))
}

#[tokio::test]
async fn approving_a_cli_login_needs_a_recent_sign_in() -> anyhow::Result<()> {
    let clock = Arc::new(FixedClock::new(1_800_000_000));
    let h = start_with(common::SQLITE, clock.clone(), |config| {
        config.cli_login_max_auth_age = Some(900);
        config.cli_token_ttl = 3600;
    })
    .await?;
    let now = clock.now();
    let (code, started) = h.call(Method::POST, "/api/v1/auth/cli/start", None, None).await?;
    assert_eq!(code, StatusCode::OK);
    let user_code = started["user_code"].as_str().context("code")?.to_string();

    for stale in [None, Some(now - 2000)] {
        let old = session(&h, stale).await?;
        let (code, body) = approve(&h, &old, &user_code).await?;
        assert_eq!(code, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "reauthentication_required");
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("/auth/login?reauth=1&return_to=%2Fcli-login%3Fcode%3D"),
            "{message}"
        );
    }
    let recent = session(&h, Some(now - 60)).await?;
    let (code, body) = approve(&h, &recent, &user_code).await?;
    assert_eq!(code, StatusCode::NO_CONTENT, "{body}");

    let (code, token) = h
        .call(
            Method::POST,
            "/api/v1/auth/cli/poll",
            None,
            Some(json!({"device_code": started["device_code"]})),
        )
        .await?;
    assert_eq!(code, StatusCode::OK, "{token}");
    let cli = token["access_token"].as_str().context("token")?.to_string();
    clock.advance(600);
    let (code, renewed) = h.post("/api/v1/auth/token/renew", &cli, json!({})).await?;
    assert_eq!(code, StatusCode::OK, "{renewed}");
    assert_eq!(
        renewed["expires_in"], 3000,
        "renewing never goes past the TTL from sign-in"
    );
    clock.advance(3001);
    let (code, _) = h.post("/api/v1/auth/token/renew", &cli, json!({})).await?;
    assert_eq!(
        code,
        StatusCode::UNAUTHORIZED,
        "an expired CLI token needs a new sekret login"
    );
    Ok(())
}

#[tokio::test]
async fn without_a_max_auth_age_any_session_approves() -> anyhow::Result<()> {
    let clock = Arc::new(FixedClock::new(1_800_000_000));
    let h = start_with(common::SQLITE, clock, |_| {}).await?;
    let (_, started) = h.call(Method::POST, "/api/v1/auth/cli/start", None, None).await?;
    let user_code = started["user_code"].as_str().context("code")?.to_string();
    let old = session(&h, None).await?;
    let (code, body) = approve(&h, &old, &user_code).await?;
    assert_eq!(code, StatusCode::NO_CONTENT, "{body}");
    Ok(())
}
