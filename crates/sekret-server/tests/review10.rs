//! Regressions for the tenth security audit: a remembered unlock outliving a move off
//! `remember` in configuration, a root key change whose commit is ambiguous, an unproven
//! passphrase wrap signed by a key-file rotation, the failed-auth limit on the token and CLI
//! review routes, and how passphrase bodies are read.

mod common;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use common::{Harness, api_error, opened, options, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_core::crypto::RootKey;
use sekret_core::seal::{SealMode, UnlockPolicy, wrap_root_key};
use sekret_server::admin::{REKEY_OUTCOME_UNKNOWN, Rotation, rotate_root_key};
use sekret_server::config::SealSettings;
use sekret_server::seal::{StartupSecrets, high_water, marks_name, record_epoch, root_recognised};
use sekret_store::{MockStore, Store, StoreError};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "violet tractor sings beneath";

fn remembering(dir: &Path, unlock: Option<UnlockPolicy>) -> SealSettings {
    SealSettings {
        remember_file: Some(dir.join("unlock.key")),
        unlock,
        ..SealSettings::default()
    }
}

async fn fresh(database_url: &str, settings: SealSettings, secrets: StartupSecrets) -> anyhow::Result<Harness> {
    start(opened(database_url, settings, secrets)).await
}

async fn state_of(h: &Harness) -> anyhow::Result<Value> {
    let (code, body) = h.call(Method::GET, "/api/v1/sys/status", None, None).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    Ok(body["state"].clone())
}

async fn init(h: &Harness) -> anyhow::Result<String> {
    let code = h.state.keyring.setup_code().context("setup code")?;
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": PASSPHRASE})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(body["admin_token"].as_str().context("token")?.to_string())
}

async fn unseal(h: &Harness) -> anyhow::Result<()> {
    let (code, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/unseal",
            None,
            Some(json!({"passphrase": PASSPHRASE})),
        )
        .await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    Ok(())
}

async fn remembered(h: &Harness) -> anyhow::Result<bool> {
    Ok(h.state
        .store
        .get_seal_config()
        .await?
        .context("config")?
        .remembered
        .is_some())
}

async fn policy_forgets(h: &Harness, admin: &str) -> anyhow::Result<usize> {
    let (code, audit) = h.get("/api/v1/audit?limit=200", admin).await?;
    assert_eq!(code, StatusCode::OK, "{audit}");
    Ok(audit["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .filter(|e| e["action"] == "sys.forget_unlock" && e["detail"]["reason"] == "policy")
        .count())
}

/// The audit's scenario: remember, then `seal.unlock: manual` and a restart. The remember file
/// goes at start, the wrap at the next unlock, and going back to `remember` unlocks nothing.
async fn moving_off_remember_in_configuration_forgets_the_unlock(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let dir = db.dir.path();
    let file = dir.join("unlock.key");
    let first = fresh(&db.url, remembering(dir, None), StartupSecrets::default()).await?;
    let admin = init(&first).await?;
    let (code, body) = first
        .put(
            "/api/v1/sys/unlock-policy",
            &admin,
            json!({"policy": "remember", "passphrase": PASSPHRASE}),
        )
        .await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert!(file.exists() && remembered(&first).await?);
    drop(first);

    let manual = fresh(
        &db.url,
        remembering(dir, Some(UnlockPolicy::Manual)),
        StartupSecrets::default(),
    )
    .await?;
    assert_eq!(state_of(&manual).await?, "sealed");
    assert!(!file.exists(), "the remember file goes at start");
    assert!(
        remembered(&manual).await?,
        "the wrap needs the root key to sign its removal"
    );
    unseal(&manual).await?;
    assert!(!remembered(&manual).await?, "the next unlock forgets the wrap");
    assert!(!file.exists());
    assert_eq!(policy_forgets(&manual, &admin).await?, 1);
    drop(manual);

    // The signed stored policy is still remember, but nothing is left to unlock from.
    let back = fresh(&db.url, remembering(dir, None), StartupSecrets::default()).await?;
    assert_eq!(state_of(&back).await?, "sealed");
    unseal(&back).await?;
    assert!(file.exists(), "a manual unlock under remember remembers afresh");
    Ok(())
}

/// The passphrase-file policy unlocks at start, and forgets the stale wrap straight away.
async fn an_unlock_at_start_forgets_a_stale_remembered_unlock(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let dir = db.dir.path();
    let file = dir.join("unlock.key");
    let first = fresh(
        &db.url,
        remembering(dir, Some(UnlockPolicy::Remember)),
        StartupSecrets::default(),
    )
    .await?;
    init(&first).await?;
    assert!(file.exists() && remembered(&first).await?);
    drop(first);

    let secrets = StartupSecrets {
        unlock_passphrase: Some(Zeroizing::new(PASSPHRASE.to_string())),
        auto_init: None,
    };
    let from_file = fresh(&db.url, remembering(dir, Some(UnlockPolicy::PassphraseFile)), secrets).await?;
    assert_eq!(state_of(&from_file).await?, "unsealed");
    assert!(!file.exists());
    assert!(!remembered(&from_file).await?);
    drop(from_file);

    let again = fresh(
        &db.url,
        remembering(dir, Some(UnlockPolicy::Remember)),
        StartupSecrets::default(),
    )
    .await?;
    assert_eq!(
        state_of(&again).await?,
        "sealed",
        "nothing remembered is left to unlock from"
    );
    Ok(())
}

/// Runs a future to completion from inside a mock's synchronous callback.
fn wait<T>(work: impl Future<Output = T>) -> T {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(work))
}

/// How the double's `replace_wrapped_keys` and the fingerprint read after it behave.
#[derive(Clone, Copy)]
enum Failure {
    /// Commits, then reports an error, as when the reply to `COMMIT` is lost.
    AfterCommit,
    /// Reports an error without committing.
    BeforeCommit,
    /// Reports an error, and the fingerprint cannot be read back either.
    Unreadable,
}

/// Every call a root key change makes goes to `real`, except that the change itself fails.
fn failing_store(real: Arc<dyn Store>, failure: Failure) -> MockStore {
    let mut mock = MockStore::new();
    let r = real.clone();
    mock.expect_get_seal_config()
        .returning(move || wait(r.get_seal_config()));
    let r = real.clone();
    mock.expect_list_projects().returning(move || wait(r.list_projects()));
    let r = real.clone();
    mock.expect_list_encrypted_values()
        .returning(move |id| wait(r.list_encrypted_values(id)));
    let r = real.clone();
    mock.expect_list_identities()
        .returning(move || wait(r.list_identities()));
    let r = real.clone();
    mock.expect_list_auth_methods()
        .returning(move |id| wait(r.list_auth_methods(id)));
    let r = real.clone();
    mock.expect_insert_meta()
        .returning(move |key, value| wait(r.insert_meta(key, value)));
    let r = real.clone();
    mock.expect_get_meta().returning(move |key| match failure {
        Failure::Unreadable if key == sekret_server::ROOT_KEY_META => {
            Err(StoreError::Database("connection reset".into()))
        }
        _ => wait(r.get_meta(key)),
    });
    let r = real;
    mock.expect_replace_wrapped_keys().returning(move |rekey| {
        if matches!(failure, Failure::AfterCommit) {
            wait(r.replace_wrapped_keys(rekey))?;
        }
        Err(StoreError::Database("connection reset".into()))
    });
    mock
}

struct Change {
    old: Arc<RootKey>,
    new: RootKey,
    marks: Vec<PathBuf>,
    _dir: tempfile::TempDir,
}

async fn prepared(h: &Harness) -> anyhow::Result<Change> {
    h.create_project("app").await?;
    h.set_secrets("app", "dev", "/", &[("A", "kept")]).await?;
    let dir = tempfile::tempdir().context("dir")?;
    let marks = vec![dir.path().join("epoch")];
    let old = h.state.keyring.root().map_err(api_error("root"))?;
    record_epoch(&marks, 0, &old.pin()?)?;
    Ok(Change {
        old,
        new: RootKey::generate()?,
        marks,
        _dir: dir,
    })
}

async fn change(h: &Harness, change: &Change, failure: Failure) -> Result<(), sekret_server::error::ApiError> {
    let store = failing_store(h.state.store.clone(), failure);
    let rotation = Rotation {
        marks: high_water(&change.marks),
        skip_unreadable: false,
        epoch_files: &change.marks,
        new_integrity_key: false,
    };
    rotate_root_key(&store, &change.old, &change.new, None, rotation)
        .await
        .map(|_| ())
}

async fn fingerprint(h: &Harness) -> anyhow::Result<Option<String>> {
    Ok(h.state.store.get_meta(sekret_server::ROOT_KEY_META).await?)
}

/// The commit reached the database but the caller saw an error: the database decides, so the
/// change counts as done and the marks move to the new key rather than back to the old one.
async fn a_commit_whose_reply_is_lost_counts_as_done(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let c = prepared(&h).await?;
    change(&h, &c, Failure::AfterCommit)
        .await
        .map_err(api_error("change"))?;
    assert_eq!(fingerprint(&h).await?, Some(c.new.fingerprint()));
    assert_eq!(marks_name(&c.marks, &c.new), Some(true));
    assert!(
        !root_recognised(&c.marks, &c.old),
        "the marks no longer accept the old key"
    );
    Ok(())
}

async fn a_change_that_was_not_committed_puts_the_marks_back(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let c = prepared(&h).await?;
    let error = change(&h, &c, Failure::BeforeCommit).await.err().context("refused")?;
    assert_ne!(error.code, REKEY_OUTCOME_UNKNOWN);
    assert_eq!(fingerprint(&h).await?, Some(c.old.fingerprint()));
    assert!(root_recognised(&c.marks, &c.old));
    assert!(!root_recognised(&c.marks, &c.new));
    Ok(())
}

/// When the database cannot say which key it holds, nothing is undone and both keys stay
/// accepted, so whichever one it holds still starts the server.
async fn an_unknown_outcome_undoes_nothing(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let c = prepared(&h).await?;
    let error = change(&h, &c, Failure::Unreadable).await.err().context("refused")?;
    assert_eq!(error.code, REKEY_OUTCOME_UNKNOWN);
    assert!(root_recognised(&c.marks, &c.old));
    assert!(root_recognised(&c.marks, &c.new));
    Ok(())
}

/// A database writer plants a passphrase wrap in a key-file configuration; a key-file rotation
/// drops it rather than signing it.
async fn a_key_file_rotation_never_signs_a_planted_wrap(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let c = prepared(&h).await?;
    let base = sekret_store::SealConfig {
        mode: SealMode::KeyFile,
        wrapped: None,
        unlock_policy: UnlockPolicy::Manual,
        remembered: None,
        epoch: 0,
        mac: None,
        flags: sekret_core::seal::SealFlags::default(),
        created_at: 0,
        updated_at: 0,
    };
    let signed = sekret_server::seal::signed(&c.old, base, high_water(&c.marks).floor())?;
    h.state
        .store
        .init_seal_config(signed.clone(), &c.old.fingerprint())
        .await?;
    let attacker = RootKey::generate()?;
    h.state
        .store
        .update_seal_config(sekret_store::SealConfig {
            wrapped: Some(wrap_root_key(&attacker, "a passphrase the attacker chose")?),
            ..signed
        })
        .await?;
    let rotation = Rotation {
        marks: high_water(&c.marks),
        skip_unreadable: false,
        epoch_files: &c.marks,
        new_integrity_key: false,
    };
    rotate_root_key(h.state.store.as_ref(), &c.old, &c.new, None, rotation)
        .await
        .map_err(api_error("rotate"))?;
    let stored = h.state.store.get_seal_config().await?.context("config")?;
    assert!(stored.wrapped.is_none(), "the planted wrap is never signed");
    assert_eq!(stored.mode, SealMode::KeyFile);
    assert_eq!(
        sekret_server::seal::check_signature(&c.new, &stored),
        sekret_server::seal::Signature::Valid
    );
    Ok(())
}

/// Each runs on a multi-threaded runtime, which the store double needs to wait on the real one.
macro_rules! on_both_backends_threaded {
    ($($name:ident),* $(,)?) => {
        $(
            mod $name {
                #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
                async fn sqlite() -> anyhow::Result<()> {
                    super::$name(super::common::SQLITE.to_string()).await
                }

                #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
                async fn postgres() -> anyhow::Result<()> {
                    let Some(db) = super::common::postgres().await? else {
                        return Ok(());
                    };
                    super::$name(db.url.clone()).await
                }
            }
        )*
    };
}

on_both_backends!(
    moving_off_remember_in_configuration_forgets_the_unlock,
    an_unlock_at_start_forgets_a_stale_remembered_unlock,
    a_key_file_rotation_never_signs_a_planted_wrap,
);

on_both_backends_threaded!(
    a_commit_whose_reply_is_lost_counts_as_done,
    a_change_that_was_not_committed_puts_the_marks_back,
    an_unknown_outcome_undoes_nothing,
);

const JUNK: &str = "skt_0000000000000000000000000000000000000000000";

/// Limits live in memory, so one backend is enough.
#[tokio::test]
async fn junk_tokens_on_the_token_routes_are_turned_away() -> anyhow::Result<()> {
    let h = start(options(common::SQLITE.into())).await?;
    let mut refused = None;
    for _ in 0..5 * sekret_server::FAILED_AUTH_PER_MINUTE {
        let (status, body) = h.post("/api/v1/auth/token/renew", JUNK, json!({})).await?;
        if status != StatusCode::UNAUTHORIZED {
            refused = Some((status, body["error"].clone()));
            break;
        }
    }
    assert_eq!(refused, Some((StatusCode::TOO_MANY_REQUESTS, json!("rate_limited"))));
    let (status, _) = h.post("/api/v1/auth/token/revoke", JUNK, json!({})).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "revoking shares the limit");
    let (status, _) = h.call(Method::GET, "/api/v1/auth/config", Some(JUNK), None).await?;
    assert_eq!(status, StatusCode::OK, "signing in again is never blocked");
    Ok(())
}

async fn raw_unseal(h: &Harness, content_type: &str, body: Vec<u8>) -> anyhow::Result<(StatusCode, Value)> {
    let response = h
        .client
        .post(format!("{}/api/v1/sys/unseal", h.base))
        .header("content-type", content_type)
        .body(body)
        .send()
        .await
        .context("unseal")?;
    let status = response.status();
    Ok((status, response.json().await.unwrap_or_default()))
}

/// Passphrase bodies go through their own reader; it refuses what `Json` refused, the same way,
/// and never echoes the body back.
#[tokio::test]
async fn passphrase_bodies_are_read_strictly() -> anyhow::Result<()> {
    let db = persistent(common::SQLITE)?;
    let first = fresh(&db.url, SealSettings::default(), StartupSecrets::default()).await?;
    init(&first).await?;
    drop(first);
    let h = fresh(&db.url, SealSettings::default(), StartupSecrets::default()).await?;
    assert_eq!(state_of(&h).await?, "sealed");

    let body = serde_json::to_vec(&json!({"passphrase": PASSPHRASE}))?;
    let (status, _) = raw_unseal(&h, "text/plain", body.clone()).await?;
    assert_eq!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "a cross-site form cannot send it"
    );
    let (status, _) = raw_unseal(&h, "application/json", vec![b' '; 64 * 1024]).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, body_back) = raw_unseal(&h, "application/json", br#"{"passphrase": "hunter2"#.to_vec()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body_back.to_string().contains("hunter2"), "{body_back}");
    let (status, body_back) = raw_unseal(&h, "application/json", br#"{"passphrase": 1234567}"#.to_vec()).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!body_back.to_string().contains("1234567"), "{body_back}");
    assert_eq!(state_of(&h).await?, "sealed");

    let (status, body_back) = raw_unseal(&h, "application/json; charset=utf-8", body).await?;
    assert_eq!(status, StatusCode::OK, "{body_back}");
    assert_eq!(state_of(&h).await?, "unsealed");
    Ok(())
}
