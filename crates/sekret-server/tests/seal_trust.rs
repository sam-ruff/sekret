//! Regressions for the fifth security audit of the seal state: a root key swap behind a planted
//! project, unsigned configurations restarting the reviewer token migration, the wrap's form
//! marker, project keys left unreadable by a rotation, and marks during a root key change.

mod common;

use std::path::Path;

use anyhow::Context;
use common::{Harness, api_error, opened, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_core::crypto::{DataKey, RootKey, seal_credential, wrap_data_key};
use sekret_core::seal::{KdfParams, SealBinding, SealFlags, UnlockPolicy, seal_config_mac, wrap_root_key_with};
use sekret_server::admin::{Rotation, rotate_root_key};
use sekret_server::config::SealSettings;
use sekret_server::seal::{
    Signature, StartupSecrets, accepted_roots, begin_rekey, check_signature, high_water, record_epoch, signed,
};
use sekret_store::{Project, SealConfig};
use serde_json::{Value, json};

const PASSPHRASE: &str = "violet tractor sings beneath";
const ATTACKER: &str = "copper lantern drifts at dawn";

fn marked(dir: &Path) -> SealSettings {
    SealSettings {
        epoch_files: vec![dir.join("seal.epoch")],
        ..SealSettings::default()
    }
}

async fn fresh(url: &str, settings: SealSettings) -> anyhow::Result<Harness> {
    start(opened(url, settings, StartupSecrets::default())).await
}

async fn init(h: &Harness) -> anyhow::Result<String> {
    let code = h.state.keyring.setup_code().context("setup code")?;
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(
                json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": PASSPHRASE,
                "unlock_policy": "manual"}),
            ),
        )
        .await?;
    anyhow::ensure!(status == StatusCode::OK, "init {status}: {body}");
    Ok(body["admin_token"].as_str().context("token")?.to_string())
}

async fn stored(h: &Harness) -> anyhow::Result<SealConfig> {
    h.state.store.get_seal_config().await?.context("config")
}

fn root(h: &Harness) -> anyhow::Result<std::sync::Arc<RootKey>> {
    h.state.keyring.root().map_err(api_error("root"))
}

async fn unseal_with(h: &Harness, passphrase: &str) -> anyhow::Result<(StatusCode, Value)> {
    let body = json!({"passphrase": passphrase});
    h.call(Method::POST, "/api/v1/sys/unseal", None, Some(body)).await
}

async fn state_of(h: &Harness) -> anyhow::Result<String> {
    let (code, body) = h.call(Method::GET, "/api/v1/sys/status", None, None).await?;
    anyhow::ensure!(code == StatusCode::OK, "status {code}: {body}");
    Ok(body["state"].as_str().context("state")?.to_string())
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

/// Without marks, a database writer installed their own root key and planted one project it
/// opens. Every real project must open too, so the swap is refused.
async fn a_planted_project_does_not_let_a_forged_root_in(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h).await?;
    h.create_project_as("real-app", &admin).await?;

    let forged = RootKey::generate().context("forged")?;
    let config = SealConfig {
        wrapped: Some(wrap_root_key_with(&forged, ATTACKER, KdfParams::FLOOR).context("wrap")?),
        mac: None,
        ..stored(&h).await?
    };
    h.state.store.update_seal_config(signed(&forged, config, 0)?).await?;
    h.state
        .store
        .set_meta(sekret_server::ROOT_KEY_META, &forged.fingerprint())
        .await?;
    let planted = Project {
        id: "planted".into(),
        slug: "planted".into(),
        name: "Planted".into(),
        description: String::new(),
        wrapped_key: wrap_data_key(&forged, &DataKey::generate().context("dk")?, "planted").context("wrap")?,
        created_at: 1,
        logo_updated_at: None,
        secret_policy: None,
    };
    h.state.store.create_project(planted, vec![]).await?;

    let restarted = fresh(&db.url, SealSettings::default()).await?;
    let (code, body) = unseal_with(&restarted, ATTACKER).await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::CONFLICT, json!("root_key_not_recognised")),
        "{body}"
    );
    assert_eq!(state_of(&restarted).await?, "sealed");
    Ok(())
}

/// Without marks, stripping the signature from a configuration that grants nothing made the
/// server sign whatever flags were stored, so a cleared migration flag moved a planted
/// old-format reviewer token to the writer's cluster.
async fn an_unsigned_configuration_never_restarts_the_reviewer_migration(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h).await?;
    let (_, identity) = h.post("/api/v1/identities", &admin, json!({"name": "k3s"})).await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    let path = format!("/api/v1/identities/{id}/auth/kubernetes");
    let (status, body) = h
        .put(
            &path,
            &admin,
            json!({"kind": "kubernetes", "mode": "token-review", "host": "https://k8s.example.com:6443",
                "reviewer_jwt": "reviewer-plaintext", "namespaces": ["apps"], "service_accounts": ["web"]}),
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let root_key = root(&h)?;
    let legacy = seal_credential(&root_key, "old-reviewer", &format!("identity:{id}:kubernetes")).context("seal")?;
    let mut method = h
        .state
        .store
        .get_auth_method(&id, "kubernetes")
        .await?
        .context("method")?;
    method.config["host"] = json!("https://attacker.example");
    method.config["reviewer_jwt"] = json!(legacy);
    h.state.store.put_auth_method(method.clone()).await?;
    let stripped = SealConfig {
        mac: None,
        flags: SealFlags::default(),
        unlock_policy: UnlockPolicy::Manual,
        remembered: None,
        ..stored(&h).await?
    };
    h.state.store.update_seal_config(stripped).await?;

    let restarted = fresh(&db.url, SealSettings::default()).await?;
    let (code, body) = unseal_with(&restarted, PASSPHRASE).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    let adopted = stored(&restarted).await?;
    assert_eq!(check_signature(&root_key, &adopted), Signature::Valid);
    assert!(
        adopted.flags.reviewer_tokens_migrated,
        "an adopted configuration counts the migration as done"
    );
    let after = restarted
        .state
        .store
        .get_auth_method(&id, "kubernetes")
        .await?
        .context("method")?;
    assert_eq!(after.config, method.config, "the planted token is not moved");
    let config: sekret_api::AuthMethodConfig = serde_json::from_value(after.config).context("config")?;
    let sekret_api::AuthMethodConfig::Kubernetes(k8s) = config else {
        anyhow::bail!("kubernetes config expected");
    };
    assert!(sekret_server::machine::unseal_reviewer(&root_key, &id, &k8s).is_err());
    Ok(())
}

/// Flipping the wrap's form marker changes the signed message, and a configuration signed before
/// the marker was is signed again with it at the next unlock.
async fn the_wrap_form_marker_is_signed(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    init(&h).await?;
    let root_key = root(&h)?;
    let config = stored(&h).await?;
    assert!(config.flags.wrap_form_signed);
    assert_eq!(check_signature(&root_key, &config), Signature::Valid);
    let mut cleared = config.clone();
    if let Some(wrap) = cleared.wrapped.as_mut() {
        wrap.params.normalised = false;
    }
    assert_eq!(check_signature(&root_key, &cleared), Signature::Invalid);

    // Signed by a version that left the marker out.
    let fingerprint = root_key.fingerprint();
    let legacy_flags = SealFlags {
        wrap_form_signed: false,
        ..config.flags
    };
    let mut unmarked = config.wrapped.clone().context("wrap")?;
    unmarked.params.normalised = false;
    let mac = seal_config_mac(
        &root_key,
        &SealBinding {
            mode: config.mode,
            policy: config.unlock_policy,
            fingerprint: &fingerprint,
            epoch: config.epoch,
            wrapped: Some(&unmarked),
            remembered: None,
            flags: legacy_flags,
        },
    )
    .context("mac")?;
    let legacy = SealConfig {
        flags: legacy_flags,
        mac: Some(mac),
        ..config.clone()
    };
    assert_eq!(check_signature(&root_key, &legacy), Signature::Valid);
    h.state.store.update_seal_config(legacy).await?;
    drop(h);

    let restarted = fresh(&db.url, settings).await?;
    assert_eq!(unseal_with(&restarted, PASSPHRASE).await?.0, StatusCode::OK);
    let upgraded = stored(&restarted).await?;
    assert!(upgraded.flags.wrap_form_signed);
    assert!(upgraded.epoch > config.epoch);
    assert_eq!(check_signature(&root_key, &upgraded), Signature::Valid);
    Ok(())
}

/// A passphrase change that skips a project key it cannot open gives that project a new key, so
/// the new root opens every project key and the server still unlocks.
async fn a_rotation_past_an_unreadable_project_key_still_unlocks(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h).await?;
    h.create_project_as("kept", &admin).await?;
    h.create_project_as("broken", &admin).await?;
    h.set_secrets_as("kept", "dev", "/", &[("A", "kept")], &admin).await?;
    let broken = h.state.store.get_project("broken").await?.context("project")?;
    let stranger = RootKey::generate().context("stranger")?;
    h.state
        .store
        .replace_wrapped_keys(sekret_store::Rekey {
            keys: vec![(
                broken.id.clone(),
                wrap_data_key(&stranger, &DataKey::generate().context("dk")?, &broken.id).context("wrap")?,
            )],
            values: vec![],
            auth_methods: vec![],
            fingerprint: root(&h)?.fingerprint(),
            seal: None,
        })
        .await?;

    let change = json!({"current": PASSPHRASE, "new": ATTACKER, "skip_unreadable": true});
    let (status, body) = h.post("/api/v1/sys/passphrase", &admin, change).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    drop(h);

    let restarted = fresh(&db.url, settings).await?;
    let (code, body) = unseal_with(&restarted, ATTACKER).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    let (status, body) = restarted
        .get("/api/v1/projects/kept/environments/dev/secrets/A", &admin)
        .await?;
    assert_eq!(
        (status, body["value"].clone()),
        (StatusCode::OK, json!("kept")),
        "{body}"
    );
    restarted
        .set_secrets_as("broken", "dev", "/", &[("NEW", "fresh")], &admin)
        .await?;
    let (status, body) = restarted
        .get("/api/v1/projects/broken/environments/dev/secrets/NEW", &admin)
        .await?;
    assert_eq!(
        (status, body["value"].clone()),
        (StatusCode::OK, json!("fresh")),
        "{body}"
    );
    Ok(())
}

/// Once a root key change has begun, the marks already sit at the new configuration's epoch, so
/// a copy of the database from before it, put back while the marks still name both keys, is a
/// rollback rather than a sound configuration.
async fn a_copy_from_before_a_key_change_is_a_rollback_meanwhile(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h).await?;
    let old = root(&h)?;
    let before = stored(&h).await?;
    let new = RootKey::generate().context("new")?;
    let epoch = before.epoch + 1;
    begin_rekey(&settings.epoch_files, &old.fingerprint(), &new.fingerprint(), epoch).context("begin")?;
    assert_eq!(high_water(&settings.epoch_files).highest, Some(epoch));
    drop(h);

    let restarted = fresh(&db.url, settings.clone()).await?;
    assert_eq!(unseal_with(&restarted, PASSPHRASE).await?.0, StatusCode::OK);
    let actions = audit_actions(&restarted, &admin).await?;
    assert!(
        actions.contains(&"sys.seal_config.rolled_back".to_string()),
        "{actions:?}"
    );
    assert!(stored(&restarted).await?.epoch > epoch);
    assert_eq!(accepted_roots(&settings.epoch_files), Some(vec![old.fingerprint()]));
    Ok(())
}

/// A mark that cannot be moved to the new key after the change is committed is reported to the
/// caller, not only logged, and an uncommitted change puts the marks back.
#[cfg(unix)]
async fn a_mark_left_behind_by_a_key_change_is_reported(db: String) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    let db = persistent(&db)?;
    let h = fresh(&db.url, marked(db.dir.path())).await?;
    init(&h).await?;
    let old = root(&h)?;
    let locked = db.dir.path().join("locked");
    std::fs::create_dir(&locked).context("dir")?;
    // Skipped while the change begins, as a broken mark names no key, but replaced after it.
    let mark = locked.join("seal.epoch");
    std::fs::write(&mark, "not a mark\n").context("mark")?;
    let paths = vec![mark.clone()];
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).context("chmod")?;
    let new = RootKey::generate().context("new")?;
    let rotation = Rotation {
        marks: high_water(&[]),
        skip_unreadable: false,
        epoch_files: &paths,
    };
    let report = rotate_root_key(h.state.store.as_ref(), &old, &new, None, rotation).await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    let report = report.map_err(api_error("rotate"))?;
    assert!(report.stale_marks.is_some(), "{report:?}");
    assert_eq!(
        h.state.store.get_meta(sekret_server::ROOT_KEY_META).await?,
        Some(new.fingerprint()),
        "the change itself was committed"
    );
    record_epoch(&paths, 1, &new.fingerprint()).context("writable again, the mark is repaired")?;
    assert_eq!(accepted_roots(&paths), Some(vec![new.fingerprint()]));
    Ok(())
}

#[cfg(not(unix))]
async fn a_mark_left_behind_by_a_key_change_is_reported(_db: String) -> anyhow::Result<()> {
    Ok(())
}

on_both_backends!(
    a_planted_project_does_not_let_a_forged_root_in,
    an_unsigned_configuration_never_restarts_the_reviewer_migration,
    the_wrap_form_marker_is_signed,
    a_rotation_past_an_unreadable_project_key_still_unlocks,
    a_copy_from_before_a_key_change_is_a_rollback_meanwhile,
    a_mark_left_behind_by_a_key_change_is_reported,
);
