//! Regressions for the third security audit of the seal state: backups of tampered
//! configurations, epoch reuse and marks, the reviewer token migration, remember secrets,
//! unsigned repairs and unreadable data during a passphrase change. Also the eighth: planted
//! epochs and marks from before pins.

mod common;

use std::path::{Path, PathBuf};

use anyhow::Context;
use common::{Harness, api_error, opened, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_core::crypto::{DataKey, RootKey, seal_credential, wrap_data_key};
use sekret_core::seal::{
    KdfParams, MAX_SEAL_EPOCH, RememberSecret, SealFlags, UnlockPolicy, decrypt_backup, parse_backup, unwrap_root_key,
    wrap_root_key_with,
};
use sekret_server::StartupError;
use sekret_server::config::SealSettings;
use sekret_server::seal::{
    Signature, StartupSecrets, accepted_roots, check_root, check_signature, high_water, root_recognised, signed,
};
use sekret_store::{EncryptedValue, Project, Rekey, SealConfig, SqlStore, Store};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "violet tractor sings beneath";
const NEW_PASSPHRASE: &str = "copper lantern drifts at dawn";
const REMEMBER_SECRET: &str = "a remember secret of at least thirty-two characters";

fn marked(dir: &Path) -> SealSettings {
    SealSettings {
        remember_file: Some(dir.join("unlock.key")),
        epoch_files: vec![dir.join("sekret.db.epoch")],
        ..SealSettings::default()
    }
}

fn with_secret(dir: &Path) -> anyhow::Result<SealSettings> {
    Ok(SealSettings {
        remember_secret: Some(RememberSecret::new(REMEMBER_SECRET).map_err(|e| anyhow::anyhow!("{e}"))?),
        ..marked(dir)
    })
}

async fn fresh(url: &str, settings: SealSettings) -> anyhow::Result<Harness> {
    start(opened(url, settings, StartupSecrets::default())).await
}

fn with_unlock_passphrase() -> StartupSecrets {
    StartupSecrets {
        unlock_passphrase: Some(Zeroizing::new(PASSPHRASE.to_string())),
        auto_init: None,
    }
}

async fn state_of(h: &Harness) -> anyhow::Result<String> {
    let (code, body) = h.call(Method::GET, "/api/v1/sys/status", None, None).await?;
    anyhow::ensure!(code == StatusCode::OK, "status {code}: {body}");
    Ok(body["state"].as_str().context("state")?.to_string())
}

async fn init(h: &Harness, policy: &str) -> anyhow::Result<String> {
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
    Ok(body["admin_token"].as_str().context("token")?.to_string())
}

async fn unseal(h: &Harness) -> anyhow::Result<StatusCode> {
    let body = json!({"passphrase": PASSPHRASE});
    Ok(h.call(Method::POST, "/api/v1/sys/unseal", None, Some(body)).await?.0)
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

async fn stored(h: &Harness) -> anyhow::Result<SealConfig> {
    h.state.store.get_seal_config().await?.context("config")
}

fn root(h: &Harness) -> anyhow::Result<std::sync::Arc<RootKey>> {
    h.state.keyring.root().map_err(api_error("root"))
}

async fn raw_backup(h: &Harness, admin: &str) -> anyhow::Result<(StatusCode, Vec<u8>)> {
    let response = h
        .client
        .post(format!("{}/api/v1/sys/backup", h.base))
        .bearer_auth(admin)
        .send()
        .await
        .context("backup")?;
    let status = response.status();
    Ok((status, response.bytes().await.context("body")?.to_vec()))
}

/// The seal configuration inside a backup, read back the way a restore would.
async fn configuration_in(backup: &[u8], dir: &Path) -> anyhow::Result<SealConfig> {
    let parsed = parse_backup(backup).context("parse")?;
    let wrapped = parsed.header.wrapped().context("header")?.context("wrap")?;
    let root = unwrap_root_key(&wrapped, PASSPHRASE).context("unwrap")?;
    let snapshot = decrypt_backup(&root, &parsed).context("decrypt")?;
    let path = dir.join("restored.db");
    std::fs::write(&path, snapshot.as_slice()).context("write")?;
    let copy = SqlStore::connect(&format!("sqlite://{}", path.display()))
        .await
        .context("open copy")?;
    copy.get_seal_config().await?.context("config")
}

/// The demonstrated attack: a database writer turns on `remember`, then a backup signed the
/// changed configuration, and restoring it unlocked without a person.
async fn a_tampered_configuration_is_never_backed_up(db: String) -> anyhow::Result<()> {
    if db.starts_with("postgres") {
        return Ok(());
    }
    let db = persistent(&db)?;
    let h = fresh(&db.url, marked(db.dir.path())).await?;
    let admin = init(&h, "manual").await?;
    let mut config = stored(&h).await?;
    config.unlock_policy = UnlockPolicy::Remember;
    config.remembered = Some(vec![0x41; 72]);
    h.state.store.update_seal_config(config).await?;

    let (code, body) = raw_backup(&h, &admin).await?;
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::CONFLICT, json!("seal_config_tampered"))
    );
    let actions = audit_actions(&h, &admin).await?;
    assert!(actions.contains(&"sys.seal_config.tampered".to_string()), "{actions:?}");
    assert!(actions.contains(&"sys.backup.refused".to_string()), "{actions:?}");
    assert!(!actions.contains(&"sys.backup".to_string()));
    let after = stored(&h).await?;
    assert_ne!(
        check_signature(root(&h)?.as_ref(), &after),
        Signature::Valid,
        "the backup did not sign the tampered fields"
    );

    // Changes that prove nothing about the stored wrap are refused too, rather than signing it.
    let (status, _) = h
        .put("/api/v1/sys/unlock-policy", &admin, json!({"policy": "manual"}))
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    Ok(())
}

/// A backup's copy sits at its own epoch and the live configuration moves past it, so the copy
/// can never be put back as if it were current.
async fn backups_never_share_an_epoch_with_the_live_configuration(db: String) -> anyhow::Result<()> {
    if db.starts_with("postgres") {
        return Ok(());
    }
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h, "manual").await?;
    let (status, body) = h
        .put(
            "/api/v1/sys/unlock-policy",
            &admin,
            json!({"policy": "passphrase-file", "passphrase": PASSPHRASE}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = stored(&h).await?.epoch;
    let (code, backup) = raw_backup(&h, &admin).await?;
    assert_eq!(code, StatusCode::OK);
    let live = stored(&h).await?;
    let copy = configuration_in(&backup, db.dir.path()).await?;
    assert!(
        copy.epoch > before && live.epoch > copy.epoch,
        "{before} {} {}",
        copy.epoch,
        live.epoch
    );
    assert_eq!(high_water(&settings.epoch_files).highest, Some(live.epoch));
    assert_eq!(copy.remembered, None);
    assert_eq!(check_signature(root(&h)?.as_ref(), &copy), Signature::Valid);

    // A database writer puts the copy back into the live database: a rollback, so no unlock.
    h.state.store.update_seal_config(copy).await?;
    let restarted = start(opened(&db.url, settings, with_unlock_passphrase())).await?;
    assert_eq!(state_of(&restarted).await?, "sealed");
    assert_eq!(stored(&restarted).await?.unlock_policy, UnlockPolicy::Manual);
    Ok(())
}

/// The demonstrated attack: an old-format reviewer token put back by a database writer, pointed
/// at another cluster, was moved to the new format bound to that cluster at the next unlock.
async fn old_format_reviewer_tokens_are_moved_only_once(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h, "manual").await?;
    assert!(
        stored(&h).await?.flags.reviewer_tokens_migrated,
        "a new server records the migration as done"
    );
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

    // The writer plants an old-format blob, sealed under this root key, and points it elsewhere.
    let legacy =
        seal_credential(root(&h)?.as_ref(), "old-reviewer", &format!("identity:{id}:kubernetes")).context("seal")?;
    let mut method = h
        .state
        .store
        .get_auth_method(&id, "kubernetes")
        .await?
        .context("method")?;
    method.config["host"] = json!("https://attacker.example");
    method.config["reviewer_jwt"] = json!(legacy);
    h.state.store.put_auth_method(method.clone()).await?;

    let restarted = fresh(&db.url, settings.clone()).await?;
    assert_eq!(unseal(&restarted).await?, StatusCode::OK);
    let after = restarted
        .state
        .store
        .get_auth_method(&id, "kubernetes")
        .await?
        .context("method")?;
    assert_eq!(after.config, method.config, "the planted token is left as it is");
    let config: sekret_api::AuthMethodConfig = serde_json::from_value(after.config).context("config")?;
    let sekret_api::AuthMethodConfig::Kubernetes(k8s) = config else {
        anyhow::bail!("kubernetes config expected");
    };
    assert!(sekret_server::machine::unseal_reviewer(root(&restarted)?.as_ref(), &id, &k8s).is_err());

    // A database from before the flag existed moves its old-format tokens once.
    let root_key = root(&restarted)?;
    let unflagged = SealConfig {
        flags: SealFlags::default(),
        ..stored(&restarted).await?
    };
    let floor = high_water(&settings.epoch_files).floor();
    let unflagged = signed(&root_key, unflagged, floor)?;
    restarted.state.store.update_seal_config(unflagged.clone()).await?;
    // As a version from before marks recorded the migrations wrote them.
    for mark in &settings.epoch_files {
        let text = format!("sekret-seal-epoch {} {}\n", unflagged.epoch, root_key.pin()?);
        std::fs::write(mark, text).context("old mark")?;
    }
    let upgraded = fresh(&db.url, settings).await?;
    assert_eq!(unseal(&upgraded).await?, StatusCode::OK);
    assert!(stored(&upgraded).await?.flags.reviewer_tokens_migrated);
    let moved = upgraded
        .state
        .store
        .get_auth_method(&id, "kubernetes")
        .await?
        .context("method")?;
    let config: sekret_api::AuthMethodConfig = serde_json::from_value(moved.config).context("config")?;
    let sekret_api::AuthMethodConfig::Kubernetes(k8s) = config else {
        anyhow::bail!("kubernetes config expected");
    };
    let opened = sekret_server::machine::unseal_reviewer(&root_key, &id, &k8s).map_err(api_error("unseal"))?;
    assert_eq!(opened.as_deref().map(String::as_str), Some("old-reviewer"));
    Ok(())
}

/// The demonstrated attack: with the remember secret missing from the configuration, the next
/// manual unlock remembered under the device key alone, so the disk alone unlocked from then on.
async fn a_missing_remember_secret_never_weakens_the_wrap(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let secured = with_secret(db.dir.path())?;
    let plain = marked(db.dir.path());
    let first = fresh(&db.url, secured.clone()).await?;
    let admin = init(&first, "remember").await?;
    let remembered = stored(&first).await?;
    assert!(remembered.flags.remember_secret);
    assert!(remembered.remembered.is_some());
    let restarted = fresh(&db.url, secured.clone()).await?;
    assert_eq!(
        state_of(&restarted).await?,
        "unsealed",
        "the secret and the file unlock"
    );

    let without = fresh(&db.url, plain.clone()).await?;
    assert_eq!(state_of(&without).await?, "sealed");
    assert_eq!(unseal(&without).await?, StatusCode::OK);
    let after = stored(&without).await?;
    assert_eq!(after.remembered, remembered.remembered, "no weaker wrap replaced it");
    assert!(after.flags.remember_secret);
    assert!(
        audit_actions(&without, &admin)
            .await?
            .contains(&"sys.remember.refused".to_string())
    );
    let again = fresh(&db.url, plain.clone()).await?;
    assert_eq!(state_of(&again).await?, "sealed", "the disk alone still cannot unlock");
    assert_eq!(unseal(&again).await?, StatusCode::OK);

    // Forgetting the unlock is the one way to stop needing the secret.
    let (status, body) = again.post("/api/v1/sys/forget-unlock", &admin, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!stored(&again).await?.flags.remember_secret);
    let next = fresh(&db.url, plain.clone()).await?;
    assert_eq!(unseal(&next).await?, StatusCode::OK);
    assert!(
        stored(&next).await?.remembered.is_some(),
        "remembered without a secret, as asked"
    );
    let last = fresh(&db.url, plain).await?;
    assert_eq!(state_of(&last).await?, "unsealed");
    Ok(())
}

fn replace_mark(path: &Path, broken: &Mark) -> anyhow::Result<()> {
    std::fs::remove_file(path).context("remove mark")?;
    match broken {
        Mark::Garbage => std::fs::write(path, "not an epoch\n").context("garbage")?,
        Mark::Symlink(target) => {
            std::fs::write(target, "sekret-seal-epoch 1\n").context("target")?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, path).context("symlink")?;
        }
    }
    Ok(())
}

enum Mark {
    Garbage,
    Symlink(PathBuf),
}

/// Marks that exist but cannot be read fail closed instead of being ignored.
async fn damaged_epoch_marks_count_as_a_rollback(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let mark = db.dir.path().join("sekret.db.epoch");
    let first = fresh(&db.url, settings.clone()).await?;
    init(&first, "passphrase-file").await?;
    let unlocked = start(opened(&db.url, settings.clone(), with_unlock_passphrase())).await?;
    assert_eq!(state_of(&unlocked).await?, "unsealed");

    for broken in [Mark::Garbage, Mark::Symlink(db.dir.path().join("elsewhere"))] {
        replace_mark(&mark, &broken)?;
        let h = start(opened(&db.url, settings.clone(), with_unlock_passphrase())).await?;
        assert_eq!(state_of(&h).await?, "sealed", "a damaged mark is a rollback");
        let config = stored(&h).await?;
        assert_eq!(config.unlock_policy, UnlockPolicy::Manual);
        assert_eq!(
            high_water(&settings.epoch_files).highest,
            Some(config.epoch),
            "the mark is written again"
        );
        assert!(mark.symlink_metadata().is_ok_and(|m| m.file_type().is_file()));
        // Put the policy back for the next case.
        assert_eq!(unseal(&h).await?, StatusCode::OK);
        let token = sekret_server::admin::bootstrap_admin(&h.state, 600)
            .await
            .map_err(api_error("bootstrap"))?;
        let (status, body) = h
            .put(
                "/api/v1/sys/unlock-policy",
                &token,
                json!({"policy": "passphrase-file", "passphrase": PASSPHRASE}),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    Ok(())
}

/// Setting up a wiped database starts above the marks a previous one left, and never lowers them.
async fn a_wiped_database_never_lowers_the_marks(db: String) -> anyhow::Result<()> {
    if db.starts_with("postgres") {
        return Ok(());
    }
    let marks_dir = tempfile::tempdir().context("dir")?;
    let settings = marked(marks_dir.path());
    let first_db = persistent(&db)?;
    let first = fresh(&first_db.url, settings.clone()).await?;
    let admin = init(&first, "manual").await?;
    for policy in ["passphrase-file", "manual", "passphrase-file", "manual"] {
        let body = json!({"policy": policy, "passphrase": PASSPHRASE});
        let (status, _) = first.put("/api/v1/sys/unlock-policy", &admin, body).await?;
        assert_eq!(status, StatusCode::OK);
    }
    let mark = high_water(&settings.epoch_files).highest.context("mark")?;

    let second_db = persistent(&db)?;
    let second = fresh(&second_db.url, settings.clone()).await?;
    init(&second, "manual").await?;
    let config = stored(&second).await?;
    assert!(config.epoch > mark, "{} <= {mark}", config.epoch);
    assert_eq!(high_water(&settings.epoch_files).highest, Some(config.epoch));
    assert!(config.flags.reviewer_tokens_migrated);
    Ok(())
}

/// A tampered configuration found by an unlock that proves nothing about the wrap stays unsigned
/// until someone with the passphrase repairs it; nothing signs the writer's fields meanwhile.
async fn tampered_fields_are_never_signed_without_proof(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let first = fresh(&db.url, settings.clone()).await?;
    let admin = init(&first, "remember").await?;
    let mut config = stored(&first).await?;
    let honest_wrap = config.wrapped.clone();
    config.epoch += 1;
    config.wrapped = config.wrapped.map(|mut w| {
        w.params = sekret_core::seal::KdfParams::FLOOR;
        w
    });
    h_update(&first, config.clone()).await?;

    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(state_of(&h).await?, "sealed");
    assert_eq!(stored(&h).await?, config, "left exactly as the writer made it");
    assert!(
        audit_actions(&first, &admin)
            .await?
            .contains(&"sys.seal_config.tampered".to_string())
    );

    // The writer's wrap cannot be opened, so the unlock fails and still signs nothing.
    let status = unseal(&h).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(stored(&h).await?, config);

    // Putting the honest wrap back lets the passphrase prove it, and the repair is signed.
    h_update(
        &h,
        SealConfig {
            wrapped: honest_wrap,
            ..config
        },
    )
    .await?;
    assert_eq!(unseal(&h).await?, StatusCode::OK);
    let repaired = stored(&h).await?;
    assert_eq!(check_signature(root(&h)?.as_ref(), &repaired), Signature::Valid);
    assert_eq!(repaired.unlock_policy, UnlockPolicy::Manual);
    assert_eq!(repaired.remembered, None);
    assert!(repaired.flags.reviewer_tokens_migrated);
    Ok(())
}

/// A database writer clears the remember-secret flag. Repairing the configuration on the next
/// unlock, with the secret no longer configured, must set it again rather than trust the writer.
async fn a_repair_never_clears_the_remember_secret_requirement(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let first = fresh(&db.url, with_secret(db.dir.path())?).await?;
    init(&first, "remember").await?;
    let config = stored(&first).await?;
    assert!(config.flags.remember_secret);
    let cleared = SealConfig {
        flags: SealFlags {
            remember_secret: false,
            ..config.flags
        },
        ..config
    };
    h_update(&first, cleared).await?;

    let h = fresh(&db.url, marked(db.dir.path())).await?;
    assert_eq!(state_of(&h).await?, "sealed");
    assert_eq!(unseal(&h).await?, StatusCode::OK);
    let repaired = stored(&h).await?;
    assert_eq!(check_signature(root(&h)?.as_ref(), &repaired), Signature::Valid);
    assert!(repaired.flags.remember_secret, "only forget-unlock lifts it");
    Ok(())
}

async fn h_update(h: &Harness, config: SealConfig) -> anyhow::Result<()> {
    h.state.store.update_seal_config(config).await.context("update")
}

/// One value that no longer decrypts used to abort the whole passphrase change.
async fn unreadable_values_are_listed_or_skipped(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, marked(db.dir.path())).await?;
    let admin = init(&h, "manual").await?;
    h.create_project_as("app", &admin).await?;
    h.set_secrets_as("app", "dev", "/", &[("A", "kept"), ("B", "broken")], &admin)
        .await?;
    let project = h.state.store.get_project("app").await?.context("project")?;
    let environments = h.state.store.list_environments(&project.id).await?;
    let environment = environments.iter().find(|e| e.slug == "dev").context("dev")?;
    let broken = h
        .state
        .store
        .get_secret(&environment.id, "/", "B")
        .await?
        .context("secret")?;
    let values = h.state.store.list_encrypted_values(&project.id).await?;
    let victim = values
        .iter()
        .find(|v| v.secret_id == broken.secret.id)
        .context("value")?
        .clone();
    h.state
        .store
        .replace_wrapped_keys(Rekey {
            keys: vec![],
            values: vec![EncryptedValue {
                value: vec![0u8; 48],
                ..victim.clone()
            }],
            auth_methods: vec![],
            fingerprint: root(&h)?.fingerprint(),
            seal: None,
            integrity_key: None,
            revoke_credentials: false,
        })
        .await?;

    let change = |skip: bool| json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE, "skip_unreadable": skip});
    let (status, body) = h.post("/api/v1/sys/passphrase", &admin, change(false)).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "unreadable_data");
    let message = body["message"].as_str().context("message")?;
    assert!(message.contains(&victim.secret_id), "{message}");
    assert!(!message.contains("kept"), "values never reach the error");
    let old_root = root(&h)?;
    assert_eq!(
        h.state.store.get_meta(sekret_server::ROOT_KEY_META).await?,
        Some(old_root.fingerprint()),
        "nothing changed"
    );

    let (status, body) = h.post("/api/v1/sys/passphrase", &admin, change(true)).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_ne!(root(&h)?.fingerprint(), old_root.fingerprint());
    let (status, body) = h.get("/api/v1/projects/app/environments/dev/secrets/A", &admin).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["value"], "kept", "readable values were re-encrypted");
    let actions = audit_actions(&h, &admin).await?;
    assert!(actions.contains(&"sys.passphrase.skipped".to_string()), "{actions:?}");
    Ok(())
}

/// What a database writer with no key material does: wraps a root key of their own under a
/// passphrase they chose, records its fingerprint and signs the configuration with it far above
/// any mark. Returns their key.
async fn swap_in_a_forged_root(h: &Harness) -> anyhow::Result<RootKey> {
    let forged = RootKey::generate().context("forged")?;
    let config = SealConfig {
        wrapped: Some(wrap_root_key_with(&forged, NEW_PASSPHRASE, KdfParams::FLOOR).context("wrap")?),
        mac: None,
        ..stored(h).await?
    };
    let config = signed(&forged, config, 1 << 40)?;
    h.state.store.update_seal_config(config).await?;
    h.state
        .store
        .set_meta(sekret_server::ROOT_KEY_META, &forged.fingerprint())
        .await?;
    Ok(forged)
}

async fn unseal_with(h: &Harness, passphrase: &str) -> anyhow::Result<(StatusCode, Value)> {
    let body = json!({"passphrase": passphrase});
    h.call(Method::POST, "/api/v1/sys/unseal", None, Some(body)).await
}

/// The demonstrated attack: a database writer installed their own root key on a sealed server
/// and unsealed it with their own passphrase.
async fn a_database_writer_cannot_swap_in_their_own_root_key(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h, "manual").await?;
    let real = root(&h)?.fingerprint();
    let real_pin = root(&h)?.pin()?;
    assert_eq!(accepted_roots(&settings.epoch_files), Some(vec![real_pin.clone()]));
    let original = stored(&h).await?;

    swap_in_a_forged_root(&h).await?;
    let restarted = fresh(&db.url, settings.clone()).await?;
    let (code, body) = unseal_with(&restarted, NEW_PASSPHRASE).await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::CONFLICT, json!("root_key_not_recognised")),
        "{body}"
    );
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("reset-epoch --adopt-root-key")),
        "{body}"
    );
    assert_eq!(state_of(&restarted).await?, "sealed");
    assert_eq!(accepted_roots(&settings.epoch_files), Some(vec![real_pin]));

    // Putting the owner's rows back, as a restore would, lets the owner in, and the refusal shows.
    restarted.state.store.update_seal_config(original).await?;
    restarted
        .state
        .store
        .set_meta(sekret_server::ROOT_KEY_META, &real)
        .await?;
    assert_eq!(unseal(&restarted).await?, StatusCode::OK);
    let actions = audit_actions(&restarted, &admin).await?;
    assert!(actions.contains(&"sys.unseal.refused".to_string()), "{actions:?}");
    Ok(())
}

/// Without any marks, a forged root key still has to open the data that is already there.
async fn a_forged_root_key_must_open_the_existing_data(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h, "manual").await?;
    h.create_project_as("app", &admin).await?;
    swap_in_a_forged_root(&h).await?;
    let restarted = fresh(&db.url, SealSettings::default()).await?;
    let (code, body) = unseal_with(&restarted, NEW_PASSPHRASE).await?;
    assert_eq!(
        (code, body["error"].clone()),
        (StatusCode::CONFLICT, json!("root_key_not_recognised")),
        "{body}"
    );
    assert_eq!(state_of(&restarted).await?, "sealed");
    Ok(())
}

/// A database with projects but no recorded fingerprint is never handed to a key that cannot
/// read them; the key that can is recorded.
async fn a_missing_fingerprint_is_only_adopted_by_a_key_that_opens_the_data(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let store = SqlStore::connect(&db.url).await.context("store")?;
    let real = RootKey::generate().context("real")?;
    let data_key = DataKey::generate().context("data key")?;
    let project = Project {
        id: "p1".into(),
        slug: "app".into(),
        name: "App".into(),
        description: String::new(),
        wrapped_key: wrap_data_key(&real, &data_key, "p1").context("wrap")?,
        created_at: 1,
        logo_updated_at: None,
        secret_policy: None,
        secret_access: false,
    };
    store.create_project(project, vec![]).await?;
    let stranger = RootKey::generate().context("stranger")?;
    assert!(matches!(
        sekret_server::check_root_key(&store, &stranger.fingerprint()).await,
        Err(StartupError::WrongRootKey)
    ));
    assert!(matches!(
        check_root(&store, &[], &stranger).await,
        Err(StartupError::WrongRootKey)
    ));
    assert_eq!(store.get_meta(sekret_server::ROOT_KEY_META).await?, None);
    check_root(&store, &[], &real).await.context("the real key")?;
    assert_eq!(
        store.get_meta(sekret_server::ROOT_KEY_META).await?,
        Some(real.fingerprint())
    );
    Ok(())
}

/// Marks written before fingerprints existed name the root key from the next unlock on.
async fn marks_without_a_fingerprint_learn_it_at_the_next_unlock(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    init(&h, "manual").await?;
    let real = root(&h)?.pin()?;
    let epoch = stored(&h).await?.epoch;
    let mark = db.dir.path().join("sekret.db.epoch");
    std::fs::write(&mark, format!("sekret-seal-epoch {epoch}\n")).context("old mark")?;
    assert_eq!(accepted_roots(&settings.epoch_files), None);

    let restarted = fresh(&db.url, settings.clone()).await?;
    assert_eq!(unseal(&restarted).await?, StatusCode::OK);
    assert_eq!(accepted_roots(&settings.epoch_files), Some(vec![real]));
    assert_eq!(high_water(&settings.epoch_files).highest, Some(epoch));
    Ok(())
}

/// A passphrase change replaces the root key, so the marks follow it and the old key is refused.
async fn a_passphrase_change_moves_the_marks_to_the_new_key(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h, "manual").await?;
    let old = root(&h)?;
    let change = json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE});
    let (status, body) = h.post("/api/v1/sys/passphrase", &admin, change).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let new = root(&h)?;
    assert_eq!(accepted_roots(&settings.epoch_files), Some(vec![new.pin()?]));
    assert!(!root_recognised(&settings.epoch_files, &old));

    let restarted = fresh(&db.url, settings.clone()).await?;
    assert_eq!(unseal_with(&restarted, NEW_PASSPHRASE).await?.0, StatusCode::OK);
    assert_eq!(root(&restarted)?.fingerprint(), new.fingerprint());
    Ok(())
}

/// A crash between the database commit and the final mark leaves marks naming both keys, and
/// the server still starts on the new one.
async fn a_rotation_cut_short_still_unlocks(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h, "manual").await?;
    let old = root(&h)?.fingerprint();
    let change = json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE});
    let (status, body) = h.post("/api/v1/sys/passphrase", &admin, change).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let new_key = root(&h)?;
    let new = new_key.fingerprint();
    let epoch = high_water(&settings.epoch_files).highest.context("mark")?;
    let mark = db.dir.path().join("sekret.db.epoch");
    // As a version from before pins left it, naming both keys by their short fingerprints.
    std::fs::write(&mark, format!("sekret-seal-epoch {epoch} {old} {new}\n")).context("mark")?;

    let restarted = fresh(&db.url, settings.clone()).await?;
    assert_eq!(unseal_with(&restarted, NEW_PASSPHRASE).await?.0, StatusCode::OK);
    assert_eq!(
        accepted_roots(&settings.epoch_files),
        Some(vec![new_key.pin()?]),
        "the unlock narrows the mark again, to the full-length value"
    );
    Ok(())
}

on_both_backends!(
    a_tampered_configuration_is_never_backed_up,
    backups_never_share_an_epoch_with_the_live_configuration,
    old_format_reviewer_tokens_are_moved_only_once,
    a_missing_remember_secret_never_weakens_the_wrap,
    damaged_epoch_marks_count_as_a_rollback,
    a_wiped_database_never_lowers_the_marks,
    tampered_fields_are_never_signed_without_proof,
    a_repair_never_clears_the_remember_secret_requirement,
    unreadable_values_are_listed_or_skipped,
    a_database_writer_cannot_swap_in_their_own_root_key,
    a_forged_root_key_must_open_the_existing_data,
    a_missing_fingerprint_is_only_adopted_by_a_key_that_opens_the_data,
    marks_without_a_fingerprint_learn_it_at_the_next_unlock,
    a_passphrase_change_moves_the_marks_to_the_new_key,
    a_rotation_cut_short_still_unlocks,
    a_planted_epoch_never_blocks_the_unseal,
    short_fingerprint_marks_never_skip_the_data_check,
);

#[test]
fn a_configuration_at_the_last_epoch_is_refused() -> anyhow::Result<()> {
    let root = RootKey::generate().context("root")?;
    let config = SealConfig {
        mode: sekret_core::seal::SealMode::KeyFile,
        wrapped: None,
        unlock_policy: UnlockPolicy::Manual,
        remembered: None,
        epoch: MAX_SEAL_EPOCH - 2,
        mac: None,
        flags: SealFlags::default(),
        created_at: 0,
        updated_at: 0,
    };
    let last = signed(&root, config.clone(), 0)?;
    assert_eq!(last.epoch, MAX_SEAL_EPOCH - 1);
    assert_eq!(check_signature(&root, &last), Signature::Valid);
    assert!(signed(&root, last, 0).is_err(), "nothing follows it");
    assert!(
        signed(&root, config.clone(), i64::MAX).is_err(),
        "the epoch never wraps around"
    );
    for epoch in [MAX_SEAL_EPOCH, i64::MAX, -1] {
        let mut planted = signed(&root, config.clone(), 0)?;
        planted.epoch = epoch;
        assert_eq!(check_signature(&root, &planted), Signature::Invalid, "{epoch}");
    }
    Ok(())
}

/// The demonstrated attack: a database writer set the stored epoch to the last one, or the one
/// before. Every signature after it overflowed: a passphrase unseal failed with an internal
/// error, and a server under the passphrase-file policy did not start at all.
async fn a_planted_epoch_never_blocks_the_unseal(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h, "passphrase-file").await?;
    drop(h);
    for planted in [i64::MAX, i64::MAX - 1] {
        let mark = high_water(&settings.epoch_files).highest.context("mark")?;
        let store = SqlStore::connect(&db.url).await.context("store")?;
        let config = store.get_seal_config().await?.context("config")?;
        store
            .update_seal_config(SealConfig {
                epoch: planted,
                ..config
            })
            .await?;
        drop(store);

        let h = start(opened(&db.url, settings.clone(), with_unlock_passphrase())).await?;
        assert_eq!(
            state_of(&h).await?,
            "sealed",
            "{planted}: tampered, so no unlock at start"
        );
        let repaired = stored(&h).await?;
        assert_eq!(repaired.epoch, mark + 1, "{planted}: started from the marks");
        assert_eq!(repaired.unlock_policy, UnlockPolicy::Manual);
        assert_eq!(high_water(&settings.epoch_files).highest, Some(mark + 1));
        assert_eq!(unseal(&h).await?, StatusCode::OK, "{planted}");
        let body = json!({"policy": "passphrase-file", "passphrase": PASSPHRASE});
        let (status, body) = h.put("/api/v1/sys/unlock-policy", &admin, body).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // A planted mark out of range reads as damaged: a rollback, then written again.
    let mark = db.dir.path().join("sekret.db.epoch");
    std::fs::write(&mark, format!("sekret-seal-epoch {} \n", i64::MAX)).context("mark")?;
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(unseal(&h).await?, StatusCode::OK);
    let config = stored(&h).await?;
    assert_eq!(high_water(&settings.epoch_files).highest, Some(config.epoch));
    assert!(config.epoch < 100, "{}", config.epoch);

    // One just below the limit stops every signature, and says so.
    let (status, body) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pin = root_pin(&config)?;
    std::fs::write(&mark, format!("sekret-seal-epoch {} {pin}\n", MAX_SEAL_EPOCH - 1)).context("mark")?;
    let (status, body) = unseal_with(&h, PASSPHRASE).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "seal_epoch_exhausted");
    assert_eq!(state_of(&h).await?, "sealed");
    Ok(())
}

fn root_pin(config: &SealConfig) -> anyhow::Result<String> {
    let wrapped = config.wrapped.as_ref().context("wrap")?;
    Ok(unwrap_root_key(wrapped, PASSPHRASE).context("unwrap")?.pin()?)
}

/// Marks from before pins name the root key by 64 bits, which a well-funded database writer could
/// match with a key of their own. Until the next unlock rewrites them, they do not stand in for
/// opening every stored value.
async fn short_fingerprint_marks_never_skip_the_data_check(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h, "manual").await?;
    h.create_project_as("app", &admin).await?;
    h.set_secrets_as("app", "dev", "/", &[("A", "damaged")], &admin).await?;
    let project = h.state.store.get_project("app").await?.context("project")?;
    let value = h
        .state
        .store
        .list_encrypted_values(&project.id)
        .await?
        .into_iter()
        .next()
        .context("value")?;
    let fingerprint = root(&h)?.fingerprint();
    h.state
        .store
        .replace_wrapped_keys(Rekey {
            values: vec![EncryptedValue {
                value: vec![0u8; 48],
                ..value
            }],
            fingerprint: fingerprint.clone(),
            ..Rekey::default()
        })
        .await?;
    let (status, body) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(unseal(&h).await?, StatusCode::OK, "pinned marks vouch for the key");

    let (status, body) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let epoch = high_water(&settings.epoch_files).highest.context("mark")?;
    let mark = db.dir.path().join("sekret.db.epoch");
    std::fs::write(&mark, format!("sekret-seal-epoch {epoch} {fingerprint}\n")).context("old mark")?;
    let (status, body) = unseal_with(&h, PASSPHRASE).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "root_key_not_recognised");
    assert_eq!(state_of(&h).await?, "sealed");
    Ok(())
}
