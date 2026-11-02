//! Regressions for the ninth security audit: a deleted or rolled back seal configuration where no
//! epoch mark can be written, replacing the integrity key with the root key, a tampered mode and
//! an unsigned passphrase wrap.

mod common;

use std::path::{Path, PathBuf};

use anyhow::Context;
use common::{Harness, Options, api_error, opened, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_core::crypto::{IntegrityKey, RootKey, hash_token};
use sekret_core::seal::{SealFlags, SealMode, SealState, UnlockPolicy, wrap_root_key};
use sekret_server::admin::{Rotation, rotate_root_key};
use sekret_server::auth::{Form, token_lookup, token_mac};
use sekret_server::config::SealSettings;
use sekret_server::seal::{
    HighWater, Signature, StartupSecrets, check_signature, high_water, load_integrity_key, marks_usable, signed,
};
use sekret_store::{AccessToken, PrincipalKind, SealConfig};
use serde_json::{Value, json};

const PASSPHRASE: &str = "violet tractor sings beneath";
const ATTACKER: &str = "mallard quietly invoices the moon";

/// A directory made read-only for the life of the guard, like a mounted secret.
struct ReadOnly(PathBuf);

impl ReadOnly {
    fn new(dir: &Path) -> anyhow::Result<Self> {
        set_mode(dir, 0o500)?;
        Ok(Self(dir.to_path_buf()))
    }
}

impl Drop for ReadOnly {
    fn drop(&mut self) {
        let _ = set_mode(&self.0, 0o700);
    }
}

fn set_mode(dir: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).context("chmod")
}

/// A key file on a read-only mount, with no other mark anywhere: Postgres with only a root key
/// file. SQLite is given the same marks so both backends see the same setup.
fn read_only_key_file(dir: &Path, root: &RootKey) -> anyhow::Result<(SealSettings, ReadOnly)> {
    let keys = dir.join("keys");
    std::fs::create_dir(&keys).context("keys dir")?;
    let key_file = keys.join("root.key");
    std::fs::write(&key_file, root.to_key_file_text().as_bytes()).context("key file")?;
    let settings = SealSettings {
        root_key_file: Some(key_file),
        epoch_files: vec![keys.join("root.key.epoch")],
        ..SealSettings::default()
    };
    Ok((settings, ReadOnly::new(&keys)?))
}

fn root(h: &Harness) -> anyhow::Result<std::sync::Arc<RootKey>> {
    h.state.keyring.root().map_err(api_error("root"))
}

async fn stored(h: &Harness) -> anyhow::Result<SealConfig> {
    h.state.store.get_seal_config().await?.context("config")
}

async fn user_id(h: &Harness, token: &str) -> anyhow::Result<String> {
    let (status, me) = h.get("/api/v1/me", token).await?;
    anyhow::ensure!(status == StatusCode::OK, "me {status}: {me}");
    Ok(me["id"].as_str().context("id")?.to_string())
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
    anyhow::ensure!(status == StatusCode::OK, "init {status}: {body}");
    Ok(body["admin_token"].as_str().context("token")?.to_string())
}

async fn unseal(h: &Harness) -> anyhow::Result<StatusCode> {
    let body = json!({"passphrase": PASSPHRASE});
    Ok(h.call(Method::POST, "/api/v1/sys/unseal", None, Some(body)).await?.0)
}

/// An admin token row as a database writer would plant it, under the old plain hash.
fn planted_token(token: &str, principal_id: &str) -> AccessToken {
    AccessToken {
        id: uuid::Uuid::new_v4().to_string(),
        token_hash: hash_token(token),
        kind: "admin".into(),
        principal_kind: PrincipalKind::User,
        principal_id: principal_id.into(),
        description: "planted".into(),
        source: String::new(),
        created_at: 0,
        expires_at: 4_000_000_000,
        max_expires_at: 4_000_000_000,
        revoked: false,
        last_used_at: None,
        auth_time: None,
        mac: None,
        sealed_hash: Some(hash_token(token)),
    }
}

/// The same row signed with an integrity key, as whoever holds it can make one.
fn forged_token(key: &IntegrityKey, token: &str, principal_id: &str) -> anyhow::Result<AccessToken> {
    let mut record = AccessToken {
        token_hash: token_lookup(key, token).map_err(api_error("lookup"))?,
        ..planted_token(token, principal_id)
    };
    record.mac = Some(token_mac(key, &record, Form::Current).map_err(api_error("mac"))?);
    Ok(record)
}

async fn universal_login(h: &Harness, id: &str, secret: &str) -> anyhow::Result<(StatusCode, Value)> {
    let body = json!({"client_id": id, "client_secret": secret});
    h.call(Method::POST, "/api/v1/auth/universal/login", None, Some(body))
        .await
}

/// H1: with the key file on a read-only mount and no other mark, a database writer deletes the
/// seal configuration and plants an unsigned admin token. The next start signs a new
/// configuration that never vouches for it.
async fn a_deleted_configuration_never_restarts_the_vouching(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    // No seal configuration, only the fingerprint: what deleting the row leaves.
    let h = start(Options {
        database_url: db.url.clone(),
        ..Options::default()
    })
    .await?;
    h.create_project("app").await?;
    h.set_secrets("app", "dev", "/", &[("DB", "hunter2")]).await?;
    let admin_id = user_id(&h, &h.admin).await?;
    let planted = "skt_planted-after-the-row-was-deleted";
    h.state.store.create_token(planted_token(planted, &admin_id)).await?;
    let (settings, _read_only) = read_only_key_file(db.dir.path(), root(&h)?.as_ref())?;
    assert!(h.state.store.get_seal_config().await?.is_none());
    drop(h);

    assert!(!marks_usable(&settings.epoch_files), "no mark can be written");
    let restarted = start(opened(&db.url, settings.clone(), StartupSecrets::default())).await?;
    let config = stored(&restarted).await?;
    assert!(config.flags.credentials_keyed, "nothing is vouched for");
    assert!(config.flags.reviewer_tokens_migrated);
    assert_eq!(restarted.get("/api/v1/me", planted).await?.0, StatusCode::UNAUTHORIZED);
    assert_eq!(restarted.get("/api/v1/me", &restarted.admin).await?.0, StatusCode::OK);
    let read = "/api/v1/projects/app/environments/dev/secrets/DB";
    assert_eq!(restarted.get(read, &restarted.admin).await?.0, StatusCode::OK);
    drop(restarted);

    // Nor on the next start, once the row exists again.
    let again = start(opened(&db.url, settings, StartupSecrets::default())).await?;
    assert_eq!(again.get("/api/v1/me", planted).await?.0, StatusCode::UNAUTHORIZED);
    Ok(())
}

/// H1, the rollback form: a signed configuration that has not run the vouching yet, put back
/// where no mark can record that it ran. The vouching waits for a mark rather than running.
async fn a_one_off_migration_waits_for_a_mark_to_record_it(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let marked = SealSettings {
        epoch_files: vec![db.dir.path().join("sekret.db.epoch")],
        ..SealSettings::default()
    };
    let h = start(opened(&db.url, marked.clone(), StartupSecrets::default())).await?;
    let admin = init(&h).await?;
    let admin_id = user_id(&h, &admin).await?;
    let current = stored(&h).await?;
    let unflagged = SealConfig {
        flags: SealFlags {
            credentials_keyed: false,
            ..current.flags
        },
        ..current
    };
    let floor = high_water(&marked.epoch_files).floor();
    h.state
        .store
        .update_seal_config(signed(root(&h)?.as_ref(), unflagged, floor)?)
        .await?;
    let planted = "skt_planted-before-a-replayed-migration";
    h.state.store.create_token(planted_token(planted, &admin_id)).await?;
    drop(h);

    let ro = db.dir.path().join("ro");
    std::fs::create_dir(&ro).context("dir")?;
    let _read_only = ReadOnly::new(&ro)?;
    let markless = SealSettings {
        epoch_files: vec![ro.join("seal.epoch")],
        ..SealSettings::default()
    };
    let restarted = start(opened(&db.url, markless, StartupSecrets::default())).await?;
    assert_eq!(unseal(&restarted).await?, StatusCode::OK);
    assert_eq!(restarted.get("/api/v1/me", planted).await?.0, StatusCode::UNAUTHORIZED);
    assert!(
        !stored(&restarted).await?.flags.credentials_keyed,
        "left for a start that can record it"
    );
    Ok(())
}

/// M1: whoever holds the old root key can open the old integrity key from any copy of the
/// database and forge credentials with it. A rotation with a new integrity key ends that, and
/// revokes every token and client secret, while auth methods keep working.
async fn a_new_integrity_key_ends_forgery_with_the_old_one(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = start(Options {
        database_url: db.url.clone(),
        ..Options::default()
    })
    .await?;
    h.create_project("app").await?;
    let (identity, machine_token) = h.machine("ci", "app", "viewer").await?;
    let (status, created) = h
        .post(
            &format!("/api/v1/identities/{identity}/client-secrets"),
            &h.admin,
            json!({}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let secret = created["client_secret"].as_str().context("secret")?.to_string();
    let admin_id = user_id(&h, &h.admin).await?;
    let old_root = root(&h)?;
    let old_integrity = load_integrity_key(h.state.store.as_ref(), &old_root)
        .await
        .map_err(api_error("integrity"))?;
    let forged = "skt_forged-with-the-old-integrity-key";
    h.state
        .store
        .create_token(forged_token(&old_integrity, forged, &admin_id)?)
        .await?;
    assert_eq!(h.get("/api/v1/me", forged).await?.0, StatusCode::OK, "the threat");

    let new_root = RootKey::generate().context("new root")?;
    let rotation = Rotation {
        marks: HighWater::default(),
        skip_unreadable: false,
        epoch_files: &[],
        new_integrity_key: true,
    };
    let report = rotate_root_key(h.state.store.as_ref(), &old_root, &new_root, None, rotation)
        .await
        .map_err(api_error("rotate"))?;
    assert!(report.credentials_revoked);
    let old_admin = h.admin.clone();
    drop(h);

    let key_file = db.dir.path().join("root.key");
    std::fs::write(&key_file, new_root.to_key_file_text().as_bytes()).context("key file")?;
    let settings = SealSettings {
        root_key_file: Some(key_file),
        epoch_files: vec![db.dir.path().join("root.key.epoch")],
        ..SealSettings::default()
    };
    let rotated = start(opened(&db.url, settings, StartupSecrets::default())).await?;
    for token in [forged, old_admin.as_str(), machine_token.as_str()] {
        assert_eq!(rotated.get("/api/v1/me", token).await?.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        universal_login(&rotated, &identity, &secret).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let again = "skt_forged-again-after-the-rotation";
    rotated
        .state
        .store
        .create_token(forged_token(&old_integrity, again, &admin_id)?)
        .await?;
    assert_eq!(rotated.get("/api/v1/me", again).await?.0, StatusCode::UNAUTHORIZED);

    // The auth method was re-signed, so a newly issued client secret logs in.
    let (status, created) = rotated
        .post(
            &format!("/api/v1/identities/{identity}/client-secrets"),
            &rotated.admin,
            json!({}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let fresh = created["client_secret"].as_str().context("secret")?;
    let (status, body) = universal_login(&rotated, &identity, fresh).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// Without the option a rotation keeps the integrity key, so nobody signs in again.
async fn a_plain_rotation_keeps_credentials(db: String) -> anyhow::Result<()> {
    let h = start(common::options(db)).await?;
    h.create_project("app").await?;
    let (_, machine_token) = h.machine("ci", "app", "viewer").await?;
    let old_root = root(&h)?;
    let new_root = RootKey::generate().context("new root")?;
    let rotation = Rotation::default();
    let report = rotate_root_key(h.state.store.as_ref(), &old_root, &new_root, None, rotation)
        .await
        .map_err(api_error("rotate"))?;
    assert!(!report.credentials_revoked);
    let integrity = load_integrity_key(h.state.store.as_ref(), &new_root)
        .await
        .map_err(api_error("integrity"))?;
    let stored = h
        .state
        .store
        .find_token(&token_lookup(&integrity, &machine_token).map_err(api_error("lookup"))?)
        .await?
        .context("token kept")?;
    assert!(!stored.revoked);
    Ok(())
}

/// L3: an unsigned configuration in passphrase mode is only signed with its wrap when a
/// passphrase has just opened that wrap. Started from the key file instead, the wrap a database
/// writer planted is dropped, and the server stays in key-file mode.
async fn an_unproven_wrap_is_never_signed(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = start(Options {
        database_url: db.url.clone(),
        ..Options::default()
    })
    .await?;
    let real = root(&h)?;
    let attacker = RootKey::generate().context("attacker")?;
    let planted = SealConfig {
        mode: SealMode::Passphrase,
        wrapped: Some(wrap_root_key(&attacker, ATTACKER)?),
        unlock_policy: UnlockPolicy::Manual,
        remembered: None,
        epoch: 0,
        mac: None,
        flags: SealFlags::default(),
        created_at: 0,
        updated_at: 0,
    };
    h.state
        .store
        .init_seal_config(planted, &real.fingerprint())
        .await
        .or_else(|e| match e {
            sekret_store::StoreError::Conflict => Ok(()),
            other => Err(other),
        })?;
    drop(h);

    let key_file = db.dir.path().join("root.key");
    std::fs::write(&key_file, real.to_key_file_text().as_bytes()).context("key file")?;
    let settings = SealSettings {
        root_key_file: Some(key_file),
        epoch_files: vec![db.dir.path().join("root.key.epoch")],
        ..SealSettings::default()
    };
    let restarted = start(opened(&db.url, settings, StartupSecrets::default())).await?;
    let config = stored(&restarted).await?;
    assert_eq!(config.mode, SealMode::KeyFile);
    assert!(config.wrapped.is_none(), "the planted wrap is gone");
    assert_eq!(check_signature(&real, &config), Signature::Valid);
    assert_eq!(restarted.state.keyring.mode(), Some(SealMode::KeyFile));
    assert_eq!(restarted.state.keyring.state(), SealState::Unsealed);
    Ok(())
}

on_both_backends!(
    a_deleted_configuration_never_restarts_the_vouching,
    a_one_off_migration_waits_for_a_mark_to_record_it,
    a_new_integrity_key_ends_forgery_with_the_old_one,
    a_plain_rotation_keeps_credentials,
    an_unproven_wrap_is_never_signed,
);
