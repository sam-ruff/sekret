//! Regressions for the seventh security audit: credentials authenticated under the integrity
//! key, the project key backstop, deleted epoch marks, the mode in the keyring and passphrase
//! changes beside a root key file.

mod common;

use std::path::Path;

use anyhow::Context;
use common::{Harness, api_error, opened, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_core::crypto::{DataKey, RootKey, hash_token, wrap_data_key};
use sekret_core::seal::{SealFlags, SealMode, wrap_root_key};
use sekret_server::auth::{Form, client_secret_mac};
use sekret_server::config::SealSettings;
use sekret_server::seal::{StartupSecrets, high_water, signed};
use sekret_store::{AccessToken, ClientSecret, PrincipalKind, Rekey, SealConfig};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "violet tractor sings beneath";
const NEW_PASSPHRASE: &str = "copper lantern drifts at dawn";
const ATTACKER: &str = "mallard quietly invoices the moon";

fn marked(dir: &Path) -> SealSettings {
    SealSettings {
        epoch_files: vec![dir.join("sekret.db.epoch")],
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
            Some(json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": PASSPHRASE})),
        )
        .await?;
    anyhow::ensure!(status == StatusCode::OK, "init {status}: {body}");
    Ok(body["admin_token"].as_str().context("token")?.to_string())
}

async fn unseal_with(h: &Harness, passphrase: &str) -> anyhow::Result<(StatusCode, Value)> {
    let body = json!({"passphrase": passphrase});
    h.call(Method::POST, "/api/v1/sys/unseal", None, Some(body)).await
}

fn root(h: &Harness) -> anyhow::Result<std::sync::Arc<RootKey>> {
    h.state.keyring.root().map_err(api_error("root"))
}

async fn stored(h: &Harness) -> anyhow::Result<SealConfig> {
    h.state.store.get_seal_config().await?.context("config")
}

async fn bootstrap_user_id(h: &Harness) -> anyhow::Result<String> {
    let (status, me) = h.get("/api/v1/me", &h.admin).await?;
    anyhow::ensure!(status == StatusCode::OK, "me {status}: {me}");
    Ok(me["id"].as_str().context("id")?.to_string())
}

/// A token row as a database writer would plant it, under the old plain hash.
fn planted_token(token: &str, principal_id: &str, mac: Option<String>) -> AccessToken {
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
        mac,
        sealed_hash: Some(hash_token(token)),
    }
}

/// The demonstrated attack: a database writer inserts an admin token row for a token of their
/// own choosing and reads secrets with it once the server is unsealed.
async fn a_database_writer_cannot_mint_or_move_a_token(db: String) -> anyhow::Result<()> {
    let h = common::start(common::options(db)).await?;
    h.create_project("app").await?;
    h.set_secrets("app", "dev", "/", &[("DB", "hunter2")]).await?;
    let admin_id = bootstrap_user_id(&h).await?;
    let read = "/api/v1/projects/app/environments/dev/secrets/DB";

    let forged = "skt_forged-by-a-database-writer";
    h.state
        .store
        .create_token(planted_token(forged, &admin_id, None))
        .await?;
    assert_eq!(h.get(read, forged).await?.0, StatusCode::UNAUTHORIZED);

    // A MAC from nowhere, and the token stored under what it would be looked up by, fare no better.
    let other = "skt_another-forged-token";
    h.state
        .store
        .create_token(AccessToken {
            mac: Some("00".repeat(32)),
            ..planted_token(other, &admin_id, None)
        })
        .await?;
    assert_eq!(h.get(read, other).await?.0, StatusCode::UNAUTHORIZED);

    // A real token of a user with no access, moved to the admin, stops working.
    let (_, token) = h.machine("reader", "app", "viewer").await?;
    assert_eq!(h.get(read, &token).await?.0, StatusCode::OK);
    let record = h.token_record(&token).await?;
    assert!(record.mac.is_some());
    assert_ne!(
        record.token_hash,
        hash_token(&token),
        "never stored under the plain hash"
    );
    let moved = AccessToken {
        id: uuid::Uuid::new_v4().to_string(),
        principal_kind: PrincipalKind::User,
        principal_id: admin_id,
        ..record.clone()
    };
    h.state.store.delete_identity(&record.principal_id).await?;
    h.state.store.create_token(moved).await?;
    assert_eq!(h.get(read, &token).await?.0, StatusCode::UNAUTHORIZED);
    Ok(())
}

/// A planted client secret, an auth method changed in the database and a CLI login approved in
/// the database all count for nothing.
async fn planted_client_secrets_auth_methods_and_approvals_are_refused(db: String) -> anyhow::Result<()> {
    let h = common::start(common::options(db)).await?;
    let (status, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "ci"})).await?;
    assert_eq!(status, StatusCode::CREATED, "{identity}");
    let id = identity["id"].as_str().context("id")?.to_string();
    let path = format!("/api/v1/identities/{id}/auth/universal");
    let (status, body) = h.put(&path, &h.admin, json!({"kind": "universal"})).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, created) = h
        .post(&format!("/api/v1/identities/{id}/client-secrets"), &h.admin, json!({}))
        .await?;
    let real = created["client_secret"].as_str().context("secret")?.to_string();
    let login = |secret: String| {
        let h = &h;
        let id = id.clone();
        async move {
            h.call(
                Method::POST,
                "/api/v1/auth/universal/login",
                None,
                Some(json!({"client_id": id, "client_secret": secret})),
            )
            .await
        }
    };
    assert_eq!(login(real.clone()).await?.0, StatusCode::OK);

    let planted = "sks_planted-by-a-database-writer";
    h.state
        .store
        .create_client_secret(ClientSecret {
            id: uuid::Uuid::new_v4().to_string(),
            identity_id: id.clone(),
            description: String::new(),
            secret_hash: hash_token(planted),
            prefix: "sks_plan".into(),
            created_at: 0,
            expires_at: None,
            uses_remaining: None,
            revoked: false,
            last_used_at: None,
            mac: None,
        })
        .await?;
    assert_eq!(login(planted.to_string()).await?.0, StatusCode::UNAUTHORIZED);

    // Signing the planted row with a key of their own does not help either.
    let stranger = sekret_core::crypto::IntegrityKey::generate().context("key")?;
    let mut signed_elsewhere = ClientSecret {
        id: uuid::Uuid::new_v4().to_string(),
        identity_id: id.clone(),
        description: String::new(),
        secret_hash: sekret_server::auth::client_secret_lookup(&stranger, "sks_x").map_err(api_error("lookup"))?,
        prefix: "sks_x".into(),
        created_at: 0,
        expires_at: None,
        uses_remaining: None,
        revoked: false,
        last_used_at: None,
        mac: None,
    };
    signed_elsewhere.mac =
        Some(client_secret_mac(&stranger, &signed_elsewhere, Form::Current).map_err(api_error("mac"))?);
    h.state.store.create_client_secret(signed_elsewhere).await?;
    assert_eq!(login("sks_x".into()).await?.0, StatusCode::UNAUTHORIZED);

    // An auth method changed in the database stops working until it is saved again.
    let mut method = h
        .state
        .store
        .get_auth_method(&id, "universal")
        .await?
        .context("method")?;
    method.config = json!({"kind": "universal", "planted": true});
    h.state.store.put_auth_method(method).await?;
    assert_eq!(login(real.clone()).await?.0, StatusCode::UNAUTHORIZED);
    let (status, body) = h.put(&path, &h.admin, json!({"kind": "universal"})).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(login(real).await?.0, StatusCode::OK);

    // A CLI login of the writer's own, approved for the admin straight in the database.
    let (status, started) = h.call(Method::POST, "/api/v1/auth/cli/start", None, None).await?;
    assert_eq!(status, StatusCode::OK, "{started}");
    let user_code = started["user_code"].as_str().context("user code")?;
    let admin_id = bootstrap_user_id(&h).await?;
    let now = h.state.clock.now();
    assert!(
        h.state
            .store
            .approve_cli_login(user_code, &admin_id, now, &"00".repeat(32))
            .await?
    );
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/auth/cli/poll",
            None,
            Some(json!({"device_code": started["device_code"]})),
        )
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.get("access_token").is_none());
    Ok(())
}

/// Tokens and client secrets from before the upgrade keep working after the first unlock vouches
/// for them, and move to the new form when used. One in the old form added afterwards is refused.
async fn credentials_from_before_the_upgrade_are_vouched_for_once(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h).await?;
    assert!(
        stored(&h).await?.flags.credentials_keyed,
        "a new database has nothing to vouch for"
    );
    let admin_id = {
        let (_, me) = h.get("/api/v1/me", &admin).await?;
        me["id"].as_str().context("id")?.to_string()
    };
    let (_, identity) = h.post("/api/v1/identities", &admin, json!({"name": "ci"})).await?;
    let identity_id = identity["id"].as_str().context("id")?.to_string();
    let (status, body) = h
        .put(
            &format!("/api/v1/identities/{identity_id}/auth/universal"),
            &admin,
            json!({"kind": "universal"}),
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Rows as an older version stored them: plain hashes, no MACs, and an unflagged configuration.
    let old_token = "skt_minted-by-an-older-version";
    h.state
        .store
        .create_token(planted_token(old_token, &admin_id, None))
        .await?;
    let old_secret = "sks_made-by-an-older-version";
    h.state
        .store
        .create_client_secret(ClientSecret {
            id: uuid::Uuid::new_v4().to_string(),
            identity_id: identity_id.clone(),
            description: String::new(),
            secret_hash: hash_token(old_secret),
            prefix: "sks_made".into(),
            created_at: 0,
            expires_at: None,
            uses_remaining: None,
            revoked: false,
            last_used_at: None,
            mac: None,
        })
        .await?;
    let mut method = h
        .state
        .store
        .get_auth_method(&identity_id, "universal")
        .await?
        .context("method")?;
    method.mac = None;
    h.state.store.put_auth_method(method).await?;
    let root_key = root(&h)?;
    let unflagged = SealConfig {
        flags: SealFlags {
            credentials_keyed: false,
            ..stored(&h).await?.flags
        },
        ..stored(&h).await?
    };
    let floor = high_water(&settings.epoch_files).floor();
    h.state
        .store
        .update_seal_config(signed(&root_key, unflagged, floor)?)
        .await?;
    drop(h);

    let upgraded = fresh(&db.url, settings.clone()).await?;
    assert_eq!(
        upgraded.get("/api/v1/me", old_token).await?.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(unseal_with(&upgraded, PASSPHRASE).await?.0, StatusCode::OK);
    assert!(stored(&upgraded).await?.flags.credentials_keyed);
    let (status, me) = upgraded.get("/api/v1/me", old_token).await?;
    assert_eq!(status, StatusCode::OK, "{me}");
    let moved = upgraded.token_record(old_token).await?;
    assert_ne!(
        moved.token_hash,
        hash_token(old_token),
        "moved to the keyed lookup on first use"
    );
    assert_eq!(moved.sealed_hash, Some(hash_token(old_token)));
    let (status, body) = upgraded
        .call(
            Method::POST,
            "/api/v1/auth/universal/login",
            None,
            Some(json!({"client_id": identity_id, "client_secret": old_secret})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The cut-off: an old-form row added after the vouching is refused, even across restarts.
    let late = "skt_planted-after-the-upgrade";
    upgraded
        .state
        .store
        .create_token(planted_token(late, &admin_id, None))
        .await?;
    assert_eq!(upgraded.get("/api/v1/me", late).await?.0, StatusCode::UNAUTHORIZED);
    drop(upgraded);
    let again = fresh(&db.url, settings).await?;
    assert_eq!(unseal_with(&again, PASSPHRASE).await?.0, StatusCode::OK);
    assert_eq!(again.get("/api/v1/me", late).await?.0, StatusCode::UNAUTHORIZED);
    assert_eq!(again.get("/api/v1/me", old_token).await?.0, StatusCode::OK);
    Ok(())
}

/// Changing the passphrase replaces the root key but keeps the integrity key, so nobody has to
/// sign in again and machines keep their client secrets.
async fn credentials_survive_a_passphrase_change(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h).await?;
    let (_, identity) = h.post("/api/v1/identities", &admin, json!({"name": "ci"})).await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    h.put(
        &format!("/api/v1/identities/{id}/auth/universal"),
        &admin,
        json!({"kind": "universal"}),
    )
    .await?;
    let (_, created) = h
        .post(&format!("/api/v1/identities/{id}/client-secrets"), &admin, json!({}))
        .await?;
    let secret = created["client_secret"].as_str().context("secret")?.to_string();
    let wrapped_before = h
        .state
        .store
        .get_meta(sekret_store::INTEGRITY_KEY_META)
        .await?
        .context("integrity key")?;

    let change = json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE});
    let (status, body) = h.post("/api/v1/sys/passphrase", &admin, change).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let wrapped_after = h
        .state
        .store
        .get_meta(sekret_store::INTEGRITY_KEY_META)
        .await?
        .context("integrity key")?;
    assert_ne!(wrapped_before, wrapped_after, "wrapped under the new root key");
    drop(h);

    let restarted = fresh(&db.url, settings).await?;
    assert_eq!(unseal_with(&restarted, NEW_PASSPHRASE).await?.0, StatusCode::OK);
    assert_eq!(restarted.get("/api/v1/me", &admin).await?.0, StatusCode::OK);
    let (status, body) = restarted
        .call(
            Method::POST,
            "/api/v1/auth/universal/login",
            None,
            Some(json!({"client_id": id, "client_secret": secret})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// The demonstrated attack: with no mark naming a key, a database writer wraps fresh data keys
/// for every project under a root key of their own, signs a configuration with it and unseals
/// with their passphrase. Values already stored do not decrypt under their keys, so it fails.
async fn a_swapped_root_key_is_refused_while_any_stored_value_is_left(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h).await?;
    h.create_project_as("app", &admin).await?;
    h.set_secrets_as("app", "dev", "/", &[("DB", "hunter2")], &admin)
        .await?;

    let theirs = RootKey::generate().context("their root")?;
    let mut keys = Vec::new();
    for project in h.state.store.list_projects().await? {
        let dek = DataKey::generate().context("dek")?;
        keys.push((
            project.id.clone(),
            wrap_data_key(&theirs, &dek, &project.id).context("wrap")?,
        ));
    }
    let config = SealConfig {
        wrapped: Some(wrap_root_key(&theirs, ATTACKER).context("wrap root")?),
        ..stored(&h).await?
    };
    let config = signed(&theirs, config, 1000).context("sign")?;
    h.state
        .store
        .replace_wrapped_keys(Rekey {
            keys,
            fingerprint: theirs.fingerprint(),
            seal: Some(config),
            ..Rekey::default()
        })
        .await?;
    drop(h);
    for mark in &settings.epoch_files {
        std::fs::remove_file(mark).context("delete the mark")?;
    }

    let restarted = fresh(&db.url, settings.clone()).await?;
    let (status, body) = unseal_with(&restarted, ATTACKER).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "root_key_not_recognised");
    assert_eq!(restarted.state.keyring.state(), sekret_core::seal::SealState::Sealed);
    assert_eq!(
        high_water(&settings.epoch_files).highest,
        None,
        "no mark was written for their key"
    );
    Ok(())
}

/// Deleting every mark no longer turns rollback detection off: a configuration that says marks
/// were written, with none left where one could be, is treated as rolled back.
async fn deleted_marks_turn_off_automatic_unlocks(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = marked(db.dir.path());
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h).await?;
    let policy = json!({"policy": "passphrase-file", "passphrase": PASSPHRASE});
    let (status, body) = h.put("/api/v1/sys/unlock-policy", &admin, policy).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    drop(h);
    let with_passphrase = || StartupSecrets {
        unlock_passphrase: Some(Zeroizing::new(PASSPHRASE.to_string())),
        auto_init: None,
    };
    let unlocked = start(opened(&db.url, settings.clone(), with_passphrase())).await?;
    assert_eq!(unlocked.state.keyring.state(), sekret_core::seal::SealState::Unsealed);
    drop(unlocked);

    for mark in &settings.epoch_files {
        std::fs::remove_file(mark).context("delete the mark")?;
    }
    let restarted = start(opened(&db.url, settings.clone(), with_passphrase())).await?;
    assert_eq!(
        restarted.state.keyring.state(),
        sekret_core::seal::SealState::Sealed,
        "no automatic unlock once the marks are gone"
    );
    assert_eq!(
        stored(&restarted).await?.unlock_policy,
        sekret_core::seal::UnlockPolicy::Manual
    );
    assert!(
        high_water(&settings.epoch_files).highest.is_some(),
        "the marks are written again"
    );
    assert_eq!(unseal_with(&restarted, PASSPHRASE).await?.0, StatusCode::OK);
    Ok(())
}

/// A database writer flips the stored mode to key-file while the server is sealed. The passphrase
/// unseal proves passphrase mode, so sealing still works, and the untrusted configuration is
/// never signed again.
async fn a_tampered_mode_never_reaches_the_keyring_or_a_signature(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, marked(db.dir.path())).await?;
    let admin = init(&h).await?;
    let (status, body) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tampered = SealConfig {
        mode: SealMode::KeyFile,
        ..stored(&h).await?
    };
    h.state.store.update_seal_config(tampered.clone()).await?;

    assert_eq!(unseal_with(&h, PASSPHRASE).await?.0, StatusCode::OK);
    assert_eq!(h.state.keyring.mode(), Some(SealMode::Passphrase));
    let change = json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE});
    let (status, body) = h.post("/api/v1/sys/passphrase", &admin, change).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "seal_config_tampered");
    assert_eq!(stored(&h).await?, tampered, "nothing the writer chose was signed");
    let (status, body) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// A passphrase change replaces the root key, so a key file read at start would hold the old
/// one and the server could not start again. It is refused while one is in use or present.
async fn the_passphrase_cannot_change_beside_a_root_key_file(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let key_file = db.dir.path().join("root.key");
    let settings = SealSettings {
        root_key_file: Some(key_file.clone()),
        ..marked(db.dir.path())
    };
    let h = fresh(&db.url, marked(db.dir.path())).await?;
    let admin = init(&h).await?;
    let before = root(&h)?;
    std::fs::write(&key_file, before.to_key_file_text().as_bytes()).context("key file")?;
    drop(h);

    let from_file = fresh(&db.url, settings.clone()).await?;
    assert_eq!(
        from_file.state.keyring.unsealed_by(),
        Some(sekret_core::seal::UnsealedBy::KeyFile)
    );
    let change = json!({"current": PASSPHRASE, "new": NEW_PASSPHRASE});
    let (status, body) = from_file.post("/api/v1/sys/passphrase", &admin, change.clone()).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "root_key_file_in_use");
    assert_eq!(root(&from_file)?.fingerprint(), before.fingerprint());
    drop(from_file);

    // Unsealed with the passphrase, but the file is still there to be read at the next start.
    let beside = fresh(&db.url, marked(db.dir.path())).await?;
    let mut configured = beside.state.config.clone();
    configured.seal.root_key_file = Some(key_file.clone());
    let state = sekret_server::state::build_state(sekret_server::state::Dependencies {
        store: beside.state.store.clone(),
        keyring: sekret_server::seal::Keyring::sealed(sekret_core::seal::UnlockPolicy::Manual, false),
        config: configured,
        clock: std::sync::Arc::new(sekret_server::clock::SystemClock),
        http: std::sync::Arc::new(sekret_server::net::ReqwestOidcHttp::new(true).context("http")?),
        token_reviewer: std::sync::Arc::new(sekret_server::net::ReqwestTokenReviewer::new(true)),
    });
    sekret_server::seal::ops::unseal(
        &state,
        sekret_server::seal::ops::Source::HostSocket,
        Zeroizing::new(PASSPHRASE.to_string()),
    )
    .await
    .map_err(api_error("unseal"))?;
    let principal = sekret_server::auth::Principal::system("test");
    let refused = sekret_server::seal::ops::change_passphrase(
        &state,
        sekret_server::seal::ops::Source::HostSocket,
        &principal,
        Zeroizing::new(PASSPHRASE.to_string()),
        Zeroizing::new(NEW_PASSPHRASE.to_string()),
        false,
    )
    .await;
    assert!(
        matches!(&refused, Err(error) if error.code == "root_key_file_in_use"),
        "{:?}",
        refused.err().map(|e| e.code)
    );

    // Without the file the change goes ahead.
    std::fs::remove_file(&key_file).context("remove the key file")?;
    assert_eq!(unseal_with(&beside, PASSPHRASE).await?.0, StatusCode::OK);
    let (status, body) = beside.post("/api/v1/sys/passphrase", &admin, change).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    Ok(())
}

/// A host command that stopped between the database commit and moving the new key file into
/// place leaves `<file>.new`; the start-up error says where it is.
async fn a_key_file_left_behind_by_a_host_command_is_pointed_out(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let key_file = db.dir.path().join("root.key");
    let settings = SealSettings {
        root_key_file: Some(key_file.clone()),
        ..marked(db.dir.path())
    };
    let first = RootKey::generate().context("root")?;
    std::fs::write(&key_file, first.to_key_file_text().as_bytes()).context("key file")?;
    let h = start(opened(&db.url, settings.clone(), StartupSecrets::default())).await?;
    assert_eq!(h.state.keyring.state(), sekret_core::seal::SealState::Unsealed);
    drop(h);
    let stale = RootKey::generate().context("stale")?;
    std::fs::write(&key_file, stale.to_key_file_text().as_bytes()).context("stale key")?;
    let refused = start(opened(&db.url, settings.clone(), StartupSecrets::default())).await;
    let message = format!("{:?}", refused.err().context("refused")?);
    assert!(!message.contains(".new"), "nothing to point at yet: {message}");

    let pending = sekret_server::seal::pending_key_file(&key_file);
    std::fs::write(
        &pending,
        RootKey::generate().context("new")?.to_key_file_text().as_bytes(),
    )
    .context("pending")?;
    let refused = start(opened(&db.url, settings, StartupSecrets::default())).await;
    let message = format!("{:?}", refused.err().context("refused")?);
    assert!(message.contains(&pending.display().to_string()), "{message}");
    Ok(())
}

/// While sealed the integrity key is out of reach, so the few routes open then find a token by
/// its plain hash. That only reaches those routes, and stops counting at the unseal.
async fn the_plain_hash_only_counts_while_sealed(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, marked(db.dir.path())).await?;
    let admin = init(&h).await?;
    let (_, me) = h.get("/api/v1/me", &admin).await?;
    let admin_id = me["id"].as_str().context("id")?.to_string();
    let planted = "skt_planted-for-the-sealed-routes";
    h.state
        .store
        .create_token(planted_token(planted, &admin_id, None))
        .await?;
    assert_eq!(
        h.get("/api/v1/sys/status/detail", planted).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, body) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Sealed: the status a database writer could read from the database anyway, nothing more.
    assert_eq!(h.get("/api/v1/sys/status/detail", planted).await?.0, StatusCode::OK);
    assert_eq!(h.get("/api/v1/me", planted).await?.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(h.get("/api/v1/sys/status/detail", &admin).await?.0, StatusCode::OK);

    assert_eq!(unseal_with(&h, PASSPHRASE).await?.0, StatusCode::OK);
    assert_eq!(
        h.get("/api/v1/sys/status/detail", planted).await?.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.get("/api/v1/me", planted).await?.0, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get("/api/v1/me", &admin).await?.0, StatusCode::OK);
    Ok(())
}

on_both_backends!(
    the_plain_hash_only_counts_while_sealed,
    a_database_writer_cannot_mint_or_move_a_token,
    planted_client_secrets_auth_methods_and_approvals_are_refused,
    credentials_from_before_the_upgrade_are_vouched_for_once,
    credentials_survive_a_passphrase_change,
    a_swapped_root_key_is_refused_while_any_stored_value_is_left,
    deleted_marks_turn_off_automatic_unlocks,
    a_tampered_mode_never_reaches_the_keyring_or_a_signature,
    the_passphrase_cannot_change_beside_a_root_key_file,
    a_key_file_left_behind_by_a_host_command_is_pointed_out,
);
