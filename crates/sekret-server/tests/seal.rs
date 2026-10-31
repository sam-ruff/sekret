//! First-boot setup, sealing, unlock policies and backups, through the real router.

mod common;

use std::path::Path;

use anyhow::Context;
use common::{Harness, api_error, opened, persistent, start};
use reqwest::{Method, StatusCode};
use sekret_core::seal::{DeviceKey, SealMode, UnlockPolicy, decrypt_backup, parse_backup};
use sekret_server::config::SealSettings;
use sekret_server::seal::{AutoInit, StartupSecrets};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PASSPHRASE: &str = "violet tractor sings beneath";
const NEW_PASSPHRASE: &str = "copper lantern drifts at dawn";

fn secret(text: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(text.to_string()))
}

fn remembering(dir: &Path) -> SealSettings {
    SealSettings {
        remember_file: Some(dir.join("unlock.key")),
        ..SealSettings::default()
    }
}

async fn fresh(database_url: &str, settings: SealSettings) -> anyhow::Result<Harness> {
    start(opened(database_url, settings, StartupSecrets::default())).await
}

async fn status(h: &Harness) -> anyhow::Result<Value> {
    let (code, body) = h.call(Method::GET, "/api/v1/sys/status", None, None).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    Ok(body)
}

/// Runs first-boot setup in passphrase mode and returns the admin token.
async fn init(h: &Harness, policy: UnlockPolicy) -> anyhow::Result<String> {
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
    assert_eq!(status, StatusCode::OK, "{body}");
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

async fn read_secret(h: &Harness, token: &str) -> anyhow::Result<(StatusCode, Value)> {
    h.get("/api/v1/projects/app/environments/dev/secrets/A", token).await
}

async fn init_flow(db: String) -> anyhow::Result<()> {
    let h = fresh(&db, SealSettings::default()).await?;
    let body = status(&h).await?;
    assert_eq!(body["state"], "uninitialised");
    assert_eq!(body["seal_mode"], Value::Null);
    assert_eq!(body["web_setup"], true);
    let (code, body) = h.call(Method::GET, "/api/v1/projects", None, None).await?;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "uninitialised");

    let (code, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/passphrase-strength",
            None,
            Some(json!({"passphrase": "password1234"})),
        )
        .await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["acceptable"], false);

    let setup =
        |code: &str, passphrase: &str| json!({"setup_code": code, "mode": "passphrase", "passphrase": passphrase});
    let (code, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(setup("AAAA-AAAA-AAAA", PASSPHRASE)),
        )
        .await?;
    assert_eq!(code, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_setup_code");

    let setup_code = h.state.keyring.setup_code().context("setup code")?;
    let (code, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(setup(&setup_code.to_lowercase(), "password1234")),
        )
        .await?;
    assert_eq!(code, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "weak_passphrase");
    assert_eq!(body["strength"]["acceptable"], false);

    let (code, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(setup(&setup_code, PASSPHRASE)),
        )
        .await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["status"]["state"], "unsealed");
    assert_eq!(body["status"]["seal_mode"], "passphrase");
    assert_eq!(body["status"]["unlock_policy"], "manual");
    assert_eq!(body["status"]["configured"], false);
    let admin = body["admin_token"].as_str().context("token")?;
    let (code, _) = h
        .post("/api/v1/projects", admin, json!({"slug": "app", "name": "App"}))
        .await?;
    assert_eq!(code, StatusCode::CREATED);
    assert!(h.state.keyring.setup_code().is_none());

    let (code, _) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(setup(&setup_code, PASSPHRASE)),
        )
        .await?;
    assert_eq!(code, StatusCode::CONFLICT);

    // Once initialised, strength checks are for org admins only.
    let check = json!({"passphrase": PASSPHRASE});
    let (code, _) = h
        .call(
            Method::POST,
            "/api/v1/sys/passphrase-strength",
            None,
            Some(check.clone()),
        )
        .await?;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    let (code, body) = h.post("/api/v1/sys/passphrase-strength", admin, check).await?;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["acceptable"], true);
    Ok(())
}

async fn key_file_init(db: String) -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let h = fresh(&db, SealSettings::default()).await?;
    let code = h.state.keyring.setup_code().context("code")?;
    let request = json!({"setup_code": code.as_str(), "mode": "key-file"});
    let (status, body) = h
        .call(Method::POST, "/api/v1/sys/init", None, Some(request.clone()))
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["message"].as_str().unwrap_or_default().contains("root key file"));

    let key_file = dir.path().join("root.key");
    let settings = SealSettings {
        root_key_file: Some(key_file.clone()),
        ..SealSettings::default()
    };
    let db = persistent(&db)?;
    let h = fresh(&db.url, settings).await?;
    let code = h.state.keyring.setup_code().context("code")?;
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(json!({"setup_code": code.as_str(), "mode": "key-file"})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"]["seal_mode"], "key-file");
    assert_eq!(body["status"]["unlock_policy"], Value::Null);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_file).context("key file")?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let admin = body["admin_token"].as_str().context("token")?;
    let (status, body) = h.post("/api/v1/sys/seal", admin, json!({})).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    Ok(())
}

async fn restart_is_sealed_until_unsealed(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let first = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&first, UnlockPolicy::Manual).await?;
    first.create_project_as("app", &admin).await?;
    first
        .set_secrets_as("app", "dev", "/", &[("A", "kept")], &admin)
        .await?;

    let h = fresh(&db.url, SealSettings::default()).await?;
    let body = status(&h).await?;
    assert_eq!(body["state"], "sealed");
    assert_eq!(body["seal_mode"], "passphrase");
    let (code, body) = read_secret(&h, &admin).await?;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "sealed");
    let (code, _) = h.call(Method::GET, "/api/v1/health", None, None).await?;
    assert_eq!(code, StatusCode::OK);
    let (code, _) = h.call(Method::GET, "/api/v1/ready", None, None).await?;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);

    let (code, body) = unseal(&h, "not the passphrase at all").await?;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_passphrase");
    let (code, body) = unseal(&h, PASSPHRASE).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "unsealed");
    let (code, body) = read_secret(&h, &admin).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["value"], "kept");
    let (code, _) = h.call(Method::GET, "/api/v1/ready", None, None).await?;
    assert_eq!(code, StatusCode::OK);
    let (code, _) = unseal(&h, "already unsealed so not checked").await?;
    assert_eq!(code, StatusCode::OK);

    let (_, audit) = h.get("/api/v1/audit?limit=50", &admin).await?;
    let actions: Vec<&str> = audit["entries"]
        .as_array()
        .context("items")?
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(actions.contains(&"sys.unseal"), "{actions:?}");
    assert!(actions.contains(&"sys.unseal.failed"), "{actions:?}");
    assert!(!audit.to_string().contains(PASSPHRASE));
    Ok(())
}

async fn seal_and_unseal(db: String) -> anyhow::Result<()> {
    let h = fresh(&db, SealSettings::default()).await?;
    let admin = init(&h, UnlockPolicy::Manual).await?;
    h.create_project_as("app", &admin).await?;
    let member = h.machine_as("reader", "app", "viewer", &admin).await?.1;
    let (code, _) = h.post("/api/v1/sys/seal", &member, json!({})).await?;
    assert_eq!(code, StatusCode::FORBIDDEN);
    let (code, body) = h.post("/api/v1/sys/seal", &admin, json!({})).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "sealed");
    let (code, _) = h.get("/api/v1/projects", &admin).await?;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    let (code, _) = unseal(&h, PASSPHRASE).await?;
    assert_eq!(code, StatusCode::OK);
    let (code, _) = h.get("/api/v1/projects", &admin).await?;
    assert_eq!(code, StatusCode::OK);
    Ok(())
}

async fn change_passphrase(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h, UnlockPolicy::Manual).await?;
    let change = |current: &str, new: &str| json!({"current": current, "new": new});
    let (code, body) = h
        .post(
            "/api/v1/sys/passphrase",
            &admin,
            change("wrong passphrase here", NEW_PASSPHRASE),
        )
        .await?;
    assert_eq!(code, StatusCode::UNAUTHORIZED, "{body}");
    let (code, body) = h
        .post("/api/v1/sys/passphrase", &admin, change(PASSPHRASE, "short"))
        .await?;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "weak_passphrase");
    let (code, body) = h
        .post("/api/v1/sys/passphrase", &admin, change(PASSPHRASE, NEW_PASSPHRASE))
        .await?;
    assert_eq!(code, StatusCode::NO_CONTENT, "{body}");

    let restarted = fresh(&db.url, SealSettings::default()).await?;
    let (code, _) = unseal(&restarted, PASSPHRASE).await?;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    let (code, _) = unseal(&restarted, NEW_PASSPHRASE).await?;
    assert_eq!(code, StatusCode::OK);
    Ok(())
}

/// Every route in the OpenAPI document, plus sign-in, answers 503 while sealed.
async fn sealed_server_answers_nothing(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let first = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&first, UnlockPolicy::Manual).await?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let (code, openapi) = h.call(Method::GET, "/api/openapi.json", None, None).await?;
    assert_eq!(code, StatusCode::OK);
    let open = [
        "/api/v1/sys/status",
        "/api/v1/sys/init",
        "/api/v1/sys/unseal",
        "/api/v1/sys/passphrase-strength",
        // Revoking a token needs no root key, so it works while sealed.
        "/api/v1/auth/token/revoke",
        "/auth/logout",
    ];
    let mut checked = 0;
    for (path, item) in openapi["paths"].as_object().context("paths")? {
        if open.contains(&path.as_str()) {
            continue;
        }
        let concrete = path
            .split('/')
            .map(|segment| if segment.starts_with('{') { "x" } else { segment })
            .collect::<Vec<_>>()
            .join("/");
        for method in item.as_object().context("methods")?.keys() {
            let method = Method::from_bytes(method.to_uppercase().as_bytes()).context("method")?;
            let body = (method != Method::GET && method != Method::DELETE).then(|| json!({}));
            let (code, response) = h.call(method.clone(), &concrete, Some(&admin), body).await?;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{method} {concrete}: {response}");
            assert_eq!(response["error"], "sealed", "{method} {concrete}");
            checked += 1;
        }
    }
    assert!(checked > 40, "only {checked} routes checked");
    for path in ["/auth/login", "/auth/callback", "/api/v1/ready"] {
        let (code, _) = h.call(Method::GET, path, None, None).await?;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{path}");
    }
    for path in ["/api/v1/sys/status", "/api/v1/health", "/api/openapi.json", "/"] {
        let (code, _) = h.call(Method::GET, path, None, None).await?;
        assert_ne!(code, StatusCode::SERVICE_UNAVAILABLE, "{path}");
    }
    let (code, _) = h
        .call(
            Method::POST,
            "/api/v1/sys/passphrase-strength",
            None,
            Some(json!({"passphrase": PASSPHRASE})),
        )
        .await?;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

async fn download_backup(h: &Harness, token: &str) -> anyhow::Result<(StatusCode, Vec<u8>, String)> {
    let response = h
        .client
        .post(format!("{}/api/v1/sys/backup", h.base))
        .bearer_auth(token)
        .send()
        .await
        .context("backup")?;
    let code = response.status();
    let disposition = response
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    Ok((code, response.bytes().await.context("bytes")?.to_vec(), disposition))
}

async fn backups(db: String) -> anyhow::Result<()> {
    let postgres = db.starts_with("postgres");
    let db = persistent(&db)?;
    let h = fresh(&db.url, SealSettings::default()).await?;
    let admin = init(&h, UnlockPolicy::Manual).await?;
    h.create_project_as("app", &admin).await?;
    h.set_secrets_as("app", "dev", "/", &[("A", "backed-up")], &admin)
        .await?;

    let (code, body, disposition) = download_backup(&h, &admin).await?;
    if postgres {
        assert_eq!(code, StatusCode::NOT_IMPLEMENTED);
        assert!(String::from_utf8_lossy(&body).contains("pg_dump"));
        return Ok(());
    }
    assert_eq!(code, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(
        disposition.contains("sekret-backup-") && disposition.ends_with(".skb\""),
        "{disposition}"
    );
    let parsed = parse_backup(&body).context("parse")?;
    assert_eq!(parsed.header.mode, SealMode::Passphrase);
    let root = h.state.keyring.root().map_err(api_error("root"))?;
    let snapshot = decrypt_backup(&root, &parsed).context("decrypt")?;
    assert!(snapshot.starts_with(b"SQLite format 3\0"));
    assert!(!body.windows(9).any(|w| w == b"backed-up"));

    let member = h.machine_as("reader", "app", "viewer", &admin).await?.1;
    let (code, _, _) = download_backup(&h, &member).await?;
    assert_eq!(code, StatusCode::FORBIDDEN);

    let reader = h.org_identity_as("backup-reader-bot", "backup-reader", &admin).await?;
    let (code, _, _) = download_backup(&h, &reader).await?;
    assert_eq!(code, StatusCode::OK);
    for path in [
        "/api/v1/users",
        "/api/v1/identities",
        "/api/v1/audit",
        "/api/v1/org/bindings",
    ] {
        let (code, _) = h.get(path, &reader).await?;
        assert_eq!(code, StatusCode::FORBIDDEN, "{path}");
    }
    let (code, _) = read_secret(&h, &reader).await?;
    assert_eq!(code, StatusCode::NOT_FOUND);
    let (code, _) = h.post("/api/v1/sys/seal", &reader, json!({})).await?;
    assert_eq!(code, StatusCode::FORBIDDEN);
    let (code, _) = h
        .post("/api/v1/projects", &reader, json!({"slug": "nope", "name": "nope"}))
        .await?;
    assert_eq!(code, StatusCode::FORBIDDEN);

    let (_, audit) = h.get("/api/v1/audit?limit=50", &admin).await?;
    let backups = audit["entries"]
        .as_array()
        .context("items")?
        .iter()
        .filter(|e| e["action"] == "sys.backup")
        .count();
    assert_eq!(backups, 2);
    Ok(())
}

async fn remember_policy(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = remembering(db.dir.path());
    let file = db.dir.path().join("unlock.key");
    let first = fresh(&db.url, settings.clone()).await?;
    let admin = init(&first, UnlockPolicy::Remember).await?;
    assert!(file.exists());
    assert_eq!(status(&first).await?["remembered"], true);

    let h = fresh(&db.url, settings.clone()).await?;
    let body = status(&h).await?;
    assert_eq!(body["state"], "unsealed", "{body}");
    assert_eq!(body["unlock_policy"], "remember");

    std::fs::remove_file(&file).context("lose the file")?;
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    assert_eq!(status(&h).await?["remembered"], false);
    let (code, _) = unseal(&h, PASSPHRASE).await?;
    assert_eq!(code, StatusCode::OK);
    assert!(file.exists(), "the next manual unlock writes a fresh file");
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(status(&h).await?["state"], "unsealed");

    // Another server's device key does not open this one.
    let other = DeviceKey::generate().context("device")?;
    std::fs::write(&file, other.to_base64().as_bytes()).context("swap")?;
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    // Garbage the size of a device key, which the server may replace; anything else it leaves alone.
    std::fs::write(&file, format!("{}\n", "!".repeat(44))).context("tamper")?;
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    let (code, _) = unseal(&h, PASSPHRASE).await?;
    assert_eq!(code, StatusCode::OK);

    let (code, body) = h.post("/api/v1/sys/forget-unlock", &admin, json!({})).await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["remembered"], false);
    assert!(!file.exists());
    let h = fresh(&db.url, settings).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    Ok(())
}

async fn unlock_policy_changes(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let settings = remembering(db.dir.path());
    let file = db.dir.path().join("unlock.key");
    let h = fresh(&db.url, settings.clone()).await?;
    let admin = init(&h, UnlockPolicy::Manual).await?;
    assert!(!file.exists());
    let (code, body) = h
        .put(
            "/api/v1/sys/unlock-policy",
            &admin,
            json!({"policy": "remember", "passphrase": PASSPHRASE}),
        )
        .await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["unlock_policy"], "remember");
    assert!(file.exists());
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(status(&h).await?["state"], "unsealed");

    let (code, _) = h
        .put("/api/v1/sys/unlock-policy", &admin, json!({"policy": "manual"}))
        .await?;
    assert_eq!(code, StatusCode::OK);
    assert!(!file.exists(), "leaving remember forgets the unlock");
    let h = fresh(&db.url, settings.clone()).await?;
    assert_eq!(status(&h).await?["state"], "sealed");

    // Configuration wins over the stored policy and cannot be changed through the API.
    let configured = SealSettings {
        unlock: Some(UnlockPolicy::PassphraseFile),
        ..settings.clone()
    };
    let secrets = StartupSecrets {
        unlock_passphrase: secret(PASSPHRASE),
        auto_init: None,
    };
    let h = start(opened(&db.url, configured.clone(), secrets)).await?;
    let body = status(&h).await?;
    assert_eq!(body["state"], "unsealed", "{body}");
    assert_eq!(body["unlock_policy"], "passphrase-file");
    assert_eq!(body["configured"], true);
    let (code, _) = h
        .put("/api/v1/sys/unlock-policy", &admin, json!({"policy": "manual"}))
        .await?;
    assert_eq!(code, StatusCode::CONFLICT);

    let wrong = StartupSecrets {
        unlock_passphrase: secret("not the right passphrase"),
        auto_init: None,
    };
    let h = start(opened(&db.url, configured.clone(), wrong)).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    let h = fresh(&db.url, configured).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    Ok(())
}

async fn auto_init_key_file(db: String) -> anyhow::Result<()> {
    let key_db = persistent(&db)?;
    let key_file = key_db.dir.path().join("root.key");
    let key_settings = SealSettings {
        mode: Some(SealMode::KeyFile),
        root_key_file: Some(key_file.clone()),
        ..SealSettings::default()
    };
    let auto = || StartupSecrets {
        unlock_passphrase: None,
        auto_init: Some(AutoInit { passphrase: None }),
    };
    let h = start(opened(&key_db.url, key_settings.clone(), auto())).await?;
    assert_eq!(status(&h).await?["state"], "unsealed");
    assert!(key_file.exists());
    let h = fresh(&key_db.url, key_settings.clone()).await?;
    let body = status(&h).await?;
    assert_eq!(body["state"], "unsealed");
    assert_eq!(body["seal_mode"], "key-file");

    // A configured mode that disagrees with the database is refused.
    let conflicting = SealSettings {
        mode: Some(SealMode::Passphrase),
        root_key_file: None,
        ..SealSettings::default()
    };
    assert!(fresh(&key_db.url, conflicting).await.is_err());
    Ok(())
}

async fn auto_init_passphrase(db: String) -> anyhow::Result<()> {
    let pass_db = persistent(&db)?;
    let weak = StartupSecrets {
        unlock_passphrase: None,
        auto_init: Some(AutoInit {
            passphrase: secret("password1234"),
        }),
    };
    assert!(
        start(opened(&pass_db.url, SealSettings::default(), weak))
            .await
            .is_err()
    );
    let strong = StartupSecrets {
        unlock_passphrase: None,
        auto_init: Some(AutoInit {
            passphrase: secret(PASSPHRASE),
        }),
    };
    let h = start(opened(&pass_db.url, SealSettings::default(), strong)).await?;
    let body = status(&h).await?;
    assert_eq!(body["state"], "unsealed");
    assert_eq!(body["seal_mode"], "passphrase");
    let h = fresh(&pass_db.url, SealSettings::default()).await?;
    assert_eq!(status(&h).await?["state"], "sealed");
    let (code, _) = unseal(&h, PASSPHRASE).await?;
    assert_eq!(code, StatusCode::OK);
    Ok(())
}

async fn auto_init_reuses_an_existing_key_file(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let key_file = db.dir.path().join("root.key");
    let root = sekret_core::crypto::RootKey::generate().context("root")?;
    std::fs::write(&key_file, root.to_base64().as_bytes()).context("write")?;
    let settings = SealSettings {
        mode: Some(SealMode::KeyFile),
        root_key_file: Some(key_file),
        ..SealSettings::default()
    };
    let secrets = StartupSecrets {
        unlock_passphrase: None,
        auto_init: Some(AutoInit { passphrase: None }),
    };
    let h = start(opened(&db.url, settings, secrets)).await?;
    let loaded = h.state.keyring.root().map_err(api_error("root"))?;
    assert_eq!(loaded.fingerprint(), root.fingerprint());
    Ok(())
}

async fn web_setup_can_be_turned_off(db: String) -> anyhow::Result<()> {
    let settings = SealSettings {
        web_setup: false,
        ..SealSettings::default()
    };
    let h = fresh(&db, settings).await?;
    assert_eq!(status(&h).await?["web_setup"], false);
    assert!(
        h.state.keyring.setup_code().is_none(),
        "no code is made when it cannot be used"
    );
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(json!({"setup_code": "AAAA-AAAA-AAAA", "mode": "passphrase", "passphrase": PASSPHRASE})),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "setup_disabled");
    Ok(())
}

async fn existing_data_needs_its_key(db: String) -> anyhow::Result<()> {
    let db = persistent(&db)?;
    let key_file = db.dir.path().join("root.key");
    let root = sekret_core::crypto::RootKey::generate().context("root")?;
    std::fs::write(&key_file, root.to_base64().as_bytes()).context("write")?;
    let with_key = SealSettings {
        root_key_file: Some(key_file.clone()),
        ..SealSettings::default()
    };
    let h = fresh(&db.url, with_key.clone()).await?;
    assert_eq!(status(&h).await?["seal_mode"], "key-file");
    // Forgetting the key file must not offer setup over existing data.
    assert!(fresh(&db.url, SealSettings::default()).await.is_err());
    let other = sekret_core::crypto::RootKey::generate().context("root")?;
    std::fs::write(&key_file, other.to_base64().as_bytes()).context("write")?;
    assert!(fresh(&db.url, with_key).await.is_err());
    Ok(())
}

on_both_backends!(
    init_flow,
    key_file_init,
    restart_is_sealed_until_unsealed,
    seal_and_unseal,
    change_passphrase,
    sealed_server_answers_nothing,
    backups,
    remember_policy,
    unlock_policy_changes,
    auto_init_key_file,
    auto_init_passphrase,
    auto_init_reuses_an_existing_key_file,
    web_setup_can_be_turned_off,
    existing_data_needs_its_key,
);
