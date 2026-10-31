mod common;

use anyhow::Context;
use common::{Harness, Options, api_error, options, start};
use reqwest::{Method, StatusCode};
use serde_json::json;

const SECRETS: &str = "/api/v1/projects/app/environments";

async fn secret_flow(h: &Harness) -> anyhow::Result<()> {
    h.create_project("app").await?;
    let (_, envs) = h.get("/api/v1/projects/app/environments", &h.admin).await?;
    let slugs: Vec<&str> = envs
        .as_array()
        .context("envs")?
        .iter()
        .filter_map(|e| e["slug"].as_str())
        .collect();
    assert_eq!(slugs, ["dev", "staging", "prod"]);

    let created = h
        .set_secrets("app", "dev", "/", &[("DB_URL", "postgres://one"), ("API_KEY", "k1")])
        .await?;
    assert_eq!(created["created"], json!(["DB_URL", "API_KEY"]));
    h.set_secrets("app", "prod", "/", &[("DB_URL", "postgres://prod")])
        .await?;
    h.set_secrets("app", "dev", "/nested/deep", &[("INNER", "x")]).await?;

    let (status, listed) = h.get(&format!("{SECRETS}/dev/secrets?values=true"), &h.admin).await?;
    assert_eq!(status, StatusCode::OK);
    let keys: Vec<&str> = listed["secrets"]
        .as_array()
        .context("secrets")?
        .iter()
        .filter_map(|s| s["key"].as_str())
        .collect();
    assert_eq!(keys, ["API_KEY", "DB_URL"]);
    assert_eq!(listed["folders"], json!(["nested"]));
    assert_eq!(listed["secrets"][1]["value"], "postgres://one");

    let (_, hidden) = h.get(&format!("{SECRETS}/dev/secrets"), &h.admin).await?;
    assert!(hidden["secrets"][0]["value"].is_null());

    let (_, recursive) = h
        .get(&format!("{SECRETS}/dev/secrets?recursive=true"), &h.admin)
        .await?;
    assert_eq!(recursive["secrets"].as_array().map(Vec::len), Some(3));

    // Update twice then roll back to the first value.
    h.set_secrets("app", "dev", "/", &[("DB_URL", "postgres://two")])
        .await?;
    let unchanged = h
        .set_secrets("app", "dev", "/", &[("DB_URL", "postgres://two")])
        .await?;
    assert_eq!(unchanged["unchanged"], json!(["DB_URL"]));
    h.set_secrets("app", "dev", "/", &[("DB_URL", "postgres://three")])
        .await?;
    let (_, versions) = h
        .get(&format!("{SECRETS}/dev/secrets/DB_URL/versions?values=true"), &h.admin)
        .await?;
    let values: Vec<&str> = versions
        .as_array()
        .context("versions")?
        .iter()
        .filter_map(|v| v["value"].as_str())
        .collect();
    assert_eq!(values, ["postgres://three", "postgres://two", "postgres://one"]);
    let (status, body) = h
        .post(
            &format!("{SECRETS}/dev/secrets/DB_URL/rollback"),
            &h.admin,
            json!({"version": 1}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, current) = h.get(&format!("{SECRETS}/dev/secrets/DB_URL"), &h.admin).await?;
    assert_eq!(
        (current["value"].as_str(), current["version"].as_i64()),
        (Some("postgres://one"), Some(4))
    );

    // Snapshot restore puts a deleted key back and removes one added later.
    let (_, snapshots) = h.get(&format!("{SECRETS}/dev/snapshots"), &h.admin).await?;
    let latest = snapshots[0]["id"].as_str().context("snapshot")?.to_string();
    let (status, _) = h.delete(&format!("{SECRETS}/dev/secrets/API_KEY"), &h.admin).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.get(&format!("{SECRETS}/dev/secrets/API_KEY"), &h.admin).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "deleted secrets are gone from single reads"
    );
    h.set_secrets("app", "dev", "/", &[("LATE", "added")]).await?;
    let (_, detail) = h.get(&format!("{SECRETS}/dev/snapshots/{latest}"), &h.admin).await?;
    let kinds: Vec<(&str, &str)> = detail["changes"]
        .as_array()
        .context("changes")?
        .iter()
        .map(|c| {
            (
                c["key"].as_str().unwrap_or_default(),
                c["kind"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(kinds, [("API_KEY", "added"), ("LATE", "removed")]);
    let (status, restored) = h
        .post(
            &format!("{SECRETS}/dev/snapshots/{latest}/restore"),
            &h.admin,
            json!({"path": "/"}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{restored}");
    let (_, after) = h.get(&format!("{SECRETS}/dev/secrets"), &h.admin).await?;
    let keys: Vec<&str> = after["secrets"]
        .as_array()
        .context("secrets")?
        .iter()
        .filter_map(|s| s["key"].as_str())
        .collect();
    assert_eq!(keys, ["API_KEY", "DB_URL"]);

    let (_, overview) = h.get("/api/v1/projects/app/overview", &h.admin).await?;
    let api_key_row = overview["rows"]
        .as_array()
        .context("rows")?
        .iter()
        .find(|r| r["key"] == "API_KEY")
        .context("row")?
        .clone();
    assert!(api_key_row["environments"]["dev"].is_i64());
    assert!(api_key_row["environments"]["prod"].is_null());

    let (status, raw) = h
        .get("/api/v1/secrets/raw?project=app&environment=prod", &h.admin)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        raw["secrets"],
        json!([{"path": "/", "key": "DB_URL", "value": "postgres://prod"}])
    );

    let (_, audit) = h
        .get("/api/v1/projects/app/audit?action=secret.rollback", &h.admin)
        .await?;
    assert_eq!(audit["entries"].as_array().map(Vec::len), Some(1));
    assert_eq!(audit["total"], 1);
    assert!(
        !audit.to_string().contains("postgres://"),
        "audit log must not contain values"
    );
    Ok(())
}

on_both_backends!(
    secrets_history_rollback_and_snapshots,
    validation_and_not_found,
    rbac_scopes_machine_identities,
    rbac_key_tag_and_folder_conditions,
    members_cannot_grant_more_than_they_hold,
    machine_tokens_respect_revocation_disable_and_cidrs,
    client_secrets_with_use_limits_and_revocation,
    organisation_and_project_administration,
    security_review_regressions,
    second_review_regressions,
    credentials_and_folders_are_scoped,
    project_logos,
    generation_and_rotation,
    third_review_regressions,
    hostile_text_is_inert,
    root_key_rotation_keeps_secrets_readable,
    kubernetes_reviewer_tokens_are_write_only_and_survive_rotation,
    backups_permission_and_the_backup_reader_role,
    system_actions_are_audited,
);

/// A key-file server set up through the production start path, so a seal configuration exists.
async fn key_file_server(db: &common::Persistent) -> anyhow::Result<Harness> {
    use sekret_core::seal::SealMode;
    use sekret_server::config::SealSettings;
    use sekret_server::seal::{AutoInit, StartupSecrets};
    let settings = SealSettings {
        mode: Some(SealMode::KeyFile),
        root_key_file: Some(db.dir.path().join("root.key")),
        ..SealSettings::default()
    };
    let secrets = StartupSecrets {
        unlock_passphrase: None,
        auto_init: Some(AutoInit { passphrase: None }),
    };
    start(common::opened(&db.url, settings, secrets)).await
}

async fn backups_permission_and_the_backup_reader_role(db: String) -> anyhow::Result<()> {
    let postgres = db.starts_with("postgres");
    let db = common::persistent(&db)?;
    let h = key_file_server(&db).await?;
    h.create_project("app").await?;
    h.set_secrets("app", "dev", "/", &[("A", "b")]).await?;

    let backups = json!({"name": "Backups", "rules": [{"effect": "allow", "subject": "backups", "actions": ["read"]}]});
    let (status, _) = h
        .put("/api/v1/projects/app/roles/backups", &h.admin, backups.clone())
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "backups is an organisation subject");
    let (status, body) = h.put("/api/v1/org/roles/backup-puller", &h.admin, backups).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let denied = json!({"name": "No backups", "rules": [
        {"effect": "allow", "subject": "backups", "actions": ["read"]},
        {"effect": "deny", "subject": "backups", "actions": ["read"]}
    ]});
    h.put("/api/v1/org/roles/no-backups", &h.admin, denied).await?;

    let custom = h.org_identity_as("puller", "backup-puller", &h.admin).await?;
    let reader = h.org_identity_as("reader", "backup-reader", &h.admin).await?;
    let member = h.org_identity_as("member", "org-member", &h.admin).await?;
    let blocked = h.org_identity_as("blocked", "no-backups", &h.admin).await?;
    let (_, project_viewer) = h.machine("viewer", "app", "viewer").await?;
    let allowed = if postgres {
        StatusCode::NOT_IMPLEMENTED
    } else {
        StatusCode::OK
    };
    for (who, token, expected) in [
        ("org-admin", h.admin.as_str(), allowed),
        ("custom role", custom.as_str(), allowed),
        ("backup-reader", reader.as_str(), allowed),
        ("org-member", member.as_str(), StatusCode::FORBIDDEN),
        ("deny wins", blocked.as_str(), StatusCode::FORBIDDEN),
        ("project viewer", project_viewer.as_str(), StatusCode::FORBIDDEN),
    ] {
        let (status, _) = h.post("/api/v1/sys/backup", token, json!({})).await?;
        assert_eq!(status, expected, "{who}");
    }

    let (_, me) = h.get("/api/v1/me", &reader).await?;
    assert_eq!(
        me["org_rules"],
        json!([{"effect": "allow", "subject": "backups", "actions": ["read"]}])
    );
    let forbidden = [
        (Method::GET, "/api/v1/users", None),
        (Method::GET, "/api/v1/identities", None),
        (Method::GET, "/api/v1/audit", None),
        (Method::GET, "/api/v1/org/bindings", None),
        (Method::GET, "/api/v1/org/roles", None),
        (
            Method::POST,
            "/api/v1/projects",
            Some(json!({"slug": "nope", "name": "nope"})),
        ),
        (Method::POST, "/api/v1/identities", Some(json!({"name": "nope"}))),
        (
            Method::POST,
            "/api/v1/org/bindings",
            Some(json!({"principal_kind": "group", "principal_id": "g", "role": "org-admin"})),
        ),
        (
            Method::PUT,
            "/api/v1/org/roles/mine",
            Some(json!({"name": "Mine", "rules": []})),
        ),
        (Method::POST, "/api/v1/sys/seal", Some(json!({}))),
        (
            Method::POST,
            "/api/v1/sys/passphrase",
            Some(json!({"current": "a", "new": "b"})),
        ),
        (
            Method::PUT,
            "/api/v1/sys/unlock-policy",
            Some(json!({"policy": "manual"})),
        ),
        (Method::POST, "/api/v1/sys/forget-unlock", Some(json!({}))),
        (
            Method::POST,
            "/api/v1/sys/passphrase-strength",
            Some(json!({"passphrase": "x"})),
        ),
    ];
    for (method, path, body) in forbidden {
        let (status, _) = h.call(method.clone(), path, Some(&reader), body).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "backup-reader {method} {path}");
    }
    for path in [
        "/api/v1/projects/app",
        "/api/v1/projects/app/environments/dev/secrets",
        "/api/v1/projects/app/environments/dev/secrets/A",
        "/api/v1/projects/app/audit",
    ] {
        let (status, _) = h.get(path, &reader).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "backup-reader {path}");
    }
    let (status, projects) = h.get("/api/v1/projects", &reader).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(!projects.to_string().contains("\"app\""), "{projects}");
    Ok(())
}

async fn system_actions_are_audited(db: String) -> anyhow::Result<()> {
    use sekret_server::config::SealSettings;
    use sekret_server::seal::StartupSecrets;

    let postgres = db.starts_with("postgres");
    let db = common::persistent(&db)?;
    let settings = SealSettings {
        remember_file: Some(db.dir.path().join("unlock.key")),
        ..SealSettings::default()
    };
    let h = start(common::opened(&db.url, settings, StartupSecrets::default())).await?;
    let first = "violet tractor sings beneath";
    let second = "copper lantern drifts at dawn";
    let code = h.state.keyring.setup_code().context("setup code")?;
    let (status, body) = h
        .call(
            Method::POST,
            "/api/v1/sys/init",
            None,
            Some(json!({"setup_code": code.as_str(), "mode": "passphrase", "passphrase": first})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let admin = body["admin_token"].as_str().context("token")?.to_string();

    let steps = [
        (
            Method::PUT,
            "/api/v1/sys/unlock-policy",
            json!({"policy": "remember", "passphrase": first}),
        ),
        (Method::POST, "/api/v1/sys/forget-unlock", json!({})),
        (
            Method::POST,
            "/api/v1/sys/passphrase",
            json!({"current": first, "new": second}),
        ),
        (Method::POST, "/api/v1/sys/seal", json!({})),
    ];
    for (method, path, body) in steps {
        let (status, response) = h.call(method, path, Some(&admin), Some(body)).await?;
        assert!(status.is_success(), "{path}: {status} {response}");
    }
    for (passphrase, expected) in [(first, StatusCode::UNAUTHORIZED), (second, StatusCode::OK)] {
        let (status, _) = h
            .call(
                Method::POST,
                "/api/v1/sys/unseal",
                None,
                Some(json!({"passphrase": passphrase})),
            )
            .await?;
        assert_eq!(status, expected);
    }
    let (status, _) = h.post("/api/v1/sys/backup", &admin, json!({})).await?;
    assert_eq!(status.is_success(), !postgres);

    let (_, audit) = h.get("/api/v1/audit?limit=100&order=asc", &admin).await?;
    let entries = audit["entries"].as_array().context("entries")?;
    let sys: Vec<(&str, &str)> = entries
        .iter()
        .filter_map(|e| Some((e["action"].as_str()?, e["actor_name"].as_str()?)))
        .filter(|(action, _)| action.starts_with("sys."))
        .collect();
    let mut expected = vec![
        ("sys.init", "identity:setup"),
        ("sys.unlock_policy", "user:bootstrap-admin"),
        ("sys.forget_unlock", "user:bootstrap-admin"),
        ("sys.passphrase", "user:bootstrap-admin"),
        ("sys.seal", "user:bootstrap-admin"),
        ("sys.unseal.failed", "identity:unseal"),
        ("sys.unseal", "identity:unseal"),
    ];
    if !postgres {
        expected.push(("sys.backup", "user:bootstrap-admin"));
    }
    assert_eq!(sys, expected);
    let policy = entries
        .iter()
        .find(|e| e["action"] == "sys.unlock_policy")
        .context("policy entry")?;
    assert_eq!(policy["detail"]["policy"], "remember");
    assert!(entries.iter().all(|e| e["ip"] == "127.0.0.1"));
    let text = audit.to_string();
    assert!(
        !text.contains(first) && !text.contains(second),
        "no passphrases in the audit log"
    );
    Ok(())
}

async fn secrets_history_rollback_and_snapshots(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    secret_flow(&h).await
}

async fn validation_and_not_found(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let (status, _) = h
        .post("/api/v1/projects", &h.admin, json!({"slug": "app", "name": "dup"}))
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = h
        .post("/api/v1/projects", &h.admin, json!({"slug": "Bad Slug", "name": "x"}))
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .post(
            &format!("{SECRETS}/dev/secrets/batch"),
            &h.admin,
            json!({"path": "/../etc", "upserts": [{"key": "A", "value": "b"}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h.get(&format!("{SECRETS}/nope/secrets"), &h.admin).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h.get("/api/v1/projects/missing", &h.admin).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = h.get("/api/v1/does-not-exist", &h.admin).await?;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    let (status, _) = h.call(Method::GET, "/api/v1/projects", None, None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .call(Method::GET, "/api/v1/projects", Some("skt_forged"), None)
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn rbac_scopes_machine_identities(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    h.set_secrets("app", "dev", "/", &[("DEV_ONLY", "d")]).await?;
    h.set_secrets("app", "prod", "/", &[("PROD_ONLY", "p")]).await?;
    h.set_secrets("app", "dev", "/team", &[("TEAM", "t")]).await?;

    let role = json!({
        "name": "Dev reader",
        "rules": [
            {"effect": "allow", "subject": "secrets", "actions": ["read", "read-value"], "conditions": {"environments": ["dev"]}},
            {"effect": "deny", "subject": "secrets", "actions": ["read-value"], "conditions": {"paths": ["/team/**", "/team"]}},
            {"effect": "allow", "subject": "environments", "actions": ["read"]}
        ]
    });
    let (status, body) = h.put("/api/v1/projects/app/roles/dev-reader", &h.admin, role).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, token) = h.machine("ci", "app", "dev-reader").await?;

    let (status, raw) = h
        .get("/api/v1/secrets/raw?project=app&environment=dev&recursive=true", &token)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(raw["secrets"], json!([{"path": "/", "key": "DEV_ONLY", "value": "d"}]));
    let (_, prod) = h
        .get("/api/v1/secrets/raw?project=app&environment=prod", &token)
        .await?;
    assert_eq!(prod["secrets"], json!([]));
    let (status, _) = h.get(&format!("{SECRETS}/prod/secrets/PROD_ONLY"), &token).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, team) = h.get(&format!("{SECRETS}/dev/secrets/TEAM?path=/team"), &token).await?;
    assert!(team["value"].is_null() && team["value_hidden"] == true);

    let (status, _) = h
        .post(
            &format!("{SECRETS}/dev/secrets/batch"),
            &token,
            json!({"upserts": [{"key": "X", "value": "y"}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h.post("/api/v1/identities", &token, json!({"name": "evil"})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .put(
            "/api/v1/projects/app/roles/mine",
            &token,
            json!({"name": "x", "rules": []}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A project the identity is not a member of is invisible.
    h.create_project("other").await?;
    let (_, projects) = h.get("/api/v1/projects", &token).await?;
    assert_eq!(projects.as_array().map(Vec::len), Some(1));
    let (status, _) = h.get("/api/v1/projects/other/environments", &token).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

async fn rbac_key_tag_and_folder_conditions(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let batch = format!("{SECRETS}/dev/secrets/batch");
    let (status, body) = h
        .post(
            &batch,
            &h.admin,
            json!({"upserts": [
                {"key": "DB_HOST", "value": "db.internal"},
                {"key": "DB_PASS", "value": "hunter2", "tags": ["sensitive"]},
                {"key": "API_KEY", "value": "k"}
            ]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    for folder in ["/public", "/private"] {
        let (status, body) = h
            .post(&format!("{SECRETS}/dev/folders"), &h.admin, json!({"path": folder}))
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    let role = json!({"name": "DB operator", "rules": [
        {"effect": "allow", "subject": "secrets", "actions": ["read", "read-value", "edit"], "conditions": {"keys": ["DB_*"]}},
        {"effect": "deny", "subject": "secrets", "actions": ["read-value", "edit"], "conditions": {"tags": ["sensitive"]}},
        {"effect": "allow", "subject": "folders", "actions": ["read"], "conditions": {"paths": ["/public"]}},
        {"effect": "allow", "subject": "environments", "actions": ["read"]}
    ]});
    let (status, body) = h.put("/api/v1/projects/app/roles/db-operator", &h.admin, role).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, token) = h.machine("db", "app", "db-operator").await?;

    let (_, listed) = h.get(&format!("{SECRETS}/dev/secrets?values=true"), &token).await?;
    let keys: Vec<&str> = listed["secrets"]
        .as_array()
        .context("secrets")?
        .iter()
        .filter_map(|s| s["key"].as_str())
        .collect();
    assert_eq!(keys, ["DB_HOST", "DB_PASS"], "key condition hides API_KEY");
    assert_eq!(listed["folders"], json!(["public"]), "folder read is path scoped");
    let (_, folders) = h.get(&format!("{SECRETS}/dev/folders"), &token).await?;
    assert_eq!(folders.as_array().map(Vec::len), Some(1));

    let (_, raw) = h.get("/api/v1/secrets/raw?project=app&environment=dev", &token).await?;
    assert_eq!(
        raw["secrets"],
        json!([{"path": "/", "key": "DB_HOST", "value": "db.internal"}])
    );
    let (_, pass) = h.get(&format!("{SECRETS}/dev/secrets/DB_PASS"), &token).await?;
    assert!(pass["value"].is_null() && pass["value_hidden"] == true, "{pass}");

    let edit = |key: &str| json!({"upserts": [{"key": key, "value": "changed"}]});
    let (status, _) = h.post(&batch, &token, edit("DB_HOST")).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.post(&batch, &token, edit("DB_PASS")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "tag-scoped deny on edit");
    let (status, _) = h.post(&batch, &token, edit("API_KEY")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let value_only = json!({"name": "Value only", "rules": [
        {"effect": "allow", "subject": "secrets", "actions": ["read-value"]}
    ]});
    h.put("/api/v1/projects/app/roles/value-only", &h.admin, value_only)
        .await?;
    let (_, value_token) = h.machine("values", "app", "value-only").await?;
    let (_, raw) = h
        .get("/api/v1/secrets/raw?project=app&environment=dev", &value_token)
        .await?;
    assert_eq!(raw["secrets"], json!([]), "raw values need read as well as read-value");
    Ok(())
}

async fn security_review_regressions(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let batch = format!("{SECRETS}/dev/secrets/batch");
    h.post(
        &batch,
        &h.admin,
        json!({"upserts": [
            {"key": "VAULT", "value": "old-secret", "tags": ["restricted"]},
            {"key": "PIN", "value": "1234"}
        ]}),
    )
    .await?;

    // Retagging a secret must not reveal versions that carried a restricted tag.
    let rotator = json!({"name": "Rotator", "rules": [
        {"effect": "allow", "subject": "secrets", "actions": ["read", "read-value", "create", "edit"]},
        {"effect": "allow", "subject": "secret-versions", "actions": ["read", "read-value"]},
        {"effect": "deny", "subject": "secrets", "actions": ["read-value"], "conditions": {"tags": ["restricted"]}}
    ]});
    h.put("/api/v1/projects/app/roles/rotator", &h.admin, rotator).await?;
    let (_, token) = h.machine("rotator", "app", "rotator").await?;
    let (status, _) = h
        .post(
            &batch,
            &token,
            json!({"upserts": [{"key": "VAULT", "value": "new", "tags": []}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (_, versions) = h
        .get(&format!("{SECRETS}/dev/secrets/VAULT/versions?values=true"), &token)
        .await?;
    assert!(!versions.to_string().contains("old-secret"), "{versions}");

    // Writing without read-value must not reveal whether the value was already the same.
    let blind = json!({"name": "Blind rotator", "rules": [
        {"effect": "allow", "subject": "secrets", "actions": ["read", "edit"]}
    ]});
    h.put("/api/v1/projects/app/roles/blind", &h.admin, blind).await?;
    let (_, blind_token) = h.machine("blind", "app", "blind").await?;
    let (_, result) = h
        .post(
            &batch,
            &blind_token,
            json!({"upserts": [{"key": "PIN", "value": "1234"}]}),
        )
        .await?;
    assert_eq!(result["updated"], json!(["PIN"]), "{result}");

    // Oversized globs are refused before they reach the matcher.
    let huge = json!({"name": "Huge", "rules": [
        {"effect": "allow", "subject": "secrets", "actions": ["read"], "conditions": {"keys": ["**".repeat(200)]}}
    ]});
    let (status, _) = h.put("/api/v1/projects/app/roles/huge", &h.admin, huge).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // An admin bound by a deny cannot lift it from themselves.
    let no_values = json!({"name": "No values", "rules": [
        {"effect": "deny", "subject": "secrets", "actions": ["read-value"]}
    ]});
    h.put("/api/v1/projects/app/roles/no-values", &h.admin, no_values)
        .await?;
    let (restricted, restricted_token) = h.machine("restricted", "app", "admin").await?;
    h.post(
        "/api/v1/projects/app/members",
        &h.admin,
        json!({"principal_kind": "identity", "principal_id": restricted, "role": "no-values"}),
    )
    .await?;
    let (status, _) = h
        .delete(
            &format!("/api/v1/projects/app/members/identity/{restricted}/no-values"),
            &restricted_token,
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .delete("/api/v1/projects/app/roles/no-values", &restricted_token)
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .put(
            "/api/v1/projects/app/roles/no-values",
            &restricted_token,
            json!({"name": "No values", "rules": []}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h.delete("/api/v1/projects/app/roles/no-values", &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "an unrestricted admin can lift it");

    // Editing identities is not a way into projects the editor cannot see.
    let manager = json!({"name": "Identity manager", "rules": [
        {"effect": "allow", "subject": "identities", "actions": ["read", "edit"]}
    ]});
    let (status, body) = h.put("/api/v1/org/roles/identity-manager", &h.admin, manager).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (manager_id, manager_token) = h.machine("manager", "app", "no-access").await?;
    h.post(
        "/api/v1/org/bindings",
        &h.admin,
        json!({"principal_kind": "identity", "principal_id": manager_id, "role": "identity-manager"}),
    )
    .await?;
    let (viewer, _) = h.machine("viewer", "app", "viewer").await?;
    let (status, _) = h
        .post(
            &format!("/api/v1/identities/{viewer}/client-secrets"),
            &manager_token,
            json!({}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .put(
            &format!("/api/v1/identities/{viewer}/auth/universal"),
            &manager_token,
            json!({"kind": "universal"}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

async fn second_review_regressions(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let batch = format!("{SECRETS}/dev/secrets/batch");
    h.post(
        &batch,
        &h.admin,
        json!({"upserts": [{"key": "DB_PASS", "value": "hunter2"}]}),
    )
    .await?;
    h.post(
        &batch,
        &h.admin,
        json!({"upserts": [{"key": "DB_PASS", "value": "hunter2", "tags": ["restricted"]}]}),
    )
    .await?;

    // Rolling back or restoring to an untagged version keeps the restriction for this caller.
    let role = json!({"name": "Restricted dev", "rules": [
        {"effect": "allow", "subject": "secrets", "actions": ["read", "read-value", "create", "edit", "delete"]},
        {"effect": "allow", "subject": "snapshots", "actions": ["read", "edit"]},
        {"effect": "deny", "subject": "secrets", "actions": ["read-value"], "conditions": {"tags": ["restricted"]}}
    ]});
    h.put("/api/v1/projects/app/roles/restricted-dev", &h.admin, role)
        .await?;
    let (_, token) = h.machine("dev", "app", "restricted-dev").await?;
    let (status, _) = h
        .post(
            &format!("{SECRETS}/dev/secrets/DB_PASS/rollback"),
            &token,
            json!({"version": 1}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (_, raw) = h.get("/api/v1/secrets/raw?project=app&environment=dev", &token).await?;
    assert!(!raw.to_string().contains("hunter2"), "{raw}");
    let (_, snapshots) = h.get(&format!("{SECRETS}/dev/snapshots"), &token).await?;
    let oldest = snapshots
        .as_array()
        .and_then(|s| s.last())
        .and_then(|s| s["id"].as_str())
        .context("snapshot")?
        .to_string();
    let (status, _) = h
        .post(
            &format!("{SECRETS}/dev/snapshots/{oldest}/restore"),
            &token,
            json!({"path": "/"}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (_, raw) = h.get("/api/v1/secrets/raw?project=app&environment=dev", &token).await?;
    assert!(!raw.to_string().contains("hunter2"), "{raw}");

    // Environment rights alone cannot destroy the secrets inside an environment.
    let (status, _) = h.delete(&format!("{SECRETS}/dev"), &h.admin).await?;
    assert_eq!(status, StatusCode::CONFLICT);

    // An identity editor without cover cannot loosen a more privileged identity.
    let manager = json!({"name": "Identity manager", "rules": [
        {"effect": "allow", "subject": "identities", "actions": ["read", "edit", "delete"]}
    ]});
    h.put("/api/v1/org/roles/identity-manager", &h.admin, manager).await?;
    let (manager_id, manager_token) = h.machine("manager", "app", "no-access").await?;
    h.post(
        "/api/v1/org/bindings",
        &h.admin,
        json!({"principal_kind": "identity", "principal_id": manager_id, "role": "identity-manager"}),
    )
    .await?;
    let (admin_identity, _) = h.machine("deployer", "app", "admin").await?;
    let update = json!({"name": "deployer", "description": "", "token_ttl": 3600, "token_max_ttl": 86400,
        "trusted_cidrs": [], "disabled": false});
    let (status, _) = h
        .patch(&format!("/api/v1/identities/{admin_identity}"), &manager_token, update)
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .delete(&format!("/api/v1/identities/{admin_identity}"), &manager_token)
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

async fn credentials_and_folders_are_scoped(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let folders = format!("{SECRETS}/dev/folders");

    let role = json!({"name": "Team folders", "rules": [
        {"effect": "allow", "subject": "folders", "actions": ["read", "create", "delete"], "conditions": {"paths": ["/team/**"]}},
        {"effect": "deny", "subject": "folders", "actions": ["delete"], "conditions": {"paths": ["/team/keep"]}}
    ]});
    h.put("/api/v1/projects/app/roles/team-folders", &h.admin, role).await?;
    let (_, token) = h.machine("folders", "app", "team-folders").await?;
    let (status, _) = h.post(&folders, &token, json!({"path": "/team/a"})).await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "creating /team/a would also create /team"
    );
    h.post(&folders, &h.admin, json!({"path": "/team/keep"})).await?;
    let (status, _) = h.post(&folders, &token, json!({"path": "/team/a"})).await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = h.delete(&format!("{folders}?path=/team/a"), &token).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    h.post(&folders, &h.admin, json!({"path": "/team/x"})).await?;
    let (status, _) = h.delete(&format!("{folders}?path=/team/x"), &token).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Revoking a client secret revokes the tokens it minted; renewals are audited.
    let (_, identity) = h
        .post("/api/v1/identities", &h.admin, json!({"name": "ansible"}))
        .await?;
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
    let login = json!({"client_id": id, "client_secret": secret["client_secret"]});
    let (status, tokens) = h
        .call(Method::POST, "/api/v1/auth/universal/login", None, Some(login))
        .await?;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let machine_token = tokens["access_token"].as_str().context("token")?.to_string();
    let (status, _) = h.post("/api/v1/auth/token/renew", &machine_token, json!({})).await?;
    assert_eq!(status, StatusCode::OK);
    let (_, audit) = h.get("/api/v1/audit?action=auth.token-renew", &h.admin).await?;
    assert_eq!(audit["total"], 1);
    let secret_id = secret["secret"]["id"].as_str().context("secret id")?;
    h.delete(&format!("/api/v1/identities/{id}/client-secrets/{secret_id}"), &h.admin)
        .await?;
    let (status, _) = h.get("/api/v1/me", &machine_token).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "tokens from a revoked secret stop working"
    );
    Ok(())
}

async fn project_logos(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let upload = |token: String, body: Vec<u8>| {
        let request = h
            .client
            .put(format!("{}/api/v1/projects/app/logo", h.base))
            .bearer_auth(token)
            .header("content-type", "image/png")
            .body(body);
        async move {
            let response = request.send().await.context("upload")?;
            let status = response.status();
            anyhow::Ok((status, response.json::<serde_json::Value>().await.unwrap_or_default()))
        }
    };
    let png = {
        let image = image::RgbaImage::from_pixel(8, 8, image::Rgba([30, 44, 67, 255]));
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image)
            .write_to(&mut out, image::ImageFormat::Png)
            .context("png")?;
        out.into_inner()
    };
    let (status, _) = upload(h.admin.clone(), b"\x89PNG\r\n\x1a\nnot really a png".to_vec()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "image headers alone are not enough");
    // A scripted SVG is rendered to pixels; the script cannot reach what is stored and served.
    let svg_attack =
        br#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 4"><script>alert(1)</script><rect width="4" height="4"/></svg>"#
            .to_vec();
    let (status, project) = upload(h.admin.clone(), svg_attack).await?;
    assert_eq!(status, StatusCode::OK, "{project}");
    let rendered = h
        .client
        .get(format!("{}{}", h.base, project["logo_url"].as_str().context("url")?))
        .bearer_auth(&h.admin)
        .send()
        .await
        .context("logo")?
        .bytes()
        .await
        .context("bytes")?;
    assert!(rendered.starts_with(b"\x89PNG"), "stored as a PNG");
    assert!(!rendered.windows(6).any(|w| w == b"script"));

    let (status, project) = upload(h.admin.clone(), png.clone()).await?;
    assert_eq!(status, StatusCode::OK, "{project}");
    let logo_url = project["logo_url"].as_str().context("logo url")?.to_string();
    let (_, listed) = h.get("/api/v1/projects", &h.admin).await?;
    assert_eq!(listed[0]["logo_url"], logo_url.as_str());

    let response = h
        .client
        .get(format!("{}{logo_url}", h.base))
        .bearer_auth(&h.admin)
        .send()
        .await
        .context("logo")?;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(headers["content-type"], "image/png");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .is_ok_and(|v| v.contains("sandbox"))
    );
    assert!(headers["cache-control"].to_str().is_ok_and(|v| v.contains("max-age")));
    let served = image::load_from_memory(&response.bytes().await.context("bytes")?).context("served png")?;
    let original = image::load_from_memory(&png).context("original png")?;
    assert_eq!(served.to_rgba8(), original.to_rgba8(), "the same picture, re-encoded");

    let (status, _) = upload(h.admin.clone(), b"<html><script>alert(1)</script>".to_vec()).await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "only images are accepted, whatever the header says"
    );
    let (status, _) = upload(h.admin.clone(), [png.clone(), vec![0; 600 * 1024]].concat()).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (_, viewer) = h.machine("viewer", "app", "viewer").await?;
    let (status, _) = upload(viewer.clone(), png.clone()).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "viewers can see but not change the logo");
    let (status, _) = h.get(&logo_url, &viewer).await?;
    assert_eq!(status, StatusCode::OK);
    h.create_project("other").await?;
    let (status, _) = h.get("/api/v1/projects/other/logo", &viewer).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "no logo leaks from a project you cannot see"
    );

    let (status, project) = h.delete("/api/v1/projects/app/logo", &h.admin).await?;
    assert_eq!(
        (status, project["logo_url"].clone()),
        (StatusCode::OK, serde_json::Value::Null)
    );
    let (status, _) = h.get("/api/v1/projects/app/logo", &h.admin).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

async fn generation_and_rotation(db: String) -> anyhow::Result<()> {
    let start_time = 1_800_000_000;
    let clock = std::sync::Arc::new(sekret_server::clock::FixedClock::new(start_time));
    let h = start(Options {
        database_url: db,
        clock: Some(clock.clone()),
        ..Options::default()
    })
    .await?;
    h.create_project("app").await?;
    let secret = |key: &str| format!("{SECRETS}/dev/secrets/{key}");

    let (_, policy) = h.get("/api/v1/projects/app/secret-policy", &h.admin).await?;
    assert_eq!(
        policy,
        json!({"generator": null, "rotation_days": null}),
        "off by default"
    );
    let (status, _) = h
        .put(
            "/api/v1/projects/app/secret-policy",
            &h.admin,
            json!({"rotation_days": 0}),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let project_policy = json!({"generator": {"length": 20, "charset": "hex"}, "rotation_days": 1});
    let (status, _) = h
        .put("/api/v1/projects/app/secret-policy", &h.admin, project_policy)
        .await?;
    assert_eq!(status, StatusCode::OK);

    for key in ["API_TOKEN", "PINNED"] {
        let (status, result) = h
            .post(&format!("{}/generate", secret(key)), &h.admin, json!({}))
            .await?;
        assert_eq!((status, result["created"].clone()), (StatusCode::OK, json!([key])));
    }
    h.set_secrets("app", "dev", "/", &[("PASTED", "from-a-vendor")]).await?;
    let (_, token) = h.get(&secret("API_TOKEN"), &h.admin).await?;
    let first = token["value"].as_str().context("value")?.to_string();
    assert_eq!(first.len(), 20);
    assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(token["generated"], true);
    assert_eq!(token["next_rotation_at"], start_time + 86400);
    let (status, _) = h
        .post(
            &format!("{SECRETS}/dev/secrets/batch"),
            &h.admin,
            json!({"upserts": [{"key": "API_TOKEN", "value": first, "tags": ["api"]}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (_, retagged) = h.get(&secret("API_TOKEN"), &h.admin).await?;
    assert_eq!(
        (retagged["generated"].clone(), retagged["tags"].clone()),
        (json!(true), json!(["api"])),
        "a tag edit keeps the value generated and rotating"
    );
    let (_, pasted) = h.get(&secret("PASTED"), &h.admin).await?;
    assert_eq!(
        (pasted["generated"].clone(), pasted["next_rotation_at"].clone()),
        (json!(false), json!(null))
    );

    let off = json!({"mode": "custom", "generator": {"length": 12, "charset": "numeric"}, "rotation_days": null});
    let (status, view) = h.put(&format!("{}/policy", secret("PINNED")), &h.admin, off).await?;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["effective"]["rotation_days"], json!(null));
    assert_eq!(view["next_rotation_at"], json!(null));
    let (status, result) = h
        .post(&format!("{}/generate", secret("PINNED")), &h.admin, json!({}))
        .await?;
    assert_eq!(status, StatusCode::OK, "{result}");
    let (_, pinned) = h.get(&secret("PINNED"), &h.admin).await?;
    let pinned_value = pinned["value"].as_str().context("value")?.to_string();
    assert!(
        pinned_value.len() == 12 && pinned_value.chars().all(|c| c.is_ascii_digit()),
        "{pinned_value}"
    );

    let (_, viewer) = h.machine("viewer", "app", "viewer").await?;
    let (status, _) = h
        .post(&format!("{}/generate", secret("API_TOKEN")), &viewer, json!({}))
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .put(
            &format!("{}/policy", secret("API_TOKEN")),
            &viewer,
            json!({"mode": "inherit"}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h.put("/api/v1/projects/app/secret-policy", &viewer, json!({})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    assert!(
        sekret_server::rotation::rotate_due(&h.state)
            .await
            .map_err(api_error("rotate"))?
            .is_empty(),
        "nothing is due yet"
    );
    clock.advance(2 * 86400);
    let rotated = sekret_server::rotation::rotate_due(&h.state)
        .await
        .map_err(api_error("rotate"))?;
    assert_eq!(
        rotated,
        ["app/dev/API_TOKEN"],
        "only due, generated, rotating secrets change"
    );

    let admin = sekret_server::admin::bootstrap_admin(&h.state, 3600)
        .await
        .map_err(api_error("fresh admin"))?;
    let (_, token) = h.get(&secret("API_TOKEN"), &admin).await?;
    assert_ne!(token["value"].as_str(), Some(first.as_str()));
    assert_eq!(
        (token["version"].clone(), token["generated"].clone()),
        (json!(3), json!(true))
    );
    let (_, pasted) = h.get(&secret("PASTED"), &admin).await?;
    assert_eq!(pasted["value"], "from-a-vendor");
    let (_, audit) = h.get("/api/v1/audit?action=secret.rotate", &admin).await?;
    assert_eq!(audit["total"], 1);
    assert_eq!(audit["entries"][0]["secret_key"], "API_TOKEN");
    assert!(!audit.to_string().contains(&first), "no values in the audit log");
    Ok(())
}

async fn third_review_regressions(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;

    // Settings alone cannot change what the rotation job does to every secret.
    let settings_only = json!({"name": "Settings", "rules": [
        {"effect": "allow", "subject": "settings", "actions": ["read", "edit"]},
        {"effect": "allow", "subject": "secrets", "actions": ["read"]}
    ]});
    h.put("/api/v1/projects/app/roles/settings-only", &h.admin, settings_only)
        .await?;
    let (_, settings_token) = h.machine("settings", "app", "settings-only").await?;
    let weak = json!({"generator": {"length": 8, "charset": "numeric"}, "rotation_days": 1});
    let (status, _) = h
        .put("/api/v1/projects/app/secret-policy", &settings_token, weak)
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Removing universal auth retires the client secrets and the tokens they issued.
    let (_, identity) = h
        .post("/api/v1/identities", &h.admin, json!({"name": "ansible"}))
        .await?;
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
    let login = json!({"client_id": id, "client_secret": secret["client_secret"]});
    let (_, tokens) = h
        .call(Method::POST, "/api/v1/auth/universal/login", None, Some(login.clone()))
        .await?;
    let token = tokens["access_token"].as_str().context("token")?.to_string();
    let (status, _) = h
        .delete(&format!("/api/v1/identities/{id}/auth/universal"), &h.admin)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.get("/api/v1/me", &token).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    h.put(
        &format!("/api/v1/identities/{id}/auth/universal"),
        &h.admin,
        json!({"kind": "universal"}),
    )
    .await?;
    let (status, _) = h
        .call(Method::POST, "/api/v1/auth/universal/login", None, Some(login))
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old client secret stays revoked");

    // Revoking a client secret needs cover of the identity, like the other identity routes.
    let manager = json!({"name": "Identity manager", "rules": [
        {"effect": "allow", "subject": "identities", "actions": ["read", "edit"]}
    ]});
    h.put("/api/v1/org/roles/identity-manager", &h.admin, manager).await?;
    let (manager_id, manager_token) = h.machine("manager", "app", "no-access").await?;
    h.post(
        "/api/v1/org/bindings",
        &h.admin,
        json!({"principal_kind": "identity", "principal_id": manager_id, "role": "identity-manager"}),
    )
    .await?;
    let (deployer, _) = h.machine("deployer", "app", "admin").await?;
    h.put(
        &format!("/api/v1/identities/{deployer}/auth/universal"),
        &h.admin,
        json!({"kind": "universal"}),
    )
    .await?;
    let (_, deployer_secret) = h
        .post(
            &format!("/api/v1/identities/{deployer}/client-secrets"),
            &h.admin,
            json!({}),
        )
        .await?;
    let deployer_secret_id = deployer_secret["secret"]["id"].as_str().context("id")?;
    let (status, _) = h
        .delete(
            &format!("/api/v1/identities/{deployer}/client-secrets/{deployer_secret_id}"),
            &manager_token,
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The project audit log hides keys the reader cannot see in the secrets view.
    h.set_secrets("app", "dev", "/", &[("DB_URL", "x"), ("HIDDEN_KEY", "y")])
        .await?;
    let narrow = json!({"name": "DB auditor", "rules": [
        {"effect": "allow", "subject": "secrets", "actions": ["read"], "conditions": {"keys": ["DB_*"]}},
        {"effect": "allow", "subject": "audit-log", "actions": ["read"]}
    ]});
    h.put("/api/v1/projects/app/roles/db-auditor", &h.admin, narrow).await?;
    let (_, auditor) = h.machine("auditor", "app", "db-auditor").await?;
    let (status, audit) = h.get("/api/v1/projects/app/audit?limit=500", &auditor).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(!audit.to_string().contains("HIDDEN_KEY"), "{audit}");

    // An organisation audit grant does not open project audit logs.
    let org_auditor = json!({"name": "Org auditor", "rules": [
        {"effect": "allow", "subject": "org-audit-log", "actions": ["read"]}
    ]});
    h.put("/api/v1/org/roles/org-auditor", &h.admin, org_auditor).await?;
    let (org_auditor_id, org_auditor_token) = h.machine("org-auditor", "app", "no-access").await?;
    h.post(
        "/api/v1/org/bindings",
        &h.admin,
        json!({"principal_kind": "identity", "principal_id": org_auditor_id, "role": "org-auditor"}),
    )
    .await?;
    let (status, _) = h.get("/api/v1/audit", &org_auditor_token).await?;
    assert_eq!(status, StatusCode::OK);
    h.create_project("other").await?;
    let (status, _) = h.get("/api/v1/projects/other/audit", &org_auditor_token).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

/// SQL and markup in every free-text field are stored and matched literally, never interpreted.
async fn hostile_text_is_inert(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let sql = "x'); DROP TABLE secrets; -- \\ % _ \" ` $(id) <script>alert(1)</script>";
    let batch = format!("{SECRETS}/dev/secrets/batch");
    let (status, body) = h
        .post(
            &batch,
            &h.admin,
            json!({"upserts": [{"key": "HOSTILE", "value": sql, "comment": sql, "tags": ["tag-ok"]}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, stored) = h.get(&format!("{SECRETS}/dev/secrets/HOSTILE"), &h.admin).await?;
    assert_eq!(
        (stored["value"].as_str(), stored["comment"].as_str()),
        (Some(sql), Some(sql))
    );

    let (status, _) = h
        .patch(
            "/api/v1/projects/app",
            &h.admin,
            json!({"name": "app", "description": sql}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, identity) = h
        .post(
            "/api/v1/identities",
            &h.admin,
            json!({"name": "evil-identity", "description": sql}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{identity}");

    for (name, value) in [
        ("key", "HOSTILE' OR '1'='1"),
        ("path", "/' OR 1=1 --"),
        ("q", "%"),
        ("q", "_"),
        ("q", "' OR 1=1 --"),
        ("q", "\\"),
        ("action", "%"),
    ] {
        let encoded: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
        let (status, page) = h
            .get(&format!("/api/v1/projects/app/audit?{name}={encoded}"), &h.admin)
            .await?;
        assert_eq!(status, StatusCode::OK, "{name}={value}");
        assert_eq!(page["total"], 0, "{name}={value} matched as a pattern: {page}");
    }
    let (_, all) = h.get("/api/v1/projects/app/audit", &h.admin).await?;
    assert!(all["total"].as_i64().is_some_and(|t| t > 0), "the log itself is intact");
    let (_, users) = h.get("/api/v1/users?q=%25", &h.admin).await?;
    assert_eq!(users["total"], 0);
    let (_, identities) = h.get("/api/v1/identities?q='%20OR%201=1", &h.admin).await?;
    assert_eq!(identities["total"], 0);
    let (_, still) = h.get(&format!("{SECRETS}/dev/secrets"), &h.admin).await?;
    assert_eq!(
        still["secrets"].as_array().map(Vec::len),
        Some(1),
        "the secrets table survived"
    );
    Ok(())
}

async fn organisation_and_project_administration(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;

    let (status, project) = h
        .patch(
            "/api/v1/projects/app",
            &h.admin,
            json!({"name": "Renamed", "description": "d"}),
        )
        .await?;
    assert_eq!((status, project["name"].as_str()), (StatusCode::OK, Some("Renamed")));

    let envs = "/api/v1/projects/app/environments";
    let (status, _) = h.post(envs, &h.admin, json!({"slug": "qa", "name": "QA"})).await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, env) = h
        .patch(
            &format!("{envs}/qa"),
            &h.admin,
            json!({"name": "Quality", "position": -1}),
        )
        .await?;
    assert_eq!((status, env["name"].as_str()), (StatusCode::OK, Some("Quality")));
    let (_, listed) = h.get(envs, &h.admin).await?;
    assert_eq!(listed[0]["slug"], "qa", "position moves the environment first");
    let (status, _) = h.delete(&format!("{envs}/qa"), &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let folders = format!("{SECRETS}/dev/folders");
    h.post(&folders, &h.admin, json!({"path": "/team"})).await?;
    h.set_secrets("app", "dev", "/team", &[("A", "b")]).await?;
    let (status, _) = h.delete(&format!("{folders}?path=/team"), &h.admin).await?;
    assert_eq!(status, StatusCode::CONFLICT, "a folder holding secrets is not deleted");
    h.post(&folders, &h.admin, json!({"path": "/empty"})).await?;
    let (status, _) = h.delete(&format!("{folders}?path=/empty"), &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (identity, _) = h.machine("ci", "app", "viewer").await?;
    let role = json!({"name": "Reader", "rules": [{"effect": "allow", "subject": "secrets", "actions": ["read"]}]});
    h.put("/api/v1/projects/app/roles/reader", &h.admin, role).await?;
    let members = "/api/v1/projects/app/members";
    let (status, _) = h
        .post(
            members,
            &h.admin,
            json!({"principal_kind": "identity", "principal_id": identity, "role": "reader"}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = h
        .delete(&format!("{members}/identity/{identity}/viewer"), &h.admin)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.delete("/api/v1/projects/app/roles/reader", &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, listed) = h.get(members, &h.admin).await?;
    assert!(
        !listed.to_string().contains(&identity),
        "deleting a role removes its memberships: {listed}"
    );

    let project_scoped =
        json!({"name": "Auditor", "rules": [{"effect": "allow", "subject": "audit-log", "actions": ["read"]}]});
    let (status, _) = h.put("/api/v1/org/roles/auditor", &h.admin, project_scoped).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "audit-log is a project subject");
    let org_role =
        json!({"name": "Auditor", "rules": [{"effect": "allow", "subject": "org-audit-log", "actions": ["read"]}]});
    let (status, body) = h.put("/api/v1/org/roles/auditor", &h.admin, org_role).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let binding = json!({"principal_kind": "group", "principal_id": "auditors", "role": "auditor"});
    let (status, _) = h.post("/api/v1/org/bindings", &h.admin, binding).await?;
    assert_eq!(status, StatusCode::CREATED);
    let (_, bindings) = h.get("/api/v1/org/bindings", &h.admin).await?;
    assert!(bindings.to_string().contains("auditors"));
    let (status, _) = h
        .delete("/api/v1/org/bindings/group/auditors/auditor", &h.admin)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.delete("/api/v1/org/roles/auditor", &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, users) = h
        .get("/api/v1/users?q=bootstrap&sort=last_login&order=desc", &h.admin)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(users["total"], 1, "{users}");
    let (_, none) = h.get("/api/v1/users?q=nobody-matches", &h.admin).await?;
    assert_eq!(
        (none["total"].as_i64(), none["items"].as_array().map(Vec::len)),
        (Some(0), Some(0))
    );
    let (_, identities) = h.get("/api/v1/identities?q=CI&status=active&limit=1", &h.admin).await?;
    assert_eq!(identities["items"][0]["name"], "ci", "{identities}");
    let (status, _) = h.get("/api/v1/identities?sort=bogus", &h.admin).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Every entry, two at a time, oldest first, with no gaps or repeats.
    let (_, all) = h.get("/api/v1/audit?limit=500&order=asc", &h.admin).await?;
    let mut paged = Vec::new();
    let mut cursor = String::new();
    loop {
        let (status, page) = h
            .get(&format!("/api/v1/audit?limit=2&order=asc{cursor}"), &h.admin)
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["total"], all["total"]);
        paged.extend(
            page["entries"]
                .as_array()
                .context("entries")?
                .iter()
                .map(|e| e["id"].clone()),
        );
        let Some(next) = page["next_cursor"].as_str() else {
            break;
        };
        cursor = format!("&cursor={next}");
    }
    let every: Vec<_> = all["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .map(|e| e["id"].clone())
        .collect();
    assert_eq!(paged, every);
    let (status, _) = h.get("/api/v1/audit?cursor=junk", &h.admin).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, searched) = h.get("/api/v1/audit?q=PROJECT.&order=desc", &h.admin).await?;
    assert!(searched["total"].as_i64().is_some_and(|t| t > 0), "{searched}");

    let (status, audit) = h.get("/api/v1/audit?limit=500", &h.admin).await?;
    assert_eq!(status, StatusCode::OK);
    let actions: Vec<&str> = audit["entries"]
        .as_array()
        .context("audit")?
        .iter()
        .filter_map(|a| a["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"project.update") || actions.iter().any(|a| a.starts_with("project")),
        "{actions:?}"
    );

    let (status, _) = h.delete("/api/v1/projects/app", &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.get("/api/v1/projects/app", &h.admin).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = h.call(Method::POST, "/auth/logout", Some(&h.admin), None).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body["logout_url"].is_null());
    Ok(())
}

async fn members_cannot_grant_more_than_they_hold(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let role = json!({"name": "Member manager", "rules": [
        {"effect": "allow", "subject": "members", "actions": ["read", "create"]},
        {"effect": "allow", "subject": "secrets", "actions": ["read"]}
    ]});
    h.put("/api/v1/projects/app/roles/member-manager", &h.admin, role)
        .await?;
    let (_, token) = h.machine("manager", "app", "member-manager").await?;
    let (target, _) = h.machine("target", "app", "no-access").await?;
    let grant = |role: &str| json!({"principal_kind": "identity", "principal_id": target, "role": role});
    let (status, body) = h.post("/api/v1/projects/app/members", &token, grant("admin")).await?;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("escalation"))
    );
    let (status, _) = h.post("/api/v1/projects/app/members", &token, grant("viewer")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let group = json!({"principal_kind": "group", "principal_id": "auditors", "role": "no-access"});
    let (status, body) = h.post("/api/v1/projects/app/members", &token, group).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Ok(())
}

async fn machine_tokens_respect_revocation_disable_and_cidrs(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let (id, token) = h.machine("ci", "app", "viewer").await?;
    let (status, _) = h.get("/api/v1/projects", &token).await?;
    assert_eq!(status, StatusCode::OK);

    let (status, renewed) = h.post("/api/v1/auth/token/renew", &token, json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{renewed}");

    let update = json!({"name": "ci", "token_ttl": 3600, "token_max_ttl": 7200, "trusted_cidrs": ["10.0.0.0/8"]});
    let (status, _) = h
        .call(
            Method::PATCH,
            &format!("/api/v1/identities/{id}"),
            Some(&h.admin),
            Some(update),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.get("/api/v1/projects", &token).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "127.0.0.1 is outside the trusted range"
    );

    let update = json!({"name": "ci", "token_ttl": 3600, "token_max_ttl": 7200, "disabled": true});
    h.call(
        Method::PATCH,
        &format!("/api/v1/identities/{id}"),
        Some(&h.admin),
        Some(update),
    )
    .await?;
    let update = json!({"name": "ci", "token_ttl": 3600, "token_max_ttl": 7200, "disabled": false});
    h.call(
        Method::PATCH,
        &format!("/api/v1/identities/{id}"),
        Some(&h.admin),
        Some(update),
    )
    .await?;
    let (status, _) = h.get("/api/v1/projects", &token).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "disabling revokes existing tokens");

    let (_, second) = h.machine("ci2", "app", "viewer").await?;
    let (status, _) = h.post("/api/v1/auth/token/revoke", &second, json!({})).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.get("/api/v1/projects", &second).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn client_secrets_with_use_limits_and_revocation(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let (_, identity) = h
        .post("/api/v1/identities", &h.admin, json!({"name": "ansible"}))
        .await?;
    let id = identity["id"].as_str().context("id")?;
    h.put(
        &format!("/api/v1/identities/{id}/auth/universal"),
        &h.admin,
        json!({"kind": "universal"}),
    )
    .await?;
    let (_, secret) = h
        .post(
            &format!("/api/v1/identities/{id}/client-secrets"),
            &h.admin,
            json!({"max_uses": 1}),
        )
        .await?;
    let login = json!({"client_id": id, "client_secret": secret["client_secret"]});
    let (status, _) = h
        .call(Method::POST, "/api/v1/auth/universal/login", None, Some(login.clone()))
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h
        .call(Method::POST, "/api/v1/auth/universal/login", None, Some(login))
        .await?;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("login_failed"))
    );

    let (_, second) = h
        .post(&format!("/api/v1/identities/{id}/client-secrets"), &h.admin, json!({}))
        .await?;
    let secret_id = second["secret"]["id"].as_str().context("id")?;
    h.delete(&format!("/api/v1/identities/{id}/client-secrets/{secret_id}"), &h.admin)
        .await?;
    let login = json!({"client_id": id, "client_secret": second["client_secret"]});
    let (status, _) = h
        .call(Method::POST, "/api/v1/auth/universal/login", None, Some(login))
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, listed) = h
        .get(&format!("/api/v1/identities/{id}/client-secrets"), &h.admin)
        .await?;
    assert_eq!(listed.as_array().map(Vec::len), Some(2));
    assert!(
        !listed
            .to_string()
            .contains(second["client_secret"].as_str().context("secret")?),
        "only prefixes are listed"
    );
    Ok(())
}

#[tokio::test]
async fn openapi_health_and_security_headers() -> anyhow::Result<()> {
    let h = start(Options::default()).await?;
    let response = h
        .client
        .get(format!("{}/api/v1/health", h.base))
        .send()
        .await
        .context("health")?;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert!(
        headers["content-security-policy"]
            .to_str()
            .context("csp")?
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["cache-control"], "no-store");
    let (status, openapi) = h.call(Method::GET, "/api/openapi.json", None, None).await?;
    assert_eq!(status, StatusCode::OK);
    for path in [
        "/api/v1/secrets/raw",
        "/api/v1/auth/kubernetes/login",
        "/api/v1/projects/{project}/environments/{env}/secrets/batch",
    ] {
        assert!(openapi["paths"].get(path).is_some(), "{path} missing from OpenAPI");
    }
    let (status, _) = h.call(Method::GET, "/api/v1/ready", None, None).await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn wrong_root_key_is_refused() -> anyhow::Result<()> {
    use sekret_core::crypto::RootKey;
    let store = sekret_store::SqlStore::connect("sqlite::memory:")
        .await
        .context("store")?;
    let first = RootKey::generate().context("key")?;
    let second = RootKey::generate().context("key")?;
    sekret_server::check_root_key(&store, &first.fingerprint())
        .await
        .context("first start")?;
    sekret_server::check_root_key(&store, &first.fingerprint())
        .await
        .context("restart")?;
    assert!(
        sekret_server::check_root_key(&store, &second.fingerprint())
            .await
            .is_err()
    );
    Ok(())
}

async fn root_key_rotation_keeps_secrets_readable(db: String) -> anyhow::Result<()> {
    use sekret_core::crypto::RootKey;
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    h.set_secrets("app", "dev", "/", &[("A", "before")]).await?;
    let new_root = RootKey::generate().context("key")?;
    let old_root = h.state.keyring.root().map_err(api_error("root"))?;
    let count = sekret_server::admin::rotate_root_key(h.state.store.as_ref(), &old_root, &new_root, None)
        .await
        .map_err(api_error("rotate"))?;
    assert_eq!(count, 1);
    let project = h
        .state
        .store
        .get_project("app")
        .await
        .context("get")?
        .context("project")?;
    let key = sekret_server::secrets::data_key(&new_root, &project).map_err(api_error("new key unwraps"))?;
    let environments = h.state.store.list_environments(&project.id).await.context("envs")?;
    let environment = environments.first().context("an environment")?;
    let s = h
        .state
        .store
        .get_secret(&environment.id, "/", "A")
        .await
        .context("get")?
        .context("secret")?;
    let value = sekret_server::secrets::decrypt(&key, &project.id, &s.version)
        .map_err(api_error("decrypt"))?
        .context("value")?;
    assert_eq!(value.as_str(), "before");
    assert!(sekret_server::secrets::data_key(&old_root, &project).is_err());
    Ok(())
}

async fn kubernetes_reviewer_tokens_are_write_only_and_survive_rotation(db: String) -> anyhow::Result<()> {
    use sekret_core::crypto::RootKey;
    let h = start(options(db)).await?;
    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "k3s"})).await?;
    let id = identity["id"].as_str().context("id")?;
    let path = format!("/api/v1/identities/{id}/auth/kubernetes");
    let config = |reviewer: &str| {
        json!({
            "kind": "kubernetes", "mode": "token-review", "host": "https://k8s.example.com:6443",
            "reviewer_jwt": reviewer, "namespaces": ["apps"], "service_accounts": ["web"],
        })
    };
    let stored_config = || async {
        anyhow::Ok(
            h.state
                .store
                .get_auth_method(id, "kubernetes")
                .await
                .context("get")?
                .context("method")?
                .config,
        )
    };

    let (status, _) = h.put(&path, &h.admin, config("reviewer-plaintext")).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let first = stored_config().await?;
    assert!(!first.to_string().contains("reviewer-plaintext"));
    let (_, listed) = h.get(&format!("/api/v1/identities/{id}/auth"), &h.admin).await?;
    assert_eq!(listed[0]["reviewer_jwt"], sekret_api::REDACTED_CREDENTIAL);

    let (status, _) = h.put(&path, &h.admin, config(sekret_api::REDACTED_CREDENTIAL)).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(stored_config().await?, first);

    let new_root = RootKey::generate().context("key")?;
    let old_root = h.state.keyring.root().map_err(api_error("root"))?;
    sekret_server::admin::rotate_root_key(h.state.store.as_ref(), &old_root, &new_root, None)
        .await
        .map_err(api_error("rotate"))?;
    let rotated: sekret_api::AuthMethodConfig = serde_json::from_value(stored_config().await?).context("config")?;
    let sekret_api::AuthMethodConfig::Kubernetes(mut k8s) = rotated else {
        anyhow::bail!("kubernetes config expected");
    };
    assert!(sekret_server::machine::unseal_reviewer(&old_root, id, &mut k8s.clone()).is_err());
    sekret_server::machine::unseal_reviewer(&new_root, id, &mut k8s).map_err(api_error("unseal"))?;
    assert_eq!(k8s.reviewer_jwt.as_deref(), Some("reviewer-plaintext"));
    Ok(())
}
