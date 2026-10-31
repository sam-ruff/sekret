//! What a reader denied part of a project can learn about the hidden part: nothing through
//! values, history, snapshots or the audit log.

mod common;

use anyhow::Context;
use common::{Harness, options, start};
use reqwest::StatusCode;
use serde_json::{Value, json};

const PROD: &str = "/api/v1/projects/app/environments/prod";

/// A project with secrets in `/`, `/payments` and `/payments/live` of prod, written twice so
/// they have history, and a token for `role`.
async fn seeded(db: String, role: Value) -> anyhow::Result<(Harness, String)> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    for value in ["one", "two"] {
        h.set_secrets("app", "prod", "/", &[("OPEN", value)]).await?;
        h.set_secrets("app", "prod", "/payments", &[("STRIPE_KEY", value)])
            .await?;
        h.set_secrets("app", "prod", "/payments/live", &[("LIVE_KEY", value)])
            .await?;
    }
    h.set_secrets("app", "dev", "/payments", &[("DEV_STRIPE", "d")]).await?;
    // Single reads put key names in the audit log.
    for (env, key, path) in [
        ("prod", "STRIPE_KEY", "/payments"),
        ("prod", "LIVE_KEY", "/payments/live"),
        ("dev", "DEV_STRIPE", "/payments"),
    ] {
        let url = format!("/api/v1/projects/app/environments/{env}/secrets/{key}?path={path}");
        let (status, _) = h.get(&url, &h.admin).await?;
        assert_eq!(status, StatusCode::OK, "{url}");
    }
    let (status, body) = h.put("/api/v1/projects/app/roles/limited", &h.admin, role).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, token) = h.machine("limited", "app", "limited").await?;
    Ok((h, token))
}

fn reader_with(extra: &[Value]) -> Value {
    let mut rules = vec![
        json!({"effect": "allow", "subject": "secrets", "actions": ["read", "read-value", "edit", "create"]}),
        json!({"effect": "allow", "subject": "secret-versions", "actions": ["read", "read-value"]}),
        json!({"effect": "allow", "subject": "snapshots", "actions": ["read"]}),
        json!({"effect": "allow", "subject": "folders", "actions": ["read"]}),
        json!({"effect": "allow", "subject": "environments", "actions": ["read"]}),
        json!({"effect": "allow", "subject": "audit-log", "actions": ["read"]}),
    ];
    rules.extend(extra.iter().cloned());
    json!({"name": "Limited", "rules": rules})
}

fn payments_hidden() -> Value {
    reader_with(&[
        json!({"effect": "deny", "subject": "secrets", "actions": ["read", "read-value"], "conditions": {"paths": ["/payments/**"]}}),
        json!({"effect": "deny", "subject": "folders", "actions": ["read"], "conditions": {"paths": ["/payments/**"]}}),
    ])
}

/// A deny on `/payments/**` covers secrets stored directly in `/payments`, not just below it.
async fn a_folder_deny_covers_the_folder_itself(db: String) -> anyhow::Result<()> {
    let (h, token) = seeded(db, payments_hidden()).await?;
    for path in ["/payments", "/payments/live"] {
        let key = if path == "/payments" { "STRIPE_KEY" } else { "LIVE_KEY" };
        let (status, body) = h.get(&format!("{PROD}/secrets/{key}?path={path}"), &token).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
        let (status, raw) = h
            .get(
                &format!("/api/v1/secrets/raw?project=app&environment=prod&path={path}"),
                &token,
            )
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(raw["secrets"], json!([]), "{path}: {raw}");
        let (_, listed) = h
            .get(&format!("{PROD}/secrets?path={path}&values=true"), &token)
            .await?;
        assert_eq!(listed["secrets"], json!([]), "{path}: {listed}");
    }
    let (_, raw) = h
        .get(
            "/api/v1/secrets/raw?project=app&environment=prod&recursive=true",
            &token,
        )
        .await?;
    assert_eq!(raw["secrets"], json!([{"path": "/", "key": "OPEN", "value": "two"}]));
    let (_, root) = h.get(&format!("{PROD}/secrets"), &token).await?;
    assert_eq!(root["folders"], json!([]), "the folder itself is hidden: {root}");
    let (status, _) = h.get(&format!("{PROD}/secrets/OPEN"), &token).await?;
    assert_eq!(status, StatusCode::OK, "secrets outside the folder stay readable");
    Ok(())
}

/// History and rollback answer 404 for a secret the caller cannot read, the same as for one
/// that does not exist, so they neither leak metadata nor confirm the key.
async fn history_needs_read_access_and_hides_existence(db: String) -> anyhow::Result<()> {
    let (h, token) = seeded(db, payments_hidden()).await?;
    let versions = format!("{PROD}/secrets/STRIPE_KEY/versions?path=/payments");
    let (status, body) = h.get(&versions, &token).await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (missing, _) = h
        .get(&format!("{PROD}/secrets/NOPE/versions?path=/payments"), &token)
        .await?;
    assert_eq!(missing, StatusCode::NOT_FOUND);
    let rollback = format!("{PROD}/secrets/STRIPE_KEY/rollback?path=/payments");
    let (status, _) = h.post(&rollback, &token, json!({"version": 1})).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .post(
            &format!("{PROD}/secrets/NOPE/rollback?path=/payments"),
            &token,
            json!({"version": 1}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, after) = h
        .get(&format!("{PROD}/secrets/STRIPE_KEY?path=/payments"), &h.admin)
        .await?;
    assert_eq!(after["value"], "two", "the refused rollback changed nothing");

    // Readable secrets keep their history and rollback, including a deleted one.
    let (status, history) = h.get(&format!("{PROD}/secrets/OPEN/versions"), &token).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(history.as_array().map(Vec::len), Some(2), "{history}");
    let (status, _) = h.delete(&format!("{PROD}/secrets/OPEN"), &h.admin).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.get(&format!("{PROD}/secrets/OPEN/versions"), &token).await?;
    assert_eq!(status, StatusCode::OK, "a deleted secret's history is still there");
    let (status, body) = h
        .post(&format!("{PROD}/secrets/OPEN/rollback"), &token, json!({"version": 1}))
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, back) = h.get(&format!("{PROD}/secrets/OPEN"), &token).await?;
    assert_eq!(back["value"], "one");
    Ok(())
}

/// Snapshot reasons name the folder written to; a reader who cannot see it gets the counts only.
async fn snapshot_reasons_hide_folders(db: String) -> anyhow::Result<()> {
    let (h, token) = seeded(db, payments_hidden()).await?;
    let (status, snapshots) = h.get(&format!("{PROD}/snapshots"), &token).await?;
    assert_eq!(status, StatusCode::OK);
    let text = snapshots.to_string();
    assert!(!text.contains("/payments"), "{text}");
    assert!(text.contains("in /\""), "visible folders are still named: {text}");
    let (_, full) = h.get(&format!("{PROD}/snapshots"), &h.admin).await?;
    assert!(full.to_string().contains("in /payments/live"), "{full}");
    Ok(())
}

async fn audit(h: &Harness, token: &str, query: &str) -> anyhow::Result<(StatusCode, Value)> {
    h.get(&format!("/api/v1/projects/app/audit?limit=500&{query}"), token)
        .await
}

/// Filters and their counts answer questions even when every matching entry is redacted, so
/// a reader with part of the project hidden cannot filter on what is hidden.
async fn audit_filters_cannot_probe_hidden_secrets(db: String) -> anyhow::Result<()> {
    let (h, token) = seeded(db, payments_hidden()).await?;
    for query in [
        "key=STRIPE_KEY",
        "path=/payments",
        "environment=prod&key=OPEN",
        "key=NOPE",
    ] {
        let (status, body) = audit(&h, &token, query).await?;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("filter_hidden")),
            "{query}: {body}"
        );
    }
    // Free text only searches actions, actors and addresses, so key and folder names give no hits.
    for probe in ["stripe", "STRIPE_K", "payments", "live_key"] {
        let (status, body) = audit(&h, &token, &format!("q={probe}")).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 0, "{probe}: {body}");
        let (_, admin) = audit(&h, &h.admin, &format!("q={probe}")).await?;
        assert!(admin["total"].as_i64().is_some_and(|t| t > 0), "{probe}: {admin}");
    }
    let (_, by_action) = audit(&h, &token, "q=secret.write").await?;
    assert!(by_action["total"].as_i64().is_some_and(|t| t > 0), "{by_action}");
    let (_, everything) = audit(&h, &token, "").await?;
    assert!(!everything.to_string().contains("STRIPE_KEY"), "{everything}");
    Ok(())
}

/// A reader who sees all of one environment may filter freely inside it.
async fn audit_filters_work_inside_a_fully_visible_environment(db: String) -> anyhow::Result<()> {
    let role = reader_with(&[json!({
        "effect": "deny", "subject": "secrets", "actions": ["read", "read-value"],
        "conditions": {"environments": ["prod"]}
    })]);
    let (h, token) = seeded(db, role).await?;
    let (status, body) = audit(&h, &token, "environment=dev&key=DEV_STRIPE").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["total"].as_i64().is_some_and(|t| t > 0), "{body}");
    let (status, body) = audit(&h, &token, "environment=dev&q=payments").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body["total"].as_i64().is_some_and(|t| t > 0), "{body}");
    let (status, _) = audit(&h, &token, "environment=prod&key=STRIPE_KEY").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = audit(&h, &token, "key=DEV_STRIPE").await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "without the environment, prod is in scope"
    );
    // An unrestricted reader keeps every filter.
    let (status, body) = audit(&h, &h.admin, "key=STRIPE_KEY").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body["total"].as_i64().is_some_and(|t| t > 0), "{body}");
    Ok(())
}

/// Environments the reader cannot list are redacted from entries and cannot be filtered on.
async fn audit_hides_environments_the_reader_cannot_list(db: String) -> anyhow::Result<()> {
    let role = json!({"name": "Dev only", "rules": [
        {"effect": "allow", "subject": "secrets", "actions": ["read"], "conditions": {"environments": ["dev"]}},
        {"effect": "allow", "subject": "environments", "actions": ["read"], "conditions": {"environments": ["dev"]}},
        {"effect": "allow", "subject": "audit-log", "actions": ["read"]}
    ]});
    let (h, token) = seeded(db, role).await?;
    let (status, body) = audit(&h, &token, "").await?;
    assert_eq!(status, StatusCode::OK);
    let entries = body["entries"].as_array().context("entries")?;
    assert!(entries.iter().all(|e| e["environment"] != "prod"), "{body}");
    assert!(entries.iter().any(|e| e["environment"] == "dev"), "{body}");
    let (status, _) = audit(&h, &token, "environment=prod").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = audit(&h, &token, "environment=staging").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, prod) = audit(&h, &token, "q=prod").await?;
    assert_eq!(prod["total"], 0, "{prod}");
    Ok(())
}

on_both_backends!(
    a_folder_deny_covers_the_folder_itself,
    history_needs_read_access_and_hides_existence,
    snapshot_reasons_hide_folders,
    audit_filters_cannot_probe_hidden_secrets,
    audit_filters_work_inside_a_fully_visible_environment,
    audit_hides_environments_the_reader_cannot_list,
);
