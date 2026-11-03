//! Per-secret access: the project setting, restricted secrets and their access lists, checked on
//! every route a secret, its value or its name can leave the server by.

mod common;

use anyhow::Context;
use common::{Harness, options, start};
use reqwest::StatusCode;
use serde_json::{Value, json};

/// A bearer token for a user stored with `groups`, as a sign-in would leave it.
async fn user_token(h: &Harness, name: &str, groups: &[&str]) -> anyhow::Result<(String, String)> {
    let now = h.state.clock.now();
    let user = h
        .state
        .store
        .upsert_user(sekret_store::UserLogin {
            subject: format!("issuer|{name}"),
            email: format!("{name}@example.com"),
            name: name.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            now,
        })
        .await?;
    let token = format!("skt_{}", uuid::Uuid::new_v4().simple());
    h.store_token(
        &token,
        sekret_store::AccessToken {
            id: uuid::Uuid::new_v4().to_string(),
            token_hash: String::new(),
            kind: "cli".into(),
            principal_kind: sekret_store::PrincipalKind::User,
            principal_id: user.id.clone(),
            description: "test".into(),
            source: String::new(),
            created_at: now,
            expires_at: now + 3600,
            max_expires_at: now + 3600,
            revoked: false,
            last_used_at: None,
            auth_time: Some(now),
            mac: None,
            sealed_hash: None,
        },
    )
    .await?;
    Ok((user.id, token))
}

async fn add_member(h: &Harness, kind: &str, id: &str, role: &str) -> anyhow::Result<()> {
    let (status, body) = h
        .post(
            "/api/v1/projects/app/members",
            &h.admin,
            json!({"principal_kind": kind, "principal_id": id, "role": role}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Ok(())
}

async fn set_setting(h: &Harness, token: &str, enabled: bool) -> anyhow::Result<(StatusCode, Value)> {
    h.put("/api/v1/projects/app/secret-access", token, json!({"enabled": enabled}))
        .await
}

fn access_url(path: &str, key: &str) -> String {
    format!("/api/v1/projects/app/environments/prod/secrets/{key}/access?path={path}")
}

async fn change(h: &Harness, token: &str, path: &str, key: &str, body: Value) -> anyhow::Result<(StatusCode, Value)> {
    h.patch(&access_url(path, key), token, body).await
}

/// A project with per-secret access on, `/payments/STRIPE` restricted and `/payments/OPEN` and
/// `/WEB` left open, all in prod.
async fn restricted_project(h: &Harness) -> anyhow::Result<()> {
    h.create_project("app").await?;
    h.set_secrets("app", "prod", "/payments", &[("STRIPE", "sk_live"), ("OPEN", "fine")])
        .await?;
    h.set_secrets("app", "prod", "/", &[("WEB", "w")]).await?;
    let (status, body) = set_setting(h, &h.admin, true).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = change(h, &h.admin, "/payments", "STRIPE", json!({"restricted": true})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"restricted": true, "grants": []}));
    Ok(())
}

fn keys(list: &Value) -> Vec<String> {
    list["secrets"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|s| s["key"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn raw_keys(raw: &Value) -> Vec<String> {
    raw["secrets"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|s| s["key"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The setting is off by default, only admins change or read it, and every change is audited.
async fn the_setting_is_off_by_default_and_for_admins_only(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let project = h.create_project("app").await?;
    assert_eq!(project["secret_access"], json!(false));
    let (_, developer) = h.machine("dev-bot", "app", "developer").await?;
    let (status, _) = h.get("/api/v1/projects/app/secret-access", &developer).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = set_setting(&h, &developer, true).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "a developer cannot turn it on");
    let (status, body) = h.get("/api/v1/projects/app/secret-access", &h.admin).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"enabled": false, "restricted": [], "restricted_count": 0}));

    h.set_secrets("app", "prod", "/", &[("DB", "x")]).await?;
    let (status, body) = change(&h, &h.admin, "/", "DB", json!({"restricted": true})).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "secret_access_off");
    let (status, body) = change(
        &h,
        &h.admin,
        "/",
        "DB",
        json!({"grant": [{"principal_kind": "group", "principal_id": "ops", "actions": ["read"]}]}),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "granting also needs the setting: {body}");

    let (status, body) = set_setting(&h, &h.admin, true).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], json!(true));
    let (_, project) = h.get("/api/v1/projects/app", &developer).await?;
    assert_eq!(
        project["secret_access"],
        json!(true),
        "everyone can see the setting is on"
    );
    let (_, permissions) = h.get("/api/v1/projects/app/permissions", &developer).await?;
    assert_eq!(permissions["manages_secret_access"], json!(false));
    let (_, permissions) = h.get("/api/v1/projects/app/permissions", &h.admin).await?;
    assert_eq!(permissions["manages_secret_access"], json!(true));

    // Setting it to what it already is changes nothing and is not audited again.
    set_setting(&h, &h.admin, true).await?;
    let (_, audit) = h
        .get("/api/v1/projects/app/audit?action=project.secret-access", &h.admin)
        .await?;
    assert_eq!(audit["total"], json!(1), "{audit}");
    assert_eq!(audit["entries"][0]["detail"]["enabled"], json!(true));
    Ok(())
}

/// Someone off a restricted secret's list never sees it, its value or its history, through any
/// route, and their writes to it answer exactly as for a secret that does not exist.
async fn an_unlisted_identity_never_sees_a_restricted_secret(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let (_, bot) = h.machine("dev-bot", "app", "developer").await?;
    let secrets = "/api/v1/projects/app/environments/prod/secrets";

    let (status, _) = h.get(&format!("{secrets}/STRIPE?path=/payments"), &bot).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, missing) = h.get(&format!("{secrets}/NOPE?path=/payments"), &bot).await?;
    let (_, hidden) = h.get(&format!("{secrets}/STRIPE?path=/payments"), &bot).await?;
    assert_eq!(hidden, missing, "a hidden secret answers exactly as a missing one");

    for query in [
        "path=/payments",
        "path=/payments&values=true",
        "path=/&recursive=true",
        "path=/&recursive=true&values=true",
    ] {
        let (status, list) = h.get(&format!("{secrets}?{query}"), &bot).await?;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert!(!keys(&list).contains(&"STRIPE".to_string()), "{query}: {list}");
        assert!(keys(&list).contains(&"OPEN".to_string()), "{query}: {list}");
        assert!(!list.to_string().contains("sk_live"), "{query}");
    }
    let (status, raw) = h
        .get("/api/v1/secrets/raw?project=app&environment=prod&recursive=true", &bot)
        .await?;
    assert_eq!(status, StatusCode::OK, "{raw}");
    assert_eq!(raw_keys(&raw), ["WEB", "OPEN"], "{raw}");
    let (_, overview) = h.get("/api/v1/projects/app/overview?path=/payments", &bot).await?;
    assert!(!overview.to_string().contains("STRIPE"), "{overview}");
    assert!(overview.to_string().contains("OPEN"), "{overview}");

    for (method, route, body) in [
        ("GET", "versions?path=/payments", None),
        ("GET", "versions?path=/payments&values=true", None),
        ("GET", "policy?path=/payments", None),
        ("POST", "rollback?path=/payments", Some(json!({"version": 1}))),
        ("POST", "generate?path=/payments", Some(json!({}))),
        ("PUT", "policy?path=/payments", Some(json!({"mode": "inherit"}))),
    ] {
        let url = format!("{secrets}/STRIPE/{route}");
        let method = reqwest::Method::from_bytes(method.as_bytes()).context("method")?;
        let (status, body) = h.call(method, &url, Some(&bot), body).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{route}: {body}");
    }
    let (status, body) = h
        .put(
            &format!("{secrets}/STRIPE?path=/payments"),
            &bot,
            json!({"value": "overwritten"}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = h.delete(&format!("{secrets}/STRIPE?path=/payments"), &bot).await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = h
        .post(
            &format!("{secrets}/batch"),
            &bot,
            json!({"path": "/payments", "upserts": [{"key": "OPEN", "value": "x"}], "deletes": ["STRIPE"]}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Only admins see or manage the list itself.
    let (status, _) = h.get(&access_url("/payments", "STRIPE"), &bot).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = change(&h, &bot, "/payments", "STRIPE", json!({"restricted": false})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = change(&h, &bot, "/payments", "OPEN", json!({"restricted": true})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The value is untouched and the admin still reads it.
    let (status, secret) = h.get(&format!("{secrets}/STRIPE?path=/payments"), &h.admin).await?;
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["value"], "sk_live");
    assert_eq!(secret["restricted"], json!(true));
    Ok(())
}

/// A listed principal gets the actions its entry grants, and never more than its role allows.
async fn a_listed_identity_gets_only_what_its_entry_and_role_allow(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let (pod, pod_token) = h.machine("payments-pod", "app", "viewer").await?;
    let (bot, bot_token) = h.machine("dev-bot", "app", "developer").await?;
    let secrets = "/api/v1/projects/app/environments/prod/secrets";
    let (status, body) = change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({"grant": [
            {"principal_kind": "identity", "principal_id": pod, "actions": ["read-value"]},
            {"principal_kind": "identity", "principal_id": bot, "actions": ["read"]},
        ]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let grants = body["grants"].as_array().context("grants")?;
    assert_eq!(grants.len(), 2);
    assert!(
        grants.iter().all(|g| g["actions"][0] == "read"),
        "read is always granted: {body}"
    );
    assert!(grants.iter().any(|g| g["principal_name"] == "payments-pod"), "{body}");

    // The pod reads the value through every route.
    let (status, secret) = h.get(&format!("{secrets}/STRIPE?path=/payments"), &pod_token).await?;
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["value"], "sk_live");
    assert_eq!(secret["restricted"], json!(true));
    let (_, raw) = h
        .get(
            "/api/v1/secrets/raw?project=app&environment=prod&path=/payments",
            &pod_token,
        )
        .await?;
    assert_eq!(raw_keys(&raw), ["OPEN", "STRIPE"], "{raw}");
    // A viewer's role cannot edit, whatever the list says.
    let (status, _) = h
        .put(
            &format!("{secrets}/STRIPE?path=/payments"),
            &pod_token,
            json!({"value": "x"}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The developer is listed for read only: it sees the key but not the value, and cannot change it.
    let (status, secret) = h.get(&format!("{secrets}/STRIPE?path=/payments"), &bot_token).await?;
    assert_eq!(status, StatusCode::OK, "{secret}");
    assert_eq!(secret["value"], Value::Null);
    assert_eq!(secret["value_hidden"], json!(true));
    let (_, raw) = h
        .get(
            "/api/v1/secrets/raw?project=app&environment=prod&path=/payments",
            &bot_token,
        )
        .await?;
    assert_eq!(raw_keys(&raw), ["OPEN"], "raw needs read-value: {raw}");
    let (status, versions) = h
        .get(
            &format!("{secrets}/STRIPE/versions?path=/payments&values=true"),
            &bot_token,
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{versions}");
    assert_eq!(versions[0]["value"], Value::Null, "{versions}");
    assert_eq!(versions[0]["value_hidden"], json!(true));
    for (method, url, body) in [
        (
            reqwest::Method::PUT,
            format!("{secrets}/STRIPE?path=/payments"),
            Some(json!({"value": "x"})),
        ),
        (
            reqwest::Method::DELETE,
            format!("{secrets}/STRIPE?path=/payments"),
            None,
        ),
        (
            reqwest::Method::POST,
            format!("{secrets}/STRIPE/rollback?path=/payments"),
            Some(json!({"version": 1})),
        ),
    ] {
        let (status, body) = h.call(method, &url, Some(&bot_token), body).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{url}: {body}");
    }

    // Widening the developer's entry to edit lets it write, and the history shows the value
    // once read-value is listed too.
    let (status, body) = change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({"grant": [{"principal_kind": "identity", "principal_id": bot, "actions": ["read-value", "edit"]}]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .put(
            &format!("{secrets}/STRIPE?path=/payments"),
            &bot_token,
            json!({"value": "sk_live_2"}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, versions) = h
        .get(
            &format!("{secrets}/STRIPE/versions?path=/payments&values=true"),
            &bot_token,
        )
        .await?;
    assert_eq!(versions[0]["value"], "sk_live_2", "{versions}");
    assert_eq!(versions[1]["value"], "sk_live", "{versions}");
    let (status, _) = h
        .delete(&format!("{secrets}/STRIPE?path=/payments"), &bot_token)
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "delete is not on the entry");

    // Revoking takes it all away again.
    let (status, body) = change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({"revoke": [{"principal_kind": "identity", "principal_id": bot}]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.get(&format!("{secrets}/STRIPE?path=/payments"), &bot_token).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

/// Users are reached by their own entries and their groups'; project and organisation admins
/// are never kept off, so a secret is never orphaned.
async fn users_groups_and_admins(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let (ann, ann_token) = user_token(&h, "ann", &[]).await?;
    let (bob, bob_token) = user_token(&h, "bob", &["payments-team"]).await?;
    let (carol, carol_token) = user_token(&h, "carol", &[]).await?;
    add_member(&h, "user", &ann, "developer").await?;
    add_member(&h, "user", &bob, "developer").await?;
    add_member(&h, "user", &carol, "admin").await?;
    let url = "/api/v1/projects/app/environments/prod/secrets/STRIPE?path=/payments";
    for token in [&ann_token, &bob_token] {
        let (status, _) = h.get(url, token).await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, secret) = h.get(url, &carol_token).await?;
    assert_eq!(status, StatusCode::OK, "a project admin keeps access: {secret}");
    assert_eq!(secret["value"], "sk_live");
    let (status, body) = change(
        &h,
        &carol_token,
        "/payments",
        "STRIPE",
        json!({"grant": [
            {"principal_kind": "user", "principal_id": ann, "actions": ["read-value"]},
            {"principal_kind": "group", "principal_id": "payments-team", "actions": ["read-value"]},
        ]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "a project admin manages the list: {body}");
    for token in [&ann_token, &bob_token] {
        let (status, secret) = h.get(url, token).await?;
        assert_eq!(status, StatusCode::OK, "{secret}");
        assert_eq!(secret["value"], "sk_live");
    }

    // Unknown users and identities are refused, and so are bad actions and duplicates.
    for (grant, wanted) in [
        (
            json!({"principal_kind": "user", "principal_id": "nobody", "actions": ["read"]}),
            "does not exist",
        ),
        (
            json!({"principal_kind": "identity", "principal_id": "nobody", "actions": ["read"]}),
            "does not exist",
        ),
        (
            json!({"principal_kind": "group", "principal_id": "ops", "actions": ["create"]}),
            "cannot grant create",
        ),
        (
            json!({"principal_kind": "group", "principal_id": "a\nb", "actions": ["read"]}),
            "control characters",
        ),
    ] {
        let (status, body) = change(&h, &h.admin, "/payments", "STRIPE", json!({"grant": [grant]})).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["message"].as_str().is_some_and(|m| m.contains(wanted)), "{body}");
    }
    let (status, body) = change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({
            "grant": [{"principal_kind": "group", "principal_id": "ops", "actions": ["read"]}],
            "revoke": [{"principal_kind": "group", "principal_id": "ops"}],
        }),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let too_many: Vec<Value> = (0..101)
        .map(|i| json!({"principal_kind": "group", "principal_id": format!("g{i}"), "actions": ["read"]}))
        .collect();
    let (status, _) = change(&h, &h.admin, "/payments", "STRIPE", json!({"grant": too_many})).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Two entries are there already; fill the list to exactly 100.
    for batch in 0..2 {
        let grants: Vec<Value> = (0..49)
            .map(|i| json!({"principal_kind": "group", "principal_id": format!("g{batch}-{i}"), "actions": ["read"]}))
            .collect();
        let (status, body) = change(&h, &h.admin, "/payments", "STRIPE", json!({"grant": grants})).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (_, full) = h.get(&access_url("/payments", "STRIPE"), &h.admin).await?;
    assert_eq!(full["grants"].as_array().map(Vec::len), Some(100));
    let (status, body) = change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({"grant": [{"principal_kind": "group", "principal_id": "g0-0", "actions": ["read", "edit"]}]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "changing an entry on a full list works: {body}");
    let (status, body) = change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({"grant": [{"principal_kind": "group", "principal_id": "one-more", "actions": ["read"]}]}),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a list holds at most 100 entries: {body}"
    );

    // A secret the admin's own rules hide stays hidden from the access routes too.
    let (status, _) = h.get(&access_url("/payments", "MISSING"), &h.admin).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

/// Turning the setting off waits until nothing is restricted, deleted secrets included, so no
/// restriction ever lapses unnoticed.
async fn turning_the_setting_off_waits_for_every_restriction(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let (status, body) = h
        .post(
            "/api/v1/projects/app/environments/prod/secrets/batch",
            &h.admin,
            json!({"path": "/payments", "deletes": ["STRIPE"]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = set_setting(&h, &h.admin, false).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "secrets_restricted");
    assert!(
        body["message"].as_str().is_some_and(|m| m.contains("1 secret ")),
        "{body}"
    );
    let (_, setting) = h.get("/api/v1/projects/app/secret-access", &h.admin).await?;
    assert_eq!(setting["enabled"], json!(true));
    assert_eq!(
        setting["restricted"],
        json!([{"environment": "prod", "path": "/payments", "key": "STRIPE", "deleted": true, "grants": 0}])
    );

    // Bringing the deleted secret back keeps it restricted.
    let (_, bot) = h.machine("dev-bot", "app", "developer").await?;
    let (status, _) = h
        .put(
            "/api/v1/projects/app/environments/prod/secrets/STRIPE?path=/payments",
            &bot,
            json!({"value": "new"}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "an unlisted caller cannot revive it");

    let (status, body) = change(&h, &h.admin, "/payments", "STRIPE", json!({"restricted": false})).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "unrestricting works on a deleted secret: {body}"
    );
    let (status, body) = set_setting(&h, &h.admin, false).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], json!(false));
    Ok(())
}

/// Creating a secret restricted leaves no moment when it is open, and needs an admin.
async fn secrets_can_be_created_restricted(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let (_, bot) = h.machine("dev-bot", "app", "developer").await?;
    let url = "/api/v1/projects/app/environments/prod/secrets/NEW?path=/";
    let restricted = json!({"value": "v", "restricted": true});
    let (status, body) = h.put(url, &h.admin, restricted.clone()).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "secret_access_off");
    set_setting(&h, &h.admin, true).await?;
    let (status, _) = h.put(url, &bot, restricted.clone()).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "only admins create restricted secrets");
    let (status, body) = h.put(url, &h.admin, restricted).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.get(url, &bot).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = h
        .put(url, &h.admin, json!({"value": "v2", "restricted": false}))
        .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a write never changes the flag: {body}"
    );
    let (_, audit) = h
        .get("/api/v1/projects/app/audit?action=secret.write", &h.admin)
        .await?;
    assert_eq!(audit["entries"][0]["detail"]["restricted"], json!(["NEW"]), "{audit}");

    // A deleted, open secret can be brought back restricted in one write, by an admin only.
    let old = "/api/v1/projects/app/environments/prod/secrets/OLD?path=/";
    h.put(old, &h.admin, json!({"value": "first"})).await?;
    let (status, _) = h.delete(old, &h.admin).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.put(old, &bot, json!({"value": "again", "restricted": true})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = h
        .put(old, &h.admin, json!({"value": "again", "restricted": true}))
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.get(old, &bot).await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "revived restricted");
    let (status, _) = h
        .get(
            "/api/v1/projects/app/environments/prod/secrets/OLD/versions?path=/",
            &bot,
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "its history went with it");

    // Deleting a project or environment that holds restricted secrets is for admins only.
    let (status, body) = h
        .put(
            "/api/v1/projects/app/roles/custodian",
            &h.admin,
            json!({"name": "Custodian", "rules": [
                {"effect": "allow", "subject": "settings", "actions": ["read", "delete"]},
                {"effect": "allow", "subject": "secrets", "actions": ["read", "delete"]},
                {"effect": "allow", "subject": "snapshots", "actions": ["edit"]},
                {"effect": "allow", "subject": "folders", "actions": ["read", "delete"]},
                {"effect": "allow", "subject": "environments", "actions": ["read", "delete"]},
            ]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, custodian) = h.machine("custodian", "app", "custodian").await?;
    let (status, body) = h.delete("/api/v1/projects/app", &custodian).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["message"].as_str().is_some_and(|m| m.contains("restricted")),
        "{body}"
    );
    let (status, _) = h.get("/api/v1/projects/app", &h.admin).await?;
    assert_eq!(status, StatusCode::OK, "the project is still there");
    let (status, _) = h
        .post(
            "/api/v1/projects/app/environments/prod/secrets/batch",
            &h.admin,
            json!({"deletes": ["NEW", "OLD"]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h.delete("/api/v1/projects/app/environments/prod", &custodian).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = h.delete("/api/v1/projects/app/environments/prod", &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    Ok(())
}

/// Snapshots neither count, list nor restore a restricted secret for someone off its list.
async fn snapshots_leave_hidden_secrets_out(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let (_, bot) = h.machine("dev-bot", "app", "developer").await?;
    let base = "/api/v1/projects/app/environments/prod";
    let (_, snapshots) = h.get(&format!("{base}/snapshots"), &bot).await?;
    let first = snapshots
        .as_array()
        .and_then(|s| s.last())
        .context("first snapshot")?
        .clone();
    let (_, as_admin) = h.get(&format!("{base}/snapshots"), &h.admin).await?;
    let newest = |s: &Value| s[0]["secret_count"].clone();
    assert_eq!(newest(&as_admin), json!(3), "{as_admin}");
    assert_eq!(
        newest(&snapshots),
        json!(2),
        "the hidden secret is not counted: {snapshots}"
    );

    // Change the restricted secret, then look at what restoring the first snapshot would do.
    h.set_secrets("app", "prod", "/payments", &[("STRIPE", "rotated")])
        .await?;
    let (_, after) = h.get(&format!("{base}/snapshots"), &bot).await?;
    assert_eq!(after, snapshots, "a change only to the hidden secret leaves no trace");
    let (_, as_admin) = h.get(&format!("{base}/snapshots"), &h.admin).await?;
    let rotation = as_admin[0]["id"].as_str().context("rotation snapshot")?;
    let (status, _) = h.get(&format!("{base}/snapshots/{rotation}"), &bot).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let id = first["id"].as_str().context("id")?;
    let (status, detail) = h.get(&format!("{base}/snapshots/{id}?path=/"), &bot).await?;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert!(!detail.to_string().contains("STRIPE"), "{detail}");
    let (_, admin_detail) = h.get(&format!("{base}/snapshots/{id}?path=/"), &h.admin).await?;
    assert!(admin_detail.to_string().contains("STRIPE"), "{admin_detail}");
    let (status, body) = h
        .post(&format!("{base}/snapshots/{id}/restore"), &bot, json!({"path": "/"}))
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.to_string().contains("STRIPE"), "{body}");
    let (_, secret) = h
        .get(&format!("{base}/secrets/STRIPE?path=/payments"), &h.admin)
        .await?;
    assert_eq!(
        secret["value"], "rotated",
        "the restore left the restricted secret alone"
    );
    Ok(())
}

/// The audit log leaves out every entry about a restricted secret for those off its list, so
/// neither entries, totals, filters nor searches show it exists. Entries are marked when written.
async fn audit_names_restricted_secrets_only_to_those_listed(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    set_setting(&h, &h.admin, true).await?;
    let stripe = "/api/v1/projects/app/environments/prod/secrets/STRIPE?path=/payments";
    let (status, body) = h
        .put(stripe, &h.admin, json!({"value": "sk_live", "restricted": true}))
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    h.set_secrets("app", "prod", "/payments", &[("OPEN", "fine")]).await?;
    let (pod, pod_token) = h.machine("payments-pod", "app", "developer").await?;
    let (_, bot) = h.machine("dev-bot", "app", "developer").await?;
    change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({"grant": [{"principal_kind": "identity", "principal_id": pod, "actions": ["read-value", "edit"]}]}),
    )
    .await?;
    let (status, _) = h.get(stripe, &pod_token).await?;
    assert_eq!(status, StatusCode::OK);
    h.put(stripe, &pod_token, json!({"value": "sk_live_2"})).await?;
    let audit = |query: &str| format!("/api/v1/projects/app/audit?limit=200&{query}");
    let (status, page) = h.get(&audit(""), &bot).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let text = page.to_string();
    assert!(!text.contains("STRIPE") && !text.contains("sk_live"), "{page}");
    let actions: Vec<&str> = page["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(!actions.contains(&"secret.access"), "{actions:?}");
    assert_eq!(
        actions.iter().filter(|a| a.starts_with("secret.")).count(),
        1,
        "only the open write remains: {actions:?}"
    );
    // Filters and searches behave as if the secret never existed.
    for query in [
        "key=STRIPE",
        "environment=prod&key=STRIPE",
        "q=STRIPE",
        "action=secret.access",
    ] {
        let (status, body) = h.get(&audit(query), &bot).await?;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        assert_eq!(body["total"], json!(0), "{query}: {body}");
    }

    // The listed pod sees entries naming the secret, but not who else is listed, nor batch
    // writes, which may name other restricted secrets too.
    let (_, page) = h.get(&audit("key=STRIPE"), &pod_token).await?;
    let actions: Vec<&str> = page["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert_eq!(actions, ["secret.read"], "{page}");

    // Admins see everything, access-list changes included, and never a value.
    let (_, page) = h.get(&audit("action=secret.access"), &h.admin).await?;
    let detail = &page["entries"][0]["detail"];
    assert_eq!(detail["granted"][0]["principal_id"], json!(pod), "{page}");
    let (_, everything) = h.get(&audit(""), &h.admin).await?;
    assert!(!everything.to_string().contains("sk_live"), "names, never values");

    // The organisation log keeps them from anyone but organisation admins.
    let (status, body) = h
        .put(
            "/api/v1/org/roles/auditor",
            &h.admin,
            json!({"name": "Auditor", "rules": [{"effect": "allow", "subject": "org-audit-log", "actions": ["read"]}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let auditor = h.org_identity_as("auditor", "auditor", &h.admin).await?;
    let (_, org) = h.get("/api/v1/audit?limit=200&q=STRIPE", &auditor).await?;
    assert_eq!(org["total"], json!(0), "{org}");
    let (_, org) = h.get("/api/v1/audit?limit=200&q=STRIPE", &h.admin).await?;
    assert!(org["total"].as_i64().is_some_and(|n| n > 0), "{org}");

    // Unrestricting does not open entries written while it was restricted.
    change(&h, &h.admin, "/payments", "STRIPE", json!({"restricted": false})).await?;
    let (_, page) = h.get(&audit("key=STRIPE&action=secret.read"), &bot).await?;
    assert_eq!(page["total"], json!(0), "{page}");
    Ok(())
}

/// Writing to a hidden secret answers exactly as a missing key would, short of a genuine clash
/// for someone who could create it; that refusal is recorded for admins.
async fn writes_cannot_probe_for_hidden_secrets(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let (_, viewer) = h.machine("viewer-bot", "app", "viewer").await?;
    let (_, developer) = h.machine("dev-bot", "app", "developer").await?;
    let url = |key: &str| format!("/api/v1/projects/app/environments/prod/secrets/{key}?path=/payments");
    let normalise = |body: Value, key: &str| body.to_string().replace(key, "KEY");
    for body in [json!({"value": "x"}), json!({"value": "x", "restricted": true})] {
        let (hidden_status, hidden) = h.put(&url("STRIPE"), &viewer, body.clone()).await?;
        let (missing_status, missing) = h.put(&url("NOPE"), &viewer, body).await?;
        assert_eq!(hidden_status, missing_status, "{hidden} / {missing}");
        assert_eq!(normalise(hidden, "STRIPE"), normalise(missing, "NOPE"));
    }
    // A malformed batch fails before any key is looked up.
    let batch = "/api/v1/projects/app/environments/prod/secrets/batch";
    let probe = json!({"path": "/payments", "upserts": [
        {"key": "STRIPE", "value": "x"},
        {"key": "LAST", "value": "x", "comment": "c".repeat(5000)},
    ]});
    let (status, _) = h.post(batch, &developer, probe).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Someone who could create there meets the clash, which is recorded but not for them.
    let (status, _) = h.put(&url("STRIPE"), &developer, json!({"value": "x"})).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, refused) = h
        .get("/api/v1/projects/app/audit?action=secret.write-refused", &h.admin)
        .await?;
    assert_eq!(refused["entries"][0]["secret_key"], "STRIPE", "{refused}");
    let (_, theirs) = h
        .get("/api/v1/projects/app/audit?action=secret.write-refused", &developer)
        .await?;
    assert_eq!(theirs["total"], json!(0), "{theirs}");
    let (status, _) = h
        .post(
            "/api/v1/projects/app/environments/prod/secrets/STRIPE/generate?path=/payments",
            &developer,
            json!({}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "generating meets the same answer");
    Ok(())
}

/// Unrestricting clears the list and turning the setting off clears every list, so no stale entry
/// comes back with a later restriction.
async fn lists_never_outlive_their_restriction(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let ops = json!({"grant": [{"principal_kind": "group", "principal_id": "ops", "actions": ["read"]}]});
    change(&h, &h.admin, "/payments", "STRIPE", ops.clone()).await?;
    let (status, body) = change(&h, &h.admin, "/payments", "STRIPE", json!({"restricted": false})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"restricted": false, "grants": []}));
    let (_, audit) = h
        .get("/api/v1/projects/app/audit?action=secret.access", &h.admin)
        .await?;
    assert_eq!(
        audit["entries"][0]["detail"]["cleared"][0]["principal_id"], "ops",
        "the cleared entries are recorded: {audit}"
    );
    // Revoking someone who is not listed is refused rather than reported as done.
    let (status, body) = change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({"revoke": [{"principal_kind": "group", "principal_id": "nobody"}]}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["message"].as_str().is_some_and(|m| m.contains("not on")), "{body}");
    // A deleted secret brought back restricted starts with an empty list, whatever it had.
    let old = "/api/v1/projects/app/environments/prod/secrets/OLD?path=/";
    h.put(old, &h.admin, json!({"value": "1"})).await?;
    change(&h, &h.admin, "/", "OLD", ops.clone()).await?;
    h.delete(old, &h.admin).await?;
    let (status, body) = h.put(old, &h.admin, json!({"value": "2", "restricted": true})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, revived) = h.get(&access_url("/", "OLD"), &h.admin).await?;
    assert_eq!(revived, json!({"restricted": true, "grants": []}));
    change(&h, &h.admin, "/", "OLD", json!({"restricted": false})).await?;
    // A list made ready on an open secret goes when the setting is turned off.
    change(&h, &h.admin, "/payments", "OPEN", ops).await?;
    let (status, body) = set_setting(&h, &h.admin, false).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    set_setting(&h, &h.admin, true).await?;
    let (_, open) = h.get(&access_url("/payments", "OPEN"), &h.admin).await?;
    assert_eq!(open["grants"], json!([]), "{open}");
    Ok(())
}

/// The built-in admin roles lift access lists, so a principal whose rules merely match them
/// cannot hand them out, to others or to themselves.
async fn only_admins_grant_the_admin_roles(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let everything: Vec<Value> = [
        "secrets",
        "secret-versions",
        "snapshots",
        "folders",
        "environments",
        "members",
        "roles",
        "audit-log",
        "settings",
    ]
    .iter()
    .map(|s| json!({"effect": "allow", "subject": s, "actions": ["read", "read-value", "create", "edit", "delete"]}))
    .collect();
    let (status, body) = h
        .put(
            "/api/v1/projects/app/roles/maintainer",
            &h.admin,
            json!({"name": "Maintainer", "rules": everything}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (maintainer_id, maintainer) = h.machine("maintainer", "app", "maintainer").await?;
    let (status, body) = h
        .post(
            "/api/v1/projects/app/members",
            &maintainer,
            json!({"principal_kind": "identity", "principal_id": maintainer_id, "role": "admin"}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "escalation");
    let (status, _) = h
        .get(
            "/api/v1/projects/app/environments/prod/secrets/STRIPE?path=/payments",
            &maintainer,
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "still off the list");

    // A real admin still can.
    let (status, body) = h
        .post(
            "/api/v1/projects/app/members",
            &h.admin,
            json!({"principal_kind": "identity", "principal_id": maintainer_id, "role": "admin"}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Ok(())
}

/// Each secret says what its list grants the caller, and a write that asked for restriction
/// confirms it.
async fn secrets_report_the_callers_entry(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    restricted_project(&h).await?;
    let (pod, pod_token) = h.machine("pod", "app", "developer").await?;
    change(
        &h,
        &h.admin,
        "/payments",
        "STRIPE",
        json!({"grant": [{"principal_kind": "identity", "principal_id": pod, "actions": ["read"]}]}),
    )
    .await?;
    let url = "/api/v1/projects/app/environments/prod/secrets/STRIPE?path=/payments";
    let (_, secret) = h.get(url, &pod_token).await?;
    assert_eq!(secret["granted"], json!(["read"]), "{secret}");
    let (_, secret) = h.get(url, &h.admin).await?;
    assert_eq!(secret.get("granted"), None, "an admin is not bound: {secret}");
    let (_, written) = h
        .put(
            "/api/v1/projects/app/environments/prod/secrets/NEW?path=/",
            &h.admin,
            json!({"value": "v", "restricted": true}),
        )
        .await?;
    assert_eq!(written["restricted"], json!(["NEW"]), "{written}");
    let (_, plain) = h
        .put(
            "/api/v1/projects/app/environments/prod/secrets/PLAIN?path=/",
            &h.admin,
            json!({"value": "v"}),
        )
        .await?;
    assert_eq!(plain["restricted"], json!([]), "{plain}");
    let (_, generated) = h
        .post(
            "/api/v1/projects/app/environments/prod/secrets/GEN/generate?path=/",
            &h.admin,
            json!({"restricted": true}),
        )
        .await?;
    assert_eq!(generated["restricted"], json!(["GEN"]), "{generated}");
    // Deleting an environment that still has live secrets says so before anything about
    // restrictions.
    let (status, body) = h.delete("/api/v1/projects/app/environments/prod", &h.admin).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "not_empty");
    Ok(())
}

on_both_backends!(
    the_setting_is_off_by_default_and_for_admins_only,
    an_unlisted_identity_never_sees_a_restricted_secret,
    a_listed_identity_gets_only_what_its_entry_and_role_allow,
    users_groups_and_admins,
    turning_the_setting_off_waits_for_every_restriction,
    secrets_can_be_created_restricted,
    snapshots_leave_hidden_secrets_out,
    audit_names_restricted_secrets_only_to_those_listed,
    writes_cannot_probe_for_hidden_secrets,
    lists_never_outlive_their_restriction,
    only_admins_grant_the_admin_roles,
    secrets_report_the_callers_entry,
);
