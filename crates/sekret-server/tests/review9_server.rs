//! Regressions for the ninth security audit's server findings: SVG logos, pattern caps through
//! groups, the CLI login limits, path and key conditions, hidden deleted secrets and admins
//! locked out by denies.

mod common;

use std::time::{Duration, Instant};

use anyhow::Context;
use common::{Harness, options, start};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

/// The audit's logo: one stroked path of 40,000 segments drawn through 250 `<use>` copies.
fn stroked_path_bomb() -> Vec<u8> {
    let mut d = String::from("M0 0");
    for i in 0..40_000 {
        d.push_str(if i % 2 == 0 { " L512 1" } else { " L0 2" });
    }
    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><defs><path id="p" d="{d}" fill="none" stroke="black" stroke-width="40" stroke-linejoin="round" stroke-linecap="round"/></defs>"#
    );
    for _ in 0..250 {
        svg.push_str(r##"<use href="#p"/>"##);
    }
    svg.push_str("</svg>");
    svg.into_bytes()
}

fn png() -> anyhow::Result<Vec<u8>> {
    let image = image::RgbaImage::from_pixel(8, 8, image::Rgba([30, 44, 67, 255]));
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut out, image::ImageFormat::Png)
        .context("png")?;
    Ok(out.into_inner())
}

async fn upload(h: &Harness, token: &str, body: Vec<u8>) -> anyhow::Result<(StatusCode, Value)> {
    let response = h
        .client
        .put(format!("{}/api/v1/projects/app/logo", h.base))
        .bearer_auth(token)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .context("upload")?;
    let status = response.status();
    Ok((status, response.json().await.unwrap_or_default()))
}

/// SVGs are never drawn on the server, so the audit's 20-second file costs nothing and leaves
/// the decode slots free for everyone else.
async fn svg_logos_are_refused_without_drawing_them(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let bomb = stroked_path_bomb();
    assert!(bomb.len() < sekret_server::api::logo::MAX_LOGO_BYTES);
    let started = Instant::now();
    for _ in 0..2 {
        let (status, body) = upload(&h, &h.admin, bomb.clone()).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["message"].as_str().is_some_and(|m| m.contains("SVG")), "{body}");
    }
    let (status, body) = upload(&h, &h.admin, png()?).await?;
    assert_eq!(status, StatusCode::OK, "a raster logo still works: {body}");
    // The render this replaces took about 20 s per upload.
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    Ok(())
}

/// A bearer token for a user stored with `groups`, as a sign-in would leave it.
async fn user_token(h: &Harness, name: &str, groups: &[&str], kind: &str) -> anyhow::Result<(String, String)> {
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
            kind: kind.into(),
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

/// A role whose deny rules hold `count` path patterns, 50 to a rule.
fn heavy_role(prefix: &str, count: usize) -> Value {
    let paths: Vec<String> = (0..count).map(|i| format!("/{prefix}{i}/**")).collect();
    let mut rules = vec![json!({"effect": "allow", "subject": "secrets", "actions": ["read"]})];
    for chunk in paths.chunks(50) {
        rules.push(
            json!({"effect": "deny", "subject": "secrets", "actions": ["read-value"], "conditions": {"paths": chunk}}),
        );
    }
    json!({"name": prefix, "rules": rules})
}

async fn bind(h: &Harness, kind: &str, id: &str, role: &str) -> anyhow::Result<StatusCode> {
    let (status, _) = h
        .post(
            "/api/v1/projects/app/members",
            &h.admin,
            json!({"principal_kind": kind, "principal_id": id, "role": role}),
        )
        .await?;
    Ok(status)
}

/// Roles reaching a user through their groups count towards the per-member cap, when bound,
/// when a role grows, and when a listing runs after the provider adds a group.
async fn group_bindings_count_towards_the_pattern_cap(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    for slug in ["heavy-a", "heavy-b", "heavy-c"] {
        let (status, body) = h
            .put(
                &format!("/api/v1/projects/app/roles/{slug}"),
                &h.admin,
                heavy_role(slug, 200),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (user, token) = user_token(&h, "grouped", &["ops", "sre"], "cli").await?;
    assert_eq!(bind(&h, "user", &user, "heavy-a").await?, StatusCode::CREATED);
    assert_eq!(bind(&h, "group", "ops", "heavy-b").await?, StatusCode::CREATED);
    assert_eq!(
        bind(&h, "group", "sre", "heavy-c").await?,
        StatusCode::BAD_REQUEST,
        "the user already holds 400 through their own binding and ops"
    );
    assert_eq!(
        bind(&h, "group", "dev", "heavy-c").await?,
        StatusCode::CREATED,
        "nobody signed in holds dev"
    );
    let (status, _) = h
        .put(
            "/api/v1/projects/app/roles/heavy-b",
            &h.admin,
            heavy_role("heavy-b", 201),
        )
        .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "growing a role a group holds counts too"
    );
    let (status, body) = h
        .get("/api/v1/projects/app/environments/dev/secrets?recursive=true", &token)
        .await?;
    assert_eq!(status, StatusCode::OK, "at the cap: {body}");

    // The provider hands the user dev at their next sign-in.
    user_token(&h, "grouped", &["ops", "sre", "dev"], "cli").await?;
    let (status, body) = h
        .get("/api/v1/projects/app/environments/dev/secrets?recursive=true", &token)
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "too_many_patterns");
    Ok(())
}

/// Anonymous CLI login starts from an address cannot use up a signed-in person's allowance for
/// answering logins.
async fn cli_login_starts_do_not_block_approvals(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let (_, session) = user_token(&h, "approver", &[], "session").await?;
    // Use up this address's allowance as a flood of anonymous starts would.
    let local = std::net::IpAddr::from([127, 0, 0, 1]);
    for _ in 0..=h.state.config.login_rate_per_minute {
        h.state.cli_login_limiter.allow_ip(local);
    }
    let (status, _) = h.call(Method::POST, "/api/v1/auth/cli/start", None, None).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "starts are limited per address");
    let response = h
        .client
        .get(format!("{}/api/v1/auth/cli/pending?code=ABCD-EFGH", h.base))
        .header("cookie", format!("sekret_session={session}"))
        .send()
        .await
        .context("pending")?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "answered, not rate limited");
    let response = h
        .client
        .post(format!("{}/api/v1/auth/cli/deny", h.base))
        .header("cookie", format!("sekret_session={session}"))
        .header("x-sekret-csrf", "1")
        .json(&json!({"code": "ABCD-EFGH"}))
        .send()
        .await
        .context("deny")?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// Path and key conditions that no stored folder or key could ever meet are refused.
async fn conditions_that_can_never_match_are_refused(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let role = |conditions: Value| {
        json!({"name": "Ops", "rules": [
            {"effect": "allow", "subject": "secrets", "actions": ["read"]},
            {"effect": "deny", "subject": "secrets", "actions": ["read-value"], "conditions": conditions}
        ]})
    };
    for bad in [
        json!({"paths": ["payments/**"]}),
        json!({"paths": ["/payments/"]}),
        json!({"paths": ["/payments//**"]}),
        json!({"paths": ["/a/../payments"]}),
        json!({"paths": ["/pay ments"]}),
        json!({"keys": ["1KEY"]}),
        json!({"keys": ["DB KEY"]}),
    ] {
        let (status, body) = h
            .put("/api/v1/projects/app/roles/ops", &h.admin, role(bad.clone()))
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert!(
            body["message"].as_str().is_some_and(|m| m.contains("never match")),
            "{body}"
        );
    }
    for good in [
        json!({"paths": ["/payments/**", "/", "/a/*/b"]}),
        json!({"keys": ["DB_*", "?ASS"]}),
    ] {
        let (status, body) = h
            .put("/api/v1/projects/app/roles/ops", &h.admin, role(good.clone()))
            .await?;
        assert_eq!(status, StatusCode::OK, "{good}: {body}");
    }
    // A good one really applies.
    h.set_secrets("app", "dev", "/payments", &[("STRIPE", "sk")]).await?;
    let (_, token) = h.machine("ops", "app", "ops").await?;
    let (status, body) = h
        .put(
            "/api/v1/projects/app/roles/ops",
            &h.admin,
            role(json!({"paths": ["/payments/**"]})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, listed) = h
        .get(
            "/api/v1/projects/app/environments/dev/secrets?path=/payments&values=true",
            &token,
        )
        .await?;
    assert_eq!(listed["secrets"][0]["value_hidden"], true, "{listed}");
    Ok(())
}

/// Writing a key over a deleted secret the caller cannot see does not reveal its history.
async fn rewriting_a_hidden_deleted_secret_is_refused(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let batch = "/api/v1/projects/app/environments/dev/secrets/batch";
    let (status, body) = h
        .post(
            batch,
            &h.admin,
            json!({"path": "/", "upserts": [{"key": "K", "value": "card", "tags": ["pci"]}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h.post(batch, &h.admin, json!({"path": "/", "deletes": ["K"]})).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .put(
            "/api/v1/projects/app/roles/no-pci",
            &h.admin,
            json!({"name": "No PCI", "rules": [
                {"effect": "allow", "subject": "secrets", "actions": ["read", "create", "edit"]},
                {"effect": "allow", "subject": "secret-versions", "actions": ["read"]},
                {"effect": "deny", "subject": "secrets", "actions": ["read"], "conditions": {"tags": ["pci"]}}
            ]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, token) = h.machine("dev", "app", "no-pci").await?;
    let (status, body) = h
        .post(
            batch,
            &token,
            json!({"path": "/", "upserts": [{"key": "K", "value": "x"}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, _) = h
        .get("/api/v1/projects/app/environments/dev/secrets/K/versions", &token)
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "the history stays hidden");
    let (status, body) = h
        .post(
            batch,
            &token,
            json!({"path": "/", "upserts": [{"key": "OTHER", "value": "x"}]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "new keys are still fine: {body}");
    Ok(())
}

fn auditors(with_denies: bool) -> Value {
    let mut rules = vec![json!({"effect": "allow", "subject": "org-audit-log", "actions": ["read"]})];
    if with_denies {
        rules.push(json!({"effect": "deny", "subject": "org-roles", "actions": ["read", "edit", "delete"]}));
        rules.push(json!({"effect": "deny", "subject": "org-members", "actions": ["read", "create", "delete"]}));
    }
    json!({"name": "Auditors", "rules": rules})
}

/// Someone with delegated rights cannot bind denies to an org admin, by editing a role the admin
/// holds or by granting one. An org admin bound by such denies anyway can still edit, unbind and
/// delete the role.
async fn delegated_org_role_editors_cannot_lock_out_admins(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let (_, me) = h.get("/api/v1/me", &h.admin).await?;
    let admin_id = me["id"].as_str().context("admin id")?.to_string();
    let bind_admin = json!({"principal_kind": "user", "principal_id": admin_id, "role": "auditors"});
    let (status, body) = h.put("/api/v1/org/roles/auditors", &h.admin, auditors(false)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h.post("/api/v1/org/bindings", &h.admin, bind_admin.clone()).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = h
        .put(
            "/api/v1/org/roles/role-editor",
            &h.admin,
            json!({"name": "Role editor", "rules": [
                {"effect": "allow", "subject": "org-roles", "actions": ["read", "create", "edit", "delete"]},
                {"effect": "allow", "subject": "org-members", "actions": ["read", "create"]},
                {"effect": "allow", "subject": "org-audit-log", "actions": ["read"]}
            ]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let editor = h.org_identity_as("editor", "role-editor", &h.admin).await?;
    let (status, body) = h.put("/api/v1/org/roles/auditors", &editor, auditors(true)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "denies on a role an admin holds: {body}");

    // A role nobody holds can take denies, but the editor cannot then hand it to an admin.
    let (status, body) = h
        .delete(&format!("/api/v1/org/bindings/user/{admin_id}/auditors"), &h.admin)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = h.put("/api/v1/org/roles/auditors", &editor, auditors(true)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h.post("/api/v1/org/bindings", &editor, bind_admin.clone()).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // An admin may still bind it to themselves, and is never locked out by it.
    let (status, body) = h.post("/api/v1/org/bindings", &h.admin, bind_admin).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, roles) = h.get("/api/v1/org/roles", &h.admin).await?;
    assert_eq!(status, StatusCode::OK, "the admin still sees the roles: {roles}");
    let (status, body) = h.put("/api/v1/org/roles/auditors", &h.admin, auditors(false)).await?;
    assert_eq!(status, StatusCode::OK, "the admin can take the denies out: {body}");
    let (status, body) = h.put("/api/v1/org/roles/auditors", &h.admin, auditors(true)).await?;
    assert_eq!(status, StatusCode::OK, "and put them back: {body}");
    let (status, body) = h
        .delete(&format!("/api/v1/org/bindings/user/{admin_id}/auditors"), &h.admin)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = h.delete("/api/v1/org/roles/auditors", &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // The delegated editor is still held to their own cover.
    let (status, _) = h
        .put(
            "/api/v1/org/roles/role-editor",
            &editor,
            json!({"name": "Role editor", "rules": [
                {"effect": "allow", "subject": "org-roles", "actions": ["read", "create", "edit", "delete"]},
                {"effect": "allow", "subject": "backups", "actions": ["read"]}
            ]}),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

fn readers(with_denies: bool) -> Value {
    let mut rules = vec![json!({"effect": "allow", "subject": "secrets", "actions": ["read"]})];
    if with_denies {
        rules.push(json!({"effect": "deny", "subject": "roles", "actions": ["read", "edit", "delete"]}));
        rules.push(json!({"effect": "deny", "subject": "members", "actions": ["read", "delete"]}));
    }
    json!({"name": "Readers", "rules": rules})
}

/// The same inside a project: a delegated role editor cannot bind denies to the project's admins,
/// directly or through a group, and an org admin can always undo a deny bound to anyone.
async fn delegated_project_role_editors_cannot_lock_out_admins(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let (lead_id, lead) = h.machine("lead", "app", "admin").await?;
    let (status, body) = h
        .put("/api/v1/projects/app/roles/readers", &h.admin, readers(false))
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bind = |kind: &str, id: &str| json!({"principal_kind": kind, "principal_id": id, "role": "readers"});
    let (status, body) = h
        .post("/api/v1/projects/app/members", &h.admin, bind("identity", &lead_id))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = h
        .put(
            "/api/v1/projects/app/roles/role-editor",
            &h.admin,
            json!({"name": "Role editor", "rules": [
                {"effect": "allow", "subject": "roles", "actions": ["read", "create", "edit", "delete"]},
                {"effect": "allow", "subject": "members", "actions": ["read", "create"]},
                {"effect": "allow", "subject": "secrets", "actions": ["read"]}
            ]}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, editor) = h.machine("editor", "app", "role-editor").await?;
    let (status, body) = h
        .put("/api/v1/projects/app/roles/readers", &editor, readers(true))
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "denies on a role an admin holds: {body}");

    // Through a group: a signed-in user in `leads` is a project admin by that group.
    user_token(&h, "grouped-lead", &["leads"], "cli").await?;
    let (status, body) = h
        .post(
            "/api/v1/projects/app/members",
            &h.admin,
            json!({"principal_kind": "group", "principal_id": "leads", "role": "admin"}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = h
        .delete(
            &format!("/api/v1/projects/app/members/identity/{lead_id}/readers"),
            &h.admin,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = h
        .put("/api/v1/projects/app/roles/readers", &editor, readers(true))
        .await?;
    assert_eq!(status, StatusCode::OK, "nobody holds it now: {body}");
    for (kind, id) in [("identity", lead_id.as_str()), ("group", "leads")] {
        let (status, body) = h.post("/api/v1/projects/app/members", &editor, bind(kind, id)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{kind}: {body}");
    }
    let (_, worker) = h.machine("worker", "app", "viewer").await?;
    let (_, me) = h.get("/api/v1/me", &worker).await?;
    let worker_id = me["id"].as_str().context("worker id")?;
    let (status, body) = h
        .post("/api/v1/projects/app/members", &editor, bind("identity", worker_id))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "others can still be given it: {body}");

    // A project admin is held to a deny an org admin binds to them; the org admin can lift it.
    let (status, body) = h
        .post("/api/v1/projects/app/members", &lead, bind("identity", &lead_id))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "an admin may bind it: {body}");
    let (status, _) = h
        .delete(
            &format!("/api/v1/projects/app/members/identity/{lead_id}/readers"),
            &lead,
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "it binds them, so they cannot lift it");
    let (status, body) = h.delete("/api/v1/projects/app/roles/readers", &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    Ok(())
}

on_both_backends!(
    svg_logos_are_refused_without_drawing_them,
    group_bindings_count_towards_the_pattern_cap,
    cli_login_starts_do_not_block_approvals,
    conditions_that_can_never_match_are_refused,
    rewriting_a_hidden_deleted_secret_is_refused,
    delegated_org_role_editors_cannot_lock_out_admins,
    delegated_project_role_editors_cannot_lock_out_admins,
);
