//! Regressions for the seventh security audit's server findings: slow request bodies, dashed
//! SVG logos and role conditions that are costly to check.

mod common;

use std::time::{Duration, Instant};

use anyhow::Context;
use common::{Harness, Options, options, start};
use reqwest::StatusCode;
use sekret_core::permissions::{MAX_PRINCIPAL_PATTERNS, MAX_ROLE_PATTERNS};
use sekret_server::BodyTimeouts;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Short enough for a test, with the same gap-to-total shape as the real ones.
const SHORT: BodyTimeouts = BodyTimeouts {
    gap: Duration::from_secs(1),
    total: Duration::from_secs(2),
    open: Duration::from_secs(2),
};

async fn short_deadlines() -> anyhow::Result<Harness> {
    start(Options {
        body_timeouts: SHORT,
        ..Options::default()
    })
    .await
}

/// Sends `head`, then one body byte every 200 ms, never finishing. Returns how long the server
/// let that go on before it answered or closed the connection.
async fn trickle(h: &Harness, head: String) -> anyhow::Result<Duration> {
    let address = h.base.trim_start_matches("http://").to_string();
    let stream = tokio::net::TcpStream::connect(&address).await.context("connect")?;
    let (mut reader, mut writer) = stream.into_split();
    writer.write_all(head.as_bytes()).await.context("head")?;
    let started = Instant::now();
    let drip = async move {
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if writer.write_all(b" ").await.is_err() {
                return;
            }
        }
    };
    let answered = async move {
        let mut buf = [0u8; 512];
        let _ = reader.read(&mut buf).await;
    };
    // Generous: CI runners are slow, and the attack held a connection for days.
    let cut = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            () = drip => {},
            () = answered => {},
        }
    })
    .await;
    anyhow::ensure!(cut.is_ok(), "the trickling body was never cut off");
    Ok(started.elapsed())
}

/// The audit's attack: no credentials, a declared body, and a byte now and then. The unseal and
/// init routes have no request time limit, so only the body deadline ends it.
#[tokio::test]
async fn a_body_that_trickles_in_is_cut_off_even_on_untimed_routes() -> anyhow::Result<()> {
    let h = short_deadlines().await?;
    for route in ["/api/v1/sys/unseal", "/api/v1/sys/init"] {
        let head = format!(
            "POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: 16000\r\n\r\n{{\"passphrase\":"
        );
        let held = trickle(&h, head).await?;
        // Each byte arrives well inside the gap, so only the total deadline can have ended it.
        assert!(
            held >= SHORT.total - Duration::from_millis(200),
            "{route} cut after {held:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_large_upload_sent_steadily_still_arrives() -> anyhow::Result<()> {
    let h = short_deadlines().await?;
    h.create_project("app").await?;
    let value = "x".repeat(60 * 1024);
    let keys: Vec<String> = (0..40).map(|i| format!("K{i}")).collect();
    let pairs: Vec<(&str, &str)> = keys.iter().map(|k| (k.as_str(), value.as_str())).collect();
    h.set_secrets("app", "dev", "/", &pairs).await?;
    let (status, body) = h.get("/api/v1/projects/app/environments/dev/secrets", &h.admin).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["secrets"].as_array().map(Vec::len), Some(40));
    Ok(())
}

#[test]
fn the_default_deadline_covers_the_largest_upload() {
    let defaults = BodyTimeouts::default();
    assert!(defaults.total >= Duration::from_secs(60), "{defaults:?}");
    assert!(defaults.gap <= defaults.total);
}

/// The audit's logo: 2,221 dashed lines that each cut into a million dashes, which took about
/// 100 s of CPU to render.
fn dash_bomb() -> String {
    let mut svg =
        String::from(r#"<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">"#);
    for i in 0..2221 {
        let y = (i % 512) as f32 + 0.5;
        svg.push_str(&format!(
            r##"<path d="M0 {y}H1000000" stroke="black" stroke-dasharray="0.5"/>"##
        ));
    }
    svg.push_str("</svg>");
    svg
}

async fn upload(h: &Harness, body: Vec<u8>) -> anyhow::Result<(StatusCode, Value)> {
    let response = h
        .client
        .put(format!("{}/api/v1/projects/app/logo", h.base))
        .bearer_auth(&h.admin)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .context("upload")?;
    let status = response.status();
    Ok((status, response.json().await.unwrap_or_default()))
}

async fn dashed_logo_bombs_are_refused(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let started = Instant::now();
    let (status, body) = upload(&h, dash_bomb().into_bytes()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"].as_str().is_some_and(|m| m.contains("too complex")),
        "{body}"
    );
    // Generous for slow runners; the render it replaces took well over a minute.
    assert!(started.elapsed() < Duration::from_secs(20), "{:?}", started.elapsed());
    let dashed = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="none" stroke="black" stroke-dasharray="4 2"/></svg>"#;
    let (status, body) = upload(&h, dashed.as_bytes().to_vec()).await?;
    assert_eq!(status, StatusCode::OK, "an ordinary dashed logo: {body}");
    Ok(())
}

/// A project role with `count` path patterns spread over deny rules, as long as a pattern may be.
fn deny_role(count: usize) -> Value {
    deny_role_on("secrets", count)
}

fn deny_role_on(subject: &str, count: usize) -> Value {
    deny_role_sized(subject, count, 256)
}

fn deny_role_sized(subject: &str, count: usize, length: usize) -> Value {
    let pattern = |i: usize| {
        let stem = format!("/{i}");
        format!("{stem}{}Z", "*x".repeat((length - stem.len() - 1) / 2))
    };
    let rules: Vec<Value> = (0..count)
        .collect::<Vec<_>>()
        .chunks(50)
        .map(|chunk| {
            json!({"effect": "deny", "subject": subject, "actions": ["read"],
                "conditions": {"paths": chunk.iter().map(|i| pattern(*i)).collect::<Vec<_>>()}})
        })
        .collect();
    json!({"name": "Heavy", "rules": rules})
}

async fn the_audits_deny_only_role_is_refused(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    // 100 rules of 50 patterns, deny only, so the escalation check never looked at it. At full
    // pattern length it is over the body limit for roles; shorter, it reaches the role checks.
    let (status, body) = h
        .put("/api/v1/projects/app/roles/heavy", &h.admin, deny_role(100 * 50))
        .await?;
    assert!(status.is_client_error(), "{status}: {body}");
    let (status, body) = h
        .put(
            "/api/v1/projects/app/roles/heavy",
            &h.admin,
            deny_role_sized("secrets", 100 * 50, 150),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"].as_str().is_some_and(|m| m.contains("patterns")),
        "{body}"
    );
    let (status, body) = h
        .put(
            "/api/v1/projects/app/roles/heavy",
            &h.admin,
            deny_role(MAX_ROLE_PATTERNS + 1),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "one over the cap: {body}");
    let (status, body) = h
        .put(
            "/api/v1/projects/app/roles/heavy",
            &h.admin,
            deny_role(MAX_ROLE_PATTERNS),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "at the cap: {body}");
    let (status, body) = h
        .put(
            "/api/v1/org/roles/heavy",
            &h.admin,
            deny_role_on("projects", MAX_ROLE_PATTERNS + 1),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "organisation roles too: {body}");
    assert!(
        body["message"].as_str().is_some_and(|m| m.contains("patterns")),
        "{body}"
    );
    let (status, body) = h
        .put(
            "/api/v1/org/roles/heavy",
            &h.admin,
            deny_role_on("projects", MAX_ROLE_PATTERNS),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// A principal bound to the heaviest role still lists a folder with a long path, and the
/// denies still apply.
async fn a_heavy_role_still_answers_correctly(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let mut role = deny_role(MAX_ROLE_PATTERNS - 1);
    if let Some(rules) = role["rules"].as_array_mut() {
        rules.push(json!({"effect": "deny", "subject": "secrets", "actions": ["read"],
            "conditions": {"keys": ["HIDDEN_*"]}}));
    }
    let (status, body) = h.put("/api/v1/projects/app/roles/heavy", &h.admin, role).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (id, token) = h.machine("reader", "app", "viewer").await?;
    let (status, body) = h
        .post(
            "/api/v1/projects/app/members",
            &h.admin,
            json!({"principal_kind": "identity", "principal_id": id, "role": "heavy"}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let folder = format!("/{}", vec!["x".repeat(60); 8].join("/"));
    let keys: Vec<String> = (0..20).map(|i| format!("K{i}")).chain(["HIDDEN_A".into()]).collect();
    let pairs: Vec<(&str, &str)> = keys.iter().map(|k| (k.as_str(), "v")).collect();
    h.set_secrets("app", "dev", &folder, &pairs).await?;
    let (status, body) = h
        .get("/api/v1/projects/app/environments/dev/secrets?recursive=true", &token)
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Vec<&str> = body["secrets"]
        .as_array()
        .context("secrets")?
        .iter()
        .filter_map(|s| s["key"].as_str())
        .collect();
    assert_eq!(listed.len(), 20, "{listed:?}");
    assert!(!listed.contains(&"HIDDEN_A"));
    Ok(())
}

async fn one_member_cannot_stack_heavy_roles(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let per_role = MAX_PRINCIPAL_PATTERNS / 2;
    for slug in ["first", "second"] {
        let (status, body) = h
            .put(
                &format!("/api/v1/projects/app/roles/{slug}"),
                &h.admin,
                deny_role(per_role),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = h
        .put("/api/v1/projects/app/roles/third", &h.admin, deny_role(1))
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (id, _) = h.machine("stacked", "app", "first").await?;
    let bind = |role: &str| json!({"principal_kind": "identity", "principal_id": id, "role": role});
    let (status, body) = h.post("/api/v1/projects/app/members", &h.admin, bind("second")).await?;
    assert_eq!(status, StatusCode::CREATED, "exactly at the cap: {body}");
    let (status, body) = h.post("/api/v1/projects/app/members", &h.admin, bind("third")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "over the cap: {body}");
    // Growing a role someone holds cannot push them over either.
    let (status, body) = h
        .put("/api/v1/projects/app/roles/second", &h.admin, deny_role(per_role + 1))
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = h
        .put("/api/v1/projects/app/roles/second", &h.admin, deny_role(per_role - 1))
        .await?;
    assert_eq!(status, StatusCode::OK, "shrinking is fine: {body}");
    // Other principals are counted separately.
    let (status, body) = h
        .post(
            "/api/v1/projects/app/members",
            &h.admin,
            json!({"principal_kind": "group", "principal_id": "ops", "role": "third"}),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    Ok(())
}

on_both_backends!(
    dashed_logo_bombs_are_refused,
    the_audits_deny_only_role_is_refused,
    a_heavy_role_still_answers_correctly,
    one_member_cannot_stack_heavy_roles,
);
