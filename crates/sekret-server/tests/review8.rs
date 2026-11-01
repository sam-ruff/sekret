//! Regressions for the eighth security audit's server findings: identity token lifetimes, role
//! and binding conditions, text limits, junk tokens, backup limits and short body deadlines on
//! the open routes.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use common::{Harness, Options, options, start};
use reqwest::{Method, StatusCode};
use sekret_server::BodyTimeouts;
use sekret_server::clock::FixedClock;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Lowering an identity's lifetimes shortens tokens already issued, renewed or not.
async fn lowered_lifetimes_apply_to_issued_tokens(db: String) -> anyhow::Result<()> {
    let clock = Arc::new(FixedClock::new(1_800_000_000));
    let h = start(Options {
        database_url: db,
        clock: Some(clock.clone()),
        ..Options::default()
    })
    .await?;
    h.create_project("app").await?;
    let (id, token) = h.machine("ci", "app", "viewer").await?;
    let identity = format!("/api/v1/identities/{id}");
    let update = |ttl: i64, max: i64| json!({"name": "ci", "token_ttl": ttl, "token_max_ttl": max});
    clock.advance(30);
    let (status, body) = h.patch(&identity, &h.admin, update(60, 120)).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.get("/api/v1/me", &token).await?;
    assert_eq!(status, StatusCode::OK, "still inside the new lifetime");
    // Raising them again does not give back what was taken.
    let (status, _) = h.patch(&identity, &h.admin, update(3600, 86_400)).await?;
    assert_eq!(status, StatusCode::OK);
    clock.advance(61);
    let (status, _) = h.get("/api/v1/me", &token).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "never renewed, yet cut short");

    // The maximum counts from when the token was minted, not from the change.
    let (id, token) = h.machine("deploy", "app", "viewer").await?;
    let identity = format!("/api/v1/identities/{id}");
    clock.advance(100);
    let (status, _) = h
        .patch(
            &identity,
            &h.admin,
            json!({"name": "deploy", "token_ttl": 60, "token_max_ttl": 120}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    clock.advance(21);
    let (status, _) = h.get("/api/v1/me", &token).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "past token_max_ttl since it was minted"
    );
    Ok(())
}

/// Environment and tag conditions match exactly, so values that could never match are refused.
async fn role_conditions_must_be_able_to_match(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let role = |conditions: Value| {
        json!({"name": "Ops", "rules": [
            {"effect": "allow", "subject": "secrets", "actions": ["read"]},
            {"effect": "deny", "subject": "secrets", "actions": ["read-value"], "conditions": conditions}
        ]})
    };
    for bad in [
        json!({"environments": ["prod*"]}),
        json!({"environments": ["Prod"]}),
        json!({"tags": ["Restricted"]}),
        json!({"tags": ["*"]}),
    ] {
        let (status, body) = h
            .put("/api/v1/projects/app/roles/ops", &h.admin, role(bad.clone()))
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    let good = role(json!({"environments": ["prod"], "tags": ["restricted"], "paths": ["/payments/**"]}));
    let (status, body) = h.put("/api/v1/projects/app/roles/ops", &h.admin, good).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// Comments and descriptions are bounded wherever they are written.
async fn comments_and_descriptions_are_bounded(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    h.create_project("app").await?;
    let comment = "c".repeat(1025);
    let description = "d".repeat(4097);
    let secret = "/api/v1/projects/app/environments/dev/secrets/K";
    let (status, body) = h
        .put(secret, &h.admin, json!({"value": "v", "comment": comment}))
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = h
        .post(&format!("{secret}/generate"), &h.admin, json!({"comment": comment}))
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .put(secret, &h.admin, json!({"value": "v", "comment": "c".repeat(1024)}))
        .await?;
    assert_eq!(status, StatusCode::OK, "the limit itself is fine");

    let (_, identity) = h.post("/api/v1/identities", &h.admin, json!({"name": "ci"})).await?;
    let id = identity["id"].as_str().context("id")?;
    let refused = [
        (
            Method::POST,
            "/api/v1/projects".to_string(),
            json!({"slug": "other", "name": "Other", "description": description}),
        ),
        (
            Method::PATCH,
            "/api/v1/projects/app".to_string(),
            json!({"name": "App", "description": description}),
        ),
        (
            Method::PUT,
            "/api/v1/projects/app/roles/ops".to_string(),
            json!({"name": "Ops", "description": description, "rules": []}),
        ),
        (
            Method::POST,
            "/api/v1/identities".to_string(),
            json!({"name": "big", "description": description}),
        ),
        (
            Method::PATCH,
            format!("/api/v1/identities/{id}"),
            json!({"name": "ci", "description": description, "token_ttl": 3600, "token_max_ttl": 86400}),
        ),
        (
            Method::POST,
            format!("/api/v1/identities/{id}/client-secrets"),
            json!({"description": description}),
        ),
    ];
    for (method, url, body) in refused {
        let (status, answer) = h.call(method.clone(), &url, Some(&h.admin), Some(body)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {url}: {answer}");
    }
    let (status, body) = h
        .patch(
            "/api/v1/projects/app",
            &h.admin,
            json!({"name": "App", "description": "d".repeat(4096)}),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// The last organisation admin binding cannot be removed until someone else holds the role.
async fn the_last_org_admin_cannot_be_removed(db: String) -> anyhow::Result<()> {
    let h = start(options(db)).await?;
    let admins = |bindings: &Value| -> Vec<(String, String)> {
        bindings
            .as_array()
            .into_iter()
            .flatten()
            .filter(|b| b["role"] == "org-admin")
            .map(|b| {
                (
                    b["principal_kind"].as_str().unwrap_or_default().to_string(),
                    b["principal_id"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };
    let (_, bindings) = h.get("/api/v1/org/bindings", &h.admin).await?;
    let held = admins(&bindings);
    let (last, rest) = held.split_last().context("an admin binding")?;
    for (kind, id) in rest {
        let (status, body) = h
            .delete(&format!("/api/v1/org/bindings/{kind}/{id}/org-admin"), &h.admin)
            .await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }
    let only = format!("/api/v1/org/bindings/{}/{}/org-admin", last.0, last.1);
    let (status, body) = h.delete(&only, &h.admin).await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("last_org_admin"))
    );

    h.org_identity_as("deputy", "org-admin", &h.admin).await?;
    let (status, body) = h.delete(&only, &h.admin).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    Ok(())
}

on_both_backends!(
    the_last_org_admin_cannot_be_removed,
    lowered_lifetimes_apply_to_issued_tokens,
    role_conditions_must_be_able_to_match,
    comments_and_descriptions_are_bounded,
);

const JUNK: &str = "skt_0000000000000000000000000000000000000000000";

/// Limits live in memory, so one backend is enough.
#[tokio::test]
async fn junk_tokens_are_turned_away_without_a_lookup() -> anyhow::Result<()> {
    let h = start(options(common::SQLITE.into())).await?;
    let mut failures = 0;
    let mut refused = None;
    // The allowance refills once a second, so allow for a slow runner before the refusal.
    for _ in 0..5 * sekret_server::FAILED_AUTH_PER_MINUTE {
        let (status, body) = h.get("/api/v1/projects", JUNK).await?;
        if status != StatusCode::UNAUTHORIZED {
            refused = Some((status, body["error"].clone()));
            break;
        }
        failures += 1;
    }
    assert_eq!(refused, Some((StatusCode::TOO_MANY_REQUESTS, json!("rate_limited"))));
    assert!(failures >= sekret_server::FAILED_AUTH_PER_MINUTE, "{failures}");
    let (status, _) = h.call(Method::GET, "/api/v1/sys/status", None, None).await?;
    assert_eq!(status, StatusCode::OK, "requests without a credential are unaffected");
    let (status, _) = h.call(Method::GET, "/api/v1/auth/config", None, None).await?;
    assert_eq!(status, StatusCode::OK, "signing in again is never blocked");
    Ok(())
}

#[tokio::test]
async fn valid_tokens_do_not_use_up_the_allowance() -> anyhow::Result<()> {
    let h = start(options(common::SQLITE.into())).await?;
    for _ in 0..2 * sekret_server::FAILED_AUTH_PER_MINUTE {
        let (status, _) = h.get("/api/v1/projects", &h.admin).await?;
        assert_eq!(status, StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn backups_are_limited_per_caller() -> anyhow::Result<()> {
    let h = start(options(common::SQLITE.into())).await?;
    let (_, me) = h.get("/api/v1/me", &h.admin).await?;
    let id = me["id"].as_str().context("id")?.to_string();
    while h.state.backup_limiter.allow(&id) {}
    let (status, body) = h.post("/api/v1/sys/backup", &h.admin, json!({})).await?;
    assert_eq!(
        (status, &body["error"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("rate_limited"))
    );
    assert!(
        h.state.backup_limiter.allow(&"someone-else".to_string()),
        "other callers keep their own allowance"
    );
    Ok(())
}

/// Sends `head`, then a body byte every 200 ms, never finishing, and returns how long the server
/// let that go on.
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
    let cut = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::select! {
            () = drip => {},
            () = answered => {},
        }
    })
    .await;
    anyhow::ensure!(cut.is_ok(), "the trickling body was never cut off");
    Ok(started.elapsed())
}

/// The sign-in and system routes take tiny bodies from anyone, so a trickle there is cut off
/// long before the general body deadline.
#[tokio::test]
async fn open_routes_have_a_short_body_deadline() -> anyhow::Result<()> {
    let timeouts = BodyTimeouts {
        gap: Duration::from_secs(10),
        total: Duration::from_secs(40),
        open: Duration::from_secs(1),
    };
    let h = start(Options {
        body_timeouts: timeouts,
        ..Options::default()
    })
    .await?;
    for route in ["/api/v1/sys/unseal", "/api/v1/auth/universal/login"] {
        let head = format!(
            "POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: 16000\r\n\r\n{{\"x\":"
        );
        let held = trickle(&h, head).await?;
        // Generous, as CI is slow; the general deadline would take 40 s.
        assert!(held < Duration::from_secs(20), "{route} held for {held:?}");
    }
    Ok(())
}

#[test]
fn open_routes_get_a_few_seconds_by_default() {
    let defaults = BodyTimeouts::default();
    assert!(defaults.open <= Duration::from_secs(10), "{defaults:?}");
    assert!(defaults.open < defaults.total);
}
