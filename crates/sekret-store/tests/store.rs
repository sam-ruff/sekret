use anyhow::Context;
use sekret_store::*;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

fn version(secret_id: &str, version: i64, value: &[u8], deleted: bool) -> SecretVersion {
    SecretVersion {
        secret_id: secret_id.into(),
        version,
        value: (!deleted).then(|| value.to_vec()),
        comment: format!("v{version}"),
        tags: vec!["t".into()],
        deleted,
        actor: "tester".into(),
        created_at: 100 + version,
        generated: version % 2 == 0,
    }
}

fn change(secret_id: &str, path: &str, key: &str, previous: i64, deleted: bool) -> SecretChange {
    SecretChange {
        secret_id: secret_id.into(),
        path: path.into(),
        key: key.into(),
        previous_version: previous,
        version: version(
            secret_id,
            previous + 1,
            format!("{key}-{}", previous + 1).as_bytes(),
            deleted,
        ),
    }
}

fn batch(snapshot: &str, changes: Vec<SecretChange>) -> WriteBatch {
    WriteBatch {
        project_id: "p1".into(),
        environment_id: "e1".into(),
        changes,
        snapshot_id: snapshot.into(),
        reason: "test".into(),
        actor: "tester".into(),
        now: 200,
    }
}

async fn seed_project(store: &SqlStore) -> anyhow::Result<()> {
    let project = Project {
        id: "p1".into(),
        slug: "app".into(),
        name: "App".into(),
        description: String::new(),
        wrapped_key: vec![1, 2, 3],
        created_at: 1,
        logo_updated_at: None,
        secret_policy: None,
    };
    let env = |id: &str, slug: &str, position| Environment {
        id: id.into(),
        project_id: "p1".into(),
        slug: slug.into(),
        name: slug.into(),
        position,
        created_at: 1,
    };
    store
        .create_project(project, vec![env("e1", "dev", 0), env("e2", "prod", 1)])
        .await
        .context("project")?;
    Ok(())
}

async fn exercise_projects_and_secrets(store: &SqlStore) -> anyhow::Result<()> {
    seed_project(store).await?;
    let logo = ProjectLogo {
        content_type: "image/png".into(),
        data: vec![0x89, b'P', b'N', b'G'],
    };
    store
        .set_project_logo("p1", Some(logo.clone()), 42)
        .await
        .context("logo")?;
    assert_eq!(store.get_project_logo("p1").await.context("get")?, Some(logo));
    assert_eq!(
        store
            .get_project("p1")
            .await
            .context("get")?
            .and_then(|p| p.logo_updated_at),
        Some(42)
    );
    store.set_project_logo("p1", None, 43).await.context("clear")?;
    assert_eq!(store.get_project_logo("p1").await.context("get")?, None);
    assert_eq!(
        store
            .get_project("p1")
            .await
            .context("get")?
            .and_then(|p| p.logo_updated_at),
        None
    );
    assert!(store.set_project_logo("missing", None, 1).await.is_err());
    assert_eq!(
        store.get_project("app").await.context("get")?.map(|p| p.id),
        Some("p1".into())
    );
    assert_eq!(
        store.get_project("p1").await.context("get")?.map(|p| p.wrapped_key),
        Some(vec![1, 2, 3])
    );
    let envs = store.list_environments("p1").await.context("envs")?;
    assert_eq!(
        envs.iter().map(|e| e.slug.as_str()).collect::<Vec<_>>(),
        ["dev", "prod"]
    );
    assert_eq!(store.list_folders("e1").await.context("folders")?.len(), 1);

    store
        .write_secrets(batch(
            "snap1",
            vec![
                change("s1", "/", "A", 0, false),
                change("s2", "/my_app", "B", 0, false),
                change("s3", "/myXapp", "C", 0, false),
            ],
        ))
        .await
        .context("write")?;

    // `_` must not behave as a LIKE wildcard when listing recursively.
    let nested = store.list_secrets("e1", "/my_app", true, false).await.context("list")?;
    assert_eq!(nested.iter().map(|s| s.secret.key.as_str()).collect::<Vec<_>>(), ["B"]);
    assert_eq!(
        store.list_secrets("e1", "/", true, false).await.context("all")?.len(),
        3
    );
    assert_eq!(
        store.list_secrets("e1", "/", false, false).await.context("root")?.len(),
        1
    );

    store
        .write_secrets(batch("snap2", vec![change("s1", "/", "A", 1, false)]))
        .await
        .context("update")?;
    let a = store
        .get_secret("e1", "/", "A")
        .await
        .context("get")?
        .context("exists")?;
    assert_eq!(a.secret.current_version, 2);
    assert_eq!(a.version.value.as_deref(), Some(&b"A-2"[..]));
    assert_eq!(a.version.tags, vec!["t".to_string()]);

    // A stale previous version is rejected and the whole batch is rolled back.
    let stale = store
        .write_secrets(batch(
            "snap3",
            vec![change("s2", "/my_app", "B", 1, false), change("s1", "/", "A", 1, false)],
        ))
        .await;
    assert!(matches!(stale, Err(StoreError::Conflict)));
    assert_eq!(
        store
            .get_secret_by_id("s2")
            .await
            .context("get")?
            .context("exists")?
            .secret
            .current_version,
        1
    );
    assert!(store.get_snapshot("snap3").await.context("snap")?.is_none());

    // Duplicate keys conflict.
    let duplicate = store
        .write_secrets(batch("snap4", vec![change("s9", "/", "A", 0, false)]))
        .await;
    assert!(matches!(duplicate, Err(StoreError::Conflict)));

    store
        .write_secrets(batch("snap5", vec![change("s3", "/myXapp", "C", 1, true)]))
        .await
        .context("delete")?;
    assert_eq!(
        store.list_secrets("e1", "/", true, false).await.context("live")?.len(),
        2
    );
    assert_eq!(
        store
            .list_secrets("e1", "/", true, true)
            .await
            .context("with deleted")?
            .len(),
        3
    );

    let versions = store.list_versions("s1").await.context("versions")?;
    assert_eq!(versions.iter().map(|v| v.version).collect::<Vec<_>>(), [2, 1]);
    assert_eq!(
        versions.iter().map(|v| v.generated).collect::<Vec<_>>(),
        [true, false],
        "the generated flag survives a round trip"
    );
    store
        .set_secret_policy("s1", Some(r#"{"mode":"inherit"}"#.into()))
        .await
        .context("policy")?;
    store
        .set_project_policy("p1", Some(r#"{"rotation_days":7}"#.into()))
        .await
        .context("project policy")?;
    assert_eq!(
        store
            .get_project("p1")
            .await
            .context("get")?
            .and_then(|p| p.secret_policy),
        Some(r#"{"rotation_days":7}"#.into())
    );
    assert!(store.set_secret_policy("missing", None).await.is_err());
    let with_policy = store.list_secrets("e1", "/", true, true).await.context("list")?;
    assert!(
        with_policy
            .iter()
            .any(|s| s.secret.id == "s1" && s.secret.policy.as_deref() == Some(r#"{"mode":"inherit"}"#))
    );
    assert_eq!(
        store.get_version("s1", 1).await.context("v1")?.map(|v| v.comment),
        Some("v1".into())
    );

    let snap = store.get_snapshot("snap5").await.context("snap")?.context("exists")?;
    let mut entries = snap.entries.clone();
    entries.sort_by(|a, b| a.secret_id.cmp(&b.secret_id));
    assert_eq!(
        entries,
        vec![
            SnapshotEntry {
                secret_id: "s1".into(),
                version: 2
            },
            SnapshotEntry {
                secret_id: "s2".into(),
                version: 1
            }
        ]
    );
    assert_eq!(store.list_snapshots("e1", 10).await.context("snaps")?.len(), 3);
    store.prune_snapshots("e1", 1).await.context("prune")?;
    assert_eq!(store.list_snapshots("e1", 10).await.context("snaps")?.len(), 1);

    store
        .create_folder(Folder {
            environment_id: "e1".into(),
            path: "/my_app".into(),
            created_at: 1,
        })
        .await
        .context("folder")?;
    assert!(matches!(
        store.delete_folder("e1", "/my_app").await,
        Err(StoreError::Conflict)
    ));

    store.delete_project("p1").await.context("delete project")?;
    assert!(store.get_project("p1").await.context("get")?.is_none());
    Ok(())
}

async fn exercise_identities_and_tokens(store: &SqlStore) -> anyhow::Result<()> {
    let identity = Identity {
        id: "i1".into(),
        name: "ci".into(),
        description: String::new(),
        token_ttl: 600,
        token_max_ttl: 3600,
        trusted_cidrs: vec!["10.0.0.0/8".into()],
        disabled: false,
        created_at: 1,
    };
    store.create_identity(identity.clone()).await.context("identity")?;
    assert!(matches!(
        store.create_identity(identity).await,
        Err(StoreError::Conflict)
    ));
    store
        .put_auth_method(AuthMethod {
            identity_id: "i1".into(),
            kind: "oidc".into(),
            config: serde_json::json!({"issuer": "https://x"}),
            created_at: 1,
        })
        .await
        .context("method")?;
    assert_eq!(store.list_auth_methods("i1").await.context("methods")?.len(), 1);

    let secret = ClientSecret {
        id: "c1".into(),
        identity_id: "i1".into(),
        description: String::new(),
        secret_hash: "h1".into(),
        prefix: "sks_ab".into(),
        created_at: 1,
        expires_at: None,
        uses_remaining: Some(1),
        revoked: false,
        last_used_at: None,
    };
    store.create_client_secret(secret).await.context("secret")?;
    assert!(store.consume_client_secret("c1", 5).await.context("consume")?);
    assert!(!store.consume_client_secret("c1", 6).await.context("exhausted")?);

    let token = AccessToken {
        id: "t1".into(),
        token_hash: "th".into(),
        kind: "machine".into(),
        principal_kind: PrincipalKind::Identity,
        principal_id: "i1".into(),
        description: String::new(),
        source: "client-secret:c1".into(),
        created_at: 1,
        expires_at: 10,
        max_expires_at: 20,
        revoked: false,
        last_used_at: None,
    };
    store
        .create_token(AccessToken {
            id: "t0".into(),
            token_hash: "th0".into(),
            ..token.clone()
        })
        .await
        .context("token")?;
    store
        .revoke_tokens_from_source("client-secret:c1")
        .await
        .context("revoke")?;
    assert!(
        store
            .find_token("th0")
            .await
            .context("find")?
            .is_some_and(|t| t.revoked)
    );
    store.create_token(token).await.context("token")?;
    assert_eq!(
        store.find_token("th").await.context("find")?.map(|t| t.principal_kind),
        Some(PrincipalKind::Identity)
    );
    store
        .revoke_principal_tokens(PrincipalKind::Identity, "i1")
        .await
        .context("revoke")?;
    assert!(store.find_token("th").await.context("find")?.context("exists")?.revoked);

    store.delete_identity("i1").await.context("delete")?;
    assert!(store.find_token("th").await.context("find")?.is_none());
    Ok(())
}

async fn exercise_logins_and_audit(store: &SqlStore) -> anyhow::Result<()> {
    let user = store
        .upsert_user(UserLogin {
            subject: "iss|u1".into(),
            email: "a@b".into(),
            name: "A".into(),
            groups: vec!["sekret-admin".into()],
            now: 1,
        })
        .await
        .context("user")?;
    let again = store
        .upsert_user(UserLogin {
            subject: "iss|u1".into(),
            email: "new@b".into(),
            name: "A".into(),
            groups: vec![],
            now: 2,
        })
        .await
        .context("user")?;
    assert_eq!(user.id, again.id);
    assert_eq!(again.email, "new@b");

    store
        .put_login_state(LoginState {
            state: "st".into(),
            nonce: "n".into(),
            pkce_verifier: "v".into(),
            return_to: "/".into(),
            created_at: 1,
        })
        .await
        .context("state")?;
    assert!(store.take_login_state("st").await.context("take")?.is_some());
    assert!(store.take_login_state("st").await.context("take twice")?.is_none());

    store
        .create_cli_login(CliLogin {
            device_code_hash: "dc".into(),
            user_code: "ABCD-EFGH".into(),
            created_at: 1,
            expires_at: 100,
            approved_user_id: None,
            consumed: false,
        })
        .await
        .context("cli")?;
    assert_eq!(store.poll_cli_login("dc", 2).await.context("poll")?, CliPoll::Pending);
    assert!(
        store
            .approve_cli_login("ABCD-EFGH", &user.id, 3)
            .await
            .context("approve")?
    );
    assert!(
        !store
            .approve_cli_login("ABCD-EFGH", "someone-else", 3)
            .await
            .context("approve twice")?
    );
    assert_eq!(
        store.poll_cli_login("dc", 4).await.context("poll")?,
        CliPoll::Approved(user.id.clone())
    );
    assert_eq!(store.poll_cli_login("dc", 5).await.context("poll")?, CliPoll::Gone);

    // id, time, actor, action, environment, path, key
    let rows = [
        (
            "a0",
            0,
            "Alice",
            "secret.read",
            Some("dev"),
            Some("/app"),
            Some("DB_URL"),
        ),
        (
            "a1",
            1,
            "Bob",
            "secret.write",
            Some("prod"),
            Some("/app/db"),
            Some("DB_PASS"),
        ),
        (
            "a2",
            2,
            "Alice",
            "secret.read",
            Some("prod"),
            Some("/web"),
            Some("API_KEY"),
        ),
        ("a3", 10, "ci_100%", "identity.update", None, None, None),
        (
            "a4",
            10,
            "Alice",
            "secret.delete",
            Some("dev"),
            Some("/app"),
            Some("OLD"),
        ),
    ];
    for (id, created_at, actor, action, environment, path, key) in rows {
        store
            .insert_audit(AuditEntry {
                id: id.into(),
                created_at,
                actor_kind: if actor.starts_with("ci") { "identity" } else { "user" }.into(),
                actor_id: actor.to_lowercase(),
                actor_name: actor.into(),
                action: action.into(),
                project_id: Some("p".into()),
                environment: environment.map(String::from),
                path: path.map(String::from),
                secret_key: key.map(String::from),
                detail: serde_json::json!({}),
                ip: "10.0.0.1".into(),
            })
            .await
            .context("audit")?;
    }
    let ids = |query: AuditQuery| async move {
        let entries = store
            .list_audit(AuditQuery { limit: 50, ..query })
            .await
            .context("audit")?;
        anyhow::Ok(entries.into_iter().map(|a| a.id).collect::<Vec<_>>())
    };
    let count = |query: AuditQuery| async move { store.count_audit(query).await.context("count") };

    let action = |a: &str| AuditQuery {
        action: Some(a.into()),
        ..Default::default()
    };
    assert_eq!(
        ids(action("secret.")).await?,
        ["a4", "a2", "a1", "a0"],
        "action is a prefix"
    );
    assert_eq!(count(action("secret.read")).await?, 2);
    let search = |s: &str| AuditQuery {
        search: Some(s.into()),
        ..Default::default()
    };
    assert_eq!(ids(search("alice")).await?, ["a4", "a2", "a0"], "search ignores case");
    assert_eq!(ids(search("db_")).await?, ["a1", "a0"], "underscore is literal");
    assert_eq!(ids(search("100%")).await?, ["a3"], "percent is literal");
    assert_eq!(ids(search("/app/db")).await?, ["a1"]);
    let scoped = AuditQuery {
        environment: Some("prod".into()),
        path: Some("/app".into()),
        ..Default::default()
    };
    assert_eq!(ids(scoped).await?, ["a1"], "environment and path prefix combine");
    let window = AuditQuery {
        since: Some(1),
        until: Some(2),
        ..Default::default()
    };
    assert_eq!(ids(window).await?, ["a2", "a1"]);
    let kind = AuditQuery {
        actor_kind: Some("identity".into()),
        ..Default::default()
    };
    assert_eq!(ids(kind).await?, ["a3"]);

    // Paging in both orders, through entries that share a timestamp.
    for oldest_first in [false, true] {
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let page = store
                .list_audit(AuditQuery {
                    project_id: Some("p".into()),
                    oldest_first,
                    after: after.clone(),
                    limit: 2,
                    ..Default::default()
                })
                .await
                .context("page")?;
            let Some(last) = page.last() else {
                break;
            };
            after = Some((last.created_at, last.id.clone()));
            seen.extend(page.into_iter().map(|a| a.id));
        }
        let mut expected = vec!["a0", "a1", "a2", "a3", "a4"];
        if !oldest_first {
            expected.reverse();
        }
        assert_eq!(seen, expected, "oldest_first = {oldest_first}");
    }
    Ok(())
}

async fn exercise(store: SqlStore) -> anyhow::Result<()> {
    exercise_projects_and_secrets(&store).await?;
    exercise_identities_and_tokens(&store).await?;
    exercise_logins_and_audit(&store).await?;
    Ok(())
}

#[tokio::test]
async fn sqlite_store() -> anyhow::Result<()> {
    exercise(SqlStore::connect("sqlite::memory:").await.context("connect")?).await
}

#[tokio::test]
async fn sqlite_file_store_reopens() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!("sekret-store-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).context("dir")?;
    let url = format!("sqlite://{}?mode=rwc", dir.join("db.sqlite").display());
    let store = SqlStore::connect(&url).await.context("connect")?;
    store.set_meta("k", "v").await.context("meta")?;
    drop(store);
    let reopened = SqlStore::connect(&url).await.context("reconnect")?;
    assert_eq!(reopened.get_meta("k").await.context("meta")?, Some("v".into()));
    std::fs::remove_dir_all(dir).ok();
    Ok(())
}

/// Needs Docker. Skipped with a message when it is unavailable unless SEKRET_REQUIRE_POSTGRES is set.
#[tokio::test]
async fn postgres_store() -> anyhow::Result<()> {
    let container = match Postgres::default().start().await {
        Ok(container) => container,
        Err(error) if std::env::var_os("SEKRET_REQUIRE_POSTGRES").is_none() => {
            eprintln!("skipping postgres test: {error}");
            return Ok(());
        }
        Err(error) => anyhow::bail!("postgres container failed: {error}"),
    };
    let port = container.get_host_port_ipv4(5432).await.context("port")?;
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    exercise(SqlStore::connect(&url).await.context("connect")?).await
}
