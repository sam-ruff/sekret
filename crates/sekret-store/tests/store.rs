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
        restricted: false,
        access_epoch: 0,
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
        secret_access: false,
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

    let versions = store.list_versions("s1", None, 100).await.context("versions")?;
    assert_eq!(versions.iter().map(|v| v.version).collect::<Vec<_>>(), [2, 1]);
    let newest = store.list_versions("s1", None, 1).await.context("first page")?;
    assert_eq!(newest.iter().map(|v| v.version).collect::<Vec<_>>(), [2]);
    let older = store.list_versions("s1", Some(2), 1).await.context("next page")?;
    assert_eq!(older.iter().map(|v| v.version).collect::<Vec<_>>(), [1]);
    assert!(
        store
            .list_versions("s1", Some(1), 1)
            .await
            .context("past the end")?
            .is_empty()
    );
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
            mac: None,
        })
        .await
        .context("method")?;
    assert_eq!(store.list_auth_methods("i1").await.context("methods")?.len(), 1);
    assert_eq!(store.list_unsigned_auth_methods().await.context("unsigned")?.len(), 1);
    let method = store
        .get_auth_method("i1", "oidc")
        .await
        .context("get")?
        .context("method")?;
    store
        .put_auth_method(AuthMethod {
            mac: Some("m1".into()),
            ..method
        })
        .await
        .context("sign")?;
    assert_eq!(
        store
            .get_auth_method("i1", "oidc")
            .await
            .context("get")?
            .and_then(|m| m.mac),
        Some("m1".into())
    );
    assert!(store.list_unsigned_auth_methods().await.context("unsigned")?.is_empty());

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
        mac: None,
    };
    store.create_client_secret(secret).await.context("secret")?;
    assert_eq!(store.list_unsigned_client_secrets().await.context("unsigned")?.len(), 1);
    store.set_client_secret_mac("c1", "legacy").await.context("mac")?;
    assert!(
        store
            .list_unsigned_client_secrets()
            .await
            .context("unsigned")?
            .is_empty()
    );
    assert!(
        !store
            .rekey_client_secret("c1", "not-h1", "h2", "m2")
            .await
            .context("rekey")?,
        "only from the hash it is stored under"
    );
    assert!(
        store
            .rekey_client_secret("c1", "h1", "h2", "m2")
            .await
            .context("rekey")?
    );
    assert!(store.find_client_secret("h1").await.context("find")?.is_none());
    assert_eq!(
        store
            .find_client_secret("h2")
            .await
            .context("find")?
            .and_then(|s| s.mac),
        Some("m2".into())
    );
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
        auth_time: Some(1),
        mac: Some("m".into()),
        sealed_hash: Some("plain".into()),
    };
    store
        .create_token(AccessToken {
            id: "t0".into(),
            token_hash: "th0".into(),
            mac: None,
            sealed_hash: Some("plain0".into()),
            ..token.clone()
        })
        .await
        .context("token")?;
    let unsigned = store.list_unsigned_tokens().await.context("unsigned")?;
    assert_eq!(unsigned.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), ["t0"]);
    store.set_token_mac("t0", "legacy").await.context("mac")?;
    assert!(store.rekey_token("t0", "th0", "th0-new", "m0").await.context("rekey")?);
    assert!(
        !store
            .rekey_token("t0", "th0", "th0-again", "m0")
            .await
            .context("rekey twice")?
    );
    let moved = store.find_token("th0-new").await.context("find")?.context("moved")?;
    assert_eq!(moved.mac.as_deref(), Some("m0"));
    assert_eq!(
        store.find_sealed_token("plain0").await.context("sealed")?.map(|t| t.id),
        Some("t0".into()),
        "moving the lookup keeps the plain hash"
    );
    store.rekey_token("t0", "th0-new", "th0", "m0").await.context("back")?;
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
    assert!(
        store.list_unsigned_tokens().await.context("unsigned")?.is_empty(),
        "revoked or signed"
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
            max_age: Some(900),
        })
        .await
        .context("state")?;
    assert_eq!(
        store
            .take_login_state("st")
            .await
            .context("take")?
            .and_then(|s| s.max_age),
        Some(900)
    );
    assert!(store.take_login_state("st").await.context("take twice")?.is_none());

    store
        .create_cli_login(CliLogin {
            device_code_hash: "dc".into(),
            user_code: "ABCD-EFGH".into(),
            created_at: 1,
            expires_at: 100,
            approved_user_id: None,
            consumed: false,
            requested_from_ip: "203.0.113.9".into(),
            user_agent: "sekret/1.0".into(),
        })
        .await
        .context("cli")?;
    let pending = store
        .get_cli_login("ABCD-EFGH", 2)
        .await
        .context("pending")?
        .context("found")?;
    assert_eq!(
        (pending.requested_from_ip.as_str(), pending.user_agent.as_str()),
        ("203.0.113.9", "sekret/1.0")
    );
    assert_eq!(store.poll_cli_login("dc", 2).await.context("poll")?, CliPoll::Pending);
    assert!(
        store
            .approve_cli_login("ABCD-EFGH", &user.id, 3, "approval")
            .await
            .context("approve")?
    );
    assert!(
        !store
            .approve_cli_login("ABCD-EFGH", "someone-else", 3, "other")
            .await
            .context("approve twice")?
    );
    assert_eq!(
        store.poll_cli_login("dc", 4).await.context("poll")?,
        CliPoll::Approved {
            user_id: user.id.clone(),
            mac: Some("approval".into())
        }
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
                restricted: key == Some("DB_PASS"),
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
    let actors_only = |s: &str| AuditQuery {
        search: Some(s.into()),
        search_actors_only: true,
        ..Default::default()
    };
    assert_eq!(ids(actors_only("alice")).await?, ["a4", "a2", "a0"]);
    assert_eq!(ids(actors_only("secret.delete")).await?, ["a4"]);
    assert_eq!(ids(actors_only("10.0.0")).await?.len(), 5, "the address is searched");
    for hidden in ["/app/db", "API_KEY", "prod"] {
        assert!(
            ids(actors_only(hidden)).await?.is_empty(),
            "{hidden} is not searched when only actors are"
        );
        assert_eq!(count(actors_only(hidden)).await?, 0);
    }
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

    // a1 is about a restricted secret; a5 changes its access list.
    store
        .insert_audit(AuditEntry {
            id: "a5".into(),
            created_at: 11,
            actor_kind: "user".into(),
            actor_id: "admin".into(),
            actor_name: "Admin".into(),
            action: "secret.access".into(),
            project_id: Some("p".into()),
            environment: Some("prod".into()),
            path: Some("/app/db".into()),
            secret_key: Some("DB_PASS".into()),
            detail: serde_json::json!({}),
            ip: "10.0.0.1".into(),
            restricted: true,
        })
        .await
        .context("access entry")?;
    let visible = |list: Option<Vec<(&str, &str, &str)>>| AuditQuery {
        restricted_visible: list.map(|l| {
            l.into_iter()
                .map(|(e, p, k)| (e.to_string(), p.to_string(), k.to_string()))
                .collect()
        }),
        limit: 50,
        oldest_first: true,
        ..Default::default()
    };
    let restricted_ids = |query: AuditQuery| async move {
        let entries = store.list_audit(query.clone()).await.context("audit")?;
        let total = store.count_audit(query).await.context("count")?;
        anyhow::Ok((entries.into_iter().map(|a| a.id).collect::<Vec<_>>(), total))
    };
    let named = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        restricted_ids(visible(None)).await?,
        (named(&["a0", "a1", "a2", "a3", "a4", "a5"]), 6),
        "an admin sees every entry"
    );
    assert_eq!(
        restricted_ids(visible(Some(vec![]))).await?,
        (named(&["a0", "a2", "a3", "a4"]), 4),
        "entries about restricted secrets are left out, and the total agrees"
    );
    assert_eq!(
        restricted_ids(visible(Some(vec![("prod", "/app/db", "DB_PASS")]))).await?,
        (named(&["a0", "a1", "a2", "a3", "a4"]), 5),
        "a listed reader sees the secret's entries but never its access-list changes"
    );
    assert_eq!(
        restricted_ids(visible(Some(vec![("dev", "/app/db", "DB_PASS")])))
            .await?
            .1,
        4,
        "the environment must match too"
    );
    Ok(())
}

fn seal_config(remembered: Option<Vec<u8>>) -> SealConfig {
    SealConfig {
        mode: sekret_core::seal::SealMode::Passphrase,
        wrapped: Some(sekret_core::seal::WrappedRootKey {
            salt: vec![1; 16],
            params: sekret_core::seal::KdfParams::default(),
            ciphertext: vec![2; 57],
        }),
        unlock_policy: sekret_core::seal::UnlockPolicy::Remember,
        remembered,
        epoch: 4,
        mac: Some(vec![6; 32]),
        flags: sekret_core::seal::SealFlags {
            reviewer_tokens_migrated: true,
            remember_secret: true,
            wrap_form_signed: true,
            credentials_keyed: true,
        },
        created_at: 10,
        updated_at: 10,
    }
}

async fn exercise_seal_config(store: &SqlStore) -> anyhow::Result<()> {
    assert_eq!(store.get_seal_config().await.context("get")?, None);
    assert!(matches!(
        store.update_seal_config(seal_config(None)).await,
        Err(StoreError::NotFound)
    ));
    store
        .init_seal_config(seal_config(Some(vec![3; 57])), "fp1")
        .await
        .context("init")?;
    assert_eq!(
        store.get_meta("root_key_fingerprint").await.context("meta")?,
        Some("fp1".into())
    );
    assert_eq!(
        store.get_seal_config().await.context("get")?,
        Some(seal_config(Some(vec![3; 57])))
    );
    assert!(matches!(
        store.init_seal_config(seal_config(None), "fp2").await,
        Err(StoreError::Conflict)
    ));
    let key_file = SealConfig {
        mode: sekret_core::seal::SealMode::KeyFile,
        wrapped: None,
        unlock_policy: sekret_core::seal::UnlockPolicy::Manual,
        remembered: None,
        epoch: 5,
        mac: None,
        flags: sekret_core::seal::SealFlags::default(),
        created_at: 10,
        updated_at: 20,
    };
    store.update_seal_config(key_file.clone()).await.context("update")?;
    assert_eq!(store.get_seal_config().await.context("get")?, Some(key_file));
    use sekret_core::seal::UnlockPolicy;
    for (policy, remembered) in [
        (UnlockPolicy::Remember, Some(vec![5; 57])),
        (UnlockPolicy::PassphraseFile, None),
        (UnlockPolicy::Manual, None),
    ] {
        let config = SealConfig {
            unlock_policy: policy,
            updated_at: 30,
            ..seal_config(remembered)
        };
        store.update_seal_config(config.clone()).await.context("policy")?;
        assert_eq!(
            store.get_seal_config().await.context("get")?,
            Some(config),
            "{policy:?}"
        );
    }
    assert_eq!(
        store.get_meta("root_key_fingerprint").await.context("meta")?,
        Some("fp1".into()),
        "updating the seal configuration leaves the fingerprint alone"
    );
    let integrity = sekret_store::INTEGRITY_KEY_META;
    assert!(store.insert_meta(integrity, "wrap-1").await.context("insert")?);
    assert!(
        !store.insert_meta(integrity, "wrap-2").await.context("insert again")?,
        "the first key stored wins"
    );
    assert_eq!(store.get_meta(integrity).await.context("meta")?, Some("wrap-1".into()));
    store
        .replace_wrapped_keys(Rekey {
            fingerprint: "fp3".into(),
            seal: Some(seal_config(Some(vec![4; 57]))),
            integrity_key: Some("wrap-3".into()),
            ..Rekey::default()
        })
        .await
        .context("replace")?;
    assert_eq!(
        store.get_meta("root_key_fingerprint").await.context("meta")?,
        Some("fp3".into())
    );
    assert_eq!(store.get_meta(integrity).await.context("meta")?, Some("wrap-3".into()));
    assert_eq!(
        store.get_seal_config().await.context("get")?,
        Some(seal_config(Some(vec![4; 57])))
    );
    Ok(())
}

/// A new integrity key revokes every token and client secret in the same transaction.
async fn exercise_revoking_credentials(store: &SqlStore) -> anyhow::Result<()> {
    store
        .create_identity(Identity {
            id: "i9".into(),
            name: "deploy".into(),
            description: String::new(),
            token_ttl: 600,
            token_max_ttl: 3600,
            trusted_cidrs: vec![],
            disabled: false,
            created_at: 1,
        })
        .await
        .context("identity")?;
    store
        .create_client_secret(ClientSecret {
            id: "c9".into(),
            identity_id: "i9".into(),
            description: String::new(),
            secret_hash: "h9".into(),
            prefix: "sks_cd".into(),
            created_at: 1,
            expires_at: None,
            uses_remaining: None,
            revoked: false,
            last_used_at: None,
            mac: Some("m".into()),
        })
        .await
        .context("secret")?;
    let token = AccessToken {
        id: "t9".into(),
        token_hash: "th9".into(),
        kind: "machine".into(),
        principal_kind: PrincipalKind::Identity,
        principal_id: "i9".into(),
        description: String::new(),
        source: String::new(),
        created_at: 1,
        expires_at: 4_000_000_000,
        max_expires_at: 4_000_000_000,
        revoked: false,
        last_used_at: None,
        auth_time: None,
        mac: Some("m".into()),
        sealed_hash: None,
    };
    store.create_token(token).await.context("token")?;
    let fingerprint = store.get_meta("root_key_fingerprint").await.context("meta")?;
    store
        .replace_wrapped_keys(Rekey {
            fingerprint: fingerprint.clone().unwrap_or_default(),
            ..Rekey::default()
        })
        .await
        .context("plain replace")?;
    assert!(!store.find_token("th9").await.context("find")?.context("token")?.revoked);
    assert!(
        !store
            .find_client_secret("h9")
            .await
            .context("find")?
            .context("secret")?
            .revoked
    );
    store
        .replace_wrapped_keys(Rekey {
            fingerprint: fingerprint.unwrap_or_default(),
            revoke_credentials: true,
            ..Rekey::default()
        })
        .await
        .context("revoking replace")?;
    assert!(store.find_token("th9").await.context("find")?.context("token")?.revoked);
    assert!(
        store
            .find_client_secret("h9")
            .await
            .context("find")?
            .context("secret")?
            .revoked
    );
    store.delete_identity("i9").await.context("delete")?;
    Ok(())
}

fn grant(secret_id: &str, kind: PrincipalKind, id: &str, actions: &[sekret_core::permissions::Action]) -> SecretGrant {
    SecretGrant {
        secret_id: secret_id.into(),
        principal_kind: kind,
        principal_id: id.into(),
        actions: actions.to_vec(),
        created_at: 7,
    }
}

async fn exercise_secret_access(store: &SqlStore) -> anyhow::Result<()> {
    use sekret_core::permissions::Action;
    seed_project(store).await?;
    let project = store.get_project("p1").await.context("get")?.context("project")?;
    assert!(!project.secret_access, "off by default");
    let restricted_new = SecretChange {
        restricted: true,
        ..change("r1", "/", "R", 0, false)
    };
    assert!(
        matches!(
            store.write_secrets(batch("a1", vec![restricted_new.clone()])).await,
            Err(StoreError::Conflict)
        ),
        "a secret cannot start restricted while the project setting is off"
    );
    assert!(store.get_secret_by_id("r1").await.context("get")?.is_none());
    store
        .write_secrets(batch("a2", vec![change("o1", "/", "OPEN", 0, false)]))
        .await
        .context("open")?;
    let restrict_open = AccessChange {
        secret_id: "o1".into(),
        restricted: Some(true),
        grant: vec![],
        revoke: vec![],
        max_grants: 100,
    };
    assert!(matches!(
        store.update_secret_access(restrict_open.clone()).await,
        Err(StoreError::Conflict)
    ));

    store.set_project_secret_access("p1", true).await.context("enable")?;
    assert!(
        store
            .get_project("p1")
            .await
            .context("get")?
            .context("project")?
            .secret_access
    );
    store
        .write_secrets(batch("a3", vec![restricted_new]))
        .await
        .context("restricted write")?;
    let r1 = store.get_secret_by_id("r1").await.context("get")?.context("r1")?;
    assert!(r1.secret.restricted);
    let o1 = store
        .get_secret("e1", "/", "OPEN")
        .await
        .context("get")?
        .context("o1")?;
    assert!(!o1.secret.restricted, "unrestricted by default");

    store
        .update_secret_access(AccessChange {
            grant: vec![
                grant("o1", PrincipalKind::Identity, "pod", &[Action::Read, Action::ReadValue]),
                grant("o1", PrincipalKind::Group, "ops", &[Action::Read]),
            ],
            ..restrict_open
        })
        .await
        .context("restrict and grant")?;
    assert!(
        store
            .get_secret_by_id("o1")
            .await
            .context("get")?
            .context("o1")?
            .secret
            .restricted
    );
    assert_eq!(store.count_restricted_secrets("p1").await.context("count")?, 2);
    let grants = store.list_secret_grants("o1").await.context("grants")?;
    assert_eq!(
        grants,
        vec![
            grant("o1", PrincipalKind::Group, "ops", &[Action::Read]),
            grant("o1", PrincipalKind::Identity, "pod", &[Action::Read, Action::ReadValue]),
        ]
    );
    // Granting again replaces the entry's actions; revoking removes it.
    store
        .update_secret_access(AccessChange {
            secret_id: "o1".into(),
            restricted: None,
            grant: vec![grant("o1", PrincipalKind::Identity, "pod", &[Action::Read])],
            revoke: vec![(PrincipalKind::Group, "ops".into())],
            max_grants: 100,
        })
        .await
        .context("regrant")?;
    assert_eq!(
        store.list_environment_grants("e1").await.context("env grants")?,
        vec![grant("o1", PrincipalKind::Identity, "pod", &[Action::Read])]
    );
    assert!(
        store
            .list_environment_grants("e2")
            .await
            .context("other env")?
            .is_empty()
    );
    let foreign = AccessChange {
        secret_id: "o1".into(),
        restricted: None,
        grant: vec![grant("r1", PrincipalKind::User, "u", &[Action::Read])],
        revoke: vec![],
        max_grants: 100,
    };
    assert!(store.update_secret_access(foreign).await.is_err());
    assert!(matches!(
        store
            .update_secret_access(AccessChange {
                secret_id: "missing".into(),
                restricted: Some(false),
                grant: vec![],
                revoke: vec![],
                max_grants: 100,
            })
            .await,
        Err(StoreError::NotFound)
    ));

    assert!(
        matches!(
            store.set_project_secret_access("p1", false).await,
            Err(StoreError::Conflict)
        ),
        "turning the setting off while secrets are restricted is refused"
    );
    assert!(
        store
            .get_project("p1")
            .await
            .context("get")?
            .context("project")?
            .secret_access
    );
    let current = store.environment_access("e1").await.context("environment access")?;
    assert_eq!(
        current.epochs,
        std::collections::HashMap::from([("o1".to_string(), 2), ("r1".to_string(), 0)]),
        "every restricted secret, listed or not"
    );
    assert_eq!(
        current.grants,
        vec![grant("o1", PrincipalKind::Identity, "pod", &[Action::Read])]
    );
    assert_eq!(
        store.environment_access("e2").await.context("other")?,
        EnvironmentAccess::default()
    );
    let snapshots = store.list_snapshots("e1", 10).await.context("snapshots")?;
    let newest = snapshots.first().context("newest")?;
    let previous = store.previous_snapshot(newest).await.context("previous")?;
    assert_eq!(previous.as_ref().map(|s| &s.id), snapshots.get(1).map(|s| &s.id));
    let oldest = snapshots.last().context("oldest")?;
    assert_eq!(store.previous_snapshot(oldest).await.context("none")?, None);

    // Every access change moves the epoch on, so a write planned before it is refused.
    let o1 = store.get_secret_by_id("o1").await.context("get")?.context("o1")?;
    assert_eq!(o1.secret.access_epoch, 2, "restricted and granted, then regranted");
    let stale = SecretChange {
        access_epoch: 1,
        ..change("o1", "/", "OPEN", 1, false)
    };
    assert!(matches!(
        store.write_secrets(batch("a4", vec![stale])).await,
        Err(StoreError::Conflict)
    ));
    let current = SecretChange {
        access_epoch: 2,
        ..change("o1", "/", "OPEN", 1, false)
    };
    store
        .write_secrets(batch("a5", vec![current]))
        .await
        .context("current epoch")?;
    assert_eq!(
        store
            .list_restricted_secrets("p1")
            .await
            .context("restricted")?
            .iter()
            .map(|s| (s.environment.as_str(), s.key.as_str()))
            .collect::<Vec<_>>(),
        [("dev", "OPEN"), ("dev", "R")]
    );
    assert_eq!(store.list_project_grants("p1").await.context("grants")?.len(), 1);

    // The cap is checked inside the transaction, and a refusal changes nothing.
    assert!(matches!(
        store
            .update_secret_access(AccessChange {
                secret_id: "o1".into(),
                restricted: None,
                grant: vec![grant("o1", PrincipalKind::Group, "extra", &[Action::Read])],
                revoke: vec![],
                max_grants: 1,
            })
            .await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(store.list_secret_grants("o1").await.context("grants")?.len(), 1);
    let mut cleared = Vec::new();
    for id in ["o1", "r1"] {
        cleared.extend(
            store
                .update_secret_access(AccessChange {
                    secret_id: id.into(),
                    restricted: Some(false),
                    grant: vec![],
                    revoke: vec![],
                    max_grants: 100,
                })
                .await
                .context("unrestrict")?,
        );
    }
    assert_eq!(
        cleared,
        vec![grant("o1", PrincipalKind::Identity, "pod", &[Action::Read])],
        "unrestricting reports what it cleared"
    );
    assert!(
        store.list_secret_grants("o1").await.context("grants")?.is_empty(),
        "unrestricting clears the list, so it cannot come back later"
    );
    assert!(
        store
            .list_restricted_secrets("p1")
            .await
            .context("restricted")?
            .is_empty()
    );
    store
        .update_secret_access(AccessChange {
            secret_id: "o1".into(),
            restricted: None,
            grant: vec![grant("o1", PrincipalKind::Group, "ops", &[Action::Read])],
            revoke: vec![],
            max_grants: 100,
        })
        .await
        .context("prepare a list on an open secret")?;
    store.set_project_secret_access("p1", false).await.context("disable")?;
    assert!(
        store.list_project_grants("p1").await.context("grants")?.is_empty(),
        "turning the setting off clears every list"
    );
    assert!(matches!(
        store.set_project_secret_access("missing", true).await,
        Err(StoreError::NotFound)
    ));
    store
        .set_project_secret_access("p1", true)
        .await
        .context("enable again")?;
    store
        .update_secret_access(AccessChange {
            secret_id: "o1".into(),
            restricted: None,
            grant: vec![grant("o1", PrincipalKind::Identity, "pod", &[Action::Read])],
            revoke: vec![],
            max_grants: 100,
        })
        .await
        .context("grant the identity")?;

    store
        .create_identity(Identity {
            id: "pod".into(),
            name: "pod".into(),
            description: String::new(),
            token_ttl: 60,
            token_max_ttl: 60,
            trusted_cidrs: vec![],
            disabled: false,
            created_at: 1,
        })
        .await
        .context("identity")?;
    store.delete_identity("pod").await.context("delete identity")?;
    assert!(
        store.list_secret_grants("o1").await.context("grants")?.is_empty(),
        "a deleted identity leaves no entries behind"
    );
    store
        .update_secret_access(AccessChange {
            secret_id: "o1".into(),
            restricted: None,
            grant: vec![grant("o1", PrincipalKind::User, "u1", &[Action::Read])],
            revoke: vec![],
            max_grants: 100,
        })
        .await
        .context("grant")?;
    store.delete_project("p1").await.context("delete project")?;
    assert!(store.list_environment_grants("e1").await.context("grants")?.is_empty());
    Ok(())
}

async fn exercise(store: SqlStore) -> anyhow::Result<()> {
    exercise_projects_and_secrets(&store).await?;
    exercise_secret_access(&store).await?;
    exercise_identities_and_tokens(&store).await?;
    exercise_logins_and_audit(&store).await?;
    exercise_seal_config(&store).await?;
    exercise_revoking_credentials(&store).await?;
    Ok(())
}

#[tokio::test]
async fn sqlite_snapshot_drops_the_remembered_unlock() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let store = SqlStore::connect(&format!("sqlite://{}?mode=rwc", dir.path().join("live.db").display()))
        .await
        .context("connect")?;
    store
        .init_seal_config(seal_config(Some(vec![9; 57])), "fp")
        .await
        .context("init")?;
    seed_project(&store).await?;
    let copy = dir.path().join("copy.db");
    let rewritten = SealConfig {
        mac: Some(vec![8; 32]),
        ..seal_config(None)
    };
    store
        .snapshot_to(&copy.display().to_string(), rewritten.clone())
        .await
        .context("snapshot")?;
    let raw = std::fs::read(&copy).context("read")?;
    assert!(raw.starts_with(b"SQLite format 3\0"));
    assert!(!raw.windows(57).any(|w| w == [9u8; 57].as_slice()));
    let reopened = SqlStore::connect(&format!("sqlite://{}", copy.display()))
        .await
        .context("reopen")?;
    let config = reopened.get_seal_config().await.context("get")?.context("config")?;
    assert_eq!(config, rewritten);
    assert_eq!(config.wrapped, seal_config(None).wrapped);
    assert!(reopened.get_project("app").await.context("project")?.is_some());
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
    let store = SqlStore::connect(&url).await.context("connect")?;
    assert!(matches!(
        store.snapshot_to("/tmp/never-written.db", seal_config(None)).await,
        Err(StoreError::Unsupported(_))
    ));
    // One server or admin command per database, through an advisory lock.
    let mut held = InstanceLock::acquire(&url).await.context("lock")?;
    held.check().await.context("the advisory lock is seen as held")?;
    assert!(
        InstanceLock::acquire(&url)
            .await
            .is_err_and(|e| InstanceLock::is_held_error(&e))
    );
    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let again = InstanceLock::acquire(&url).await.context("lock after release")?;
    drop(again);
    exercise(store).await?;
    replacing_keys_rewrites_the_tables_on_postgres(&url).await
}

/// The table files that held old wraps and ciphertexts are replaced, so their dead rows go too.
async fn replacing_keys_rewrites_the_tables_on_postgres(url: &str) -> anyhow::Result<()> {
    use sqlx::Row;
    let pool = sqlx::PgPool::connect(url).await.context("pool")?;
    let filenodes = || async {
        let mut nodes = Vec::new();
        for table in ["seal_config", "projects", "secret_versions", "identity_auth_methods"] {
            let row = sqlx::query("SELECT pg_relation_filenode($1::regclass)::bigint")
                .bind(table)
                .fetch_one(&pool)
                .await
                .context("filenode")?;
            nodes.push(row.try_get::<i64, _>(0).context("node")?);
        }
        anyhow::Ok(nodes)
    };
    let store = SqlStore::connect(url).await.context("connect")?;
    let before = filenodes().await?;
    store.update_seal_config(seal_config(None)).await.context("update")?;
    let after_update = filenodes().await?;
    assert_ne!(before[0], after_update[0], "seal_config is rewritten on every change");
    assert_eq!(before[1..], after_update[1..], "the rest only when keys are replaced");
    store
        .replace_wrapped_keys(Rekey {
            fingerprint: "fp4".into(),
            seal: Some(seal_config(None)),
            ..Rekey::default()
        })
        .await
        .context("replace")?;
    let after_rekey = filenodes().await?;
    for (table, (old, new)) in after_update.iter().zip(&after_rekey).enumerate() {
        assert_ne!(old, new, "table {table} was rewritten");
    }
    Ok(())
}
