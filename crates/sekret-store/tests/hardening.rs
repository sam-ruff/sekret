//! Regressions from the first security audit: file permissions, re-encryption and the
//! backup-reader migration.

use anyhow::Context;
use sekret_store::*;

fn url(dir: &std::path::Path) -> String {
    format!("sqlite://{}?mode=rwc", dir.join("sekret.db").display())
}

async fn seed(store: &SqlStore) -> anyhow::Result<(String, String)> {
    let project = Project {
        id: "p1".into(),
        slug: "app".into(),
        name: "App".into(),
        description: String::new(),
        wrapped_key: vec![1; 57],
        created_at: 1,
        logo_updated_at: None,
        secret_policy: None,
    };
    let environment = Environment {
        id: "e1".into(),
        project_id: "p1".into(),
        slug: "dev".into(),
        name: "dev".into(),
        position: 0,
        created_at: 1,
    };
    store
        .create_project(project, vec![environment])
        .await
        .context("project")?;
    let mut changes = Vec::new();
    for version in 1..=2 {
        changes.push(SecretChange {
            secret_id: "s1".into(),
            path: "/".into(),
            key: "A".into(),
            previous_version: version - 1,
            version: SecretVersion {
                secret_id: "s1".into(),
                version,
                value: Some(vec![u8::try_from(version).context("byte")?; 40]),
                comment: String::new(),
                tags: vec![],
                deleted: false,
                generated: false,
                actor: "test".into(),
                created_at: version,
            },
        });
    }
    for change in changes {
        store
            .write_secrets(WriteBatch {
                project_id: "p1".into(),
                environment_id: "e1".into(),
                changes: vec![change],
                snapshot_id: uuid::Uuid::new_v4().to_string(),
                reason: "test".into(),
                actor: "test".into(),
                now: 5,
            })
            .await
            .context("write")?;
    }
    Ok(("p1".into(), "s1".into()))
}

#[tokio::test]
async fn every_value_is_listed_and_replaced_in_one_go() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let store = SqlStore::connect(&url(dir.path())).await.context("connect")?;
    let (project, secret) = seed(&store).await?;
    let values = store.list_encrypted_values(&project).await.context("list")?;
    assert_eq!(values.iter().map(|v| v.version).collect::<Vec<_>>(), vec![1, 2]);
    assert!(values.iter().all(|v| v.secret_id == secret));
    let replaced: Vec<EncryptedValue> = values
        .iter()
        .map(|v| EncryptedValue {
            value: vec![9; 41],
            ..v.clone()
        })
        .collect();
    store
        .replace_wrapped_keys(Rekey {
            keys: vec![(project.clone(), vec![7; 57])],
            values: replaced.clone(),
            fingerprint: "fp-new".into(),
            ..Rekey::default()
        })
        .await
        .context("replace")?;
    assert_eq!(store.list_encrypted_values(&project).await.context("list")?, replaced);
    let stored = store.get_project("app").await.context("get")?.context("project")?;
    assert_eq!(stored.wrapped_key, vec![7; 57]);
    assert_eq!(
        store.get_meta("root_key_fingerprint").await.context("meta")?,
        Some("fp-new".into())
    );

    // A value that vanished in between fails the whole swap, leaving the old keys in place.
    let missing = EncryptedValue {
        secret_id: "gone".into(),
        version: 1,
        value: vec![1],
    };
    let result = store
        .replace_wrapped_keys(Rekey {
            keys: vec![(project.clone(), vec![3; 57])],
            values: vec![missing],
            fingerprint: "fp-other".into(),
            ..Rekey::default()
        })
        .await;
    assert!(matches!(result, Err(StoreError::Conflict)));
    let stored = store.get_project("app").await.context("get")?.context("project")?;
    assert_eq!(stored.wrapped_key, vec![7; 57]);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn the_database_and_its_wal_are_owner_only() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().context("dir")?;
    let store = SqlStore::connect(&url(dir.path())).await.context("connect")?;
    store.set_meta("k", "v").await.context("meta")?;
    for name in ["sekret.db", "sekret.db-wal", "sekret.db-shm"] {
        let path = dir.path().join(name);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        assert_eq!(meta.permissions().mode() & 0o077, 0, "{name}");
    }
    drop(store);

    // An existing database readable by others is tightened on the next start.
    let loose = dir.path().join("sekret.db");
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).context("chmod")?;
    let store = SqlStore::connect(&url(dir.path())).await.context("reconnect")?;
    assert_eq!(
        std::fs::metadata(&loose).context("meta")?.permissions().mode() & 0o777,
        0o600
    );
    drop(store);
    Ok(())
}

#[tokio::test]
async fn only_one_process_holds_a_database_at_a_time() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let database = url(dir.path());
    let held = InstanceLock::acquire(&database).await.context("first")?;
    let refused = InstanceLock::acquire(&database).await;
    assert!(refused.as_ref().is_err_and(InstanceLock::is_held_error), "{refused:?}");
    drop(held);
    InstanceLock::acquire(&database).await.context("after release")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(lock_file(&dir.path().join("sekret.db")))
            .context("lock file")?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(matches!(
        InstanceLock::acquire("sqlite::memory:").await,
        Ok(InstanceLock::Private)
    ));
    Ok(())
}

/// Before the fix, a custom role at the built-in slug stayed there when `backup-reader-custom`
/// was already taken, silently shadowed by the built-in role.
#[tokio::test]
async fn a_custom_backup_reader_role_moves_to_a_free_slug_whatever_is_taken() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let database = url(dir.path());
    let store = SqlStore::connect(&database).await.context("store")?;
    for (id, slug) in [
        ("r1", "backup-reader-custom"),
        ("r2", "backup-reader-custom-2"),
        ("r3", "backup-reader"),
    ] {
        store
            .upsert_role(Role {
                id: id.into(),
                project_id: String::new(),
                slug: slug.into(),
                name: slug.into(),
                description: String::new(),
                rules: vec![],
                created_at: 1,
            })
            .await
            .context("role")?;
    }
    store
        .add_org_binding(Binding {
            principal_kind: PrincipalKind::User,
            principal_id: "u1".into(),
            role_slug: "backup-reader".into(),
            created_at: 1,
        })
        .await
        .context("binding")?;
    drop(store);
    let store = SqlStore::connect(&database).await.context("restart")?;
    let mut slugs: Vec<String> = store
        .list_roles("")
        .await
        .context("roles")?
        .into_iter()
        .map(|r| r.slug)
        .collect();
    slugs.sort();
    assert_eq!(
        slugs,
        vec![
            "backup-reader-custom",
            "backup-reader-custom-2",
            "backup-reader-custom-3"
        ]
    );
    let bindings = store.list_org_bindings().await.context("bindings")?;
    assert_eq!(
        bindings.iter().map(|b| b.role_slug.as_str()).collect::<Vec<_>>(),
        vec!["backup-reader-custom-3"]
    );
    Ok(())
}

#[tokio::test]
async fn a_custom_backup_reader_role_is_renamed() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let migrations = dir.path().join("migrations");
    std::fs::create_dir(&migrations).context("mkdir")?;
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite");
    for entry in std::fs::read_dir(&source).context("read migrations")? {
        let entry = entry.context("entry")?;
        let name = entry.file_name();
        if name.to_string_lossy().as_ref() < "0006" {
            std::fs::copy(entry.path(), migrations.join(&name)).context("copy")?;
        }
    }
    let database = url(dir.path());
    {
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(&database).await.context("pool")?;
        sqlx::migrate::Migrator::new(migrations.as_path())
            .await
            .context("migrator")?
            .run(&pool)
            .await
            .context("old migrations")?;
        sqlx::query(
            "INSERT INTO roles (id, project_id, slug, name, description, rules, created_at) \
             VALUES ('r1', '', 'backup-reader', 'Mine', '', '[]', 1)",
        )
        .execute(&pool)
        .await
        .context("role")?;
        sqlx::query(
            "INSERT INTO org_bindings (principal_kind, principal_id, role_slug, created_at) \
             VALUES ('user', 'u1', 'backup-reader', 1)",
        )
        .execute(&pool)
        .await
        .context("binding")?;
        pool.close().await;
    }
    let store = SqlStore::connect(&database).await.context("upgrade")?;
    let roles = store.list_roles("").await.context("roles")?;
    assert_eq!(
        roles.iter().map(|r| r.slug.as_str()).collect::<Vec<_>>(),
        vec!["backup-reader-custom"]
    );
    let bindings = store.list_org_bindings().await.context("bindings")?;
    assert_eq!(
        bindings.iter().map(|b| b.role_slug.as_str()).collect::<Vec<_>>(),
        vec!["backup-reader-custom"]
    );
    Ok(())
}
