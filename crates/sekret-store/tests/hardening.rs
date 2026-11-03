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
        secret_access: false,
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
            restricted: false,
            access_epoch: 0,
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

/// The demonstrated attack reached a locked database through a symlink, whose `.lock` sidecar
/// was a different file. Every name for the database now meets the same lock.
#[cfg(unix)]
#[tokio::test]
async fn the_lock_follows_the_database_through_symlinks_and_hard_links() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let held = InstanceLock::acquire(&url(dir.path())).await.context("first")?;
    assert!(
        dir.path().join("sekret.db").exists(),
        "the lock creates the file it locks"
    );
    let other = tempfile::tempdir().context("other")?;
    std::os::unix::fs::symlink(dir.path().join("sekret.db"), other.path().join("link.db")).context("symlink")?;
    std::os::unix::fs::symlink(dir.path(), other.path().join("linked-dir")).context("dir symlink")?;
    std::fs::hard_link(dir.path().join("sekret.db"), dir.path().join("hard.db")).context("hard link")?;
    for name in [
        other.path().join("link.db"),
        other.path().join("linked-dir").join("sekret.db"),
        dir.path().join("hard.db"),
    ] {
        let refused = InstanceLock::acquire(&format!("sqlite://{}?mode=rw", name.display())).await;
        assert!(
            refused.as_ref().is_err_and(InstanceLock::is_held_error),
            "{}: {refused:?}",
            name.display()
        );
    }
    drop(held);
    InstanceLock::acquire(&format!("sqlite://{}", other.path().join("link.db").display()))
        .await
        .context("free once released")?;
    Ok(())
}

#[tokio::test]
async fn a_waiting_lock_is_taken_once_released_or_refused_after_the_wait() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let database = url(dir.path());
    let held = InstanceLock::acquire(&database).await.context("first")?;
    let started = std::time::Instant::now();
    let refused = InstanceLock::acquire_within(&database, std::time::Duration::from_secs(1)).await;
    assert!(refused.as_ref().is_err_and(InstanceLock::is_held_error), "{refused:?}");
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    let release = async move {
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        drop(held);
    };
    let (taken, ()) = tokio::join!(
        InstanceLock::acquire_within(&database, std::time::Duration::from_secs(10)),
        release
    );
    let mut taken = taken.context("taken after release")?;
    taken.check().await.context("still held")?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_replaced_database_file_counts_as_a_lost_lock() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let mut held = InstanceLock::acquire(&url(dir.path())).await.context("lock")?;
    held.check().await.context("held")?;
    std::fs::rename(dir.path().join("sekret.db"), dir.path().join("moved.db")).context("move")?;
    std::fs::write(dir.path().join("sekret.db"), b"").context("replace")?;
    assert!(held.check().await.is_err());
    Ok(())
}

/// The demonstrated attack: a newer `admin bootstrap` migrated the database of an older server
/// still running on it. Opening for commands that run beside a server never migrates.
#[tokio::test]
async fn an_exact_open_refuses_another_schema_and_changes_nothing() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let store = SqlStore::connect(&url(dir.path())).await.context("create")?;
    drop(store);
    SqlStore::open(&url(dir.path()), Open::Exact)
        .await
        .context("the current schema opens")?;
    {
        use sqlx::ConnectOptions;
        let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("sekret.db"))
            .connect()
            .await
            .context("raw")?;
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = (SELECT MAX(version) FROM _sqlx_migrations)")
            .execute(&mut conn)
            .await
            .context("rewind")?;
    }
    let refused = SqlStore::open(&url(dir.path()), Open::Exact).await;
    assert!(
        matches!(&refused, Err(StoreError::Unsupported(message)) if message.contains("schema")),
        "{:?}",
        refused.err()
    );
    let refused = SqlStore::open(&url(dir.path()), Open::Exact).await;
    assert!(refused.is_err(), "still behind: nothing was migrated");

    let missing = format!("sqlite://{}?mode=rwc", dir.path().join("missing.db").display());
    for how in [Open::Exact, Open::Migrate] {
        assert!(SqlStore::open(&missing, how).await.is_err(), "{how:?}");
        assert!(!dir.path().join("missing.db").exists(), "{how:?} created nothing");
    }
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

/// A database at migration 0001, made with that migration alone.
async fn database_at_0001(database: &str, backend: &str) -> anyhow::Result<(tempfile::TempDir, sqlx::AnyPool)> {
    let dir = tempfile::tempdir().context("dir")?;
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join(backend);
    for entry in std::fs::read_dir(&source).context("read migrations")? {
        let entry = entry.context("entry")?;
        if entry.file_name().to_string_lossy().starts_with("0001") {
            std::fs::copy(entry.path(), dir.path().join(entry.file_name())).context("copy")?;
        }
    }
    sqlx::any::install_default_drivers();
    let pool = sqlx::AnyPool::connect(database).await.context("pool")?;
    sqlx::migrate::Migrator::new(dir.path())
        .await
        .context("migrator")?
        .run(&pool)
        .await
        .context("migration 0001")?;
    Ok((dir, pool))
}

/// Machine tokens minted before 0002 name no credential, so revoking the client secret or auth
/// method they came from would miss them. The upgrade revokes them; nothing else changes.
async fn machine_tokens_without_a_source_are_revoked_on_upgrade(database: &str, backend: &str) -> anyhow::Result<()> {
    let (_migrations, pool) = database_at_0001(database, backend).await?;
    for (id, kind, principal_kind) in [
        ("m1", "machine", "identity"),
        ("c1", "cli", "user"),
        ("a1", "admin", "user"),
    ] {
        sqlx::query(
            "INSERT INTO access_tokens (id, token_hash, kind, principal_kind, principal_id, description, created_at, \
             expires_at, max_expires_at, revoked) VALUES ($1, $2, $3, $4, 'p1', '', 1, 4000000000, 4000000000, 0)",
        )
        .bind(id)
        .bind(format!("hash-{id}"))
        .bind(kind)
        .bind(principal_kind)
        .execute(&pool)
        .await
        .context("token")?;
    }
    pool.close().await;
    let store = SqlStore::connect(database).await.context("upgrade")?;
    let found = |id: &'static str| {
        let store = store.clone();
        async move {
            store
                .find_token(&format!("hash-{id}"))
                .await
                .context("find")?
                .context(id)
        }
    };
    assert!(found("m1").await?.revoked, "a machine token with no source");
    for id in ["c1", "a1"] {
        let token = found(id).await?;
        assert!(!token.revoked, "{id} names no credential by design");
        assert_eq!(token.mac, None, "{id} waits for the first unlock to be vouched for");
        assert_eq!(
            token.sealed_hash,
            Some(format!("hash-{id}")),
            "{id} keeps working on the routes open while sealed"
        );
    }
    let unsigned: Vec<String> = store
        .list_unsigned_tokens()
        .await
        .context("unsigned")?
        .into_iter()
        .map(|t| t.id)
        .collect();
    assert_eq!(unsigned, ["a1", "c1"]);
    Ok(())
}

#[tokio::test]
async fn sqlite_machine_tokens_without_a_source_are_revoked_on_upgrade() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    machine_tokens_without_a_source_are_revoked_on_upgrade(&url(dir.path()), "sqlite").await
}

/// Needs Docker. Skipped with a message when it is unavailable unless SEKRET_REQUIRE_POSTGRES is set.
#[tokio::test]
async fn postgres_machine_tokens_without_a_source_are_revoked_on_upgrade() -> anyhow::Result<()> {
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    let container = match testcontainers_modules::postgres::Postgres::default().start().await {
        Ok(container) => container,
        Err(error) if std::env::var_os("SEKRET_REQUIRE_POSTGRES").is_none() => {
            eprintln!("skipping postgres test: {error}");
            return Ok(());
        }
        Err(error) => anyhow::bail!("postgres container failed: {error}"),
    };
    let port = container.get_host_port_ipv4(5432).await.context("port")?;
    let database = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    machine_tokens_without_a_source_are_revoked_on_upgrade(&database, "postgres").await
}

/// A database with every migration before `first_missing` applied.
async fn database_before(
    database: &str,
    backend: &str,
    first_missing: &str,
) -> anyhow::Result<(tempfile::TempDir, sqlx::AnyPool)> {
    let dir = tempfile::tempdir().context("dir")?;
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join(backend);
    for entry in std::fs::read_dir(&source).context("read migrations")? {
        let entry = entry.context("entry")?;
        if entry.file_name().to_string_lossy().as_ref() < first_missing {
            std::fs::copy(entry.path(), dir.path().join(entry.file_name())).context("copy")?;
        }
    }
    sqlx::any::install_default_drivers();
    let pool = sqlx::AnyPool::connect(database).await.context("pool")?;
    sqlx::migrate::Migrator::new(dir.path())
        .await
        .context("migrator")?
        .run(&pool)
        .await
        .context("older migrations")?;
    Ok((dir, pool))
}

/// Projects and secrets from before per-secret access come through the upgrade with the
/// setting off, nothing restricted and no access lists, and behave exactly as before.
async fn secrets_from_before_secret_access_stay_open(database: &str, backend: &str) -> anyhow::Result<()> {
    let (_migrations, pool) = database_before(database, backend, "0010").await?;
    for statement in [
        "INSERT INTO projects (id, slug, name, description, wrapped_key, created_at) VALUES ('p1', 'app', 'App', '', $1, 1)",
        "INSERT INTO environments (id, project_id, slug, name, position, created_at) VALUES ('e1', 'p1', 'dev', 'dev', 0, 1)",
        "INSERT INTO secrets (id, project_id, environment_id, path, key, current_version, deleted, created_at, updated_at) \
         VALUES ('s1', 'p1', 'e1', '/', 'A', 1, 0, 1, 1)",
        "INSERT INTO secret_versions (secret_id, version, value, comment, tags, deleted, actor, created_at) \
         VALUES ('s1', 1, $1, '', '[]', 0, 'old', 1)",
    ] {
        sqlx::query(statement)
            .bind(vec![7u8; 8])
            .execute(&pool)
            .await
            .with_context(|| statement.to_string())?;
    }
    pool.close().await;
    let store = SqlStore::connect(database).await.context("upgrade")?;
    let project = store.get_project("p1").await.context("project")?.context("p1")?;
    assert!(!project.secret_access, "the setting starts off");
    let secret = store.get_secret("e1", "/", "A").await.context("get")?.context("s1")?;
    assert!(!secret.secret.restricted, "nothing starts restricted");
    assert_eq!(secret.version.value, Some(vec![7u8; 8]));
    assert!(store.list_environment_grants("e1").await.context("grants")?.is_empty());
    assert_eq!(store.count_restricted_secrets("p1").await.context("count")?, 0);
    store.set_project_secret_access("p1", true).await.context("enable")?;
    store
        .update_secret_access(AccessChange {
            secret_id: "s1".into(),
            restricted: Some(true),
            grant: vec![],
            revoke: vec![],
            max_grants: 100,
        })
        .await
        .context("restrict an old secret")?;
    assert!(
        store
            .get_secret_by_id("s1")
            .await
            .context("get")?
            .context("s1")?
            .secret
            .restricted
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_secrets_from_before_secret_access_stay_open() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    secrets_from_before_secret_access_stay_open(&url(dir.path()), "sqlite").await
}

/// Needs Docker. Skipped with a message when it is unavailable unless SEKRET_REQUIRE_POSTGRES is set.
#[tokio::test]
async fn postgres_secrets_from_before_secret_access_stay_open() -> anyhow::Result<()> {
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    let container = match testcontainers_modules::postgres::Postgres::default().start().await {
        Ok(container) => container,
        Err(error) if std::env::var_os("SEKRET_REQUIRE_POSTGRES").is_none() => {
            eprintln!("skipping postgres test: {error}");
            return Ok(());
        }
        Err(error) => anyhow::bail!("postgres container failed: {error}"),
    };
    let port = container.get_host_port_ipv4(5432).await.context("port")?;
    let database = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    secrets_from_before_secret_access_stay_open(&database, "postgres").await
}
