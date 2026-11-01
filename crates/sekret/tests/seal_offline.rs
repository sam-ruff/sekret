//! Regressions for the offline admin commands and the seal epoch marks, through the real binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::Context;
use sekret_core::crypto::RootKey;
use sekret_core::seal::{SealFlags, UnlockPolicy, unwrap_root_key};
use sekret_server::seal::{Signature, accepted_roots, check_signature, high_water, record_epoch, signed};
use sekret_store::{SealConfig, SqlStore, Store};

const BIN: &str = env!("CARGO_BIN_EXE_sekret");
const PASSPHRASE: &str = "violet tractor sings beneath";

fn run(args: &[&str], dir: &Path) -> anyhow::Result<Output> {
    Command::new(BIN)
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .context("run")
}

fn ok(output: Output) -> anyhow::Result<String> {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(output.status.success(), "command failed: {text}");
    Ok(text)
}

struct Fixture {
    dir: tempfile::TempDir,
    db: String,
}

impl Fixture {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn marks(&self) -> Vec<PathBuf> {
        sekret_server::config::epoch_files(&self.db, None, None, None)
    }

    async fn store(&self) -> anyhow::Result<SqlStore> {
        SqlStore::connect(&self.db).await.context("store")
    }

    async fn config(&self) -> anyhow::Result<SealConfig> {
        self.store().await?.get_seal_config().await?.context("config")
    }

    fn root(config: &SealConfig) -> anyhow::Result<RootKey> {
        let wrapped = config.wrapped.as_ref().context("wrap")?;
        unwrap_root_key(wrapped, PASSPHRASE).context("unwrap")
    }

    fn admin(&self, args: &[&str]) -> anyhow::Result<String> {
        let mut full = vec!["admin"];
        full.extend_from_slice(args);
        full.extend_from_slice(&["--database-url", &self.db, "--passphrase-file", "pass"]);
        ok(run(&full, self.path())?)
    }
}

/// A passphrase-mode database under the passphrase-file policy, then moved on to `manual` the way
/// a running server would: signed one epoch later, with the mark raised to match.
async fn rolled_forward() -> anyhow::Result<(Fixture, SealConfig)> {
    let dir = tempfile::tempdir().context("dir")?;
    std::fs::write(dir.path().join("pass"), format!("{PASSPHRASE}\n")).context("pass")?;
    let db = format!("sqlite://{}?mode=rwc", dir.path().join("sekret.db").display());
    let fixture = Fixture { dir, db };
    ok(run(
        &[
            "admin",
            "init",
            "--database-url",
            &fixture.db,
            "--passphrase-file",
            "pass",
            "--unlock",
            "passphrase-file",
        ],
        fixture.path(),
    )?)?;
    let granting = fixture.config().await?;
    assert_eq!(granting.unlock_policy, UnlockPolicy::PassphraseFile);
    let root = Fixture::root(&granting)?;
    let marks = fixture.marks();
    let manual = signed(
        &root,
        SealConfig {
            unlock_policy: UnlockPolicy::Manual,
            ..granting.clone()
        },
        high_water(&marks).floor(),
    )?;
    fixture.store().await?.update_seal_config(manual.clone()).await?;
    record_epoch(&marks, manual.epoch, &root.fingerprint())?;
    Ok((fixture, granting))
}

/// The demonstrated attack: the older, granting configuration put back one step behind the mark
/// was signed again by an offline rotation at the mark's own epoch, which laundered it.
#[tokio::test]
async fn offline_rotation_never_launders_a_one_step_rollback() -> anyhow::Result<()> {
    let (fixture, granting) = rolled_forward().await?;
    let mark = high_water(&fixture.marks()).highest.context("mark")?;
    assert_eq!(granting.epoch + 1, mark);
    fixture.store().await?.update_seal_config(granting).await?;

    fixture.admin(&["rotate-root-key"])?;
    let rotated = fixture.config().await?;
    assert_eq!(rotated.unlock_policy, UnlockPolicy::Manual, "the rollback is not kept");
    assert!(rotated.epoch > mark, "{} <= {mark}", rotated.epoch);
    assert_eq!(high_water(&fixture.marks()).highest, Some(rotated.epoch));
    let root = Fixture::root(&rotated)?;
    assert_eq!(check_signature(&root, &rotated), Signature::Valid);
    Ok(())
}

#[tokio::test]
async fn switching_the_seal_mode_signs_above_the_marks() -> anyhow::Result<()> {
    let (fixture, granting) = rolled_forward().await?;
    let mark = high_water(&fixture.marks()).highest.context("mark")?;
    fixture.store().await?.update_seal_config(granting).await?;
    ok(run(
        &[
            "admin",
            "set-seal-mode",
            "key-file",
            "--database-url",
            &fixture.db,
            "--root-key-file",
            "root.key",
            "--passphrase-file",
            "pass",
        ],
        fixture.path(),
    )?)?;
    let switched = fixture.config().await?;
    assert!(switched.epoch > mark, "{} <= {mark}", switched.epoch);
    assert!(
        switched.flags.reviewer_tokens_migrated,
        "a rolled-back source migrates nothing"
    );
    Ok(())
}

/// Restoring an older database in place: the reset signs above the marks and never lowers them,
/// so nothing signed in between can be replayed, and the rolled-back configuration grants nothing.
#[tokio::test]
async fn reset_epoch_signs_above_the_marks_and_never_lowers_them() -> anyhow::Result<()> {
    let (fixture, granting) = rolled_forward().await?;
    let marks = fixture.marks();
    let fingerprint = Fixture::root(&granting)?.fingerprint();
    record_epoch(&marks, 1000, &fingerprint)?;
    assert_eq!(high_water(&marks).highest, Some(1000), "raising is allowed");
    record_epoch(&marks, 5, &fingerprint)?;
    assert_eq!(high_water(&marks).highest, Some(1000), "lowering is not");
    fixture.store().await?.update_seal_config(granting).await?;

    let printed = fixture.admin(&["reset-epoch"])?;
    assert!(printed.contains("older than the marks"), "{printed}");
    let config = fixture.config().await?;
    assert!(config.epoch > 1000, "{}", config.epoch);
    assert_eq!(high_water(&marks).highest, Some(config.epoch), "{printed}");
    let root = Fixture::root(&config)?;
    assert_eq!(check_signature(&root, &config), Signature::Valid);
    assert_eq!(
        config.unlock_policy,
        UnlockPolicy::Manual,
        "a rolled-back configuration loses its grant"
    );

    // A sound configuration keeps what it grants.
    let granting = signed(
        &root,
        SealConfig {
            unlock_policy: UnlockPolicy::PassphraseFile,
            ..config
        },
        high_water(&marks).floor(),
    )?;
    fixture.store().await?.update_seal_config(granting.clone()).await?;
    record_epoch(&marks, granting.epoch, &fingerprint)?;
    fixture.admin(&["reset-epoch"])?;
    let config = fixture.config().await?;
    assert_eq!(config.unlock_policy, UnlockPolicy::PassphraseFile);
    assert!(config.epoch > granting.epoch);

    // A damaged mark is repaired the same way, and a tampered configuration loses its grant.
    for mark in &marks {
        std::fs::write(mark, "garbage").context("damage")?;
    }
    assert!(high_water(&marks).broken);
    let tampered = SealConfig {
        unlock_policy: UnlockPolicy::Remember,
        ..config
    };
    fixture.store().await?.update_seal_config(tampered).await?;
    let printed = fixture.admin(&["reset-epoch"])?;
    assert!(printed.contains("failed its signature"), "{printed}");
    let repaired = fixture.config().await?;
    assert_eq!(repaired.unlock_policy, UnlockPolicy::Manual);
    assert_eq!(check_signature(&root, &repaired), Signature::Valid);
    let after = high_water(&marks);
    assert!(!after.broken);
    assert_eq!(after.highest, Some(repaired.epoch));
    Ok(())
}

fn fingerprint_in(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read(path).context("key file")?;
    Ok(RootKey::parse(&text).context("parse")?.fingerprint())
}

/// Switching mode replaces the root key, so whatever opened the database before, an old key
/// file or the old passphrase with an old wrap, opens nothing in it afterwards.
#[tokio::test]
async fn switching_the_seal_mode_replaces_the_root_key() -> anyhow::Result<()> {
    let (fixture, granting) = rolled_forward().await?;
    let first = Fixture::root(&granting)?;
    let old_wrap = fixture.config().await?.wrapped.context("wrap")?;
    let switch = |mode: &str| {
        run(
            &[
                "admin",
                "set-seal-mode",
                mode,
                "--database-url",
                &fixture.db,
                "--root-key-file",
                "root.key",
                "--passphrase-file",
                "pass",
            ],
            fixture.path(),
        )
    };
    let printed = ok(switch("key-file")?)?;
    assert!(printed.contains("new root key"), "{printed}");
    let second = fingerprint_in(&fixture.path().join("root.key"))?;
    assert_ne!(second, first.fingerprint());
    let store = fixture.store().await?;
    assert_eq!(
        store.get_meta(sekret_server::ROOT_KEY_META).await?,
        Some(second.clone())
    );
    let marks = sekret_server::config::epoch_files(&fixture.db, None, Some(&fixture.path().join("root.key")), None);
    assert_eq!(accepted_roots(&marks), Some(vec![second.clone()]));
    let wrapped = unwrap_root_key(&old_wrap, PASSPHRASE).context("the old wrap still opens")?;
    assert_ne!(wrapped.fingerprint(), second, "but only the old key");

    // Back to passphrase mode: the key file that ran the server until now is refused.
    std::fs::rename(fixture.path().join("root.key"), fixture.path().join("old.key")).context("move")?;
    std::fs::copy(fixture.path().join("old.key"), fixture.path().join("root.key")).context("copy")?;
    ok(switch("passphrase")?)?;
    let config = fixture.config().await?;
    let third = Fixture::root(&config)?.fingerprint();
    assert_ne!(third, second);
    assert_eq!(
        fixture.store().await?.get_meta(sekret_server::ROOT_KEY_META).await?,
        Some(third)
    );
    let bootstrap = run(
        &[
            "admin",
            "bootstrap",
            "--database-url",
            &fixture.db,
            "--root-key-file",
            "old.key",
        ],
        fixture.path(),
    )?;
    assert!(!bootstrap.status.success(), "the old key file opens nothing");
    std::fs::remove_file(fixture.path().join("root.key")).context("remove")?;
    fixture.admin(&["bootstrap"])?;
    Ok(())
}

fn copy_database(from: &Path, to: &Path) -> anyhow::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let mut source = from.as_os_str().to_os_string();
        source.push(suffix);
        let mut target = to.as_os_str().to_os_string();
        target.push(suffix);
        let _ = std::fs::remove_file(&target);
        if Path::new(&source).exists() {
            std::fs::copy(&source, &target).context("copy")?;
        }
    }
    Ok(())
}

/// A database put back from before a root key rotation is under a key the marks no longer
/// name. Only the explicit host command accepts it, and it moves the marks to that key.
#[tokio::test]
async fn only_reset_epoch_adopt_root_key_accepts_a_key_the_marks_do_not_name() -> anyhow::Result<()> {
    let (fixture, granting) = rolled_forward().await?;
    let first = Fixture::root(&granting)?.fingerprint();
    let live = fixture.path().join("sekret.db");
    let saved = fixture.path().join("saved.db");
    copy_database(&live, &saved)?;
    fixture.admin(&["rotate-root-key"])?;
    let rotated = Fixture::root(&fixture.config().await?)?.fingerprint();
    assert_eq!(accepted_roots(&fixture.marks()), Some(vec![rotated]));

    copy_database(&saved, &live)?;
    for command in [&["bootstrap"][..], &["reset-epoch"][..]] {
        let mut full = vec!["admin"];
        full.extend_from_slice(command);
        full.extend_from_slice(&["--database-url", &fixture.db, "--passphrase-file", "pass"]);
        let refused = run(&full, fixture.path())?;
        let shown = format!("{}", String::from_utf8_lossy(&refused.stderr));
        assert!(!refused.status.success(), "{command:?}");
        assert!(shown.contains("--adopt-root-key"), "{command:?}: {shown}");
    }
    let printed = fixture.admin(&["reset-epoch", "--adopt-root-key"])?;
    assert!(printed.contains(&first), "{printed}");
    assert_eq!(accepted_roots(&fixture.marks()), Some(vec![first]));
    let config = fixture.config().await?;
    assert_eq!(high_water(&fixture.marks()).highest, Some(config.epoch));
    fixture.admin(&["bootstrap"])?;
    Ok(())
}

/// With no mark, a stripped signature looks like a database from before signing. The offline
/// commands sign it again, but never with a cleared migration flag a database writer chose.
#[tokio::test]
async fn offline_commands_never_restart_the_migration_from_an_unsigned_configuration() -> anyhow::Result<()> {
    for command in [&["rotate-root-key"][..], &["reset-epoch"][..]] {
        let (fixture, _) = rolled_forward().await?;
        let stripped = SealConfig {
            mac: None,
            flags: SealFlags::default(),
            ..fixture.config().await?
        };
        assert!(!stripped.flags.reviewer_tokens_migrated);
        fixture.store().await?.update_seal_config(stripped).await?;
        for mark in fixture.marks() {
            std::fs::remove_file(&mark).context("mark")?;
        }
        fixture.admin(command)?;
        let signed_again = fixture.config().await?;
        let root = Fixture::root(&signed_again)?;
        assert_eq!(check_signature(&root, &signed_again), Signature::Valid, "{command:?}");
        assert!(signed_again.flags.reviewer_tokens_migrated, "{command:?}");
    }
    Ok(())
}

/// Postgres has no file to keep a mark beside, and the admin commands share the server's
/// `seal.epoch_file` rule; SQLite always has one, so the option only adds a mark there.
#[tokio::test]
async fn an_epoch_file_is_raised_by_the_offline_commands() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let extra = fixture.path().join("seal.epoch");
    let extra_arg = extra.display().to_string();
    fixture.admin(&["reset-epoch", "--epoch-file", &extra_arg])?;
    let config = fixture.config().await?;
    assert_eq!(high_water(std::slice::from_ref(&extra)).highest, Some(config.epoch));
    let root = Fixture::root(&config)?;
    assert_eq!(accepted_roots(&[extra]), Some(vec![root.fingerprint()]));
    Ok(())
}
