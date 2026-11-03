//! Regressions for the offline admin commands and the seal epoch marks, through the real binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::Context;
use sekret_core::crypto::{IntegrityKey, RootKey};
use sekret_core::seal::{
    SealBinding, SealFlags, SealMode, UnlockPolicy, seal_config_mac, unwrap_root_key, wrap_root_key,
};
use sekret_server::seal::{Signature, accepted_roots, check_signature, high_water, record_epoch, signed};
use sekret_store::{INTEGRITY_KEY_META, SealConfig, SqlStore, Store};

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
        ok(self.admin_output(args)?)
    }

    fn admin_output(&self, args: &[&str]) -> anyhow::Result<Output> {
        let mut full = vec!["admin"];
        full.extend_from_slice(args);
        full.extend_from_slice(&["--database-url", &self.db, "--passphrase-file", "pass"]);
        run(&full, self.path())
    }

    /// Writes the live root key to `root.key`, as a passphrase-mode server may also have.
    async fn with_key_file(&self) -> anyhow::Result<RootKey> {
        let root = Self::root(&self.config().await?)?;
        std::fs::write(self.path().join("root.key"), root.to_key_file_text().as_bytes()).context("key file")?;
        Ok(root)
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
    record_epoch(&marks, manual.epoch, &root.pin()?)?;
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

/// What the epoch marks record for the key in `path`.
fn pin_in(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read(path).context("key file")?;
    RootKey::parse(&text).context("parse")?.pin().context("pin")
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
    assert_eq!(
        accepted_roots(&marks),
        Some(vec![pin_in(&fixture.path().join("root.key"))?])
    );
    assert!(
        !fixture.path().join("root.key.new").exists(),
        "the new key was staged and moved into place"
    );
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
    let first_key = Fixture::root(&granting)?;
    let first = first_key.fingerprint();
    let live = fixture.path().join("sekret.db");
    let saved = fixture.path().join("saved.db");
    copy_database(&live, &saved)?;
    fixture.admin(&["rotate-root-key"])?;
    let rotated = Fixture::root(&fixture.config().await?)?.pin()?;
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
    assert_eq!(accepted_roots(&fixture.marks()), Some(vec![first_key.pin()?]));
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
    assert_eq!(accepted_roots(&[extra]), Some(vec![root.pin()?]));
    Ok(())
}

/// A database writer swaps the passphrase wrap for one of their own. Repairing with the key file
/// must not sign it as trusted, which would lock the owner's passphrase out for good.
#[tokio::test]
async fn reset_epoch_with_a_key_file_never_signs_a_planted_wrap() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let root = fixture.with_key_file().await?;
    let planted = SealConfig {
        wrapped: Some(wrap_root_key(&RootKey::generate()?, "attacker chosen words here")?),
        ..fixture.config().await?
    };
    fixture.store().await?.update_seal_config(planted.clone()).await?;

    let refused = fixture.admin_output(&["reset-epoch", "--root-key-file", "root.key"])?;
    let shown = String::from_utf8_lossy(&refused.stderr).to_string();
    assert!(!refused.status.success(), "{shown}");
    assert!(shown.contains("--drop-passphrase-wrap"), "{shown}");
    assert_eq!(fixture.config().await?, planted, "nothing was signed");

    fixture.admin(&["reset-epoch", "--root-key-file", "root.key", "--drop-passphrase-wrap"])?;
    let repaired = fixture.config().await?;
    assert_eq!(repaired.mode, SealMode::KeyFile);
    assert!(repaired.wrapped.is_none());
    assert_eq!(check_signature(&root, &repaired), Signature::Valid);
    fixture.admin(&["bootstrap", "--root-key-file", "root.key"])?;
    Ok(())
}

/// When only other fields were changed, the owner's passphrase proves the wrap and it is kept.
#[tokio::test]
async fn reset_epoch_with_a_key_file_keeps_a_wrap_the_passphrase_opens() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let root = fixture.with_key_file().await?;
    let refused = fixture.admin_output(&["reset-epoch", "--root-key-file", "root.key", "--drop-passphrase-wrap"])?;
    assert!(!refused.status.success(), "a sound wrap is never dropped");
    let tampered = SealConfig {
        unlock_policy: UnlockPolicy::Remember,
        ..fixture.config().await?
    };
    fixture.store().await?.update_seal_config(tampered.clone()).await?;

    fixture.admin(&["reset-epoch", "--root-key-file", "root.key"])?;
    let repaired = fixture.config().await?;
    assert_eq!(repaired.mode, SealMode::Passphrase);
    assert_eq!(repaired.wrapped, tampered.wrapped);
    assert_eq!(repaired.unlock_policy, UnlockPolicy::Manual);
    assert_eq!(check_signature(&root, &repaired), Signature::Valid);
    Ok(())
}

/// A database writer clears the flag that keeps a remember secret required. Every repair sets it
/// again, so only `forget-unlock` can lift it.
#[tokio::test]
async fn repairs_keep_the_remember_secret_required() -> anyhow::Result<()> {
    for command in [&["reset-epoch"][..], &["rotate-root-key"][..]] {
        let (fixture, _) = rolled_forward().await?;
        let config = fixture.config().await?;
        assert!(!config.flags.remember_secret);
        let tampered = SealConfig {
            flags: SealFlags {
                remember_secret: false,
                ..config.flags
            },
            unlock_policy: UnlockPolicy::Remember,
            ..config
        };
        fixture.store().await?.update_seal_config(tampered).await?;
        fixture.admin(command)?;
        let repaired = fixture.config().await?;
        assert!(repaired.flags.remember_secret, "{command:?}");
    }
    Ok(())
}

/// A passphrase-mode server with a key file reads the file first, so rotating must leave it
/// holding the new key, not the old one that opens every earlier backup.
#[tokio::test]
async fn rotating_in_passphrase_mode_replaces_the_key_file() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let old = fixture.with_key_file().await?;
    let printed = fixture.admin(&["rotate-root-key", "--root-key-file", "root.key"])?;
    assert!(printed.contains("wrote the new root key"), "{printed}");
    let new = Fixture::root(&fixture.config().await?)?;
    assert_ne!(new.fingerprint(), old.fingerprint());
    assert_eq!(fingerprint_in(&fixture.path().join("root.key"))?, new.fingerprint());
    assert!(
        !fixture.path().join("root.key.new").exists(),
        "the staged key was moved into place"
    );
    fixture.admin(&["bootstrap", "--root-key-file", "root.key"])?;
    Ok(())
}

/// A rotation that fails before the commit leaves the key file and the database as they were,
/// and takes away the key it staged; one left by an earlier run is replaced, never trusted.
#[tokio::test]
async fn a_rotation_that_fails_leaves_no_staged_key_behind() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let old = fixture.with_key_file().await?;
    std::fs::write(fixture.path().join("root.key.new"), b"left by a crash").context("stale")?;
    // A value that no longer decrypts makes the rotation refuse before it commits.
    let store = fixture.store().await?;
    let root = Fixture::root(&fixture.config().await?)?;
    let dek = sekret_core::crypto::DataKey::generate()?;
    let project = sekret_store::Project {
        id: "p1".into(),
        slug: "app".into(),
        name: "app".into(),
        description: String::new(),
        wrapped_key: sekret_core::crypto::wrap_data_key(&RootKey::generate()?, &dek, "p1")?,
        created_at: 0,
        logo_updated_at: None,
        secret_policy: None,
        secret_access: false,
    };
    store.create_project(project, vec![]).await?;
    drop(store);
    let refused = fixture.admin_output(&["rotate-root-key", "--root-key-file", "root.key"])?;
    assert!(
        !refused.status.success(),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!fixture.path().join("root.key.new").exists(), "nothing staged is left");
    assert_eq!(fingerprint_in(&fixture.path().join("root.key"))?, old.fingerprint());
    assert_eq!(
        Fixture::root(&fixture.config().await?)?.fingerprint(),
        root.fingerprint()
    );
    Ok(())
}

/// Switching to key-file mode refuses a key file that is already there before changing anything,
/// rather than after the database has moved to a key it then cannot write.
#[tokio::test]
async fn set_seal_mode_refuses_an_existing_key_file_before_changing_anything() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let before = fixture.config().await?;
    std::fs::write(fixture.path().join("root.key"), b"someone else's file").context("key file")?;
    let refused = fixture.admin_output(&["set-seal-mode", "key-file", "--root-key-file", "root.key"])?;
    let shown = String::from_utf8_lossy(&refused.stderr).to_string();
    assert!(!refused.status.success(), "{shown}");
    assert!(shown.contains("already exists"), "{shown}");
    assert_eq!(fixture.config().await?, before, "the database was not touched");
    assert_eq!(
        std::fs::read(fixture.path().join("root.key")).context("key file")?,
        b"someone else's file"
    );
    assert!(!fixture.path().join("root.key.new").exists());

    std::fs::remove_file(fixture.path().join("root.key")).context("remove")?;
    fixture.admin(&["set-seal-mode", "key-file", "--root-key-file", "root.key"])?;
    let config = fixture.config().await?;
    assert_eq!(config.mode, SealMode::KeyFile);
    assert!(!fixture.path().join("root.key.new").exists(), "moved into place");
    fixture.admin(&["bootstrap", "--root-key-file", "root.key"])?;
    Ok(())
}

/// The demonstrated attack: with the stored epoch planted at the last one, `reset-epoch` could not
/// sign above the marks, so it lowered every mark to 1, and an older signed configuration put
/// back afterwards passed as sound.
#[tokio::test]
async fn reset_epoch_never_lowers_the_marks_for_a_planted_epoch() -> anyhow::Result<()> {
    for planted in [i64::MAX, i64::MAX - 1] {
        let (fixture, granting) = rolled_forward().await?;
        let marks = fixture.marks();
        let mark = high_water(&marks).highest.context("mark")?;
        let tampered = SealConfig {
            epoch: planted,
            ..fixture.config().await?
        };
        fixture.store().await?.update_seal_config(tampered).await?;

        let printed = fixture.admin(&["reset-epoch"])?;
        assert!(printed.contains("failed its signature"), "{printed}");
        let config = fixture.config().await?;
        assert_eq!(config.epoch, mark + 1, "{planted}: started from the marks");
        assert_eq!(high_water(&marks).highest, Some(mark + 1), "{planted}");

        // The older copy is still a rollback afterwards, and grants nothing.
        fixture.store().await?.update_seal_config(granting).await?;
        let printed = fixture.admin(&["reset-epoch"])?;
        assert!(printed.contains("older than the marks"), "{printed}");
        assert_eq!(fixture.config().await?.unlock_policy, UnlockPolicy::Manual);
    }
    Ok(())
}

/// A planted mark just below the epoch limit stops every signature. Only `--lower-marks` lowers
/// the marks, only when it has to, never for a configuration that fails its signature, and the
/// record of the one-off migrations survives it.
#[tokio::test]
async fn only_lower_marks_lowers_the_marks() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let refused = fixture.admin_output(&["reset-epoch", "--lower-marks"])?;
    let shown = String::from_utf8_lossy(&refused.stderr).to_string();
    assert!(!refused.status.success(), "{shown}");
    assert!(shown.contains("have not"), "{shown}");

    let marks = fixture.marks();
    let sound = fixture.config().await?;
    let root = Fixture::root(&sound)?;
    let ceiling = sekret_core::seal::MAX_SEAL_EPOCH - 1;
    std::fs::write(
        &marks[0],
        format!("sekret-seal-epoch {ceiling} {} migrated\n", root.pin()?),
    )
    .context("mark")?;
    let refused = fixture.admin_output(&["reset-epoch"])?;
    let shown = String::from_utf8_lossy(&refused.stderr).to_string();
    assert!(!refused.status.success(), "{shown}");
    assert!(shown.contains("--lower-marks"), "{shown}");
    assert_eq!(high_water(&marks).highest, Some(ceiling), "nothing was lowered");

    let tampered = SealConfig {
        unlock_policy: UnlockPolicy::Remember,
        ..sound.clone()
    };
    fixture.store().await?.update_seal_config(tampered).await?;
    let refused = fixture.admin_output(&["reset-epoch", "--lower-marks"])?;
    let shown = String::from_utf8_lossy(&refused.stderr).to_string();
    assert!(!refused.status.success(), "{shown}");
    assert!(shown.contains("fails its signature"), "{shown}");
    assert_eq!(high_water(&marks).highest, Some(ceiling));

    fixture.store().await?.update_seal_config(sound.clone()).await?;
    let printed = fixture.admin(&["reset-epoch", "--lower-marks"])?;
    assert!(printed.contains("lowered every epoch mark"), "{printed}");
    let config = fixture.config().await?;
    assert_eq!(config.epoch, sound.epoch + 1);
    assert_eq!(check_signature(&root, &config), Signature::Valid);
    assert_eq!(config.unlock_policy, UnlockPolicy::Manual);
    let after = high_water(&marks);
    assert_eq!(after.highest, Some(config.epoch));
    assert!(after.migrated);
    fixture.admin(&["bootstrap"])?;
    Ok(())
}

/// The configuration as a version from before `wrap_form_signed` signed it, with no flags set.
fn signed_before_the_wrap_form(root: &RootKey, config: SealConfig) -> anyhow::Result<SealConfig> {
    let config = SealConfig {
        flags: SealFlags::default(),
        ..config
    };
    let fingerprint = root.fingerprint();
    let binding = SealBinding {
        mode: config.mode,
        policy: config.unlock_policy,
        fingerprint: &fingerprint,
        epoch: config.epoch,
        wrapped: config.wrapped.as_ref(),
        remembered: config.remembered.as_deref(),
        flags: config.flags,
    };
    let mac = seal_config_mac(root, &binding).context("mac")?;
    Ok(SealConfig {
        mac: Some(mac),
        ..config
    })
}

/// The demonstrated attack, offline: a configuration signed before `wrap_form_signed`, put back
/// with the marks deleted, kept its cleared migration flags when a host command signed it again.
#[tokio::test]
async fn offline_commands_never_restart_the_migrations_for_a_replayed_configuration() -> anyhow::Result<()> {
    for command in [&["rotate-root-key"][..], &["reset-epoch"][..]] {
        let (fixture, _) = rolled_forward().await?;
        let current = fixture.config().await?;
        let root = Fixture::root(&current)?;
        let replayed = signed_before_the_wrap_form(&root, current)?;
        assert_eq!(check_signature(&root, &replayed), Signature::Valid);
        fixture.store().await?.update_seal_config(replayed).await?;
        for mark in fixture.marks() {
            std::fs::remove_file(&mark).context("mark")?;
        }
        fixture.admin(command)?;
        let signed_again = fixture.config().await?;
        assert!(signed_again.flags.reviewer_tokens_migrated, "{command:?}");
        assert!(signed_again.flags.credentials_keyed, "{command:?}");
        assert!(high_water(&fixture.marks()).migrated, "{command:?}");
    }
    Ok(())
}

/// A 32-character password in a key file, in any language, is refused rather than taken as 32
/// raw key bytes, and so is encoded key material with an obvious pattern, such as all zeros.
#[tokio::test]
async fn a_password_is_not_accepted_as_a_raw_root_key() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let mut accented = "pässwörd-für-den-sekret-server".as_bytes().to_vec();
    accented.resize(32, b'!');
    let zeros = "0".repeat(64);
    let materials: [&[u8]; 4] = [
        b"correct horse battery staple 123",
        &accented,
        zeros.as_bytes(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
    ];
    for material in materials {
        std::fs::write(fixture.path().join("root.key"), material).context("key file")?;
        let refused = fixture.admin_output(&["bootstrap", "--root-key-file", "root.key"])?;
        let shown = String::from_utf8_lossy(&refused.stderr).to_string();
        assert!(!refused.status.success(), "{shown}");
        assert!(shown.contains("password is not a key"), "{shown}");
    }
    Ok(())
}

/// The audit's mode flip: a database writer sets the stored mode to key-file. The passphrase still
/// opens the wrap, which proves passphrase mode, so `reset-epoch` repairs it without a key file.
#[tokio::test]
async fn reset_epoch_with_the_passphrase_repairs_a_tampered_mode() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let tampered = SealConfig {
        mode: SealMode::KeyFile,
        ..fixture.config().await?
    };
    fixture.store().await?.update_seal_config(tampered.clone()).await?;
    fixture.admin(&["reset-epoch"])?;
    let repaired = fixture.config().await?;
    assert_eq!(repaired.mode, SealMode::Passphrase);
    assert_eq!(repaired.wrapped, tampered.wrapped);
    assert_eq!(repaired.unlock_policy, UnlockPolicy::Manual);
    let root = Fixture::root(&repaired)?;
    assert_eq!(check_signature(&root, &repaired), Signature::Valid);
    fixture.admin(&["bootstrap"])?;
    Ok(())
}

async fn live_tokens(fixture: &Fixture) -> anyhow::Result<i64> {
    let pool = sqlx::SqlitePool::connect(&fixture.db).await.context("pool")?;
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM access_tokens WHERE revoked = 0")
        .fetch_one(&pool)
        .await
        .context("count")?;
    Ok(row.0)
}

async fn integrity_key(fixture: &Fixture) -> anyhow::Result<IntegrityKey> {
    let root = Fixture::root(&fixture.config().await?)?;
    let wrapped = fixture
        .store()
        .await?
        .get_meta(INTEGRITY_KEY_META)
        .await?
        .context("integrity key")?;
    IntegrityKey::unwrap(&root, &wrapped).context("unwrap")
}

/// After a root key leak, `--new-integrity-key` replaces the key that authenticates credentials,
/// so the leaked key cannot forge them against the live database, and revokes every token.
/// Without it, a rotation keeps both.
#[tokio::test]
async fn rotate_root_key_can_replace_the_integrity_key() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    fixture.admin(&["bootstrap"])?;
    let before = integrity_key(&fixture).await?;
    fixture.admin(&["rotate-root-key"])?;
    let kept = integrity_key(&fixture).await?;
    assert_eq!(
        kept.lookup("t", "x")?,
        before.lookup("t", "x")?,
        "a plain rotation keeps it"
    );
    assert!(live_tokens(&fixture).await? > 0);

    let printed = fixture.admin(&["rotate-root-key", "--new-integrity-key"])?;
    assert!(printed.contains("revoked every token and client secret"), "{printed}");
    let replaced = integrity_key(&fixture).await?;
    assert_ne!(replaced.lookup("t", "x")?, before.lookup("t", "x")?);
    assert_eq!(live_tokens(&fixture).await?, 0);
    fixture.admin(&["bootstrap"])?;
    assert_eq!(live_tokens(&fixture).await?, 1, "a new admin token works as before");
    Ok(())
}

fn exits_with(mut child: std::process::Child) -> anyhow::Result<Output> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        if child.try_wait().context("wait")?.is_some() {
            return child.wait_with_output().context("output");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    anyhow::bail!("the server kept running")
}

/// A Postgres server whose only mark would sit beside a key file on a read-only mount has nowhere
/// to record the seal epoch, so the server and the admin commands refuse to start until
/// `seal.epoch_file` is set.
#[tokio::test]
async fn a_read_only_key_file_alone_is_not_enough_for_the_marks() -> anyhow::Result<()> {
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
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
    let dir = tempfile::tempdir().context("dir")?;
    let keys = dir.path().join("keys");
    std::fs::create_dir(&keys).context("keys")?;
    let key_file = keys.join("root.key");
    let key_arg = key_file.display().to_string();
    let mark = dir.path().join("seal.epoch").display().to_string();
    let admin = |args: &[&str]| {
        let mut full = vec!["admin"];
        full.extend_from_slice(args);
        full.extend_from_slice(&["--database-url", &url, "--root-key-file", &key_arg]);
        run(&full, dir.path())
    };
    ok(admin(&["init", "--key-file-mode", "--epoch-file", &mark])?)?;
    // A key file mounted from a secret never had a mark beside it.
    std::fs::remove_file(keys.join("root.key.epoch")).context("mark beside the key")?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o500)).context("chmod")?;

    let refused = admin(&["bootstrap"]);
    let server = Command::new(BIN)
        .args([
            "server",
            "--listen",
            "127.0.0.1:0",
            "--public-url",
            "http://127.0.0.1",
            "--database-url",
            &url,
            "--root-key-file",
            &key_arg,
        ])
        .env_clear()
        .env("HOME", dir.path())
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("server")
        .and_then(exits_with);
    let with_mark = admin(&["bootstrap", "--epoch-file", &mark]);
    // Put back before asserting, so the temporary directory can be removed.
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).context("chmod back")?;

    let refused = refused?;
    let shown = String::from_utf8_lossy(&refused.stderr).to_string();
    assert!(!refused.status.success(), "{shown}");
    assert!(shown.contains("none can be written"), "{shown}");
    assert!(shown.contains("seal.epoch_file"), "{shown}");
    let server = server?;
    let shown = String::from_utf8_lossy(&server.stderr).to_string();
    assert!(!server.status.success(), "{shown}");
    assert!(shown.contains("none can be written"), "{shown}");
    ok(with_mark?)?;
    Ok(())
}
