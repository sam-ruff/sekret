//! Regressions for the offline admin commands and the seal epoch marks, through the real binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::Context;
use sekret_core::crypto::RootKey;
use sekret_core::seal::{UnlockPolicy, unwrap_root_key};
use sekret_server::seal::{Signature, check_signature, high_water, record_epoch, signed};
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
        sekret_server::config::epoch_files(&self.db, None, None)
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
    record_epoch(&marks, manual.epoch);
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

/// Lowering the marks takes this explicit command, which also re-signs the configuration.
#[tokio::test]
async fn reset_epoch_is_the_only_way_to_lower_the_marks() -> anyhow::Result<()> {
    let (fixture, _) = rolled_forward().await?;
    let marks = fixture.marks();
    record_epoch(&marks, 1000);
    assert_eq!(high_water(&marks).highest, Some(1000), "raising is allowed");
    record_epoch(&marks, 5);
    assert_eq!(high_water(&marks).highest, Some(1000), "lowering is not");

    let printed = fixture.admin(&["reset-epoch"])?;
    let config = fixture.config().await?;
    assert!(config.epoch < 1000);
    assert_eq!(high_water(&marks).highest, Some(config.epoch), "{printed}");
    let root = Fixture::root(&config)?;
    assert_eq!(check_signature(&root, &config), Signature::Valid);
    assert_eq!(
        config.unlock_policy,
        UnlockPolicy::Manual,
        "a sound configuration keeps its policy"
    );

    // A damaged mark is repaired the same way, and a tampered configuration loses its grant.
    for mark in &marks {
        std::fs::write(mark, "garbage").context("damage")?;
    }
    assert!(high_water(&marks).broken);
    let tampered = SealConfig {
        unlock_policy: UnlockPolicy::PassphraseFile,
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
