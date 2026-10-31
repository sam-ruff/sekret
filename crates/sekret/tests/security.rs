//! Regressions for the first security audit, through the real binary: setup codes, passphrase
//! sources, offline rotation and restore.

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context;
use sekret_server::testkit::process::{log_filter, read_log, wait_for_listening};

const BIN: &str = env!("CARGO_BIN_EXE_sekret");
const PASSPHRASE: &str = "violet tractor sings beneath";
const START_TIMEOUT: Duration = Duration::from_secs(20);

static LAUNCHES: AtomicUsize = AtomicUsize::new(0);

fn run(args: &[&str], env: &[(&str, &str)], dir: &Path) -> anyhow::Result<Output> {
    Command::new(BIN)
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .envs(env.iter().copied())
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .context("run")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn ok(output: Output) -> anyhow::Result<String> {
    anyhow::ensure!(output.status.success(), "command failed: {}", text(&output));
    String::from_utf8(output.stdout).context("utf8")
}

struct Server {
    child: Child,
    url: String,
    log: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn log(&self) -> String {
        read_log(&self.log)
    }

    fn sys_status(&self, dir: &Path) -> anyhow::Result<Option<i32>> {
        Ok(run(&["sys", "status"], &[("SEKRET_URL", self.url.as_str())], dir)?
            .status
            .code())
    }
}

async fn spawn(args: &[&str], env: &[(&str, &str)], dir: &Path) -> anyhow::Result<Server> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let n = LAUNCHES.fetch_add(1, Ordering::SeqCst);
    let log = dir.join(format!("server-{n}.log"));
    let level = env
        .iter()
        .find(|(key, _)| *key == "SEKRET_LOG")
        .map_or("info", |(_, value)| *value);
    let mut full = vec!["server", "--listen", "127.0.0.1:0", "--public-url", "http://127.0.0.1"];
    full.extend_from_slice(args);
    let child = Command::new(BIN)
        .args(&full)
        .current_dir(dir)
        .env_clear()
        .envs(env.iter().copied())
        .env("SEKRET_LOG", log_filter(level))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).context("log")?)
        .spawn()
        .context("server")?;
    let mut server = Server {
        child,
        url: String::new(),
        log,
    };
    let address = wait_for_listening(&mut server.child, &server.log, START_TIMEOUT).await?;
    server.url = format!("http://{address}");
    Ok(server)
}

fn sqlite(dir: &Path, name: &str) -> String {
    format!("sqlite://{}?mode=rwc", dir.join(name).display())
}

fn passphrase_db(dir: &Path) -> anyhow::Result<String> {
    std::fs::write(dir.join("pass"), format!("{PASSPHRASE}\n")).context("pass")?;
    let db = sqlite(dir, "sekret.db");
    ok(run(
        &["admin", "init", "--database-url", &db, "--passphrase-file", "pass"],
        &[],
        dir,
    )?)?;
    Ok(db)
}

#[tokio::test]
async fn the_setup_code_reaches_stderr_with_quiet_logging_and_goes_after_setup() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    std::fs::write(d.join("pass"), format!("{PASSPHRASE}\n")).context("pass")?;
    let db = sqlite(d, "sekret.db");
    let server = spawn(
        &["--database-url", &db, "--setup-code-file", "code"],
        &[("SEKRET_LOG", "warn")],
        d,
    )
    .await?;
    let log = server.log();
    let line = log
        .lines()
        .find(|l| l.starts_with("sekret setup code: "))
        .with_context(|| format!("no setup code on stderr: {log}"))?;
    let code = line.trim_start_matches("sekret setup code: ").trim().to_string();
    assert_eq!(
        std::fs::read_to_string(d.join("code")).context("code file")?.trim(),
        code
    );
    let output = run(
        &[
            "sys",
            "init",
            "--setup-code-file",
            "code",
            "--passphrase-file",
            "pass",
            "--unlock",
            "manual",
        ],
        &[("SEKRET_URL", server.url.as_str())],
        d,
    )?;
    ok(output)?;
    assert!(!d.join("code").exists(), "the setup code file is removed after setup");
    Ok(())
}

#[tokio::test]
async fn no_setup_code_is_made_when_web_setup_is_off() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = sqlite(d, "sekret.db");
    let server = spawn(
        &["--database-url", &db, "--web-setup=false", "--setup-code-file", "code"],
        &[],
        d,
    )
    .await?;
    let log = server.log();
    assert!(!log.contains("setup code:"), "{log}");
    assert!(log.contains("sekret admin init"), "{log}");
    assert!(!d.join("code").exists());
    Ok(())
}

#[tokio::test]
async fn the_unlock_passphrase_from_the_environment_loses_its_newline() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = passphrase_db(d)?;
    let with_newline = format!("{PASSPHRASE}\n");
    let server = spawn(
        &["--database-url", &db, "--unlock", "passphrase-file"],
        &[("SEKRET_UNLOCK_PASSPHRASE", with_newline.as_str())],
        d,
    )
    .await?;
    assert_eq!(server.sys_status(d)?, Some(0), "{}", server.log());
    let log = server.log();
    assert!(
        log.contains("seal.unlock") && log.contains("passphrase-file") && log.contains("flag"),
        "the startup log names each setting's origin: {log}"
    );
    assert!(!log.contains(PASSPHRASE), "but never a secret");
    drop(server);

    // Under the manual policy the variable is not used at all.
    let server = spawn(&["--database-url", &db], &[("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE)], d).await?;
    assert_eq!(server.sys_status(d)?, Some(2));
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_device_as_the_passphrase_file_cannot_hang_or_exhaust_the_server() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = passphrase_db(d)?;
    let server = spawn(
        &[
            "--database-url",
            &db,
            "--unlock",
            "passphrase-file",
            "--unlock-passphrase-file",
            "/dev/zero",
        ],
        &[],
        d,
    )
    .await?;
    assert_eq!(server.sys_status(d)?, Some(2));
    assert!(server.log().contains("not a regular file"), "{}", server.log());
    Ok(())
}

#[tokio::test]
async fn auto_init_checks_the_admin_token_file_first() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    std::fs::write(d.join("pass"), format!("{PASSPHRASE}\n")).context("pass")?;
    std::fs::write(d.join("token"), "already here").context("token")?;
    let db = sqlite(d, "sekret.db");
    let output = run(
        &[
            "server",
            "--listen",
            "127.0.0.1:0",
            "--public-url",
            "http://127.0.0.1",
            "--database-url",
            &db,
            "--auto-init",
            "--setup-passphrase-file",
            "pass",
            "--setup-admin-token-file",
            "token",
        ],
        &[],
        d,
    )?;
    assert!(!output.status.success());
    assert!(text(&output).contains("must not exist yet"), "{}", text(&output));
    let store = sekret_store::SqlStore::connect(&db).await.context("store")?;
    use sekret_store::Store;
    assert!(store.get_seal_config().await?.is_none(), "nothing was initialised");
    Ok(())
}

#[tokio::test]
async fn rotating_the_root_key_always_checks_the_passphrase() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    std::fs::write(d.join("pass"), format!("{PASSPHRASE}\n")).context("pass")?;
    std::fs::write(d.join("typo"), "violet tractor sings beneathh\n").context("typo")?;
    let db = sqlite(d, "sekret.db");
    ok(run(
        &[
            "admin",
            "init",
            "--database-url",
            &db,
            "--key-file-mode",
            "--root-key-file",
            "root.key",
        ],
        &[],
        d,
    )?)?;
    ok(run(
        &[
            "admin",
            "set-seal-mode",
            "passphrase",
            "--database-url",
            &db,
            "--root-key-file",
            "root.key",
            "--passphrase-file",
            "pass",
        ],
        &[],
        d,
    )?)?;
    // The key file is still there; a typo must not become the new passphrase.
    let typo = run(
        &[
            "admin",
            "rotate-root-key",
            "--database-url",
            &db,
            "--root-key-file",
            "root.key",
            "--passphrase-file",
            "typo",
        ],
        &[],
        d,
    )?;
    assert!(!typo.status.success());
    assert!(text(&typo).contains("the passphrase is wrong"), "{}", text(&typo));
    let rotated = ok(run(
        &[
            "admin",
            "rotate-root-key",
            "--database-url",
            &db,
            "--root-key-file",
            "root.key",
            "--passphrase-file",
            "pass",
        ],
        &[],
        d,
    )?);
    assert!(rotated.is_ok());
    ok(run(
        &["admin", "bootstrap", "--database-url", &db, "--passphrase-file", "pass"],
        &[],
        d,
    )?)?;
    Ok(())
}

/// A real key-file database in a `.skb` backup, and the key that opens it.
async fn sample_backup(dir: &Path) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf, String)> {
    use sekret_core::crypto::RootKey;
    use sekret_core::seal::{BackupHeader, SealMode, encrypt_backup};
    let root = RootKey::generate().context("root")?;
    let source = dir.join("source.db");
    {
        let store = sekret_store::SqlStore::connect(&format!("sqlite://{}?mode=rwc", source.display()))
            .await
            .context("store")?;
        sekret_server::check_root_key(&store, &root.fingerprint())
            .await
            .context("fingerprint")?;
        let snapshot = dir.join("snapshot.db");
        let config = sekret_store::SealConfig {
            mode: SealMode::KeyFile,
            wrapped: None,
            unlock_policy: sekret_core::seal::UnlockPolicy::Manual,
            remembered: None,
            epoch: 0,
            mac: None,
            flags: sekret_core::seal::SealFlags::default(),
            created_at: 1,
            updated_at: 1,
        };
        use sekret_store::Store;
        store
            .init_seal_config(config.clone(), &root.fingerprint())
            .await
            .context("seal")?;
        store
            .snapshot_to(&snapshot.display().to_string(), config)
            .await
            .context("snapshot")?;
    }
    let snapshot = std::fs::read(dir.join("snapshot.db")).context("read")?;
    let header = BackupHeader::new(SealMode::KeyFile, None, &root, 1_700_000_123, "test");
    let file = encrypt_backup(&root, &header, &snapshot).context("encrypt")?;
    let backup = dir.join("backup.skb");
    std::fs::write(&backup, file).context("write")?;
    let key = dir.join("root.key");
    std::fs::write(&key, root.to_base64().as_bytes()).context("key")?;
    Ok((backup, key, root.fingerprint()))
}

#[tokio::test]
async fn restore_refuses_leftovers_and_places_the_file_atomically() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let (backup, key, fingerprint) = sample_backup(d).await?;
    let target = sqlite(d, "restored.db");
    let restore = |target: &str| {
        run(
            &[
                "admin",
                "restore",
                "--backup",
                &backup.display().to_string(),
                "--database-url",
                target,
                "--root-key-file",
                &key.display().to_string(),
            ],
            &[],
            d,
        )
    };
    for leftover in ["restored.db-wal", "restored.db-shm", "restored.db-journal"] {
        std::fs::write(d.join(leftover), "x").context("leftover")?;
        let refused = restore(&target)?;
        assert!(!refused.status.success(), "{leftover}");
        assert!(text(&refused).contains(leftover), "{}", text(&refused));
        assert!(!d.join("restored.db").exists());
        std::fs::remove_file(d.join(leftover)).context("remove")?;
    }
    let output = restore(&target)?;
    let shown = text(&output);
    assert!(output.status.success(), "{shown}");
    assert!(shown.contains("1700000123") && shown.contains(&fingerprint), "{shown}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.join("restored.db"))
            .context("meta")?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let names: Vec<String> = std::fs::read_dir(d)
        .context("list")?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(!names.iter().any(|n| n.contains(".restore-")), "{names:?}");
    let again = restore(&target)?;
    assert!(!again.status.success(), "an existing database is never overwritten");
    Ok(())
}

#[test]
fn config_errors_do_not_print_database_passwords() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    std::fs::write(
        d.join("sekret.yaml"),
        "database:\n  url: postgres://sekret:hunter2secret@db/sekret\n  snapshots_to_keep: lots\n",
    )
    .context("config")?;
    let output = run(
        &["server", "--config", "sekret.yaml", "--public-url", "https://x"],
        &[],
        d,
    )?;
    assert!(!output.status.success());
    assert!(!text(&output).contains("hunter2secret"), "{}", text(&output));
    Ok(())
}
