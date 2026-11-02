//! Regressions for the tenth security audit, through the real binary: a remembered unlock left
//! behind by `--unlock manual`, a passphrase wrap planted in a key-file database, and core dumps.

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context;
use sekret_core::crypto::RootKey;
use sekret_core::seal::{SealMode, wrap_root_key};
use sekret_server::testkit::process::{log_filter, wait_for_listening};
use sekret_store::{SqlStore, Store};

const BIN: &str = env!("CARGO_BIN_EXE_sekret");
const START_TIMEOUT: Duration = Duration::from_secs(20);
const PASSPHRASE: &str = "violet tractor sings beneath";

static LAUNCHES: AtomicUsize = AtomicUsize::new(0);

struct Server {
    child: Child,
    url: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run(args: &[&str], dir: &Path, url: Option<&str>) -> anyhow::Result<Output> {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .current_dir(dir)
        .stdin(Stdio::null());
    if let Some(url) = url {
        command.env("SEKRET_URL", url);
    }
    command.output().context("run")
}

fn ok(output: Output) -> anyhow::Result<String> {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("utf8")
}

async fn spawn(args: &[&str], dir: &Path) -> anyhow::Result<Server> {
    let n = LAUNCHES.fetch_add(1, Ordering::SeqCst);
    let log = dir.join(format!("server-{n}.log"));
    let child = Command::new(BIN)
        .args(["server", "--listen", "127.0.0.1:0", "--public-url", "http://127.0.0.1"])
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("SEKRET_LOG", log_filter("warn"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).context("log")?)
        .spawn()
        .context("server")?;
    let mut server = Server {
        child,
        url: String::new(),
    };
    let address = wait_for_listening(&mut server.child, &log, START_TIMEOUT).await?;
    server.url = format!("http://{address}");
    Ok(server)
}

fn state(server: &Server, dir: &Path) -> anyhow::Result<Option<i32>> {
    Ok(run(&["sys", "status"], dir, Some(&server.url))?.status.code())
}

async fn stored(db: &str) -> anyhow::Result<sekret_store::SealConfig> {
    let store = SqlStore::connect(db).await.context("store")?;
    store.get_seal_config().await?.context("config")
}

/// The audit's scenario through the flags: remember, then restart with `--unlock manual`.
#[tokio::test]
async fn unlock_manual_forgets_what_remember_kept() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = format!("sqlite://{}?mode=rwc", d.join("sekret.db").display());
    std::fs::write(d.join("pass"), format!("{PASSPHRASE}\n")).context("passphrase file")?;
    ok(run(
        &["admin", "init", "--database-url", &db, "--passphrase-file", "pass"],
        d,
        None,
    )?)?;
    let file = d.join("sekret.unlock-key");
    let with = |unlock: &'static str| {
        vec![
            "--database-url".to_string(),
            db.clone(),
            "--unlock".into(),
            unlock.into(),
            "--remember-file".into(),
            "sekret.unlock-key".into(),
        ]
    };
    let remember = with("remember");
    let remember: Vec<&str> = remember.iter().map(String::as_str).collect();

    let server = spawn(&remember, d).await?;
    ok(run(
        &["sys", "unseal", "--passphrase-file", "pass"],
        d,
        Some(&server.url),
    )?)?;
    assert!(file.exists());
    drop(server);
    assert!(stored(&db).await?.remembered.is_some());

    let manual = with("manual");
    let manual: Vec<&str> = manual.iter().map(String::as_str).collect();
    let server = spawn(&manual, d).await?;
    assert_eq!(state(&server, d)?, Some(2), "sealed");
    assert!(!file.exists(), "the remember file goes at start");
    ok(run(
        &["sys", "unseal", "--passphrase-file", "pass"],
        d,
        Some(&server.url),
    )?)?;
    drop(server);
    assert!(stored(&db).await?.remembered.is_none(), "the unlock forgot the wrap");

    let server = spawn(&remember, d).await?;
    assert_eq!(state(&server, d)?, Some(2), "nothing is left to unlock from");
    Ok(())
}

/// A database writer plants a passphrase wrap of their own in a key-file database. Rotating
/// the root key drops it instead of signing it.
#[tokio::test]
async fn rotating_a_key_file_database_drops_a_planted_wrap() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = format!("sqlite://{}?mode=rwc", d.join("sekret.db").display());
    let key = d.join("root.key").display().to_string();
    ok(run(
        &[
            "admin",
            "init",
            "--database-url",
            &db,
            "--key-file-mode",
            "--root-key-file",
            &key,
        ],
        d,
        None,
    )?)?;
    let config = stored(&db).await?;
    assert_eq!(config.mode, SealMode::KeyFile);
    let attacker = RootKey::generate()?;
    let store = SqlStore::connect(&db).await.context("store")?;
    store
        .update_seal_config(sekret_store::SealConfig {
            wrapped: Some(wrap_root_key(&attacker, "a passphrase the attacker chose")?),
            ..config
        })
        .await?;
    drop(store);

    let new_key = d.join("new.key");
    let generated = ok(run(&["admin", "generate-root-key"], d, None)?)?;
    std::fs::write(&new_key, generated).context("new key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_key, std::fs::Permissions::from_mode(0o600)).context("mode")?;
    }
    let rotated = run(
        &[
            "admin",
            "rotate-root-key",
            "--database-url",
            &db,
            "--root-key-file",
            &key,
            "--new-root-key-file",
            &new_key.display().to_string(),
        ],
        d,
        None,
    )?;
    let stderr = String::from_utf8_lossy(&rotated.stderr).to_string();
    assert!(rotated.status.success(), "{stderr}");
    assert!(stderr.contains("dropping a passphrase wrap"), "{stderr}");
    let config = stored(&db).await?;
    assert!(config.wrapped.is_none(), "the planted wrap is never signed");
    assert_eq!(config.mode, SealMode::KeyFile);

    let server = spawn(
        &["--database-url", &db, "--root-key-file", &new_key.display().to_string()],
        d,
    )
    .await?;
    assert_eq!(state(&server, d)?, Some(0), "unsealed under the new key");
    Ok(())
}

/// The server turns core dumps off before it reads any key.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_server_writes_no_core_dump() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = format!("sqlite://{}?mode=rwc", d.join("sekret.db").display());
    let server = spawn(&["--database-url", &db], d).await?;
    let limits = std::fs::read_to_string(format!("/proc/{}/limits", server.child.id())).context("limits")?;
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .context("core limit")?;
    let fields: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(fields.get(4..6), Some(&["0", "0"][..]), "{core}");
    Ok(())
}
