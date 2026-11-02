//! `sekret token` on the real binary: the saved login for the resolved server, its exit codes, the
//! terminal refusal, and `--context` with where each setting came from.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use anyhow::Context;

const BIN: &str = env!("CARGO_BIN_EXE_sekret");
const LATER: i64 = 4_102_444_800;

fn command(args: &[&str], env: &[(&str, &str)], dir: &Path) -> Command {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .current_dir(dir.join("work"));
    for (k, v) in env {
        command.env(k, v);
    }
    command
}

fn run(args: &[&str], env: &[(&str, &str)], dir: &Path) -> anyhow::Result<Output> {
    command(args, env, dir).output().context("run sekret")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn home() -> anyhow::Result<tempfile::TempDir> {
    let dir = tempfile::tempdir().context("dir")?;
    let config = dir.path().join("config").join("sekret");
    std::fs::create_dir_all(&config).context("config dir")?;
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    std::fs::create_dir(dir.path().join("work")).context("work dir")?;
    Ok(dir)
}

fn private_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents).context("write")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).context("chmod")
}

fn save_login(dir: &Path, server: &str, token: &str, expires_at: i64) -> anyhow::Result<()> {
    private_file(
        &dir.join("config/sekret/credentials.toml"),
        &format!("[servers.\"{server}\"]\ntoken = \"{token}\"\nexpires_at = {expires_at}\n"),
    )
}

#[test]
fn prints_the_saved_token_for_the_chosen_server_and_nothing_else() -> anyhow::Result<()> {
    let dir = home()?;
    save_login(dir.path(), "https://saved.test", "saved-token", LATER)?;
    let output = run(&["token", "--server", "https://saved.test"], &[], dir.path())?;
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "saved-token\n");
    Ok(())
}

#[test]
fn not_logged_in_and_expired_have_their_own_exit_codes() -> anyhow::Result<()> {
    let dir = home()?;
    save_login(dir.path(), "https://old.test", "old-token", 1)?;
    let missing = run(&["token", "--server", "https://other.test"], &[], dir.path())?;
    assert_eq!(missing.status.code(), Some(3));
    assert!(text(&missing.stderr).contains("not logged in"));
    let expired = run(&["token", "--server", "https://old.test"], &[], dir.path())?;
    assert_eq!(expired.status.code(), Some(4));
    assert!(text(&expired.stderr).contains("expired"));
    assert!(expired.stdout.is_empty() && !text(&expired.stderr).contains("old-token"));
    Ok(())
}

#[test]
fn a_token_in_the_environment_is_never_printed_as_the_saved_one() -> anyhow::Result<()> {
    let dir = home()?;
    let output = run(
        &["token", "--server", "https://none.test"],
        &[("SEKRET_TOKEN", "from-env")],
        dir.path(),
    )?;
    assert_eq!(output.status.code(), Some(3));
    assert!(!text(&output.stdout).contains("from-env") && !text(&output.stderr).contains("from-env"));
    Ok(())
}

#[test]
fn the_server_comes_from_the_environment_or_the_user_config() -> anyhow::Result<()> {
    let dir = home()?;
    save_login(dir.path(), "https://env.test", "env-token", LATER)?;
    let output = run(&["token"], &[("SEKRET_URL", "https://env.test")], dir.path())?;
    assert_eq!(text(&output.stdout), "env-token\n");

    private_file(
        &dir.path().join("config/sekret/config.toml"),
        "server = \"https://env.test\"\n",
    )?;
    let output = run(&["token"], &[], dir.path())?;
    assert_eq!(text(&output.stdout), "env-token\n");
    Ok(())
}

/// Opens a pseudo-terminal and returns its secondary side, for a child's stdout.
fn terminal() -> anyhow::Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::FromRawFd;
    // SAFETY: posix_openpt returns a new descriptor or -1; it is owned by the File from here on.
    let primary = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    anyhow::ensure!(primary >= 0, "posix_openpt: {}", std::io::Error::last_os_error());
    // SAFETY: as above.
    let primary_file = unsafe { std::fs::File::from_raw_fd(primary) };
    // SAFETY: primary is a valid pseudo-terminal descriptor.
    anyhow::ensure!(unsafe { libc::grantpt(primary) } == 0, "grantpt");
    // SAFETY: as above.
    anyhow::ensure!(unsafe { libc::unlockpt(primary) } == 0, "unlockpt");
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: the buffer and its length describe `name`.
    anyhow::ensure!(
        unsafe { libc::ptsname_r(primary, name.as_mut_ptr(), name.len()) } == 0,
        "ptsname_r"
    );
    // SAFETY: ptsname_r wrote a NUL-terminated path into `name`.
    let path = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let secondary = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .context("open terminal")?;
    Ok((primary_file, secondary))
}

#[cfg(target_os = "linux")]
#[test]
fn a_terminal_gets_the_token_only_with_show() -> anyhow::Result<()> {
    let dir = home()?;
    save_login(dir.path(), "https://saved.test", "saved-token", LATER)?;
    let (_primary, secondary) = terminal()?;
    let refused = command(&["token", "--server", "https://saved.test"], &[], dir.path())
        .stdout(Stdio::from(secondary.try_clone().context("clone")?))
        .stderr(Stdio::piped())
        .output()
        .context("run")?;
    assert!(!refused.status.success());
    assert!(text(&refused.stderr).contains("--show"), "{}", text(&refused.stderr));

    let shown = command(&["token", "--show", "--server", "https://saved.test"], &[], dir.path())
        .stdout(Stdio::from(secondary))
        .stderr(Stdio::piped())
        .status()
        .context("run")?;
    assert!(shown.success());
    Ok(())
}

fn context(env: &[(&str, &str)], args: &[&str], dir: &Path) -> anyhow::Result<serde_json::Value> {
    let mut all = vec!["token", "--context"];
    all.extend_from_slice(args);
    let output = run(&all, env, dir)?;
    anyhow::ensure!(output.status.success(), "{}", text(&output.stderr));
    serde_json::from_slice(&output.stdout).context("json")
}

#[test]
fn context_reports_each_setting_and_its_source_without_a_token() -> anyhow::Result<()> {
    let dir = home()?;
    save_login(dir.path(), "https://saved.test", "saved-token", LATER)?;
    let value = context(
        &[("SEKRET_URL", "https://saved.test"), ("SEKRET_ENVIRONMENT", "staging")],
        &["--project", "app"],
        dir.path(),
    )?;
    assert_eq!(value["server"], "https://saved.test");
    assert_eq!(value["server_source"], "environment");
    assert_eq!(value["project"], "app");
    assert_eq!(value["project_source"], "flag");
    assert_eq!(value["environment"], "staging");
    assert_eq!(value["environment_source"], "environment");
    assert_eq!(value["path"], "/");
    assert_eq!(value["path_source"], "default");
    assert!(!value.to_string().contains("saved-token"));
    Ok(())
}

#[test]
fn context_refuses_a_project_file_choice_nobody_confirmed() -> anyhow::Result<()> {
    let dir = home()?;
    std::fs::write(
        dir.path().join("work/.sekret.toml"),
        "project = \"app\"\nenvironment = \"prod\"\n",
    )
    .context("project file")?;
    let output = run(
        &["token", "--context", "--server", "https://saved.test"],
        &[],
        dir.path(),
    )?;
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("sekret export"),
        "{}",
        text(&output.stderr)
    );

    // Named explicitly, the file's choice no longer matters.
    let value = context(
        &[("SEKRET_PROJECT", "app"), ("SEKRET_ENVIRONMENT", "prod")],
        &["--server", "https://saved.test"],
        dir.path(),
    )?;
    assert_eq!(value["project_source"], "environment");
    Ok(())
}
