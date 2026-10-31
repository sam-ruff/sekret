//! Files the CLI reads secrets from are checked before use: a warning names any that other users
//! can read, that another user owns, or whose directory lets others replace them.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::Context;

const BIN: &str = env!("CARGO_BIN_EXE_sekret");
const PASSPHRASE: &str = "violet tractor sings beneath";
/// Nothing listens here, so commands that would go to a server fail straight away.
const CLOSED: &str = "http://127.0.0.1:1";
const READABLE: &str = "other users can read it";
const REPLACEABLE: &str = "writable by every user";

fn run(args: &[&str], env: &[(&str, &str)], dir: &Path) -> anyhow::Result<Output> {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .current_dir(dir);
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().context("run sekret")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn write(path: &Path, contents: &str, mode: u32) -> anyhow::Result<String> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).context("chmod")?;
    Ok(path.display().to_string())
}

/// A directory anyone can write to, inside `dir`.
fn open_dir(dir: &Path) -> anyhow::Result<PathBuf> {
    let open = dir.join("open");
    std::fs::create_dir(&open).context("mkdir")?;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
    Ok(open)
}

/// Runs `args` with `{file}` replaced by a file holding `contents`, as it is mode 0644, mode 0600
/// and mode 0600 in an open directory, and checks which runs warn.
fn check_warnings(
    args: &[&str],
    env: &[(&str, &str)],
    contents: &str,
    prepare: &dyn Fn(&Path) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let cases = [
        (0o644, false, Some(READABLE)),
        (0o600, false, None),
        (0o600, true, Some(REPLACEABLE)),
    ];
    for (mode, in_open_dir, expected) in cases {
        let dir = tempfile::tempdir().context("dir")?;
        prepare(dir.path())?;
        let home = if in_open_dir {
            open_dir(dir.path())?
        } else {
            dir.path().to_path_buf()
        };
        let file = write(&home.join("secret"), contents, mode)?;
        let args: Vec<&str> = args
            .iter()
            .map(|a| if *a == "{file}" { file.as_str() } else { a })
            .collect();
        let env: Vec<(&str, &str)> = env
            .iter()
            .map(|(k, v)| (*k, if *v == "{file}" { file.as_str() } else { v }))
            .collect();
        let text = stderr(&run(&args, &env, dir.path())?);
        match expected {
            Some(warning) => assert!(
                text.contains("sekret: warning:") && text.contains(warning) && text.contains(&file),
                "{args:?} {mode:o} {in_open_dir}: {text}"
            ),
            None => assert!(!text.contains("sekret: warning:"), "{args:?} {mode:o}: {text}"),
        }
        assert!(!text.contains(PASSPHRASE) && !text.contains("sks_secret"), "{text}");
    }
    Ok(())
}

fn nothing(_: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[test]
fn passphrase_files_others_can_read_or_replace_are_warned_about() -> anyhow::Result<()> {
    check_warnings(
        &[
            "admin",
            "init",
            "--database-url",
            "sqlite://sekret.db?mode=rwc",
            "--passphrase-file",
            "{file}",
            "--unlock",
            "manual",
        ],
        &[],
        &format!("{PASSPHRASE}\n"),
        &nothing,
    )?;
    check_warnings(
        &["sys", "unseal", "--passphrase-file", "{file}"],
        &[("SEKRET_URL", CLOSED)],
        &format!("{PASSPHRASE}\n"),
        &nothing,
    )
}

#[test]
fn setup_code_files_are_checked() -> anyhow::Result<()> {
    check_warnings(
        &[
            "sys",
            "init",
            "--setup-code-file",
            "{file}",
            "--passphrase-file",
            "-",
            "--unlock",
            "manual",
        ],
        &[("SEKRET_URL", CLOSED)],
        "ABCD-EFGH\n",
        &nothing,
    )
}

#[test]
fn client_secret_files_are_checked() -> anyhow::Result<()> {
    check_warnings(
        &[
            "login",
            "--client-id",
            "id",
            "--client-secret-file",
            "{file}",
            "--print-token",
        ],
        &[("SEKRET_URL", CLOSED)],
        "sks_secret\n",
        &nothing,
    )
}

#[test]
fn client_keys_are_checked_from_flags_and_the_environment() -> anyhow::Result<()> {
    let cert = |dir: &Path| write(&dir.join("cert.pem"), "not a certificate", 0o644).map(|_| ());
    check_warnings(
        &["whoami", "--client-cert", "cert.pem", "--client-key", "{file}"],
        &[("SEKRET_URL", CLOSED), ("SEKRET_TOKEN", "skt_x")],
        "not a key",
        &cert,
    )?;
    check_warnings(
        &["whoami"],
        &[
            ("SEKRET_URL", CLOSED),
            ("SEKRET_TOKEN", "skt_x"),
            ("SEKRET_CLIENT_CERT", "cert.pem"),
            ("SEKRET_CLIENT_KEY", "{file}"),
        ],
        "not a key",
        &cert,
    )
}
