//! The CLI must not hand its credentials to a server it was not told to trust.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::Context;

const BIN: &str = env!("CARGO_BIN_EXE_sekret");

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

/// A listener standing in for an attacker's server; it records whether anything connected.
struct Trap {
    listener: TcpListener,
    url: String,
}

impl Trap {
    fn new() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").context("bind")?;
        listener.set_nonblocking(true).context("nonblocking")?;
        let url = format!("http://{}", listener.local_addr().context("addr")?);
        Ok(Self { listener, url })
    }

    fn untouched(&self) -> bool {
        matches!(self.listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_hostile_project_file_does_not_receive_the_environment_token() -> anyhow::Result<()> {
    let trap = Trap::new()?;
    let dir = tempfile::tempdir().context("dir")?;
    std::fs::write(
        dir.path().join(".sekret.toml"),
        format!("server = \"{}\"\nproject = \"app\"\nenvironment = \"prod\"\n", trap.url),
    )
    .context("project file")?;
    let env = [("SEKRET_TOKEN", "skt_victim")];
    for args in [&["whoami"][..], &["secrets", "list"], &["sys", "status"], &["export"]] {
        let output = run(args, &env, dir.path())?;
        assert!(!output.status.success(), "{args:?}");
        assert!(stderr(&output).contains("not sent"), "{args:?}: {}", stderr(&output));
    }
    assert!(trap.untouched(), "the token never reached the planted server");

    let login = run(
        &["login", "--client-id", "id"],
        &[("SEKRET_CLIENT_SECRET", "sks_victim")],
        dir.path(),
    )?;
    assert!(!login.status.success());
    assert!(stderr(&login).contains("no credential is sent"), "{}", stderr(&login));
    assert!(trap.untouched(), "the client secret never reached the planted server");

    // Naming the server explicitly is a deliberate choice and goes ahead. The trap is closed first
    // so the attempt fails at once instead of waiting for an answer.
    let url = trap.url.clone();
    drop(trap);
    let confirmed = run(
        &["whoami"],
        &[("SEKRET_TOKEN", "skt_victim"), ("SEKRET_URL", &url)],
        dir.path(),
    )?;
    assert!(!confirmed.status.success(), "nothing listens any more");
    assert!(!stderr(&confirmed).contains("not sent"), "{}", stderr(&confirmed));
    Ok(())
}

#[cfg(unix)]
#[test]
fn project_files_in_world_writable_directories_are_ignored() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let trap = Trap::new()?;
    let dir = tempfile::tempdir().context("dir")?;
    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).context("mkdir")?;
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
    std::fs::write(shared.join(".sekret.toml"), format!("server = \"{}\"\n", trap.url)).context("plant")?;
    let output = run(&["whoami"], &[], &shared)?;
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(
        text.contains("ignoring") && text.contains("writable by every user"),
        "{text}"
    );
    assert!(text.contains("no server configured"), "{text}");
    assert!(trap.untouched());
    Ok(())
}

#[test]
fn plain_http_to_another_host_is_refused_unless_allowed() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    // 0.0.0.0 is not a loopback name, but a connection to it fails at once when it is allowed.
    let env = [("SEKRET_URL", "http://0.0.0.0:1"), ("SEKRET_TOKEN", "skt_x")];
    let refused = run(&["whoami"], &env, dir.path())?;
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("plain http"), "{}", stderr(&refused));
    let status = run(&["sys", "status"], &env, dir.path())?;
    assert!(stderr(&status).contains("plain http"), "{}", stderr(&status));

    let mut allowed_env = env.to_vec();
    allowed_env.push(("SEKRET_CLIENT_ALLOW_INSECURE_HTTP", "true"));
    for (args, env) in [
        (&["whoami", "--allow-insecure-http"][..], &env[..]),
        (&["whoami"][..], &allowed_env[..]),
    ] {
        let allowed = run(args, env, dir.path())?;
        assert!(
            !stderr(&allowed).contains("plain http"),
            "{args:?}: {}",
            stderr(&allowed)
        );
    }
    Ok(())
}
