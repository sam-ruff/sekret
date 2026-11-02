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

fn plant_project_file(dir: &Path, server: &str) -> anyhow::Result<()> {
    std::fs::write(dir.join(".sekret.toml"), format!("server = \"{server}\"\n")).context("project file")
}

/// `sys` commands carry passphrases and setup codes, so a planted project file must not be
/// enough to send them (round 3, demonstrated).
#[test]
fn sys_commands_never_send_secrets_to_a_server_only_the_project_file_names() -> anyhow::Result<()> {
    let trap = Trap::new()?;
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    plant_project_file(d, &trap.url)?;
    std::fs::write(d.join("pass"), "violet tractor sings beneath\n").context("pass")?;
    let commands: [&[&str]; 6] = [
        &["sys", "unseal", "--passphrase-file", "pass"],
        &[
            "sys",
            "init",
            "--setup-code",
            "ABCD-EFGH-JKMN",
            "--passphrase-file",
            "pass",
            "--unlock",
            "manual",
        ],
        &[
            "sys",
            "change-passphrase",
            "--passphrase-file",
            "pass",
            "--new-passphrase-file",
            "pass",
        ],
        &["sys", "unlock-policy", "remember", "--passphrase-file", "pass"],
        &["sys", "status"],
        &["sys", "backup", "-o", "out.skb"],
    ];
    for args in commands {
        let output = run(args, &[], d)?;
        assert!(!output.status.success(), "{args:?}");
        assert!(
            stderr(&output).contains("no credential is sent"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    assert!(trap.untouched(), "nothing reached the planted server");
    Ok(())
}

/// Logging in once to a planted server must not make it trusted for every later token, and the
/// login itself needs a person at a terminal.
#[test]
fn a_saved_login_does_not_vouch_for_other_credentials() -> anyhow::Result<()> {
    let trap = Trap::new()?;
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    plant_project_file(d, &trap.url)?;

    let login = run(&["login", "--no-browser"], &[], d)?;
    assert!(!login.status.success(), "no terminal to confirm on");
    assert!(stderr(&login).contains("no credential is sent"), "{}", stderr(&login));
    assert!(trap.untouched(), "the login never started");

    // As if the person had logged in to it earlier.
    let config = d.join("config").join("sekret");
    std::fs::create_dir_all(&config).context("config dir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    }
    let credentials = config.join("credentials.toml");
    std::fs::write(
        &credentials,
        format!(
            "[servers.\"{}\"]\ntoken = \"skt_planted\"\nexpires_at = 99999999999\n",
            trap.url
        ),
    )
    .context("credentials")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    }
    let with_env_token = run(&["whoami"], &[("SEKRET_TOKEN", "skt_victim")], d)?;
    assert!(!with_env_token.status.success());
    assert!(
        stderr(&with_env_token).contains("not sent"),
        "{}",
        stderr(&with_env_token)
    );
    let machine = run(
        &["login", "--client-id", "id"],
        &[("SEKRET_CLIENT_SECRET", "sks_victim")],
        d,
    )?;
    assert!(
        stderr(&machine).contains("no credential is sent"),
        "{}",
        stderr(&machine)
    );
    assert!(trap.untouched(), "neither the token nor the client secret was sent");
    Ok(())
}

#[cfg(unix)]
#[test]
fn credentials_others_can_change_are_refused() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let config = d.join("config").join("sekret");
    std::fs::create_dir_all(&config).context("config dir")?;
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    let credentials = config.join("credentials.toml");
    std::fs::write(&credentials, "").context("credentials")?;
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
    let output = run(&["whoami"], &[("SEKRET_URL", "http://127.0.0.1:1")], d)?;
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("other users can change it"),
        "{}",
        stderr(&output)
    );
    Ok(())
}

/// A relative `XDG_CONFIG_HOME` would read credentials from whatever directory the command runs in.
#[test]
fn a_relative_xdg_config_home_is_not_used() -> anyhow::Result<()> {
    let trap = Trap::new()?;
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    plant_project_file(d, &trap.url)?;
    let planted = d.join("rel").join("sekret");
    std::fs::create_dir_all(&planted).context("dir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    }
    std::fs::write(
        planted.join("credentials.toml"),
        format!(
            "[servers.\"{}\"]\ntoken = \"skt_planted\"\nexpires_at = 99999999999\n",
            trap.url
        ),
    )
    .context("credentials")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(planted.join("credentials.toml"), std::fs::Permissions::from_mode(0o600))
            .context("chmod")?;
    }
    let output = run(
        &["sys", "unseal", "--passphrase-file", "-"],
        &[("XDG_CONFIG_HOME", "rel")],
        d,
    )?;
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no credential is sent"), "{}", stderr(&output));
    assert!(trap.untouched());
    Ok(())
}

/// One of this user's groups other than their private one (same number as their user id).
#[cfg(unix)]
fn shared_group() -> anyhow::Result<Option<u32>> {
    let id = |flag: &str| -> anyhow::Result<String> {
        let output = Command::new("id").arg(flag).output().context("id")?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    };
    let uid = id("-u")?;
    let gid = id("-g")?;
    Ok(id("-G")?
        .split_whitespace()
        .find(|g| !(*g == gid && *g == uid))
        .and_then(|g| g.parse().ok()))
}

#[cfg(unix)]
#[test]
fn project_files_in_group_writable_directories_are_ignored() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(group) = shared_group()? else {
        return Ok(());
    };
    let trap = Trap::new()?;
    let dir = tempfile::tempdir().context("dir")?;
    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).context("mkdir")?;
    std::os::unix::fs::chown(&shared, None, Some(group)).context("chgrp")?;
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o770)).context("chmod")?;
    plant_project_file(&shared, &trap.url)?;
    let output = run(&["whoami"], &[], &shared)?;
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(text.contains("writable by its group"), "{text}");
    assert!(text.contains("no server configured"), "{text}");
    assert!(trap.untouched());
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

#[cfg(unix)]
#[test]
fn project_files_others_can_edit_are_ignored() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let trap = Trap::new()?;
    let dir = tempfile::tempdir().context("dir")?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    let path = dir.path().join(".sekret.toml");
    std::fs::write(&path, format!("server = \"{}\"\n", trap.url)).context("write")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
    let output = run(&["whoami"], &[], dir.path())?;
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(
        text.contains("ignoring") && text.contains("it is writable by every user"),
        "{text}"
    );
    assert!(text.contains("no server configured"), "{text}");
    assert!(trap.untouched());
    Ok(())
}

/// Answers every connection with a 401 and records the request heads it saw, so a client that
/// reaches it gets a quick failure instead of waiting for a timeout.
struct Responder {
    url: String,
    seen: std::sync::mpsc::Receiver<String>,
}

impl Responder {
    fn start() -> anyhow::Result<Self> {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").context("bind")?;
        let url = format!("http://{}", listener.local_addr().context("addr")?);
        let (tx, seen) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(&stream);
                let mut first = [0u8; 1];
                let mut head = String::new();
                // A TLS handshake starts with 0x16 and has no header lines to wait for.
                if reader.read_exact(&mut first).is_ok() && first[0].is_ascii_alphabetic() {
                    head.push(char::from(first[0]));
                    let mut line = String::new();
                    while reader.read_line(&mut line).is_ok_and(|n| n > 0) && line != "\r\n" {
                        head.push_str(&line);
                        line.clear();
                    }
                }
                if tx.send(head).is_err() {
                    return;
                }
                let _ = (&stream).write_all(
                    b"HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
                );
            }
        });
        Ok(Self { url, seen })
    }

    fn requests(&self) -> Vec<String> {
        self.seen.try_iter().collect()
    }
}

fn proxy_env(proxy: &str) -> Vec<(&'static str, String)> {
    [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ]
    .into_iter()
    .map(|name| (name, proxy.to_string()))
    .collect()
}

/// A proxy would read plain http, tokens and passphrases included, and would reach its own
/// loopback rather than ours, so the CLI never uses one for plain http or for this machine.
#[test]
fn proxies_are_not_used_for_plain_http_or_loopback() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let proxy = Responder::start()?;
    let server = Responder::start()?;
    let port = server.url.rsplit(':').next().context("port")?.to_string();
    let mut env: Vec<(&str, String)> = proxy_env(&proxy.url);
    env.push(("SEKRET_TOKEN", "skt_proxy_canary".to_string()));
    env.push(("NO_PROXY", String::new()));
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    for host in ["localhost", "127.0.0.1", "LOCALHOST"] {
        let url = format!("http://{host}:{port}");
        let output = run(&["--server", &url, "whoami"], &env, dir.path())?;
        assert!(!output.status.success(), "the stand-in server answers 401");
        let direct = server.requests();
        assert_eq!(direct.len(), 1, "{host}: {direct:?}");
        assert!(direct[0].contains("skt_proxy_canary"), "{host}: {direct:?}");
    }
    // https to this machine also stays off the proxy. The stand-in does not speak TLS, so the
    // handshake fails, but it fails against the right listener.
    let output = run(
        &["--server", &format!("https://localhost:{port}"), "whoami"],
        &env,
        dir.path(),
    )?;
    assert!(!output.status.success());
    assert_eq!(
        server.requests().len(),
        1,
        "the TLS attempt went straight to the server"
    );
    // Plain http to another host, once allowed, does not go through the proxy either.
    let output = run(
        &["--server", "http://0.0.0.0:1", "--allow-insecure-http", "whoami"],
        &env,
        dir.path(),
    )?;
    assert!(!output.status.success());
    assert!(proxy.requests().is_empty(), "{:?}", proxy.requests());

    // The proxy settings above are live: https to another host does use them.
    let output = run(&["--server", "https://sekret.invalid", "whoami"], &env, dir.path())?;
    assert!(!output.status.success());
    let tunnelled = proxy.requests();
    assert_eq!(tunnelled.len(), 1, "{tunnelled:?}");
    assert!(tunnelled[0].starts_with("CONNECT sekret.invalid:443"), "{tunnelled:?}");
    assert!(!tunnelled[0].contains("skt_proxy_canary"), "the token stays inside TLS");
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
