//! Drives the real `sekret` binary: a server process plus CLI commands against it.

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context;
use sekret_server::testkit::process::{log_filter, wait_for_listening};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_sekret");
const START_TIMEOUT: Duration = Duration::from_secs(20);

static LAUNCHES: AtomicUsize = AtomicUsize::new(0);

struct Server {
    _process: Process,
    url: String,
    admin: String,
    _dir: tempfile::TempDir,
}

fn run(args: &[&str], env: &[(&str, &str)], home: &Path, stdin: Option<&str>) -> anyhow::Result<Output> {
    use std::io::Write;
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        command.env(k, v);
    }
    let mut child = command.spawn().context("spawn")?;
    if let Some(input) = stdin
        && let Some(mut pipe) = child.stdin.take()
    {
        pipe.write_all(input.as_bytes()).context("stdin")?;
    }
    drop(child.stdin.take());
    child.wait_with_output().context("output")
}

fn ok(output: Output) -> anyhow::Result<String> {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("utf8")
}

/// Records the yes a person gives at a terminal to a project file's `allow` list, for loading
/// from `server`, `project`, `environment` and `path`.
fn confirm_allow(home: &Path, project_file: &Path, at: [&str; 4], names: &[&str]) -> anyhow::Result<()> {
    let dir = home.join("config").join("sekret");
    std::fs::create_dir_all(&dir).context("config dir")?;
    let path = dir.join("credentials.toml");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let file = std::fs::canonicalize(project_file).context("canonical")?;
    let [server, project, environment, folder] = at;
    let key = json!([file.display().to_string(), server, project, environment, folder]).to_string();
    let list: Vec<String> = names.iter().map(|n| format!("{n:?}")).collect();
    let text = format!("{existing}\n[confirmed_allow]\n{key:?} = [{}]\n", list.join(", "));
    std::fs::write(&path, text).context("write credentials")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).context("chmod dir")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    }
    Ok(())
}

/// How the round-trip server keeps its root key.
#[derive(Debug, Clone, Copy)]
enum Mode {
    KeyFile,
    /// Set up unattended, then sealed and unsealed again before the test uses it.
    Passphrase,
}

/// Runs each `async fn name(mode: Mode) -> anyhow::Result<()>` as `name::key_file` and `name::passphrase`.
macro_rules! in_both_seal_modes {
    ($($name:ident),* $(,)?) => {
        $(
            mod $name {
                #[tokio::test]
                async fn key_file() -> anyhow::Result<()> {
                    super::$name(super::Mode::KeyFile).await
                }

                #[tokio::test]
                async fn passphrase() -> anyhow::Result<()> {
                    super::$name(super::Mode::Passphrase).await
                }
            }
        )*
    };
}

in_both_seal_modes!(
    cli_end_to_end,
    machine_login_saves_and_uses_a_token,
    shell_switches_between_environments,
    generate_and_policy_commands,
);

const PASSPHRASE: &str = "violet tractor sings beneath";

async fn start_server(mode: Mode) -> anyhow::Result<Server> {
    match mode {
        Mode::KeyFile => start_key_file_server().await,
        Mode::Passphrase => start_passphrase_server().await,
    }
}

async fn start_passphrase_server() -> anyhow::Result<Server> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    std::fs::write(d.join("pass"), format!("{PASSPHRASE}\n")).context("passphrase file")?;
    let db = format!("sqlite://{}?mode=rwc", d.join("sekret.db").display());
    let token_file = d.join("admin-token").display().to_string();
    let process = spawn(
        &[
            "--database-url",
            &db,
            "--seal-mode",
            "passphrase",
            "--auto-init",
            "--setup-passphrase-file",
            "pass",
            "--setup-admin-token-file",
            &token_file,
        ],
        d,
    )
    .await?;
    let url = process.url.clone();
    let admin = std::fs::read_to_string(&token_file)
        .context("admin token")?
        .trim()
        .to_string();
    let env = [("SEKRET_URL", url.as_str()), ("SEKRET_TOKEN", admin.as_str())];
    let sealed = ok(run(&["sys", "seal"], &env, d, None)?)?;
    assert!(sealed.contains("state: sealed"), "{sealed}");
    assert_eq!(run(&["sys", "status"], &env, d, None)?.status.code(), Some(2));
    ok(run(
        &["sys", "unseal", "--passphrase-file", "-"],
        &env,
        d,
        Some(PASSPHRASE),
    )?)?;
    assert_eq!(run(&["sys", "status"], &env, d, None)?.status.code(), Some(0));
    Ok(Server {
        _process: process,
        url,
        admin,
        _dir: dir,
    })
}

async fn start_key_file_server() -> anyhow::Result<Server> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().context("dir")?;
    let key_file = dir.path().join("root.key");
    let key = ok(run(&["admin", "generate-root-key"], &[], dir.path(), None)?)?;
    std::fs::write(&key_file, key).context("write key")?;
    let db = format!("sqlite://{}?mode=rwc", dir.path().join("sekret.db").display());
    let key_path = key_file.display().to_string();
    let process = spawn(&["--database-url", &db, "--root-key-file", &key_path], dir.path()).await?;
    let url = process.url.clone();
    let admin = ok(run(
        &[
            "admin",
            "bootstrap",
            "--database-url",
            &db,
            "--root-key-file",
            &key_path,
        ],
        &[],
        dir.path(),
        None,
    )?)?
    .trim()
    .to_string();
    Ok(Server {
        _process: process,
        url,
        admin,
        _dir: dir,
    })
}

async fn api(server: &Server, method: reqwest::Method, path: &str, body: Value) -> anyhow::Result<Value> {
    let response = reqwest::Client::new()
        .request(method, format!("{}{path}", server.url))
        .bearer_auth(&server.admin)
        .json(&body)
        .send()
        .await
        .context("request")?;
    assert!(response.status().is_success(), "{path}: {}", response.status());
    Ok(response.json().await.unwrap_or(Value::Null))
}

async fn cli_end_to_end(mode: Mode) -> anyhow::Result<()> {
    let server = start_server(mode).await?;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": "app", "name": "App"}),
    )
    .await?;
    let home = tempfile::tempdir().context("home")?;
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", server.admin.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];
    let h = home.path();

    assert!(ok(run(&["projects"], &env, h, None)?)?.contains("app"));
    assert!(ok(run(&["whoami"], &env, h, None)?)?.contains("bootstrap-admin"));
    // A token in argv is readable by every local user, so the flag form is warned about.
    let from_env = run(&["whoami"], &env, h, None)?;
    assert!(!String::from_utf8_lossy(&from_env.stderr).contains("process list"));
    let no_token: Vec<(&str, &str)> = env.iter().copied().filter(|(k, _)| *k != "SEKRET_TOKEN").collect();
    let from_flag = run(&["--token", &server.admin, "whoami"], &no_token, h, None)?;
    let stderr = String::from_utf8_lossy(&from_flag.stderr).into_owned();
    assert!(ok(from_flag)?.contains("bootstrap-admin"));
    assert!(
        stderr.contains("--token") && stderr.contains("process list"),
        "{stderr}"
    );
    assert!(!stderr.contains(&server.admin), "{stderr}");

    std::fs::write(h.join("import.env"), "FROM_FILE=imported\n# comment\n").context("env file")?;
    let set = ok(run(
        &[
            "secrets",
            "set",
            "DB_URL=postgres://one",
            "PASSWORD=-",
            "--from-dotenv",
            "import.env",
        ],
        &env,
        h,
        Some("s3cret\n"),
    )?)?;
    assert!(set.contains("created"), "{set}");
    assert_eq!(ok(run(&["secrets", "get", "PASSWORD"], &env, h, None)?)?, "s3cret\n");
    ok(run(&["secrets", "set", "DB_URL=postgres://two"], &env, h, None)?)?;

    let listed = ok(run(&["secrets", "list", "--values"], &env, h, None)?)?;
    assert!(listed.contains("postgres://two") && listed.contains("FROM_FILE"));

    let history = ok(run(&["secrets", "history", "DB_URL", "--values"], &env, h, None)?)?;
    assert!(history.contains("postgres://one") && history.contains("postgres://two"));
    let diff = ok(run(
        &["secrets", "history", "DB_URL", "--diff", "1", "2"],
        &env,
        h,
        None,
    )?)?;
    assert_eq!(
        diff,
        "--- version 1\n+++ version 2\n- postgres://one\n+ postgres://two\n"
    );
    ok(run(&["secrets", "rollback", "DB_URL", "1"], &env, h, None)?)?;
    assert_eq!(
        ok(run(&["secrets", "get", "DB_URL"], &env, h, None)?)?,
        "postgres://one\n"
    );

    let exported = ok(run(&["export", "--format", "json"], &env, h, None)?)?;
    let parsed: Value = serde_json::from_str(&exported).context("json")?;
    assert_eq!(parsed["PASSWORD"], "s3cret");

    // Only a terminal is protected from escape sequences; a pipe or file gets the value exactly,
    // with or without --raw.
    ok(run(&["secrets", "set", "TRAP=-"], &env, h, Some("x\u{1b}[2Jy\n"))?)?;
    for args in [vec!["export"], vec!["export", "--raw"]] {
        let piped = ok(run(&args, &env, h, None)?)?;
        assert!(piped.contains("TRAP=\"x\u{1b}[2Jy\""), "{args:?}: {piped:?}");
    }
    ok(run(&["secrets", "delete", "TRAP"], &env, h, None)?)?;

    let status = run(
        &["run", "--", "sh", "-c", "test \"$DB_URL\" = postgres://one && exit 3"],
        &env,
        h,
        None,
    )?;
    assert_eq!(status.status.code(), Some(3));

    // The child gets the secrets but never the credentials, and no secret can redirect it.
    ok(run(
        &[
            "secrets",
            "set",
            "HTTPS_PROXY=http://evil.test:3128",
            "SEKRET_URL=https://evil.test",
        ],
        &env,
        h,
        None,
    )?)?;
    let leak_env = [
        ("SEKRET_CLIENT_SECRET", "sks_client"),
        ("SEKRET_UNLOCK_PASSPHRASE", "violet tractor sings beneath"),
        ("SEKRET_REMEMBER_SECRET", "a remember secret of at least 32 chars"),
    ];
    let mut with_leaks = env.to_vec();
    with_leaks.extend_from_slice(&leak_env);
    let child = run(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "test -z \"${SEKRET_TOKEN-}${SEKRET_CLIENT_SECRET-}${SEKRET_UNLOCK_PASSPHRASE-}${SEKRET_REMEMBER_SECRET-}\" \
             && test -z \"${HTTPS_PROXY-}\" && test \"$SEKRET_URL\" != https://evil.test \
             && ! grep -qa -e sks_client -e skt_ /proc/$PPID/environ && exit 4",
        ],
        &with_leaks,
        h,
        None,
    )?;
    assert_eq!(
        child.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(String::from_utf8_lossy(&child.stderr).contains("HTTPS_PROXY"));
    let dotenv = ok(run(&["export"], &env, h, None)?)?;
    assert!(dotenv.contains("DB_URL") && !dotenv.contains("HTTPS_PROXY") && !dotenv.contains("evil.test"));
    ok(run(&["secrets", "delete", "HTTPS_PROXY", "SEKRET_URL"], &env, h, None)?)?;

    // A secret named GIT_EXTERNAL_DIFF would run a program at the next `git diff`; it is skipped
    // with a reason unless the person names it with --allow.
    let marker = h.join("pwned");
    let payload = format!("GIT_EXTERNAL_DIFF=touch {}", marker.display());
    ok(run(&["secrets", "set", &payload, "GIT_PAGER=less"], &env, h, None)?)?;
    let probe = "test -z \"${GIT_EXTERNAL_DIFF-}\" && test -z \"${GIT_PAGER-}\" && exit 5";
    let skipped = run(&["run", "--", "sh", "-c", probe], &env, h, None)?;
    let notes = String::from_utf8_lossy(&skipped.stderr).into_owned();
    assert_eq!(skipped.status.code(), Some(5), "{notes}");
    assert!(
        notes.contains("GIT_EXTERNAL_DIFF") && notes.contains("--allow") && !notes.contains("touch"),
        "{notes}"
    );
    let allowed = run(
        &[
            "run",
            "--allow",
            "GIT_PAGER",
            "--",
            "sh",
            "-c",
            "test \"$GIT_PAGER\" = less && exit 6",
        ],
        &env,
        h,
        None,
    )?;
    assert_eq!(
        allowed.status.code(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let exported = ok(run(&["export", "--format", "shell"], &env, h, None)?)?;
    assert!(!exported.contains("GIT_EXTERNAL_DIFF"), "{exported}");
    // A project file comes with the repository, so its `allow` list needs the person's yes first.
    std::fs::write(h.join(".sekret.toml"), "allow = [\"GIT_EXTERNAL_DIFF\"]\n").context("project file")?;
    let unconfirmed = run(&["export", "--format", "shell"], &env, h, Some(""))?;
    let notes = String::from_utf8_lossy(&unconfirmed.stderr).into_owned();
    assert!(!ok(unconfirmed)?.contains("GIT_EXTERNAL_DIFF"));
    assert!(notes.contains("confirm"), "{notes}");
    confirm_allow(
        h,
        &h.join(".sekret.toml"),
        [server.url.as_str(), "app", "dev", "/"],
        &["GIT_EXTERNAL_DIFF"],
    )?;
    let from_file = run(&["export", "--format", "shell"], &env, h, None)?;
    let notes = String::from_utf8_lossy(&from_file.stderr).into_owned();
    let from_file = ok(from_file)?;
    assert!(from_file.contains("export GIT_EXTERNAL_DIFF="), "{from_file}");
    assert!(!notes.contains("confirm"), "{notes}");
    // The yes was for app/dev; loading from another environment asks again.
    let mut staging = env.to_vec();
    staging.retain(|(k, _)| *k != "SEKRET_ENVIRONMENT");
    staging.push(("SEKRET_ENVIRONMENT", "staging"));
    let elsewhere = run(&["export", "--format", "shell"], &staging, h, None)?;
    let notes = String::from_utf8_lossy(&elsewhere.stderr).into_owned();
    ok(elsewhere)?;
    assert!(notes.contains("confirm") && notes.contains("app/staging"), "{notes}");
    std::fs::write(
        h.join(".sekret.toml"),
        "allow = [\"GIT_EXTERNAL_DIFF\", \"LD_PRELOAD\"]\n",
    )
    .context("grown project file")?;
    let grown = ok(run(&["export", "--format", "shell"], &env, h, None)?)?;
    assert!(
        !grown.contains("GIT_EXTERNAL_DIFF"),
        "a changed list needs a new yes: {grown}"
    );
    std::fs::remove_file(h.join(".sekret.toml")).context("remove project file")?;
    let refused = run(&["run", "--allow", "SEKRET_URL", "--", "true"], &env, h, None)?;
    assert!(!refused.status.success());
    assert!(!marker.exists());
    ok(run(
        &["secrets", "delete", "GIT_EXTERNAL_DIFF", "GIT_PAGER"],
        &env,
        h,
        None,
    )?)?;

    ok(run(
        &["secrets", "set", "DB_URL=postgres://three", "EXTRA=added-later"],
        &env,
        h,
        None,
    )?)?;
    let snapshots = ok(run(&["snapshots", "list"], &env, h, None)?)?;
    let oldest = snapshots
        .lines()
        .last()
        .and_then(|l| l.split_whitespace().next())
        .context("snapshot id")?
        .to_string();
    ok(run(&["snapshots", "restore", &oldest], &env, h, None)?)?;
    assert_eq!(
        ok(run(&["secrets", "get", "DB_URL"], &env, h, None)?)?,
        "postgres://one\n"
    );
    assert_eq!(ok(run(&["secrets", "get", "FROM_FILE"], &env, h, None)?)?, "imported\n");
    assert!(
        !run(&["secrets", "get", "EXTRA"], &env, h, None)?.status.success(),
        "keys created after the snapshot are removed by the restore"
    );

    ok(run(&["secrets", "delete", "PASSWORD"], &env, h, None)?)?;
    assert!(!run(&["secrets", "get", "PASSWORD"], &env, h, None)?.status.success());
    Ok(())
}

async fn machine_login_saves_and_uses_a_token(mode: Mode) -> anyhow::Result<()> {
    let server = start_server(mode).await?;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": "app", "name": "App"}),
    )
    .await?;
    let identity = api(
        &server,
        reqwest::Method::POST,
        "/api/v1/identities",
        json!({"name": "ansible"}),
    )
    .await?;
    let id = identity["id"].as_str().context("id")?.to_string();
    api(
        &server,
        reqwest::Method::PUT,
        &format!("/api/v1/identities/{id}/auth/universal"),
        json!({"kind": "universal"}),
    )
    .await?;
    let secret = api(
        &server,
        reqwest::Method::POST,
        &format!("/api/v1/identities/{id}/client-secrets"),
        json!({}),
    )
    .await?;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects/app/members",
        json!({"principal_kind": "identity", "principal_id": id, "role": "viewer"}),
    )
    .await?;

    let home = tempfile::tempdir().context("home")?;
    let h = home.path();
    std::fs::write(
        h.join(".sekret.toml"),
        format!(
            "server = \"{}\"\nproject = \"app\"\nenvironment = \"prod\"\n",
            server.url
        ),
    )
    .context("project file")?;
    let secret_value = secret["client_secret"].as_str().context("secret")?;
    let login_env = [("SEKRET_CLIENT_SECRET", secret_value)];
    let unconfirmed = run(&["login", "--client-id", &id], &login_env, h, None)?;
    assert!(
        !unconfirmed.status.success(),
        "a client secret is not sent to a server only the project file names"
    );
    assert!(String::from_utf8_lossy(&unconfirmed.stderr).contains("no credential is sent"));
    ok(run(
        &["login", "--client-id", &id, "--server", &server.url],
        &login_env,
        h,
        None,
    )?)?;
    let saved = std::fs::read_to_string(h.join("config/sekret/credentials.toml")).context("credentials")?;
    assert!(saved.contains(&server.url));

    assert!(ok(run(&["whoami"], &[], h, None)?)?.contains("ansible"));
    let denied = run(&["secrets", "set", "X=1"], &[], h, None)?;
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("permission"));

    // The saved login vouches only for its own token, never for a client secret from the environment.
    let saved_only = run(&["login", "--client-id", &id, "--print-token"], &login_env, h, None)?;
    assert!(!saved_only.status.success());
    assert!(String::from_utf8_lossy(&saved_only.stderr).contains("no credential is sent"));
    let printed = ok(run(
        &["login", "--client-id", &id, "--print-token", "--server", &server.url],
        &login_env,
        h,
        None,
    )?)?;
    assert!(printed.trim().starts_with("skt_"));

    ok(run(&["logout"], &[], h, None)?)?;
    let after = run(&["whoami"], &[], h, None)?;
    assert!(String::from_utf8_lossy(&after.stderr).contains("not logged in"));
    Ok(())
}

async fn shell_switches_between_environments(mode: Mode) -> anyhow::Result<()> {
    let server = start_server(mode).await?;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": "app", "name": "App"}),
    )
    .await?;
    for (env, url) in [("dev", "postgres://dev"), ("prod", "postgres://prod")] {
        let mut pairs = vec![json!({"key": "DB_URL", "value": url})];
        if env == "dev" {
            pairs.push(json!({"key": "DEV_ONLY", "value": "debug"}));
        }
        api(
            &server,
            reqwest::Method::POST,
            &format!("/api/v1/projects/app/environments/{env}/secrets/batch"),
            json!({"upserts": pairs}),
        )
        .await?;
    }
    let home = tempfile::tempdir().context("home")?;
    let bin_dir = Path::new(BIN).parent().context("bin dir")?.display().to_string();
    let script = r#"
        eval "$(sekret shell-init bash)"
        sekret-env dev
        echo "1:$DB_URL:${DEV_ONLY-unset}:$SEKRET_ENVIRONMENT"
        sekret-env prod
        echo "2:$DB_URL:${DEV_ONLY-unset}:$SEKRET_ENVIRONMENT"
        sekret-env
        sekret-env off
        echo "3:${DB_URL-unset}"
    "#;
    let output = Command::new("bash")
        .arg("-c")
        .arg(script)
        .env_clear()
        .env(
            "PATH",
            format!("{bin_dir}:{}", std::env::var("PATH").unwrap_or_default()),
        )
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("SEKRET_URL", &server.url)
        .env("SEKRET_TOKEN", &server.admin)
        .env("SEKRET_PROJECT", "app")
        .current_dir(home.path())
        .output()
        .context("bash")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("1:postgres://dev:debug:dev"), "{stdout}\n{stderr}");
    assert!(stdout.contains("2:postgres://prod:unset:prod"), "{stdout}\n{stderr}");
    assert!(stdout.contains("app/prod: DB_URL"), "{stdout}");
    assert!(stdout.contains("3:unset"), "{stdout}");
    assert!(stderr.contains("loaded 2 secrets from app/dev"), "{stderr}");
    assert!(!stderr.contains("postgres://"), "values never reach stderr");

    let direct = run(
        &["env", "use", "dev"],
        &[
            ("SEKRET_URL", server.url.as_str()),
            ("SEKRET_TOKEN", server.admin.as_str()),
            ("SEKRET_PROJECT", "app"),
        ],
        home.path(),
        None,
    )?;
    assert!(ok(direct)?.contains("export DB_URL="), "piped output is shell code");
    Ok(())
}

struct Pki {
    dir: tempfile::TempDir,
}

impl Pki {
    /// A CA, a server certificate for 127.0.0.1, a client certificate from the same CA, and one
    /// from an unrelated CA.
    fn new() -> anyhow::Result<Self> {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let dir = tempfile::tempdir().context("pki dir")?;
        let write = |name: &str, contents: String| -> anyhow::Result<()> {
            std::fs::write(dir.path().join(name), contents).context("write pem")
        };
        let ca = |name: &str| -> anyhow::Result<_> {
            let key = KeyPair::generate().context("ca key")?;
            let mut params = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.distinguished_name.push(rcgen::DnType::CommonName, name);
            let cert = params.self_signed(&key).context("ca cert")?;
            Ok((Issuer::new(params, key), cert))
        };
        let (ca_issuer, ca_cert) = ca("sekret test CA")?;
        let (rogue_issuer, _) = ca("rogue CA")?;
        write("ca.pem", ca_cert.pem())?;
        let leaf = |names: Vec<String>, issuer: &Issuer<'_, KeyPair>, prefix: &str| -> anyhow::Result<()> {
            let key = KeyPair::generate().context("leaf key")?;
            let cert = CertificateParams::new(names)
                .context("leaf params")?
                .signed_by(&key, issuer)
                .context("leaf cert")?;
            write(&format!("{prefix}.pem"), cert.pem())?;
            write(&format!("{prefix}-key.pem"), key.serialize_pem())
        };
        leaf(vec!["127.0.0.1".into(), "localhost".into()], &ca_issuer, "server")?;
        leaf(vec!["ci-runner".into()], &ca_issuer, "client")?;
        leaf(vec!["intruder".into()], &rogue_issuer, "rogue")?;
        Ok(Self { dir })
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
}

#[tokio::test]
async fn mutual_tls_end_to_end() -> anyhow::Result<()> {
    let pki = Pki::new()?;
    let dir = tempfile::tempdir().context("dir")?;
    let key_file = dir.path().join("root.key");
    std::fs::write(
        &key_file,
        ok(run(&["admin", "generate-root-key"], &[], dir.path(), None)?)?,
    )
    .context("key")?;
    let db = format!("sqlite://{}?mode=rwc", dir.path().join("sekret.db").display());
    let key_path = key_file.display().to_string();
    let server = spawn_on(
        "https",
        &[
            "--database-url",
            &db,
            "--root-key-file",
            &key_path,
            "--tls-cert-file",
            &pki.path("server.pem"),
            "--tls-key-file",
            &pki.path("server-key.pem"),
            "--tls-client-ca-file",
            &pki.path("ca.pem"),
        ],
        &[],
        dir.path(),
    )
    .await?;
    let url = server.url.clone();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_pem = std::fs::read(pki.path("ca.pem")).context("ca")?;
    let identity_pem = [
        std::fs::read(pki.path("client.pem")).context("cert")?,
        std::fs::read(pki.path("client-key.pem")).context("key")?,
    ]
    .join(&b'\n');
    let probe = reqwest::Client::builder()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&ca_pem).context("ca bundle")?)
        .identity(reqwest::Identity::from_pem(&identity_pem).context("identity")?)
        .build()
        .context("probe client")?;
    for _ in 0..100 {
        if probe.get(format!("{url}/api/v1/health")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let home = tempfile::tempdir().context("home")?;
    let h = home.path();
    let admin = ok(run(
        &[
            "admin",
            "bootstrap",
            "--database-url",
            &db,
            "--root-key-file",
            &key_path,
        ],
        &[],
        h,
        None,
    )?)?
    .trim()
    .to_string();
    let ca = pki.path("ca.pem");
    let whoami = |cert: Option<&str>| {
        let mut args = vec!["whoami".to_string(), "--ca-file".into(), ca.clone()];
        if let Some(prefix) = cert {
            args.extend([
                "--client-cert".into(),
                pki.path(&format!("{prefix}.pem")),
                "--client-key".into(),
                pki.path(&format!("{prefix}-key.pem")),
            ]);
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run(
            &args,
            &[("SEKRET_URL", url.as_str()), ("SEKRET_TOKEN", admin.as_str())],
            h,
            None,
        )
    };
    let mut ready = false;
    for _ in 0..100 {
        if whoami(Some("client"))?.status.success() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "a client certificate from the trusted CA is accepted");
    assert!(ok(whoami(Some("client"))?)?.contains("bootstrap-admin"));
    assert!(!whoami(None)?.status.success(), "no client certificate, no connection");
    assert!(
        !whoami(Some("rogue"))?.status.success(),
        "a certificate from another CA is refused"
    );
    let half = run(
        &["whoami", "--client-cert", &pki.path("client.pem")],
        &[("SEKRET_URL", url.as_str())],
        h,
        None,
    )?;
    assert!(!half.status.success(), "a certificate without its key is a usage error");
    Ok(())
}

async fn generate_and_policy_commands(mode: Mode) -> anyhow::Result<()> {
    let server = start_server(mode).await?;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": "app", "name": "App"}),
    )
    .await?;
    let home = tempfile::tempdir().context("home")?;
    let h = home.path();
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", server.admin.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];

    assert!(ok(run(&["policy"], &env, h, None)?)?.contains("rotation:  off"));
    let set = ok(run(
        &["policy", "--rotate-days", "30", "--charset", "hex"],
        &env,
        h,
        None,
    )?)?;
    assert!(set.contains("every 30 days") && set.contains("Hex"), "{set}");

    let generated = ok(run(&["secrets", "generate", "SESSION_KEY"], &env, h, None)?)?;
    assert!(generated.contains("created"), "{generated}");
    let value = ok(run(&["secrets", "get", "SESSION_KEY"], &env, h, None)?)?;
    assert!(!generated.contains(value.trim()), "generate never prints the value");
    assert_eq!(value.trim().len(), 32);
    assert!(value.trim().chars().all(|c| c.is_ascii_hexdigit()));

    let shown = ok(run(&["secrets", "policy", "SESSION_KEY"], &env, h, None)?)?;
    assert!(
        shown.contains("project default") && shown.contains("next rotation: "),
        "{shown}"
    );
    let custom = ok(run(&["secrets", "policy", "SESSION_KEY", "--off"], &env, h, None)?)?;
    assert!(
        custom.contains("this secret") && custom.contains("rotation:  off"),
        "{custom}"
    );
    let back = ok(run(&["secrets", "policy", "SESSION_KEY", "--inherit"], &env, h, None)?)?;
    assert!(back.contains("project default"), "{back}");

    ok(run(&["secrets", "set", "VENDOR_KEY=abc"], &env, h, None)?)?;
    let vendor = ok(run(&["secrets", "policy", "VENDOR_KEY"], &env, h, None)?)?;
    assert!(vendor.contains("not rotating"), "pasted values are explained: {vendor}");
    let pin = ok(run(
        &["secrets", "generate", "PIN", "--length", "8", "--charset", "numeric"],
        &env,
        h,
        None,
    )?)?;
    assert!(pin.contains("created"));
    let pin = ok(run(&["secrets", "get", "PIN"], &env, h, None)?)?;
    assert!(pin.trim().len() == 8 && pin.trim().chars().all(|c| c.is_ascii_digit()));
    Ok(())
}

/// A server process that is stopped when dropped.
struct Process {
    child: Child,
    url: String,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn spawn(args: &[&str], dir: &Path) -> anyhow::Result<Process> {
    spawn_with_env(args, &[], dir).await
}

async fn spawn_with_env(args: &[&str], env: &[(&str, &str)], dir: &Path) -> anyhow::Result<Process> {
    spawn_on("http", args, env, dir).await
}

/// Starts `sekret server` in `dir` on a port the kernel picks, logging to a file there.
async fn spawn_on(scheme: &str, args: &[&str], env: &[(&str, &str)], dir: &Path) -> anyhow::Result<Process> {
    let n = LAUNCHES.fetch_add(1, Ordering::SeqCst);
    let log = dir.join(format!("server-{n}.log"));
    let public_url = format!("{scheme}://127.0.0.1");
    let level = env
        .iter()
        .find(|(key, _)| *key == "SEKRET_LOG")
        .map_or("warn", |(_, value)| *value);
    let child = Command::new(BIN)
        .args(["server", "--listen", "127.0.0.1:0", "--public-url", &public_url])
        .args(args)
        .current_dir(dir)
        .env_clear()
        .envs(env.iter().copied())
        .env("SEKRET_LOG", log_filter(level))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).context("log")?)
        .spawn()
        .context("server")?;
    let mut process = Process {
        child,
        url: String::new(),
    };
    let address = wait_for_listening(&mut process.child, &log, START_TIMEOUT).await?;
    process.url = format!("{scheme}://{address}");
    Ok(process)
}

#[tokio::test]
async fn passphrase_setup_backup_and_restore_round_trip() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = format!("sqlite://{}?mode=rwc", d.join("sekret.db").display());
    let code_file = d.join("setup-code").display().to_string();
    std::fs::write(d.join("pass"), "violet tractor sings beneath\n").context("passphrase file")?;

    let server = spawn(&["--database-url", &db, "--setup-code-file", &code_file], d).await?;
    let anonymous = [("SEKRET_URL", server.url.as_str())];
    let status = run(&["sys", "status"], &anonymous, d, None)?;
    assert_eq!(status.status.code(), Some(3), "uninitialised");
    let code = std::fs::read_to_string(&code_file).context("setup code")?;
    let token = ok(run(
        &["sys", "init", "--setup-code", code.trim(), "--passphrase-file", "pass"],
        &anonymous,
        d,
        None,
    )?)?
    .trim()
    .to_string();
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", token.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];
    ok(run(&["projects", "create", "app"], &env, d, None)?)?;
    ok(run(&["secrets", "set", "A=round-trip"], &env, d, None)?)?;
    ok(run(&["sys", "backup", "-o", "nightly.skb"], &env, d, None)?)?;
    let backup = std::fs::read(d.join("nightly.skb")).context("backup")?;
    assert!(backup.starts_with(b"SKB1"));
    assert!(!backup.windows(10).any(|w| w == b"round-trip"));
    drop(server);

    // A restart comes up sealed; the config file stands in for the flags.
    std::fs::write(
        d.join("sekret.yaml"),
        format!("database:\n  url: {db}\nseal:\n  mode: passphrase\n"),
    )
    .context("config")?;
    let server = spawn(&["--config", "sekret.yaml"], d).await?;
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", token.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];
    assert_eq!(run(&["sys", "status"], &env, d, None)?.status.code(), Some(2));
    assert!(!run(&["secrets", "get", "A"], &env, d, None)?.status.success());
    let unsealed = ok(run(
        &["sys", "unseal", "--passphrase-file", "-"],
        &env,
        d,
        Some("violet tractor sings beneath\n"),
    )?)?;
    assert!(unsealed.contains("state: unsealed"), "{unsealed}");
    assert_eq!(ok(run(&["secrets", "get", "A"], &env, d, None)?)?, "round-trip\n");
    drop(server);

    let restored = format!("sqlite://{}", d.join("restored.db").display());
    let wrong = run(
        &[
            "admin",
            "restore",
            "--backup",
            "nightly.skb",
            "--database-url",
            &restored,
            "--passphrase-file",
            "-",
        ],
        &[],
        d,
        Some("not the passphrase at all\n"),
    )?;
    assert!(!wrong.status.success());
    assert!(!d.join("restored.db").exists());
    ok(run(
        &[
            "admin",
            "restore",
            "--backup",
            "nightly.skb",
            "--database-url",
            &restored,
            "--passphrase-file",
            "pass",
        ],
        &[],
        d,
        None,
    )?)?;
    let again = run(
        &[
            "admin",
            "restore",
            "--backup",
            "nightly.skb",
            "--database-url",
            &restored,
            "--passphrase-file",
            "pass",
        ],
        &[],
        d,
        None,
    )?;
    assert!(!again.status.success(), "restore never overwrites");

    let server = spawn(&["--database-url", &restored], d).await?;
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", token.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];
    assert_eq!(run(&["sys", "status"], &env, d, None)?.status.code(), Some(2));
    ok(run(&["sys", "unseal", "--passphrase-file", "pass"], &env, d, None)?)?;
    assert_eq!(ok(run(&["secrets", "get", "A"], &env, d, None)?)?, "round-trip\n");
    Ok(())
}

#[tokio::test]
async fn host_side_setup_rotation_and_mode_changes() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = format!("sqlite://{}?mode=rwc", d.join("sekret.db").display());
    std::fs::write(d.join("pass"), "violet tractor sings beneath\n").context("passphrase file")?;

    let server = spawn(&["--database-url", &db, "--web-setup=false"], d).await?;
    let anonymous = [("SEKRET_URL", server.url.as_str())];
    let status = run(&["sys", "status", "--json"], &anonymous, d, None)?;
    assert_eq!(status.status.code(), Some(3));
    let status: Value = serde_json::from_slice(&status.stdout).context("json")?;
    assert_eq!(status["web_setup"], false);
    let refused = run(
        &[
            "sys",
            "init",
            "--setup-code",
            "AAAA-AAAA-AAAA",
            "--passphrase-file",
            "pass",
        ],
        &anonymous,
        d,
        None,
    )?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("admin init"));
    drop(server);

    let token = ok(run(
        &["admin", "init", "--database-url", &db, "--passphrase-file", "pass"],
        &[],
        d,
        None,
    )?)?
    .trim()
    .to_string();
    let server = spawn(&["--database-url", &db], d).await?;
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", token.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];
    ok(run(&["sys", "unseal", "--passphrase-file", "pass"], &env, d, None)?)?;
    ok(run(&["projects", "create", "app"], &env, d, None)?)?;
    ok(run(&["secrets", "set", "A=kept"], &env, d, None)?)?;
    drop(server);

    // Rotation keeps the passphrase; switching to key-file mode writes the key out.
    ok(run(
        &[
            "admin",
            "rotate-root-key",
            "--database-url",
            &db,
            "--passphrase-file",
            "pass",
        ],
        &[],
        d,
        None,
    )?)?;
    let key = d.join("root.key").display().to_string();
    ok(run(
        &[
            "admin",
            "set-seal-mode",
            "key-file",
            "--database-url",
            &db,
            "--root-key-file",
            &key,
            "--passphrase-file",
            "pass",
        ],
        &[],
        d,
        None,
    )?)?;
    let conflicting = Command::new(BIN)
        .args([
            "server",
            "--public-url",
            "http://x",
            "--database-url",
            &db,
            "--seal-mode",
            "passphrase",
            "--root-key-file",
            &key,
        ])
        .current_dir(d)
        .env_clear()
        .output()
        .context("conflicting start")?;
    assert!(!conflicting.status.success());
    assert!(String::from_utf8_lossy(&conflicting.stderr).contains("set-seal-mode"));
    let server = spawn(&["--database-url", &db, "--root-key-file", &key], d).await?;
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", token.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];
    assert_eq!(run(&["sys", "status"], &env, d, None)?.status.code(), Some(0));
    assert_eq!(ok(run(&["secrets", "get", "A"], &env, d, None)?)?, "kept\n");
    drop(server);

    // Unattended first boot in key-file mode, with a break-glass token on disk.
    let auto_db = format!("sqlite://{}?mode=rwc", d.join("auto.db").display());
    let auto_key = d.join("auto.key").display().to_string();
    let token_file = d.join("admin-token");
    let server = spawn(
        &[
            "--database-url",
            &auto_db,
            "--seal-mode",
            "key-file",
            "--root-key-file",
            &auto_key,
            "--auto-init",
            "--setup-admin-token-file",
            &token_file.display().to_string(),
        ],
        d,
    )
    .await?;
    let auto_token = std::fs::read_to_string(&token_file).context("token file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&token_file).context("meta")?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let env = [("SEKRET_URL", server.url.as_str()), ("SEKRET_TOKEN", auto_token.trim())];
    assert!(ok(run(&["whoami"], &env, d, None)?)?.contains("bootstrap-admin"));
    Ok(())
}

#[tokio::test]
async fn unlock_policies_across_restarts() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().context("dir")?;
    let d = dir.path();
    let db = format!("sqlite://{}?mode=rwc", d.join("sekret.db").display());
    std::fs::write(d.join("pass"), "violet tractor sings beneath\n").context("passphrase file")?;
    ok(run(
        &["admin", "init", "--database-url", &db, "--passphrase-file", "pass"],
        &[],
        d,
        None,
    )?)?;
    let state = |server: &Process| -> anyhow::Result<Option<i32>> {
        Ok(
            run(&["sys", "status"], &[("SEKRET_URL", server.url.as_str())], d, None)?
                .status
                .code(),
        )
    };

    let from_env = spawn_with_env(
        &["--database-url", &db, "--unlock", "passphrase-file"],
        &[("SEKRET_UNLOCK_PASSPHRASE", "violet tractor sings beneath")],
        d,
    )
    .await?;
    assert_eq!(state(&from_env)?, Some(0));
    drop(from_env);
    let from_file = spawn(
        &[
            "--database-url",
            &db,
            "--unlock",
            "passphrase-file",
            "--unlock-passphrase-file",
            "pass",
        ],
        d,
    )
    .await?;
    assert_eq!(state(&from_file)?, Some(0));
    drop(from_file);
    let wrong = spawn_with_env(
        &["--database-url", &db, "--unlock", "passphrase-file"],
        &[("SEKRET_UNLOCK_PASSPHRASE", "not the passphrase at all")],
        d,
    )
    .await?;
    assert_eq!(state(&wrong)?, Some(2));
    drop(wrong);

    // Remember: the first manual unlock writes the device key to the configured remember file.
    let remember_flags = [
        "--database-url",
        &db,
        "--unlock",
        "remember",
        "--remember-file",
        "sekret.unlock-key",
    ];
    let remember = spawn(&remember_flags, d).await?;
    assert_eq!(state(&remember)?, Some(2));
    ok(run(
        &["sys", "unseal", "--passphrase-file", "pass"],
        &[("SEKRET_URL", remember.url.as_str())],
        d,
        None,
    )?)?;
    assert!(d.join("sekret.unlock-key").exists());
    drop(remember);
    let remembered = spawn(&remember_flags, d).await?;
    assert_eq!(state(&remembered)?, Some(0));
    Ok(())
}

#[test]
fn version_output_is_the_release_version() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let printed = ok(run(&["--version"], &[], dir.path(), None)?)?;
    // Release tooling checks this exact form.
    assert_eq!(printed, format!("sekret {}\n", sekret_core::VERSION));
    Ok(())
}

#[cfg(unix)]
#[test]
fn paths_that_are_not_utf8_are_reported_not_panicked_on() -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().context("dir")?;
    let path = dir.path().join(std::ffi::OsStr::from_bytes(b"\xff.yaml"));
    for command in [&["admin", "bootstrap", "--config"][..], &["server", "--config"]] {
        let output = Command::new(BIN)
            .args(command)
            .arg(&path)
            .env_clear()
            .env("HOME", dir.path())
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .output()
            .context("run")?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{command:?}: the file does not exist");
        assert_ne!(output.status.code(), Some(101), "{command:?}: {stderr}");
        assert!(!stderr.contains("panicked"), "{command:?}: {stderr}");
    }
    Ok(())
}

#[tokio::test]
async fn print_config_matches_the_docs() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("dir")?;
    let printed = ok(run(&["server", "--print-config"], &[], dir.path(), None)?)?;
    let docs = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/sekret.example.yaml"))
        .context("docs")?;
    assert_eq!(printed, docs);
    Ok(())
}
