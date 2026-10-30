//! Drives the real `sekret` binary: a server process plus CLI commands against it.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_sekret");

struct Server {
    child: Child,
    url: String,
    admin: String,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

fn run(args: &[&str], env: &[(&str, &str)], home: &Path, stdin: Option<&str>) -> Output {
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
    let mut child = command.spawn().expect("spawn");
    if let Some(input) = stdin
        && let Some(mut pipe) = child.stdin.take()
    {
        pipe.write_all(input.as_bytes()).expect("stdin");
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("output")
}

fn ok(output: Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8")
}

async fn start_server() -> Server {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("dir");
    let key_file = dir.path().join("root.key");
    let key = ok(run(&["admin", "generate-root-key"], &[], dir.path(), None));
    std::fs::write(&key_file, key).expect("write key");
    let db = format!("sqlite://{}?mode=rwc", dir.path().join("sekret.db").display());
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let key_path = key_file.display().to_string();
    let child = Command::new(BIN)
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--public-url",
            &url,
            "--database-url",
            &db,
            "--root-key-file",
            &key_path,
        ])
        .env("SEKRET_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("server");
    let client = reqwest::Client::new();
    for _ in 0..100 {
        if client.get(format!("{url}/api/v1/health")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
    ))
    .trim()
    .to_string();
    Server {
        child,
        url,
        admin,
        _dir: dir,
    }
}

async fn api(server: &Server, method: reqwest::Method, path: &str, body: Value) -> Value {
    let response = reqwest::Client::new()
        .request(method, format!("{}{path}", server.url))
        .bearer_auth(&server.admin)
        .json(&body)
        .send()
        .await
        .expect("request");
    assert!(response.status().is_success(), "{path}: {}", response.status());
    response.json().await.unwrap_or(Value::Null)
}

#[tokio::test]
async fn cli_end_to_end() {
    let server = start_server().await;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": "app", "name": "App"}),
    )
    .await;
    let home = tempfile::tempdir().expect("home");
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", server.admin.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];
    let h = home.path();

    assert!(ok(run(&["projects"], &env, h, None)).contains("app"));
    assert!(ok(run(&["whoami"], &env, h, None)).contains("bootstrap-admin"));

    std::fs::write(h.join("import.env"), "FROM_FILE=imported\n# comment\n").expect("env file");
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
    ));
    assert!(set.contains("created"), "{set}");
    assert_eq!(ok(run(&["secrets", "get", "PASSWORD"], &env, h, None)), "s3cret\n");
    ok(run(&["secrets", "set", "DB_URL=postgres://two"], &env, h, None));

    let listed = ok(run(&["secrets", "list", "--values"], &env, h, None));
    assert!(listed.contains("postgres://two") && listed.contains("FROM_FILE"));

    let history = ok(run(&["secrets", "history", "DB_URL", "--values"], &env, h, None));
    assert!(history.contains("postgres://one") && history.contains("postgres://two"));
    let diff = ok(run(
        &["secrets", "history", "DB_URL", "--diff", "1", "2"],
        &env,
        h,
        None,
    ));
    assert_eq!(
        diff,
        "--- version 1\n+++ version 2\n- postgres://one\n+ postgres://two\n"
    );
    ok(run(&["secrets", "rollback", "DB_URL", "1"], &env, h, None));
    assert_eq!(
        ok(run(&["secrets", "get", "DB_URL"], &env, h, None)),
        "postgres://one\n"
    );

    let exported = ok(run(&["export", "--format", "json"], &env, h, None));
    let parsed: Value = serde_json::from_str(&exported).expect("json");
    assert_eq!(parsed["PASSWORD"], "s3cret");

    let status = run(
        &["run", "--", "sh", "-c", "test \"$DB_URL\" = postgres://one && exit 3"],
        &env,
        h,
        None,
    );
    assert_eq!(status.status.code(), Some(3));

    ok(run(
        &["secrets", "set", "DB_URL=postgres://three", "EXTRA=added-later"],
        &env,
        h,
        None,
    ));
    let snapshots = ok(run(&["snapshots", "list"], &env, h, None));
    let oldest = snapshots
        .lines()
        .last()
        .and_then(|l| l.split_whitespace().next())
        .expect("snapshot id")
        .to_string();
    ok(run(&["snapshots", "restore", &oldest], &env, h, None));
    assert_eq!(
        ok(run(&["secrets", "get", "DB_URL"], &env, h, None)),
        "postgres://one\n"
    );
    assert_eq!(ok(run(&["secrets", "get", "FROM_FILE"], &env, h, None)), "imported\n");
    assert!(
        !run(&["secrets", "get", "EXTRA"], &env, h, None).status.success(),
        "keys created after the snapshot are removed by the restore"
    );

    ok(run(&["secrets", "delete", "PASSWORD"], &env, h, None));
    assert!(!run(&["secrets", "get", "PASSWORD"], &env, h, None).status.success());
}

#[tokio::test]
async fn machine_login_saves_and_uses_a_token() {
    let server = start_server().await;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": "app", "name": "App"}),
    )
    .await;
    let identity = api(
        &server,
        reqwest::Method::POST,
        "/api/v1/identities",
        json!({"name": "ansible"}),
    )
    .await;
    let id = identity["id"].as_str().expect("id").to_string();
    api(
        &server,
        reqwest::Method::PUT,
        &format!("/api/v1/identities/{id}/auth/universal"),
        json!({"kind": "universal"}),
    )
    .await;
    let secret = api(
        &server,
        reqwest::Method::POST,
        &format!("/api/v1/identities/{id}/client-secrets"),
        json!({}),
    )
    .await;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects/app/members",
        json!({"principal_kind": "identity", "principal_id": id, "role": "viewer"}),
    )
    .await;

    let home = tempfile::tempdir().expect("home");
    let h = home.path();
    std::fs::write(
        h.join(".sekret.toml"),
        format!(
            "server = \"{}\"\nproject = \"app\"\nenvironment = \"prod\"\n",
            server.url
        ),
    )
    .expect("project file");
    let secret_value = secret["client_secret"].as_str().expect("secret");
    let login_env = [("SEKRET_CLIENT_SECRET", secret_value)];
    ok(run(&["login", "--client-id", &id], &login_env, h, None));
    let saved = std::fs::read_to_string(h.join("config/sekret/credentials.toml")).expect("credentials");
    assert!(saved.contains(&server.url));

    assert!(ok(run(&["whoami"], &[], h, None)).contains("ansible"));
    let denied = run(&["secrets", "set", "X=1"], &[], h, None);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("permission"));

    let printed = ok(run(
        &["login", "--client-id", &id, "--print-token"],
        &login_env,
        h,
        None,
    ));
    assert!(printed.trim().starts_with("skt_"));

    ok(run(&["logout"], &[], h, None));
    let after = run(&["whoami"], &[], h, None);
    assert!(String::from_utf8_lossy(&after.stderr).contains("not logged in"));
}

#[tokio::test]
async fn shell_switches_between_environments() {
    let server = start_server().await;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": "app", "name": "App"}),
    )
    .await;
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
        .await;
    }
    let home = tempfile::tempdir().expect("home");
    let bin_dir = Path::new(BIN).parent().expect("bin dir").display().to_string();
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
        .expect("bash");
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
    );
    assert!(ok(direct).contains("export DB_URL="), "piped output is shell code");
}

struct Pki {
    dir: tempfile::TempDir,
}

impl Pki {
    /// A CA, a server certificate for 127.0.0.1, a client certificate from the same CA, and one
    /// from an unrelated CA.
    fn new() -> Self {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let dir = tempfile::tempdir().expect("pki dir");
        let write = |name: &str, contents: String| std::fs::write(dir.path().join(name), contents).expect("write pem");
        let ca = |name: &str| {
            let key = KeyPair::generate().expect("ca key");
            let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.distinguished_name.push(rcgen::DnType::CommonName, name);
            let cert = params.self_signed(&key).expect("ca cert");
            (Issuer::new(params, key), cert)
        };
        let (ca_issuer, ca_cert) = ca("sekret test CA");
        let (rogue_issuer, _) = ca("rogue CA");
        write("ca.pem", ca_cert.pem());
        let leaf = |names: Vec<String>, issuer: &Issuer<'_, KeyPair>, prefix: &str| {
            let key = KeyPair::generate().expect("leaf key");
            let cert = CertificateParams::new(names)
                .expect("leaf params")
                .signed_by(&key, issuer)
                .expect("leaf cert");
            write(&format!("{prefix}.pem"), cert.pem());
            write(&format!("{prefix}-key.pem"), key.serialize_pem());
        };
        leaf(vec!["127.0.0.1".into(), "localhost".into()], &ca_issuer, "server");
        leaf(vec!["ci-runner".into()], &ca_issuer, "client");
        leaf(vec!["intruder".into()], &rogue_issuer, "rogue");
        Self { dir }
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
}

#[tokio::test]
async fn mutual_tls_end_to_end() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().expect("dir");
    let key_file = dir.path().join("root.key");
    std::fs::write(
        &key_file,
        ok(run(&["admin", "generate-root-key"], &[], dir.path(), None)),
    )
    .expect("key");
    let db = format!("sqlite://{}?mode=rwc", dir.path().join("sekret.db").display());
    let port = free_port();
    let url = format!("https://127.0.0.1:{port}");
    let key_path = key_file.display().to_string();
    let _server = Server {
        child: Command::new(BIN)
            .args(["server", "--listen", &format!("127.0.0.1:{port}"), "--public-url", &url])
            .args(["--database-url", &db, "--root-key-file", &key_path])
            .args(["--tls-cert-file", &pki.path("server.pem")])
            .args(["--tls-key-file", &pki.path("server-key.pem")])
            .args(["--tls-client-ca-file", &pki.path("ca.pem")])
            .env("SEKRET_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("server"),
        url: url.clone(),
        admin: String::new(),
        _dir: dir,
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_pem = std::fs::read(pki.path("ca.pem")).expect("ca");
    let identity_pem = [
        std::fs::read(pki.path("client.pem")).expect("cert"),
        std::fs::read(pki.path("client-key.pem")).expect("key"),
    ]
    .join(&b'\n');
    let probe = reqwest::Client::builder()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&ca_pem).expect("ca bundle"))
        .identity(reqwest::Identity::from_pem(&identity_pem).expect("identity"))
        .build()
        .expect("probe client");
    for _ in 0..100 {
        if probe.get(format!("{url}/api/v1/health")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let home = tempfile::tempdir().expect("home");
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
    ))
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
        if whoami(Some("client")).status.success() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "a client certificate from the trusted CA is accepted");
    assert!(ok(whoami(Some("client"))).contains("bootstrap-admin"));
    assert!(!whoami(None).status.success(), "no client certificate, no connection");
    assert!(
        !whoami(Some("rogue")).status.success(),
        "a certificate from another CA is refused"
    );
    let half = run(
        &["whoami", "--client-cert", &pki.path("client.pem")],
        &[("SEKRET_URL", url.as_str())],
        h,
        None,
    );
    assert!(!half.status.success(), "a certificate without its key is a usage error");
}

#[tokio::test]
async fn generate_and_policy_commands() {
    let server = start_server().await;
    api(
        &server,
        reqwest::Method::POST,
        "/api/v1/projects",
        json!({"slug": "app", "name": "App"}),
    )
    .await;
    let home = tempfile::tempdir().expect("home");
    let h = home.path();
    let env = [
        ("SEKRET_URL", server.url.as_str()),
        ("SEKRET_TOKEN", server.admin.as_str()),
        ("SEKRET_PROJECT", "app"),
        ("SEKRET_ENVIRONMENT", "dev"),
    ];

    assert!(ok(run(&["policy"], &env, h, None)).contains("rotation:  off"));
    let set = ok(run(
        &["policy", "--rotate-days", "30", "--charset", "hex"],
        &env,
        h,
        None,
    ));
    assert!(set.contains("every 30 days") && set.contains("Hex"), "{set}");

    let generated = ok(run(&["secrets", "generate", "SESSION_KEY"], &env, h, None));
    assert!(generated.contains("created"), "{generated}");
    let value = ok(run(&["secrets", "get", "SESSION_KEY"], &env, h, None));
    assert!(!generated.contains(value.trim()), "generate never prints the value");
    assert_eq!(value.trim().len(), 32);
    assert!(value.trim().chars().all(|c| c.is_ascii_hexdigit()));

    let shown = ok(run(&["secrets", "policy", "SESSION_KEY"], &env, h, None));
    assert!(
        shown.contains("project default") && shown.contains("next rotation: "),
        "{shown}"
    );
    let custom = ok(run(&["secrets", "policy", "SESSION_KEY", "--off"], &env, h, None));
    assert!(
        custom.contains("this secret") && custom.contains("rotation:  off"),
        "{custom}"
    );
    let back = ok(run(&["secrets", "policy", "SESSION_KEY", "--inherit"], &env, h, None));
    assert!(back.contains("project default"), "{back}");

    ok(run(&["secrets", "set", "VENDOR_KEY=abc"], &env, h, None));
    let vendor = ok(run(&["secrets", "policy", "VENDOR_KEY"], &env, h, None));
    assert!(vendor.contains("not rotating"), "pasted values are explained: {vendor}");
    let pin = ok(run(
        &["secrets", "generate", "PIN", "--length", "8", "--charset", "numeric"],
        &env,
        h,
        None,
    ));
    assert!(pin.contains("created"));
    let pin = ok(run(&["secrets", "get", "PIN"], &env, h, None));
    assert!(pin.trim().len() == 8 && pin.trim().chars().all(|c| c.is_ascii_digit()));
}
