//! The configuration matrix. Every documented server option is set through the YAML file, a flag
//! and an environment variable on the real `sekret` binary, and each test checks the option
//! changes what the server does, not only that it parses. Precedence and the combinations that
//! change an option's meaning are covered at the end.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use reqwest::header::{COOKIE, LOCATION, SET_COOKIE, STRICT_TRANSPORT_SECURITY};
use reqwest::{Method, StatusCode};
use sekret_server::testkit::TestIssuer;
use sekret_server::testkit::process::{HeldPort, ListenError, listening_address, read_log, wait_for_listening};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_sekret");
const PASSPHRASE: &str = "violet tractor sings beneath";
const WRONG_PASSPHRASE: &str = "copper lantern drifts westward";
const START_TIMEOUT: Duration = Duration::from_secs(20);
/// Starts on a chosen port retry this often when another process takes the port first.
const PORT_ATTEMPTS: usize = 5;

static LAUNCHES: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------------------------
// The option table
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Way {
    File,
    Flag,
    Env,
}

const WAYS: [Way; 3] = [Way::File, Way::Flag, Way::Env];

/// One documented server option and the three ways to set it.
struct Opt {
    key: &'static str,
    flag: &'static str,
    env: &'static str,
    /// How a list is joined on the command line and in the environment; `None` for scalars.
    list: Option<&'static str>,
}

const fn scalar(key: &'static str, flag: &'static str, env: &'static str) -> Opt {
    Opt {
        key,
        flag,
        env,
        list: None,
    }
}

const fn list(key: &'static str, flag: &'static str, env: &'static str, separator: &'static str) -> Opt {
    Opt {
        key,
        flag,
        env,
        list: Some(separator),
    }
}

const OPTIONS: [Opt; 41] = [
    scalar(
        "server.allow_shared_config",
        "allow-shared-config",
        "SEKRET_ALLOW_SHARED_CONFIG",
    ),
    scalar("server.max_connections", "max-connections", "SEKRET_MAX_CONNECTIONS"),
    scalar("server.unix_socket", "unix-socket", "SEKRET_UNIX_SOCKET"),
    scalar("server.unix_socket_mode", "unix-socket-mode", "SEKRET_UNIX_SOCKET_MODE"),
    scalar("server.public_url", "public-url", "SEKRET_PUBLIC_URL"),
    scalar("server.listen", "listen", "SEKRET_LISTEN"),
    list(
        "server.trusted_proxies",
        "trusted-proxies",
        "SEKRET_TRUSTED_PROXIES",
        ",",
    ),
    scalar(
        "server.allow_insecure_http",
        "allow-insecure-http",
        "SEKRET_ALLOW_INSECURE_HTTP",
    ),
    scalar("database.url", "database-url", "SEKRET_DATABASE_URL"),
    scalar("database.url_file", "database-url-file", "SEKRET_DATABASE_URL_FILE"),
    scalar(
        "database.snapshots_to_keep",
        "snapshots-to-keep",
        "SEKRET_SNAPSHOTS_TO_KEEP",
    ),
    scalar("auth.default_org_role", "default-org-role", "SEKRET_DEFAULT_ORG_ROLE"),
    scalar("auth.session_ttl", "session-ttl", "SEKRET_SESSION_TTL"),
    scalar("auth.cli_token_ttl", "cli-token-ttl", "SEKRET_CLI_TOKEN_TTL"),
    scalar(
        "auth.login_rate_per_minute",
        "login-rate-per-minute",
        "SEKRET_LOGIN_RATE_PER_MINUTE",
    ),
    scalar("oidc.issuer", "oidc-issuer", "SEKRET_OIDC_ISSUER"),
    scalar("oidc.client_id", "oidc-client-id", "SEKRET_OIDC_CLIENT_ID"),
    scalar(
        "oidc.client_secret_file",
        "oidc-client-secret-file",
        "SEKRET_OIDC_CLIENT_SECRET_FILE",
    ),
    list("oidc.scopes", "oidc-scopes", "SEKRET_OIDC_SCOPES", " "),
    list(
        "oidc.group_claims",
        "oidc-group-claims",
        "SEKRET_OIDC_GROUP_CLAIMS",
        ",",
    ),
    list(
        "oidc.admin_groups",
        "oidc-admin-groups",
        "SEKRET_OIDC_ADMIN_GROUPS",
        ",",
    ),
    list(
        "oidc.required_groups",
        "oidc-required-groups",
        "SEKRET_OIDC_REQUIRED_GROUPS",
        ",",
    ),
    list(
        "oidc.allowed_subjects",
        "oidc-allowed-subjects",
        "SEKRET_OIDC_ALLOWED_SUBJECTS",
        ",",
    ),
    scalar("tls.cert_file", "tls-cert-file", "SEKRET_TLS_CERT_FILE"),
    scalar("tls.key_file", "tls-key-file", "SEKRET_TLS_KEY_FILE"),
    scalar("tls.client_ca_file", "tls-client-ca-file", "SEKRET_TLS_CLIENT_CA_FILE"),
    scalar("tls.client_auth", "tls-client-auth", "SEKRET_TLS_CLIENT_AUTH"),
    scalar("seal.mode", "seal-mode", "SEKRET_SEAL_MODE"),
    scalar("seal.root_key_file", "root-key-file", "SEKRET_ROOT_KEY_FILE"),
    scalar("seal.unlock", "unlock", "SEKRET_UNLOCK"),
    scalar("seal.remember_file", "remember-file", "SEKRET_REMEMBER_FILE"),
    scalar("seal.epoch_file", "epoch-file", "SEKRET_EPOCH_FILE"),
    scalar(
        "seal.remember_secret_file",
        "remember-secret-file",
        "SEKRET_REMEMBER_SECRET_FILE",
    ),
    scalar(
        "auth.cli_login_max_auth_age",
        "cli-login-max-auth-age",
        "SEKRET_CLI_LOGIN_MAX_AUTH_AGE",
    ),
    scalar("backup.temp_dir", "backup-temp-dir", "SEKRET_BACKUP_TEMP_DIR"),
    scalar(
        "seal.passphrase_file",
        "unlock-passphrase-file",
        "SEKRET_UNLOCK_PASSPHRASE_FILE",
    ),
    scalar("setup.web", "web-setup", "SEKRET_WEB_SETUP"),
    scalar("setup.auto_init", "auto-init", "SEKRET_AUTO_INIT"),
    scalar(
        "setup.passphrase_file",
        "setup-passphrase-file",
        "SEKRET_SETUP_PASSPHRASE_FILE",
    ),
    scalar(
        "setup.admin_token_file",
        "setup-admin-token-file",
        "SEKRET_SETUP_ADMIN_TOKEN_FILE",
    ),
    scalar("setup.code_file", "setup-code-file", "SEKRET_SETUP_CODE_FILE"),
];

fn option(key: &str) -> anyhow::Result<&'static Opt> {
    OPTIONS
        .iter()
        .find(|o| o.key == key)
        .with_context(|| format!("{key} is not in the option table"))
}

/// Puts one option into the arguments, the environment or the YAML sections.
fn place(
    way: Way,
    opt: &Opt,
    values: &[String],
    args: &mut Vec<String>,
    env: &mut Vec<(String, String)>,
    sections: &mut BTreeMap<String, Vec<String>>,
) -> anyhow::Result<()> {
    let joined = values.join(opt.list.unwrap_or(""));
    match way {
        Way::Flag => args.push(format!("--{}={joined}", opt.flag)),
        Way::Env => env.push((opt.env.to_string(), joined)),
        Way::File => {
            let (section, name) = opt.key.split_once('.').context("option key")?;
            let rendered = match (opt.list, joined.is_empty()) {
                (Some(_), _) => format!("[{}]", values.join(", ")),
                (None, true) => "\"\"".to_string(),
                (None, false) => joined,
            };
            sections
                .entry(section.to_string())
                .or_default()
                .push(format!("{name}: {rendered}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Sandboxes, launches and running servers
// ---------------------------------------------------------------------------------------------

fn ok(output: Output) -> anyhow::Result<String> {
    ensure!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("utf8")
}

#[cfg(unix)]
fn mode_of(path: &Path) -> anyhow::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::symlink_metadata(path)
        .with_context(|| format!("{}", path.display()))?
        .permissions()
        .mode()
        & 0o777)
}

/// An org admin token for the passphrase-mode `sekret.db` in `dir`, made on the host while any
/// server keeps running.
fn admin_token_for(dir: &Path) -> anyhow::Result<String> {
    let pass = dir.join("admin-pass");
    std::fs::write(&pass, format!("{PASSPHRASE}\n")).context("passphrase file")?;
    let db = format!("sqlite://{}?mode=rwc", dir.join("sekret.db").display());
    let output = Command::new(BIN)
        .args(["admin", "bootstrap", "--database-url", &db, "--passphrase-file"])
        .arg(&pass)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir)
        .current_dir(dir)
        .output()
        .context("bootstrap")?;
    Ok(ok(output)?.trim().to_string())
}

/// A temporary directory holding one server's database, keys and logs.
struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = tempfile::Builder::new();
        // Private whatever the umask, as the unseal socket's directory must be.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            dir: builder.tempdir().context("sandbox")?,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn p(&self, name: &str) -> String {
        self.path(name).display().to_string()
    }

    fn db(&self) -> String {
        self.db_named("sekret.db")
    }

    fn db_named(&self, name: &str) -> String {
        format!("sqlite://{}?mode=rwc", self.p(name))
    }

    fn write(&self, name: &str, contents: &str) -> anyhow::Result<String> {
        std::fs::write(self.path(name), contents).with_context(|| format!("writing {name}"))?;
        Ok(self.p(name))
    }

    fn passphrase_file(&self) -> anyhow::Result<String> {
        self.write("pass", &format!("{PASSPHRASE}\n"))
    }

    fn cli(&self, args: &[&str], env: &[(&str, &str)], stdin: Option<&str>) -> anyhow::Result<Output> {
        use std::io::Write;
        let mut command = Command::new(BIN);
        command
            .args(args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.dir.path())
            .env("XDG_CONFIG_HOME", self.path("config"))
            .current_dir(self.dir.path())
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

    /// A new random root key in `name`.
    fn root_key(&self, name: &str) -> anyhow::Result<String> {
        let key = ok(self.cli(&["admin", "generate-root-key"], &[], None)?)?;
        self.write(name, &key)
    }

    /// An org admin token for a key-file database.
    fn bootstrap(&self, key: &str) -> anyhow::Result<String> {
        self.bootstrap_on(&self.db(), key)
    }

    /// An org admin token for the default database in passphrase mode.
    fn bootstrap_passphrase(&self) -> anyhow::Result<String> {
        admin_token_for(self.dir.path())
    }

    fn bootstrap_on(&self, db: &str, key: &str) -> anyhow::Result<String> {
        Ok(ok(self.cli(
            &["admin", "bootstrap", "--database-url", db, "--root-key-file", key],
            &[],
            None,
        )?)?
        .trim()
        .to_string())
    }

    /// Initialises the default database in passphrase mode on the host, returning the admin token.
    fn passphrase_db(&self, unlock: &str) -> anyhow::Result<String> {
        let pass = self.passphrase_file()?;
        Ok(ok(self.cli(
            &[
                "admin",
                "init",
                "--database-url",
                &self.db(),
                "--passphrase-file",
                &pass,
                "--unlock",
                unlock,
            ],
            &[],
            None,
        )?)?
        .trim()
        .to_string())
    }

    /// A launch with the remember file set beside the database, which the remember policy needs.
    fn remembering(&self) -> Launch<'_> {
        let file = self.p("sekret.unlock-key");
        self.launch().default("seal.remember_file", &file)
    }

    fn launch(&self) -> Launch<'_> {
        Launch {
            sandbox: self,
            held: None,
            settings: Vec::new(),
            defaults: Vec::new(),
            omitted: Vec::new(),
            args: Vec::new(),
            env: Vec::new(),
            raw_config: None,
            https: None,
        }
    }

    /// A launch that starts unsealed in key-file mode with the key in `key`.
    fn keyed(&self, key: &str) -> Launch<'_> {
        self.launch().default("seal.root_key_file", key)
    }
}

/// One server start: options set in particular ways, plus defaults for whatever is left.
struct Launch<'a> {
    sandbox: &'a Sandbox,
    /// A port to free just before the server starts; without one it listens on a port the kernel picks.
    held: Option<HeldPort>,
    settings: Vec<(Way, &'static str, Vec<String>)>,
    /// Passed as flags unless the test sets the option itself.
    defaults: Vec<(&'static str, String)>,
    /// Built-in defaults (listen, public URL, database) left out entirely.
    omitted: Vec<&'static str>,
    args: Vec<String>,
    env: Vec<(String, String)>,
    raw_config: Option<String>,
    https: Option<reqwest::Client>,
}

impl<'a> Launch<'a> {
    /// The built-in listen address and the port the built-in public URL names, if any.
    fn listen(&self) -> anyhow::Result<(String, Option<u16>)> {
        Ok(match &self.held {
            Some(held) => {
                let port = held.port().context("held port")?;
                (format!("127.0.0.1:{port}"), Some(port))
            }
            None => ("127.0.0.1:0".to_string(), None),
        })
    }

    /// Frees `held` just before the server starts, for tests about a particular port.
    fn hold(mut self, held: HeldPort) -> Self {
        self.held = Some(held);
        self
    }

    fn set(mut self, way: Way, key: &'static str, value: &str) -> Self {
        self.settings.push((way, key, vec![value.to_string()]));
        self
    }

    fn set_list(mut self, way: Way, key: &'static str, values: &[&str]) -> Self {
        self.settings
            .push((way, key, values.iter().map(|v| v.to_string()).collect()));
        self
    }

    fn default(mut self, key: &'static str, value: &str) -> Self {
        self.defaults.push((key, value.to_string()));
        self
    }

    fn without(mut self, key: &'static str) -> Self {
        self.omitted.push(key);
        self
    }

    fn arg(mut self, arg: &str) -> Self {
        self.args.push(arg.to_string());
        self
    }

    fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    fn raw_config(mut self, text: &str) -> Self {
        self.raw_config = Some(text.to_string());
        self
    }

    fn https(mut self, client: reqwest::Client) -> Self {
        self.https = Some(client);
        self
    }

    /// OIDC sign-in against `issuer`, which is plain HTTP and so needs `allow_insecure_http`.
    fn oidc(self, issuer: &Issuer) -> anyhow::Result<Self> {
        let secret = self.sandbox.write("oidc-secret", "test-client-secret\n")?;
        Ok(self
            .default("oidc.issuer", &issuer.url)
            .default("oidc.client_secret_file", &secret)
            .default("server.allow_insecure_http", "true"))
    }

    fn sets(&self, key: &str) -> bool {
        self.settings.iter().any(|(_, k, _)| *k == key)
    }

    fn scheme(&self) -> &'static str {
        if self.https.is_some() { "https" } else { "http" }
    }

    fn command(&self) -> anyhow::Result<(Command, PathBuf)> {
        let n = LAUNCHES.fetch_add(1, Ordering::SeqCst);
        let mut args = vec!["server".to_string()];
        let mut env = Vec::new();
        let mut sections = BTreeMap::new();
        for (way, key, values) in &self.settings {
            place(*way, option(key)?, values, &mut args, &mut env, &mut sections)?;
        }
        let (listen, port) = self.listen()?;
        let public_url = match port {
            Some(port) => format!("{}://127.0.0.1:{port}", self.scheme()),
            None => format!("{}://127.0.0.1", self.scheme()),
        };
        let built_in = [
            ("server.listen", listen),
            ("server.public_url", public_url),
            ("database.url", self.sandbox.db()),
        ];
        let defaults = built_in
            .into_iter()
            .chain(self.defaults.iter().map(|(k, v)| (*k, v.clone())));
        let mut seen = BTreeSet::new();
        for (key, value) in defaults {
            if self.sets(key) || self.omitted.contains(&key) || !seen.insert(key) {
                continue;
            }
            place(Way::Flag, option(key)?, &[value], &mut args, &mut env, &mut sections)?;
        }
        let mut yaml = String::new();
        for (section, lines) in &sections {
            yaml.push_str(&format!("{section}:\n"));
            for line in lines {
                yaml.push_str(&format!("  {line}\n"));
            }
        }
        if let Some(raw) = &self.raw_config {
            yaml.push_str(raw);
        }
        if !sections.is_empty() || self.raw_config.is_some() {
            let path = self.sandbox.write(&format!("config-{n}.yaml"), &yaml)?;
            args.push(format!("--config={path}"));
        }
        args.extend(self.args.iter().cloned());
        env.extend(self.env.iter().cloned());
        let log = self.sandbox.path(&format!("server-{n}.log"));
        let stderr = std::fs::File::create(&log).context("log file")?;
        let mut command = Command::new(BIN);
        command
            .args(&args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.sandbox.dir.path())
            .env("SEKRET_LOG", "info")
            .env("NO_COLOR", "1")
            .envs(env)
            .current_dir(self.sandbox.dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        Ok((command, log))
    }

    fn client(&self) -> anyhow::Result<reqwest::Client> {
        match &self.https {
            Some(client) => Ok(client.clone()),
            None => plain_client(),
        }
    }

    /// Spawns the server, freeing any held port at the last moment.
    fn spawn(&mut self) -> anyhow::Result<(Child, PathBuf)> {
        let (mut command, log) = self.command()?;
        if let Some(held) = self.held.take() {
            held.release().context("release port")?;
        }
        Ok((command.spawn().context("spawn server")?, log))
    }

    /// Starts the server and waits until it answers its health check.
    async fn start(mut self) -> anyhow::Result<Running> {
        let client = self.client()?;
        let scheme = self.scheme();
        let deadline = Instant::now() + START_TIMEOUT;
        let (child, log) = self.spawn()?;
        let mut running = Running {
            child,
            url: String::new(),
            log,
            dir: self.sandbox.dir.path().to_path_buf(),
            client,
        };
        let address = wait_for_listening(&mut running.child, &running.log, START_TIMEOUT).await?;
        running.url = format!("{scheme}://{}", loopback(address));
        while Instant::now() < deadline {
            if let Some(status) = running.child.try_wait().context("wait")? {
                bail!("server exited with {status}:\n{}", running.log());
            }
            let health = format!("{}/api/v1/health", running.url);
            if running.client.get(health).send().await.is_ok() {
                return Ok(running);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        bail!("server did not start:\n{}", running.log())
    }

    /// Starts the server expecting it to refuse, and returns its log.
    async fn refused(mut self) -> anyhow::Result<String> {
        let (mut child, log) = self.spawn()?;
        let outcome = wait_for_listening(&mut child, &log, START_TIMEOUT).await;
        let _ = child.kill();
        let _ = child.wait();
        match outcome {
            Ok(address) => bail!(
                "server started on {address} but should have refused:\n{}",
                read_log(&log)
            ),
            Err(ListenError::Exited { status, log }) => {
                ensure!(!status.success(), "server exited cleanly:\n{log}");
                Ok(log)
            }
            Err(error) => bail!("server neither started nor exited: {error}"),
        }
    }
}

/// Where a client reaches a server bound to `address`, which may be the unspecified address.
fn loopback(address: SocketAddr) -> SocketAddr {
    if address.ip().is_unspecified() {
        return SocketAddr::from(([127, 0, 0, 1], address.port()));
    }
    address
}

/// Starts `launch` on a port of its own, which it is given, retrying with another port when
/// something else takes it in the moment between freeing it and the server binding it.
async fn start_on_port<'a>(launch: impl Fn(u16) -> Launch<'a>) -> anyhow::Result<(Running, u16)> {
    for _ in 0..PORT_ATTEMPTS {
        let held = HeldPort::new().context("hold port")?;
        let port = held.port().context("held port")?;
        match launch(port).hold(held).start().await {
            Ok(running) => return Ok((running, port)),
            Err(error) if lost_port(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    bail!("lost the port to another process {PORT_ATTEMPTS} times")
}

fn lost_port(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ListenError>().is_some_and(ListenError::lost_port)
}

fn plain_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .context("client")
}

enum Auth<'a> {
    None,
    Bearer(&'a str),
    /// A browser session cookie, with the CSRF header the API wants on writes.
    Session(&'a str),
}

/// A server process, killed when dropped.
struct Running {
    child: Child,
    url: String,
    log: PathBuf,
    /// The sandbox directory, for probes that need its files.
    dir: PathBuf,
    client: reqwest::Client,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    fn log(&self) -> String {
        read_log(&self.log)
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        auth: Auth<'_>,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<reqwest::Response> {
        let mut request = self.client.request(method, format!("{}{path}", self.url));
        request = match auth {
            Auth::None => request,
            Auth::Bearer(token) => request.bearer_auth(token),
            Auth::Session(session) => request
                .header(COOKIE, format!("sekret_session={session}"))
                .header("x-sekret-csrf", "1"),
        };
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        request.send().await.with_context(|| format!("request {path}"))
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        auth: Auth<'_>,
        body: Option<Value>,
    ) -> anyhow::Result<(StatusCode, Value)> {
        let response = self.send(method, path, auth, body, &[]).await?;
        let status = response.status();
        let text = response.text().await.context("body")?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::String(text))))
    }

    async fn get(&self, path: &str, auth: Auth<'_>) -> anyhow::Result<(StatusCode, Value)> {
        self.call(Method::GET, path, auth, None).await
    }

    async fn status(&self) -> anyhow::Result<Value> {
        let (code, body) = self.get("/api/v1/sys/status", Auth::None).await?;
        ensure!(code == StatusCode::OK, "status answered {code}: {body}");
        Ok(body)
    }

    /// Every status field, which only organisation admins see.
    async fn detail(&self, admin: &str) -> anyhow::Result<Value> {
        let (code, body) = self.get("/api/v1/sys/status/detail", Auth::Bearer(admin)).await?;
        ensure!(code == StatusCode::OK, "detail answered {code}: {body}");
        Ok(body)
    }

    async fn state(&self) -> anyhow::Result<String> {
        Ok(self.status().await?["state"].as_str().unwrap_or_default().to_string())
    }

    async fn unseal(&self, passphrase: &str) -> anyhow::Result<StatusCode> {
        let (code, _) = self
            .call(
                Method::POST,
                "/api/v1/sys/unseal",
                Auth::None,
                Some(json!({"passphrase": passphrase})),
            )
            .await?;
        Ok(code)
    }

    async fn create_project(&self, token: &str, slug: &str) -> anyhow::Result<()> {
        let (code, body) = self
            .call(
                Method::POST,
                "/api/v1/projects",
                Auth::Bearer(token),
                Some(json!({"slug": slug, "name": slug})),
            )
            .await?;
        ensure!(code == StatusCode::CREATED, "create project: {code} {body}");
        Ok(())
    }

    async fn write_secret(&self, token: &str, key: &str, value: &str) -> anyhow::Result<()> {
        let (code, body) = self
            .call(
                Method::POST,
                "/api/v1/projects/app/environments/dev/secrets/batch",
                Auth::Bearer(token),
                Some(json!({"upserts": [{"key": key, "value": value}]})),
            )
            .await?;
        ensure!(code == StatusCode::OK, "write secret: {code} {body}");
        Ok(())
    }

    async fn read_secret(&self, token: &str, key: &str) -> anyhow::Result<(StatusCode, Value)> {
        self.get(
            &format!("/api/v1/projects/app/environments/dev/secrets/{key}"),
            Auth::Bearer(token),
        )
        .await
    }

    /// Starts a device login, returning the verification URL and how the limiter answered.
    async fn cli_start(&self) -> anyhow::Result<(StatusCode, Value)> {
        self.call(Method::POST, "/api/v1/auth/cli/start", Auth::None, None)
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// A small OIDC provider for browser sign-in
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct IssuerState {
    signer: Arc<TestIssuer>,
    claims: Arc<Mutex<Value>>,
    forms: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
}

/// Serves discovery, a JWKS and a token endpoint that hands out whatever ID token the test set.
struct Issuer {
    url: String,
    state: IssuerState,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Issuer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn issuer_discovery(axum::extract::State(state): axum::extract::State<IssuerState>) -> axum::Json<Value> {
    axum::Json(state.signer.discovery())
}

async fn issuer_jwks(axum::extract::State(state): axum::extract::State<IssuerState>) -> axum::Json<Value> {
    axum::Json(state.signer.jwks())
}

async fn issuer_token(
    axum::extract::State(state): axum::extract::State<IssuerState>,
    axum::Form(form): axum::Form<BTreeMap<String, String>>,
) -> Result<axum::Json<Value>, axum::http::StatusCode> {
    let failed = |_| axum::http::StatusCode::INTERNAL_SERVER_ERROR;
    state.forms.lock().map_err(|_| failed(()))?.push(form);
    let claims = state.claims.lock().map_err(|_| failed(()))?.clone();
    let id_token = state.signer.sign(claims).map_err(|_| failed(()))?;
    Ok(axum::Json(
        json!({"access_token": "opaque", "token_type": "Bearer", "id_token": id_token}),
    ))
}

impl Issuer {
    async fn start() -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("issuer bind")?;
        let url = format!("http://{}", listener.local_addr().context("issuer addr")?);
        let state = IssuerState {
            signer: Arc::new(TestIssuer::new(&url)),
            claims: Arc::new(Mutex::new(Value::Null)),
            forms: Arc::new(Mutex::new(Vec::new())),
        };
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(issuer_discovery),
            )
            .route("/jwks", axum::routing::get(issuer_jwks))
            .route("/token", axum::routing::post(issuer_token))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                eprintln!("issuer stopped: {error}");
            }
        });
        Ok(Self { url, state, task })
    }

    fn next_claims(&self, claims: Value) -> anyhow::Result<()> {
        *self.state.claims.lock().map_err(|_| anyhow::anyhow!("issuer lock"))? = claims;
        Ok(())
    }

    fn last_form(&self) -> anyhow::Result<BTreeMap<String, String>> {
        self.state
            .forms
            .lock()
            .map_err(|_| anyhow::anyhow!("issuer lock"))?
            .last()
            .cloned()
            .context("no token request reached the issuer")
    }
}

fn query_param(url: &url::Url, name: &str) -> anyhow::Result<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.to_string())
        .with_context(|| format!("{name} missing from {url}"))
}

/// The redirect to the provider and the login-state cookie that came with it.
struct Login {
    authorize: url::Url,
    cookie: String,
}

async fn begin_login(server: &Running) -> anyhow::Result<Login> {
    let response = server
        .send(Method::GET, "/auth/login?return_to=/projects", Auth::None, None, &[])
        .await?;
    let status = response.status();
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let cookie = response
        .headers()
        .get(SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = response.text().await.unwrap_or_default();
    ensure!(status == StatusCode::SEE_OTHER, "login answered {status}: {body}");
    let authorize = url::Url::parse(&location.context("no redirect")?).context("authorize url")?;
    Ok(Login { authorize, cookie })
}

struct SignedIn {
    /// Where the callback sent the browser.
    landed: String,
    session: Option<String>,
    cookies: Vec<String>,
}

/// The whole authorisation code flow, with the provider vouching for `claims`.
async fn sign_in(server: &Running, issuer: &Issuer, claims: Value) -> anyhow::Result<SignedIn> {
    let login = begin_login(server).await?;
    let state = query_param(&login.authorize, "state")?;
    let mut claims = claims;
    let fields = claims.as_object_mut().context("claims object")?;
    fields.entry("sub").or_insert_with(|| json!("user-1"));
    fields.entry("email").or_insert_with(|| json!("someone@example.com"));
    fields.insert("nonce".into(), json!(query_param(&login.authorize, "nonce")?));
    fields.insert("aud".into(), json!(query_param(&login.authorize, "client_id")?));
    issuer.next_claims(claims)?;
    let callback = url::Url::parse_with_params(
        &format!("{}/auth/callback", server.url),
        &[("code", "the-code"), ("state", state.as_str())],
    )
    .context("callback url")?;
    let response = server
        .client
        .get(callback)
        .header(COOKIE, format!("sekret_login={state}"))
        .send()
        .await
        .context("callback")?;
    let landed = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();
    let session = cookies
        .iter()
        .filter_map(|c| c.strip_prefix("sekret_session="))
        .filter_map(|c| c.split(';').next())
        .find(|v| !v.is_empty())
        .map(String::from);
    Ok(SignedIn {
        landed,
        session,
        cookies,
    })
}

async fn session_of(server: &Running, issuer: &Issuer, claims: Value) -> anyhow::Result<String> {
    let signed_in = sign_in(server, issuer, claims).await?;
    signed_in
        .session
        .with_context(|| format!("sign-in refused, landed on {}", signed_in.landed))
}

// ---------------------------------------------------------------------------------------------
// TLS material
// ---------------------------------------------------------------------------------------------

/// A CA, a server certificate for 127.0.0.1, a client certificate from that CA and one from
/// another CA, written into the sandbox.
fn pki(sandbox: &Sandbox) -> anyhow::Result<()> {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer as CertIssuer, KeyPair};
    let ca = |name: &str| -> anyhow::Result<_> {
        let key = KeyPair::generate().context("ca key")?;
        let mut params = CertificateParams::new(Vec::<String>::new()).context("ca params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, name);
        let cert = params.self_signed(&key).context("ca cert")?;
        Ok((CertIssuer::new(params, key), cert))
    };
    let (ca_issuer, ca_cert) = ca("sekret test CA")?;
    let (rogue_issuer, _) = ca("rogue CA")?;
    sandbox.write("ca.pem", &ca_cert.pem())?;
    let leaf = |names: Vec<String>, issuer: &CertIssuer<'_, KeyPair>, prefix: &str| -> anyhow::Result<()> {
        let key = KeyPair::generate().context("leaf key")?;
        let cert = CertificateParams::new(names)
            .context("leaf params")?
            .signed_by(&key, issuer)
            .context("leaf cert")?;
        sandbox.write(&format!("{prefix}.pem"), &cert.pem())?;
        sandbox.write(&format!("{prefix}-key.pem"), &key.serialize_pem())?;
        Ok(())
    };
    leaf(vec!["127.0.0.1".into(), "localhost".into()], &ca_issuer, "server")?;
    leaf(vec!["ci-runner".into()], &ca_issuer, "client")?;
    leaf(vec!["intruder".into()], &rogue_issuer, "rogue")?;
    Ok(())
}

/// An HTTPS client trusting the sandbox CA, presenting `identity`'s certificate when given.
fn tls_client(sandbox: &Sandbox, identity: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let ca = std::fs::read(sandbox.path("ca.pem")).context("ca")?;
    let mut builder = reqwest::Client::builder()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&ca).context("ca bundle")?)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(prefix) = identity {
        let pem = [
            std::fs::read(sandbox.path(&format!("{prefix}.pem"))).context("cert")?,
            std::fs::read(sandbox.path(&format!("{prefix}-key.pem"))).context("key")?,
        ]
        .join(&b'\n');
        builder = builder.identity(reqwest::Identity::from_pem(&pem).context("identity")?);
    }
    builder.build().context("tls client")
}

async fn reaches(client: &reqwest::Client, url: &str) -> bool {
    client
        .get(format!("{url}/api/v1/health"))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success())
}

// ---------------------------------------------------------------------------------------------
// The documentation and the matrix agree
// ---------------------------------------------------------------------------------------------

#[test]
fn the_matrix_lists_every_documented_option() -> anyhow::Result<()> {
    let docs = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/configuration.md"))
        .context("docs/configuration.md")?;
    let documented: BTreeSet<(String, String, String)> = docs
        .lines()
        .filter(|line| line.starts_with("| `"))
        .filter_map(|line| {
            let cells: Vec<String> = line
                .split('|')
                .map(|c| c.trim().trim_matches('`').to_string())
                .collect();
            Some((cells.get(1)?.clone(), cells.get(2)?.clone(), cells.get(3)?.clone()))
        })
        .collect();
    let tested: BTreeSet<(String, String, String)> = OPTIONS
        .iter()
        .map(|o| (o.key.to_string(), format!("--{}", o.flag), o.env.to_string()))
        .collect();
    assert_eq!(documented, tested);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// server.*
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn listen_sets_the_address_served() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let (server, port) =
            start_on_port(|port| sb.keyed(&key).set(way, "server.listen", &format!("127.0.0.1:{port}"))).await?;
        let addr = format!("127.0.0.1:{port}");
        assert!(server.url.ends_with(&addr), "{way:?}");
        let (code, _) = server.get("/api/v1/ready", Auth::None).await?;
        assert_eq!(code, StatusCode::OK, "{way:?}");
        assert!(server.log().contains(&addr), "{way:?}: the log names the address");
    }
    Ok(())
}

#[tokio::test]
async fn public_url_builds_links_redirects_and_cookies() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let public = format!("https://sekret-{way:?}.example").to_lowercase();
        let server = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "server.public_url", &format!("{public}/"))
            .start()
            .await?;
        let (code, body) = server.cli_start().await?;
        assert_eq!(code, StatusCode::OK);
        let link = body["verification_url"].as_str().context("verification url")?;
        assert!(
            link.starts_with(&format!("{public}/cli-login?code=")),
            "{way:?}: {link}"
        );
        let health = server
            .send(Method::GET, "/api/v1/health", Auth::None, None, &[])
            .await?;
        assert!(
            health.headers().contains_key(STRICT_TRANSPORT_SECURITY),
            "{way:?}: an https public URL turns on HSTS"
        );
        let login = begin_login(&server).await?;
        assert_eq!(
            query_param(&login.authorize, "redirect_uri")?,
            format!("{public}/auth/callback"),
            "{way:?}"
        );
        assert!(login.cookie.contains("; Secure"), "{way:?}: {}", login.cookie);
    }

    // An http public URL: no Secure cookies and no HSTS.
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).oidc(&issuer)?.start().await?;
    let login = begin_login(&server).await?;
    assert!(!login.cookie.contains("Secure"), "{}", login.cookie);
    let health = server
        .send(Method::GET, "/api/v1/health", Auth::None, None, &[])
        .await?;
    assert!(!health.headers().contains_key(STRICT_TRANSPORT_SECURITY));
    Ok(())
}

#[tokio::test]
async fn a_public_url_is_required_and_must_be_http() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let log = sb.launch().without("server.public_url").refused().await?;
    assert!(log.contains("a public URL is required"), "{log}");
    for way in WAYS {
        let log = sb
            .launch()
            .set(way, "server.public_url", "ftp://sekret.example")
            .refused()
            .await?;
        assert!(log.contains("must start with http:// or https://"), "{way:?}: {log}");
    }
    Ok(())
}

/// The address the audit log records for a project created through a proxy at 127.0.0.1.
async fn audited_address(server: &Running, admin: &str) -> anyhow::Result<String> {
    let response = server
        .send(
            Method::POST,
            "/api/v1/projects",
            Auth::Bearer(admin),
            Some(json!({"slug": "proxied", "name": "Proxied"})),
            &[("x-forwarded-for", "198.51.100.4, 203.0.113.7")],
        )
        .await?;
    ensure!(
        response.status() == StatusCode::CREATED,
        "create: {}",
        response.status()
    );
    let (_, audit) = server
        .get("/api/v1/audit?action=project.create", Auth::Bearer(admin))
        .await?;
    Ok(audit["entries"][0]["ip"].as_str().context("audit ip")?.to_string())
}

#[tokio::test]
async fn trusted_proxies_decide_which_address_is_audited() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .set_list(way, "server.trusted_proxies", &["10.0.0.0/8", "127.0.0.1/32"])
            .start()
            .await?;
        let admin = sb.bootstrap(&key)?;
        assert_eq!(audited_address(&server, &admin).await?, "203.0.113.7", "{way:?}");
    }
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).start().await?;
    let admin = sb.bootstrap(&key)?;
    assert_eq!(
        audited_address(&server, &admin).await?,
        "127.0.0.1",
        "without trusted proxies the header is ignored"
    );
    Ok(())
}

/// Whether an identity may be pointed at an `http://` OIDC issuer.
async fn http_issuer_accepted(server: &Running, admin: &str) -> anyhow::Result<bool> {
    let (code, identity) = server
        .call(
            Method::POST,
            "/api/v1/identities",
            Auth::Bearer(admin),
            Some(json!({"name": "ci"})),
        )
        .await?;
    ensure!(code == StatusCode::CREATED, "{identity}");
    let id = identity["id"].as_str().context("id")?;
    let (code, body) = server
        .call(
            Method::PUT,
            &format!("/api/v1/identities/{id}/auth/oidc"),
            Auth::Bearer(admin),
            Some(json!({"kind": "oidc", "issuer": "http://issuer.internal",
                "bindings": {"audiences": ["sekret"], "claims": {"sub": ["ci"]}}})),
        )
        .await?;
    match code {
        StatusCode::NO_CONTENT => Ok(true),
        StatusCode::BAD_REQUEST if body.to_string().contains("url not allowed") => Ok(false),
        other => bail!("unexpected {other}: {body}"),
    }
}

#[cfg(unix)]
fn chmod(path: &str, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {path}"))
}

/// A key file another user can change stops the server, unless `allow_shared_config` is set
/// in any of the three ways, which turns the refusal into a warning.
#[cfg(unix)]
#[tokio::test]
async fn allow_shared_config_starts_with_shared_key_files() -> anyhow::Result<()> {
    const KEY: &str = "server.allow_shared_config";
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        chmod(&key, 0o606)?;
        let log = sb.keyed(&key).refused().await?;
        assert!(
            log.contains("refusing to start") && log.contains("root key file") && log.contains("--allow-shared-config"),
            "{way:?}: {log}"
        );
        let log = sb.keyed(&key).set(way, KEY, "false").refused().await?;
        assert!(log.contains("refusing to start"), "{way:?}: {log}");

        let server = sb.keyed(&key).set(way, KEY, "true").start().await?;
        assert_eq!(server.state().await?, "unsealed", "{way:?}");
        let log = server.log();
        assert!(
            log.contains("root key file") && log.contains("swap what the server trusts"),
            "{way:?}: the refusal becomes a warning: {log}"
        );
        drop(server);

        chmod(&key, 0o600)?;
        let server = sb.keyed(&key).set(way, KEY, "false").start().await?;
        assert!(!server.log().contains("swap what the server trusts"), "{way:?}");
    }
    Ok(())
}

/// The configuration file cannot excuse itself; only a flag or environment variable can.
#[cfg(unix)]
#[tokio::test]
async fn allow_shared_config_in_a_shared_file_does_not_cover_that_file() -> anyhow::Result<()> {
    const KEY: &str = "server.allow_shared_config";
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let config = sb.write("shared.yaml", "server:\n  allow_shared_config: true\n")?;
    chmod(&config, 0o666)?;
    let config_arg = format!("--config={config}");
    let log = sb.keyed(&key).arg(&config_arg).refused().await?;
    assert!(
        log.contains("configuration file") && log.contains("does not cover the file itself"),
        "{log}"
    );
    for way in [Way::Flag, Way::Env] {
        let server = sb.keyed(&key).arg(&config_arg).set(way, KEY, "true").start().await?;
        assert!(
            server.log().contains("decides who signs in"),
            "{way:?}: {}",
            server.log()
        );
        drop(server);
        let log = sb.keyed(&key).arg(&config_arg).set(way, KEY, "false").refused().await?;
        assert!(log.contains("refusing to start"), "{way:?}: {log}");
    }

    // A flag or variable saying false beats the file's true for the other files too.
    chmod(&key, 0o606)?;
    for way in [Way::Flag, Way::Env] {
        let log = sb
            .keyed(&key)
            .set(Way::File, KEY, "true")
            .set(way, KEY, "false")
            .refused()
            .await?;
        assert!(log.contains("root key file"), "{way:?}: {log}");
    }
    Ok(())
}

/// The epoch mark pins the seal configuration and root key, so an epoch file others could
/// plant or rewrite stops the server like a shared key file, set any of the three ways.
#[cfg(unix)]
#[tokio::test]
async fn an_epoch_file_others_can_replace_is_refused() -> anyhow::Result<()> {
    const ALLOW: &str = "server.allow_shared_config";
    for way in WAYS {
        let sb = Sandbox::new()?;
        sb.passphrase_db("manual")?;
        std::fs::create_dir(sb.path("shared")).context("mkdir")?;
        chmod(&sb.p("shared"), 0o777)?;
        let planted = sb.p("shared/seal.epoch");
        let log = sb.launch().set(way, "seal.epoch_file", &planted).refused().await?;
        assert!(
            log.contains("refusing to start") && log.contains("the epoch file") && log.contains("every user"),
            "{way:?}: a mark that does not exist yet could be planted: {log}"
        );
        let server = sb
            .launch()
            .set(way, "seal.epoch_file", &planted)
            .set(way, ALLOW, "true")
            .start()
            .await?;
        assert!(
            server.log().contains("the epoch file") && server.log().contains("swap what the server trusts"),
            "{way:?}: {}",
            server.log()
        );
        drop(server);

        let private = sb.write("private.epoch", "sekret-seal-epoch 0\n")?;
        chmod(&private, 0o666)?;
        let log = sb.launch().set(way, "seal.epoch_file", &private).refused().await?;
        assert!(
            log.contains("the epoch file") && log.contains("can be written by every user"),
            "{way:?}: {log}"
        );
        chmod(&private, 0o600)?;
        let server = sb.launch().set(way, "seal.epoch_file", &private).start().await?;
        assert!(!server.log().contains("swap what the server trusts"), "{way:?}");
    }
    Ok(())
}

/// Admin commands write the root key and epoch marks, so they refuse shared files as the server
/// does, and take the same override from a flag, the environment or (for files other than the
/// configuration itself) the configuration file.
#[cfg(unix)]
#[test]
fn admin_commands_refuse_shared_files_unless_allowed() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    std::fs::create_dir(sb.path("shared")).context("mkdir")?;
    chmod(&sb.p("shared"), 0o777)?;
    let init = |db: &str, extra: &[&str], env: &[(&str, &str)]| -> anyhow::Result<Output> {
        let mut args = vec!["admin", "init", "--key-file-mode", "--database-url", db];
        args.extend_from_slice(extra);
        sb.cli(&args, env, None)
    };

    let key = sb.p("shared/root.key");
    let output = init(&sb.db_named("a.db"), &["--root-key-file", &key], &[])?;
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{text}");
    assert!(
        text.contains("refusing to run")
            && text.contains("the root key file")
            && text.contains("--allow-shared-config"),
        "{text}"
    );
    assert!(
        !sb.path("shared/root.key").exists(),
        "no key is written where others can take it"
    );

    let epoch = sb.p("shared/seal.epoch");
    let own_key = sb.p("own.key");
    let output = init(
        &sb.db_named("b.db"),
        &["--root-key-file", &own_key, "--epoch-file", &epoch],
        &[],
    )?;
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success() && text.contains("the epoch file"), "{text}");

    let flag = init(
        &sb.db_named("c.db"),
        &["--root-key-file", &sb.p("shared/c.key"), "--allow-shared-config"],
        &[],
    )?;
    let text = String::from_utf8_lossy(&flag.stderr);
    assert!(flag.status.success() && text.contains("the root key file"), "{text}");
    let env = init(
        &sb.db_named("d.db"),
        &["--root-key-file", &sb.p("shared/d.key")],
        &[("SEKRET_ALLOW_SHARED_CONFIG", "true")],
    )?;
    assert!(env.status.success(), "{}", String::from_utf8_lossy(&env.stderr));
    let in_file = sb.write(
        "allow.yaml",
        &format!(
            "server:\n  allow_shared_config: true\nseal:\n  root_key_file: {}\n",
            sb.p("shared/e.key")
        ),
    )?;
    chmod(&in_file, 0o600)?;
    let file = init(&sb.db_named("e.db"), &["--config", &in_file], &[])?;
    assert!(file.status.success(), "{}", String::from_utf8_lossy(&file.stderr));

    // A configuration file others can change cannot excuse itself.
    chmod(&in_file, 0o666)?;
    let output = init(&sb.db_named("f.db"), &["--config", &in_file], &[])?;
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && text.contains("does not cover the file itself"),
        "{text}"
    );
    let output = init(
        &sb.db_named("f.db"),
        &["--config", &in_file],
        &[("SEKRET_ALLOW_SHARED_CONFIG", "false")],
    )?;
    assert!(!output.status.success());

    // Commands that only read are held to the same rule.
    let output = sb.cli(
        &[
            "admin",
            "bootstrap",
            "--database-url",
            &sb.db_named("c.db"),
            "--root-key-file",
            &sb.p("shared/c.key"),
        ],
        &[],
        None,
    )?;
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success() && text.contains("refusing to run"), "{text}");
    Ok(())
}

/// A relative staging directory is checked from the working directory, so one that does not
/// exist yet below a directory everyone can write to is refused, set any of the three ways.
#[cfg(unix)]
#[tokio::test]
async fn a_relative_backup_temp_dir_below_an_open_directory_is_refused() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        sb.passphrase_db("manual")?;
        let server = sb.launch().set(way, "backup.temp_dir", "staging").start().await?;
        drop(server);
        chmod(&sb.p(""), 0o777)?;
        let log = sb.launch().set(way, "backup.temp_dir", "staging").refused().await;
        chmod(&sb.p(""), 0o700)?;
        let log = log?;
        assert!(
            log.contains("backup.temp_dir staging is not safe") && log.contains("every user"),
            "{way:?}: {log}"
        );
    }
    Ok(())
}

/// Making mutual TLS optional is a weakening the environment should not slip in unnoticed.
#[tokio::test]
async fn optional_client_auth_from_the_environment_is_warned_about() -> anyhow::Result<()> {
    const WARNING: &str = "SEKRET_TLS_CLIENT_AUTH in the environment";
    for way in WAYS {
        let sb = Sandbox::new()?;
        pki(&sb)?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .https(tls_client(&sb, Some("client"))?)
            .default("tls.cert_file", &sb.p("server.pem"))
            .default("tls.key_file", &sb.p("server-key.pem"))
            .default("tls.client_ca_file", &sb.p("ca.pem"))
            .set(way, "tls.client_auth", "optional")
            .start()
            .await?;
        assert_eq!(
            server.log().contains(WARNING),
            way == Way::Env,
            "{way:?}: {}",
            server.log()
        );
    }
    Ok(())
}

/// A Postgres password given as a query parameter never reaches the startup log.
#[tokio::test]
async fn a_database_password_parameter_is_not_logged() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let log = sb
            .launch()
            .set(
                way,
                "database.url",
                "postgres://sekret@127.0.0.1:1/sekret?sslmode=disable&password=Hunter2Secret",
            )
            .refused()
            .await?;
        assert!(log.contains("password=***"), "{way:?}: {log}");
        assert!(!log.contains("Hunter2Secret"), "{way:?}: {log}");
    }
    Ok(())
}

#[tokio::test]
async fn allow_insecure_http_gates_http_issuers() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "server.allow_insecure_http", "true")
            .start()
            .await?;
        let admin = sb.bootstrap(&key)?;
        assert!(http_issuer_accepted(&server, &admin).await?, "{way:?}");
        begin_login(&server)
            .await
            .context("browser sign-in to an http issuer")?;
    }
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "server.allow_insecure_http", "false")
            .start()
            .await?;
        let admin = sb.bootstrap(&key)?;
        assert!(!http_issuer_accepted(&server, &admin).await?, "{way:?}");
        let (code, _) = server.get("/auth/login", Auth::None).await?;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{way:?}: discovery is refused");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// database.*
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn database_url_chooses_the_database() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let db = sb.db_named("chosen.db");
        let server = sb.keyed(&key).set(way, "database.url", &db).start().await?;
        let admin = sb.bootstrap_on(&db, &key)?;
        server.create_project(&admin, "app").await?;
        assert!(sb.path("chosen.db").exists(), "{way:?}");
        assert!(!sb.path("sekret.db").exists(), "{way:?}");
    }
    Ok(())
}

async fn snapshots_after_writes(server: &Running, admin: &str, writes: usize) -> anyhow::Result<usize> {
    server.create_project(admin, "app").await?;
    for n in 0..writes {
        server.write_secret(admin, "A", &n.to_string()).await?;
    }
    let (code, snapshots) = server
        .get("/api/v1/projects/app/environments/dev/snapshots", Auth::Bearer(admin))
        .await?;
    ensure!(code == StatusCode::OK, "{snapshots}");
    Ok(snapshots.as_array().map(Vec::len).unwrap_or_default())
}

#[tokio::test]
async fn snapshots_to_keep_prunes_old_snapshots() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .set(way, "database.snapshots_to_keep", "2")
            .start()
            .await?;
        let admin = sb.bootstrap(&key)?;
        assert_eq!(snapshots_after_writes(&server, &admin, 5).await?, 2, "{way:?}");
    }
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).start().await?;
    let admin = sb.bootstrap(&key)?;
    assert_eq!(
        snapshots_after_writes(&server, &admin, 5).await?,
        5,
        "the default keeps 200"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// auth.*
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn default_org_role_is_granted_to_everyone_who_signs_in() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "auth.default_org_role", "backup-reader")
            .start()
            .await?;
        let session = session_of(&server, &issuer, json!({})).await?;
        let (code, _) = server
            .call(Method::POST, "/api/v1/sys/backup", Auth::Session(&session), None)
            .await?;
        assert_eq!(code, StatusCode::OK, "{way:?}: backup-reader may download backups");
        let (code, _) = server.get("/api/v1/identities", Auth::Session(&session)).await?;
        assert_eq!(code, StatusCode::FORBIDDEN, "{way:?}: and nothing org-member could");
    }
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "auth.default_org_role", "")
            .start()
            .await?;
        let session = session_of(&server, &issuer, json!({})).await?;
        let (_, me) = server.get("/api/v1/me", Auth::Session(&session)).await?;
        assert_eq!(me["org_rules"], json!([]), "{way:?}: empty means no role");
        let (code, _) = server.get("/api/v1/identities", Auth::Session(&session)).await?;
        assert_eq!(code, StatusCode::FORBIDDEN, "{way:?}");
    }
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).oidc(&issuer)?.start().await?;
    let session = session_of(&server, &issuer, json!({})).await?;
    let (code, _) = server.get("/api/v1/identities", Auth::Session(&session)).await?;
    assert_eq!(code, StatusCode::OK, "the default org-member may list identities");
    let (code, _) = server
        .call(Method::POST, "/api/v1/sys/backup", Auth::Session(&session), None)
        .await?;
    assert_eq!(code, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn session_ttl_sets_the_cookie_and_the_expiry() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let mut sessions = Vec::new();
    let mut servers = Vec::new();
    for way in WAYS {
        let db = sb.db_named(&format!("{way:?}.db"));
        let server = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "database.url", &db)
            .set(way, "auth.session_ttl", "2")
            .start()
            .await?;
        let signed_in = sign_in(&server, &issuer, json!({})).await?;
        let cookie = signed_in
            .cookies
            .iter()
            .find(|c| c.starts_with("sekret_session="))
            .context("session cookie")?;
        assert!(cookie.contains("Max-Age=2"), "{way:?}: {cookie}");
        let session = signed_in.session.context("session")?;
        let (code, _) = server.get("/api/v1/me", Auth::Session(&session)).await?;
        assert_eq!(code, StatusCode::OK, "{way:?}");
        sessions.push(session);
        servers.push(server);
    }
    tokio::time::sleep(Duration::from_millis(3100)).await;
    for (server, session) in servers.iter().zip(&sessions) {
        let (code, _) = server.get("/api/v1/me", Auth::Session(session)).await?;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "the session token itself expired");
    }

    let server = sb.keyed(&key).oidc(&issuer)?.start().await?;
    let signed_in = sign_in(&server, &issuer, json!({})).await?;
    assert!(
        signed_in.cookies.iter().any(|c| c.contains("Max-Age=43200")),
        "{:?}",
        signed_in.cookies
    );
    Ok(())
}

/// A device login approved by a browser session, returning the CLI token's lifetime.
async fn cli_token_lifetime(server: &Running, issuer: &Issuer) -> anyhow::Result<i64> {
    let session = session_of(server, issuer, json!({})).await?;
    let (code, started) = server.cli_start().await?;
    ensure!(code == StatusCode::OK, "{started}");
    let (code, body) = server
        .call(
            Method::POST,
            "/api/v1/auth/cli/approve",
            Auth::Session(&session),
            Some(json!({"code": started["user_code"]})),
        )
        .await?;
    ensure!(code == StatusCode::NO_CONTENT, "approve: {code} {body}");
    let (code, token) = server
        .call(
            Method::POST,
            "/api/v1/auth/cli/poll",
            Auth::None,
            Some(json!({"device_code": started["device_code"]})),
        )
        .await?;
    ensure!(code == StatusCode::OK, "poll: {token}");
    token["expires_in"].as_i64().context("expires_in")
}

#[tokio::test]
async fn cli_token_ttl_sets_the_device_login_lifetime() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "auth.cli_token_ttl", "150")
            .start()
            .await?;
        // A second can tick between the poll and minting the token.
        let lifetime = cli_token_lifetime(&server, &issuer).await?;
        assert!((150..=151).contains(&lifetime), "{way:?}: {lifetime}");
    }
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).oidc(&issuer)?.start().await?;
    let lifetime = cli_token_lifetime(&server, &issuer).await?;
    assert!((86400..=86401).contains(&lifetime), "{lifetime}");
    Ok(())
}

/// A lifetime that is not positive, or over a year (most likely milliseconds), stops the server
/// whichever way it is set; one past the recommended most starts with a warning.
#[tokio::test]
async fn token_lifetimes_are_bounded() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    for way in WAYS {
        for (option, value) in [
            ("auth.session_ttl", "0"),
            ("auth.session_ttl", "-60"),
            ("auth.cli_token_ttl", "0"),
            ("auth.cli_token_ttl", "86400000"),
        ] {
            let log = sb.keyed(&key).set(way, option, value).refused().await?;
            assert!(log.contains(option), "{way:?} {option}={value}: {log}");
        }
        let server = sb
            .keyed(&key)
            .set(way, "auth.session_ttl", &(40 * 86400).to_string())
            .set(way, "auth.cli_token_ttl", &(100 * 86400).to_string())
            .start()
            .await?;
        let log = server.log();
        assert!(
            log.contains("auth.session_ttl is 40 days") && log.contains("auth.cli_token_ttl is 100 days"),
            "{way:?}: {log}"
        );
    }
    // Only the winning value is judged: a good flag over a bad environment or file value starts.
    let server = sb
        .keyed(&key)
        .set(Way::File, "auth.session_ttl", "0")
        .set(Way::Env, "auth.session_ttl", "-1")
        .set(Way::Flag, "auth.session_ttl", "3600")
        .start()
        .await?;
    assert!(!server.log().contains("auth.session_ttl must be"), "{}", server.log());
    drop(server);
    let log = sb
        .keyed(&key)
        .set(Way::File, "auth.cli_token_ttl", "3600")
        .set(Way::Env, "auth.cli_token_ttl", "0")
        .refused()
        .await?;
    assert!(
        log.contains("auth.cli_token_ttl must be"),
        "the environment beats the file: {log}"
    );
    Ok(())
}

/// How many device-login starts in a row the limiter lets through, up to `cap`.
async fn allowed_in_a_row(server: &Running, cap: usize) -> anyhow::Result<usize> {
    for n in 0..cap {
        let (code, body) = server.cli_start().await?;
        match code {
            StatusCode::OK => {}
            StatusCode::TOO_MANY_REQUESTS => return Ok(n),
            other => bail!("unexpected {other}: {body}"),
        }
    }
    Ok(cap)
}

#[tokio::test]
async fn login_rate_per_minute_limits_attempts() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .set(way, "auth.login_rate_per_minute", "3")
            .start()
            .await?;
        assert_eq!(allowed_in_a_row(&server, 10).await?, 3, "{way:?}");
    }
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).start().await?;
    assert_eq!(allowed_in_a_row(&server, 31).await?, 30, "the default is 30");
    assert!(!server.log().contains(HIGH_LOGIN_RATE), "{}", server.log());
    Ok(())
}

const HIGH_LOGIN_RATE: &str = "also lets each address try that many unseal and setup passphrases";

/// A high login rate is also a high passphrase guessing rate, so it starts with a warning, and the
/// limit it warns about really applies.
#[tokio::test]
async fn a_high_login_rate_is_warned_about() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    for way in WAYS {
        let server = sb
            .keyed(&key)
            .set(way, "auth.login_rate_per_minute", "301")
            .start()
            .await?;
        let log = server.log();
        assert!(
            log.contains(HIGH_LOGIN_RATE) && log.contains("is 301"),
            "{way:?}: {log}"
        );
        assert_eq!(
            allowed_in_a_row(&server, 40).await?,
            40,
            "{way:?}: the higher rate applies"
        );
        drop(server);
        let server = sb
            .keyed(&key)
            .set(way, "auth.login_rate_per_minute", "300")
            .start()
            .await?;
        assert!(!server.log().contains(HIGH_LOGIN_RATE), "{way:?}: {}", server.log());
    }
    let server = sb
        .keyed(&key)
        .set(Way::File, "auth.login_rate_per_minute", "1000")
        .set(Way::Flag, "auth.login_rate_per_minute", "30")
        .start()
        .await?;
    assert!(
        !server.log().contains(HIGH_LOGIN_RATE),
        "the flag wins: {}",
        server.log()
    );
    Ok(())
}

/// Whether a fresh connection's request is answered quickly. It asks to close afterwards, so it
/// gives its slot back.
async fn answers_promptly(address: &str) -> anyhow::Result<bool> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await.context("connect")?;
    stream
        .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .context("write")?;
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_millis(400), stream.read(&mut buf)).await;
    Ok(matches!(read, Ok(Ok(n)) if buf[..n].starts_with(b"HTTP/1.1 200")))
}

/// How many connections the server serves at once, up to `cap`, found by holding idle ones open
/// until a new request has to wait.
async fn connections_served(server: &Running, cap: usize) -> anyhow::Result<usize> {
    let address = server.url.trim_start_matches("http://").to_string();
    let mut held = Vec::new();
    // The health check at start left one pooled connection open, which takes a slot.
    while held.len() + 1 < cap {
        if !answers_promptly(&address).await? {
            break;
        }
        held.push(tokio::net::TcpStream::connect(&address).await.context("connect")?);
    }
    Ok(held.len() + 1)
}

#[tokio::test]
async fn max_connections_caps_open_connections() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb.keyed(&key).set(way, "server.max_connections", "3").start().await?;
        assert_eq!(connections_served(&server, 8).await?, 3, "{way:?}");
    }
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).start().await?;
    assert_eq!(connections_served(&server, 8).await?, 8, "the default is far higher");
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let log = sb.keyed(&key).set(way, "server.max_connections", "0").refused().await?;
        assert!(log.contains("max_connections must be at least 1"), "{way:?}: {log}");
    }
    Ok(())
}

#[tokio::test]
async fn login_rate_also_limits_unlock_attempts() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    sb.passphrase_db("manual")?;
    let server = sb
        .launch()
        .set(Way::Env, "auth.login_rate_per_minute", "2")
        .start()
        .await?;
    assert_eq!(server.unseal(WRONG_PASSPHRASE).await?, StatusCode::UNAUTHORIZED);
    assert_eq!(server.unseal(WRONG_PASSPHRASE).await?, StatusCode::UNAUTHORIZED);
    assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(server.state().await?, "sealed");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// oidc.*
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn oidc_settings_shape_browser_sign_in() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let secret = sb.write("client-secret", "s3cret-from-file\n")?;
        let server = sb
            .keyed(&key)
            .default("server.allow_insecure_http", "true")
            .set(way, "oidc.issuer", &format!("{}/", issuer.url))
            .set(way, "oidc.client_id", "portal")
            .set(way, "oidc.client_secret_file", &secret)
            .set_list(way, "oidc.scopes", &["openid", "email"])
            .set_list(way, "oidc.group_claims", &["teams", "/realm_access/roles"])
            .set_list(way, "oidc.admin_groups", &["platform"])
            .set_list(way, "oidc.required_groups", &["staff", "platform"])
            .start()
            .await?;
        let login = begin_login(&server).await?;
        assert!(
            login
                .authorize
                .as_str()
                .starts_with(&format!("{}/authorize?", issuer.url)),
            "{way:?}: {}",
            login.authorize
        );
        assert_eq!(query_param(&login.authorize, "client_id")?, "portal", "{way:?}");
        assert_eq!(query_param(&login.authorize, "scope")?, "openid email", "{way:?}");

        let admin = session_of(&server, &issuer, json!({"realm_access": {"roles": ["platform"]}})).await?;
        let form = issuer.last_form()?;
        assert_eq!(form.get("client_id").map(String::as_str), Some("portal"), "{way:?}");
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            Some("s3cret-from-file"),
            "{way:?}: the secret is read from the file and trimmed"
        );
        let (_, me) = server.get("/api/v1/me", Auth::Session(&admin)).await?;
        assert_eq!(me["groups"], json!(["platform"]), "{way:?}: from the JSON pointer");
        let (code, _) = server.get("/api/v1/audit", Auth::Session(&admin)).await?;
        assert_eq!(code, StatusCode::OK, "{way:?}: platform is an admin group");

        let member = session_of(&server, &issuer, json!({"sub": "user-2", "teams": "staff"})).await?;
        let (code, _) = server.get("/api/v1/audit", Auth::Session(&member)).await?;
        assert_eq!(code, StatusCode::FORBIDDEN, "{way:?}: staff is not an admin group");

        let outsider = sign_in(
            &server,
            &issuer,
            json!({"sub": "user-3", "roles": ["staff"], "groups": ["platform"]}),
        )
        .await?;
        assert!(
            outsider.session.is_none(),
            "{way:?}: roles and groups are no longer read"
        );
        assert!(
            outsider.landed.starts_with("/login?error="),
            "{way:?}: {}",
            outsider.landed
        );
    }
    Ok(())
}

#[tokio::test]
async fn oidc_allowed_subjects_pin_who_may_sign_in() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set_list(way, "oidc.required_groups", &["sekret-users"])
            .set_list(way, "oidc.allowed_subjects", &["owner", "deputy"])
            .start()
            .await?;
        let admin = sb.bootstrap(&key)?;
        session_of(&server, &issuer, json!({"sub": "owner", "roles": ["sekret-users"]})).await?;
        session_of(&server, &issuer, json!({"sub": "deputy", "roles": ["sekret-users"]})).await?;

        let intruder = sign_in(
            &server,
            &issuer,
            json!({"sub": "intruder", "roles": ["sekret-users", "sekret-admin"]}),
        )
        .await?;
        assert!(intruder.session.is_none(), "{way:?}: the right groups are not enough");
        assert!(
            intruder.landed.starts_with("/login?error="),
            "{way:?}: {}",
            intruder.landed
        );

        let ungrouped = sign_in(&server, &issuer, json!({"sub": "owner", "roles": ["guests"]})).await?;
        assert!(ungrouped.session.is_none(), "{way:?}: required groups still apply");

        let (_, audit) = server
            .get("/api/v1/audit?action=auth.login.refused", Auth::Bearer(&admin))
            .await?;
        let entries = audit["entries"].as_array().context("entries")?;
        assert!(
            entries.iter().any(|e| e["detail"]["subject"] == "intruder"
                && e["detail"]["reason"] == "subject not in oidc.allowed_subjects"),
            "{way:?}: {audit}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn oidc_allowed_subjects_stop_older_sessions_approving_cli_logins() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let open = sb.keyed(&key).oidc(&issuer)?.start().await?;
    let session = session_of(&open, &issuer, json!({"sub": "someone"})).await?;
    drop(open);

    let pinned = sb
        .keyed(&key)
        .oidc(&issuer)?
        .set_list(Way::Flag, "oidc.allowed_subjects", &["owner"])
        .start()
        .await?;
    let (code, started) = pinned.cli_start().await?;
    ensure!(code == StatusCode::OK, "{started}");
    let (code, body) = pinned
        .call(
            Method::POST,
            "/api/v1/auth/cli/approve",
            Auth::Session(&session),
            Some(json!({"code": started["user_code"]})),
        )
        .await?;
    assert_eq!(
        code,
        StatusCode::UNAUTHORIZED,
        "the session itself stops working once its subject is no longer allowed: {body}"
    );
    let (code, _) = pinned.get("/api/v1/me", Auth::Session(&session)).await?;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    assert!(
        pinned.log().contains("revoked the sessions and tokens of a user"),
        "revoked at start: {}",
        pinned.log()
    );
    Ok(())
}

#[tokio::test]
async fn oidc_defaults_apply_with_only_an_issuer() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).oidc(&issuer)?.start().await?;
    let login = begin_login(&server).await?;
    assert_eq!(query_param(&login.authorize, "client_id")?, "sekret");
    assert_eq!(query_param(&login.authorize, "scope")?, "openid profile email");
    let admin = session_of(&server, &issuer, json!({"roles": ["sekret-admin"]})).await?;
    let (code, _) = server.get("/api/v1/audit", Auth::Session(&admin)).await?;
    assert_eq!(code, StatusCode::OK, "sekret-admin from the roles claim");
    let anyone = session_of(&server, &issuer, json!({"sub": "user-2", "groups": ["devs"]})).await?;
    let (_, me) = server.get("/api/v1/me", Auth::Session(&anyone)).await?;
    assert_eq!(me["groups"], json!(["devs"]), "no required groups, groups claim read");
    let (code, _) = server.get("/api/v1/audit", Auth::Session(&anyone)).await?;
    assert_eq!(code, StatusCode::FORBIDDEN);

    let no_oidc = Sandbox::new()?;
    let key = no_oidc.root_key("root.key")?;
    let server = no_oidc.keyed(&key).start().await?;
    let (code, _) = server.get("/auth/login", Auth::None).await?;
    assert_eq!(code, StatusCode::NOT_FOUND, "no issuer, no browser sign-in");
    let (_, config) = server.get("/api/v1/auth/config", Auth::None).await?;
    assert_eq!(config["oidc_enabled"], false);
    Ok(())
}

const OPEN_SIGN_IN: &str = "OIDC sign-in is open to every account at";

/// The warning matches the behaviour: anyone at the provider gets in while it shows, and any one
/// of the restrictions, set in any way, both removes it and keeps strangers out.
#[tokio::test]
async fn oidc_open_to_everyone_at_the_provider_is_warned_about() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let open = sb.keyed(&key).oidc(&issuer)?.start().await?;
    let log = open.log();
    assert!(log.contains(OPEN_SIGN_IN) && log.contains("org-member"), "{log}");
    let stranger = sign_in(&open, &issuer, json!({"sub": "stranger"})).await?;
    assert!(stranger.session.is_some(), "anyone at the provider signs in");
    drop(open);

    let explicit_empty = sb
        .keyed(&key)
        .oidc(&issuer)?
        .raw_config("oidc:\n  required_groups: []\n  allowed_subjects: []\n")
        .start()
        .await?;
    assert!(explicit_empty.log().contains(OPEN_SIGN_IN), "[] is no restriction");
    drop(explicit_empty);

    for way in WAYS {
        for (option, value) in [("oidc.required_groups", "staff"), ("oidc.allowed_subjects", "owner")] {
            let server = sb
                .keyed(&key)
                .oidc(&issuer)?
                .set_list(way, option, &[value])
                .start()
                .await?;
            assert!(
                !server.log().contains(OPEN_SIGN_IN),
                "{way:?} {option}: {}",
                server.log()
            );
            let stranger = sign_in(&server, &issuer, json!({"sub": "stranger"})).await?;
            assert!(stranger.session.is_none(), "{way:?} {option}: strangers are kept out");
        }
        // No default role still leaves admin_groups, so the warning stays and is true.
        let no_role = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "auth.default_org_role", "")
            .start()
            .await?;
        let log = no_role.log();
        assert!(
            log.contains(OPEN_SIGN_IN) && log.contains("organisation admin") && !log.contains("becomes org-member"),
            "{way:?}: {log}"
        );
        let session = session_of(&no_role, &issuer, json!({"sub": format!("newcomer-{way:?}")})).await?;
        let (code, _) = no_role.get("/api/v1/identities", Auth::Session(&session)).await?;
        assert_eq!(code, StatusCode::FORBIDDEN, "{way:?}: a stranger gets no role");
        let claimer = session_of(
            &no_role,
            &issuer,
            json!({"sub": format!("claimer-{way:?}"), "groups": ["sekret-admin"]}),
        )
        .await?;
        let (code, _) = no_role.get("/api/v1/identities", Auth::Session(&claimer)).await?;
        assert_eq!(code, StatusCode::OK, "{way:?}: claiming the admin group is enough");
        drop(no_role);

        // Only with no default role and no group claims does nothing grant a stranger power.
        let granting_nothing = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "auth.default_org_role", "")
            .set_list(way, "oidc.group_claims", &[])
            .start()
            .await?;
        assert!(
            !granting_nothing.log().contains(OPEN_SIGN_IN),
            "{way:?}: {}",
            granting_nothing.log()
        );
        let claimer = session_of(
            &granting_nothing,
            &issuer,
            json!({"sub": format!("claimer2-{way:?}"), "groups": ["sekret-admin"]}),
        )
        .await?;
        let (code, _) = granting_nothing
            .get("/api/v1/identities", Auth::Session(&claimer))
            .await?;
        assert_eq!(code, StatusCode::FORBIDDEN, "{way:?}: group claims are ignored");
        drop(granting_nothing);

        let no_admin_groups = sb
            .keyed(&key)
            .oidc(&issuer)?
            .set(way, "auth.default_org_role", "")
            .set_list(way, "oidc.admin_groups", &[])
            .start()
            .await?;
        let log = no_admin_groups.log();
        assert!(
            log.contains(OPEN_SIGN_IN)
                && log.contains("any role bound to a group")
                && !log.contains("organisation admin"),
            "{way:?}: group bindings still grant roles: {log}"
        );
    }

    // Only the winning value counts: the environment's role beats the file's empty one.
    let overridden = sb
        .keyed(&key)
        .oidc(&issuer)?
        .set(Way::File, "auth.default_org_role", "")
        .set(Way::Env, "auth.default_org_role", "org-member")
        .set_list(Way::File, "oidc.group_claims", &[])
        .start()
        .await?;
    assert!(overridden.log().contains(OPEN_SIGN_IN), "{}", overridden.log());
    drop(overridden);
    let flag_wins = sb
        .keyed(&key)
        .oidc(&issuer)?
        .set(Way::Env, "auth.default_org_role", "org-member")
        .set(Way::Flag, "auth.default_org_role", "")
        .set_list(Way::File, "oidc.group_claims", &[])
        .start()
        .await?;
    assert!(!flag_wins.log().contains(OPEN_SIGN_IN), "{}", flag_wins.log());
    drop(flag_wins);
    let env_claims_win = sb
        .keyed(&key)
        .oidc(&issuer)?
        .set(Way::Flag, "auth.default_org_role", "")
        .set_list(Way::File, "oidc.group_claims", &[])
        .set_list(Way::Env, "oidc.group_claims", &["groups"])
        .start()
        .await?;
    assert!(env_claims_win.log().contains(OPEN_SIGN_IN), "{}", env_claims_win.log());
    drop(env_claims_win);

    let no_oidc = sb.keyed(&key).start().await?;
    assert!(!no_oidc.log().contains(OPEN_SIGN_IN), "no issuer, no warning");
    Ok(())
}

#[tokio::test]
async fn an_oidc_issuer_needs_a_client_secret_file() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let log = sb
            .launch()
            .set(way, "oidc.issuer", "https://auth.example")
            .refused()
            .await?;
        assert!(log.contains("client secret file is required"), "{way:?}: {log}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// tls.*
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn tls_cert_and_key_serve_https() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        pki(&sb)?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .https(tls_client(&sb, None)?)
            .set(way, "tls.cert_file", &sb.p("server.pem"))
            .set(way, "tls.key_file", &sb.p("server-key.pem"))
            .start()
            .await?;
        assert!(server.url.starts_with("https://"));
        let plain = server.url.replacen("https://", "http://", 1);
        assert!(!reaches(&plain_client()?, &plain).await, "{way:?}: no plain HTTP");
    }
    Ok(())
}

#[tokio::test]
async fn tls_client_ca_turns_on_mutual_tls() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        pki(&sb)?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .https(tls_client(&sb, Some("client"))?)
            .set(way, "tls.cert_file", &sb.p("server.pem"))
            .set(way, "tls.key_file", &sb.p("server-key.pem"))
            .set(way, "tls.client_ca_file", &sb.p("ca.pem"))
            .start()
            .await?;
        assert!(!reaches(&tls_client(&sb, None)?, &server.url).await, "{way:?}");
        assert!(!reaches(&tls_client(&sb, Some("rogue"))?, &server.url).await, "{way:?}");
    }
    Ok(())
}

#[tokio::test]
async fn tls_client_auth_optional_only_checks_offered_certificates() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        pki(&sb)?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .https(tls_client(&sb, None)?)
            .default("tls.cert_file", &sb.p("server.pem"))
            .default("tls.key_file", &sb.p("server-key.pem"))
            .default("tls.client_ca_file", &sb.p("ca.pem"))
            .set(way, "tls.client_auth", "optional")
            .start()
            .await?;
        assert!(reaches(&tls_client(&sb, Some("client"))?, &server.url).await, "{way:?}");
        assert!(!reaches(&tls_client(&sb, Some("rogue"))?, &server.url).await, "{way:?}");
    }
    for way in WAYS {
        let sb = Sandbox::new()?;
        pki(&sb)?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .https(tls_client(&sb, Some("client"))?)
            .default("tls.cert_file", &sb.p("server.pem"))
            .default("tls.key_file", &sb.p("server-key.pem"))
            .default("tls.client_ca_file", &sb.p("ca.pem"))
            .set(way, "tls.client_auth", "required")
            .start()
            .await?;
        assert!(!reaches(&tls_client(&sb, None)?, &server.url).await, "{way:?}");
    }
    Ok(())
}

#[tokio::test]
async fn tls_settings_must_come_in_pairs() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        pki(&sb)?;
        let log = sb
            .launch()
            .set(way, "tls.cert_file", &sb.p("server.pem"))
            .refused()
            .await?;
        assert!(log.contains("both a certificate file and a key file"), "{way:?}: {log}");
        let log = sb
            .launch()
            .set(way, "tls.client_ca_file", &sb.p("ca.pem"))
            .refused()
            .await?;
        assert!(log.contains("both a certificate file and a key file"), "{way:?}: {log}");
    }
    let sb = Sandbox::new()?;
    for way in WAYS {
        let log = sb.launch().set(way, "tls.client_auth", "sometimes").refused().await?;
        assert!(log.contains("sometimes"), "{way:?}: {log}");
    }
    Ok(())
}

#[tokio::test]
async fn tls_client_auth_without_a_client_ca_is_warned_about() -> anyhow::Result<()> {
    const WARNING: &str = "tls.client_auth is set but tls.client_ca_file is not";
    for way in WAYS {
        let sb = Sandbox::new()?;
        pki(&sb)?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .https(tls_client(&sb, None)?)
            .default("tls.cert_file", &sb.p("server.pem"))
            .default("tls.key_file", &sb.p("server-key.pem"))
            .set(way, "tls.client_auth", "required")
            .start()
            .await?;
        assert!(server.log().contains(WARNING), "{way:?}: {}", server.log());
        assert!(
            reaches(&tls_client(&sb, None)?, &server.url).await,
            "{way:?}: no certificate is asked for"
        );
        drop(server);
        let server = sb.keyed(&key).set(way, "tls.client_auth", "optional").start().await?;
        assert!(server.log().contains(WARNING), "{way:?}: without TLS at all");
    }
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = tls_base(&sb)?
        .set(Way::Env, "tls.client_auth", "required")
        .start()
        .await?;
    assert!(!server.log().contains(WARNING), "{}", server.log());
    drop(server);
    let server = sb.keyed(&key).start().await?;
    assert!(!server.log().contains(WARNING), "{}", server.log());
    Ok(())
}

#[tokio::test]
async fn plain_http_on_all_interfaces_behind_an_https_url_is_warned_about() -> anyhow::Result<()> {
    const WARNING: &str = "speaks plain http on";
    const PUBLIC: &str = "https://sekret.example.com";
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb
            .keyed(&key)
            .set(way, "server.listen", "0.0.0.0:0")
            .set(way, "server.public_url", PUBLIC)
            .start()
            .await?;
        assert!(server.log().contains(WARNING), "{way:?}: {}", server.log());
        drop(server);
        let server = sb
            .keyed(&key)
            .set(way, "server.listen", "127.0.0.1:0")
            .set(way, "server.public_url", PUBLIC)
            .start()
            .await?;
        assert!(!server.log().contains(WARNING), "{way:?}: loopback is fine");
    }
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb
        .keyed(&key)
        .set(Way::File, "server.listen", "0.0.0.0:0")
        .set(Way::Env, "server.listen", "127.0.0.1:0")
        .set(Way::File, "server.public_url", PUBLIC)
        .start()
        .await?;
    assert!(!server.log().contains(WARNING), "the environment beats the file");
    drop(server);
    let server = sb
        .keyed(&key)
        .set(Way::Env, "server.listen", "0.0.0.0:0")
        .set(Way::Flag, "server.public_url", PUBLIC)
        .start()
        .await?;
    assert!(server.log().contains(WARNING), "{}", server.log());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// seal.*
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn seal_mode_picks_the_mode_and_refuses_the_other() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.p("root.key");
        let server = sb
            .launch()
            .set(way, "seal.mode", "key-file")
            .default("seal.root_key_file", &key)
            .arg("--auto-init")
            .start()
            .await?;
        let status = server.detail(&sb.bootstrap(&key)?).await?;
        assert_eq!(
            (status["state"].as_str(), status["seal_mode"].as_str()),
            (Some("unsealed"), Some("key-file")),
            "{way:?}"
        );
        drop(server);
        let log = sb.launch().set(way, "seal.mode", "passphrase").refused().await?;
        assert!(
            log.contains("seal mode passphrase but the database is in key-file mode")
                && log.contains("sekret admin set-seal-mode"),
            "{way:?}: {log}"
        );

        let sb = Sandbox::new()?;
        let pass = sb.passphrase_file()?;
        let server = sb
            .launch()
            .set(way, "seal.mode", "passphrase")
            .arg("--auto-init")
            .arg(&format!("--setup-passphrase-file={pass}"))
            .start()
            .await?;
        let admin = sb.bootstrap_passphrase()?;
        assert_eq!(server.detail(&admin).await?["seal_mode"], "passphrase", "{way:?}");
        drop(server);
        let log = sb.launch().set(way, "seal.mode", "key-file").refused().await?;
        assert!(
            log.contains("seal mode key-file but the database is in passphrase mode"),
            "{way:?}: {log}"
        );
    }
    let sb = Sandbox::new()?;
    let log = sb.launch().set(Way::Env, "seal.mode", "sealed").refused().await?;
    assert!(log.contains("expected passphrase or key-file"), "{log}");
    Ok(())
}

#[tokio::test]
async fn root_key_file_unlocks_key_file_mode() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let server = sb.launch().set(way, "seal.root_key_file", &key).start().await?;
        assert_eq!(server.state().await?, "unsealed", "{way:?}");
        let admin = sb.bootstrap(&key)?;
        server.create_project(&admin, "app").await?;
        server.write_secret(&admin, "A", "kept").await?;
        drop(server);

        let server = sb.launch().set(way, "seal.root_key_file", &key).start().await?;
        let (code, secret) = server.read_secret(&admin, "A").await?;
        assert_eq!(
            (code, secret["value"].as_str()),
            (StatusCode::OK, Some("kept")),
            "{way:?}"
        );
        drop(server);

        let log = sb.launch().refused().await?;
        assert!(log.contains("needs its root key file"), "{way:?}: {log}");
        let other = sb.root_key("other.key")?;
        let log = sb.launch().set(way, "seal.root_key_file", &other).refused().await?;
        assert!(log.contains("does not match"), "{way:?}: {log}");
    }
    Ok(())
}

/// A passphrase-mode database whose root key is also in `root.key`, with a secret and a token.
/// Switching mode replaces the root key, so the key is put in place by a rotation instead.
fn passphrase_db_with_known_key(sb: &Sandbox) -> anyhow::Result<(String, String)> {
    let pass = sb.passphrase_file()?;
    sb.passphrase_db("manual")?;
    let key = sb.root_key("root.key")?;
    ok(sb.cli(
        &[
            "admin",
            "rotate-root-key",
            "--database-url",
            &sb.db(),
            "--new-root-key-file",
            &key,
            "--passphrase-file",
            &pass,
        ],
        &[],
        None,
    )?)?;
    let admin = sb.bootstrap(&key)?;
    Ok((key, admin))
}

/// A new root key file that others can read is warned about before it is used.
#[cfg(unix)]
#[test]
fn rotate_root_key_warns_about_an_exposed_new_key_file() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new()?;
    let pass = sb.passphrase_file()?;
    sb.passphrase_db("manual")?;
    let key = sb.root_key("root.key")?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).context("chmod")?;
    let output = sb.cli(
        &[
            "admin",
            "rotate-root-key",
            "--database-url",
            &sb.db(),
            "--new-root-key-file",
            &key,
            "--passphrase-file",
            &pass,
        ],
        &[],
        None,
    )?;
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("sekret: warning: the root key file") && text.contains("other users can read it"),
        "{text}"
    );
    Ok(())
}

#[tokio::test]
async fn root_key_file_is_an_emergency_way_into_passphrase_mode() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let (key, admin) = passphrase_db_with_known_key(&sb)?;
        let server = sb.launch().start().await?;
        assert_eq!(server.state().await?, "sealed", "{way:?}");
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
        server.create_project(&admin, "app").await?;
        server.write_secret(&admin, "A", "emergency").await?;
        drop(server);

        let server = sb.launch().set(way, "seal.root_key_file", &key).start().await?;
        let status = server.detail(&admin).await?;
        assert_eq!(
            (status["state"].as_str(), status["seal_mode"].as_str()),
            (Some("unsealed"), Some("passphrase")),
            "{way:?}"
        );
        assert!(
            server.log().contains("started unsealed from the root key file"),
            "{way:?}"
        );
        let (_, secret) = server.read_secret(&admin, "A").await?;
        assert_eq!(secret["value"], "emergency", "{way:?}");
        drop(server);

        let wrong = sb.root_key("wrong.key")?;
        let log = sb.launch().set(way, "seal.root_key_file", &wrong).refused().await?;
        assert!(log.contains("does not match"), "{way:?}: {log}");
        let missing = sb.p("missing.key");
        let server = sb.launch().set(way, "seal.root_key_file", &missing).start().await?;
        assert_eq!(
            server.state().await?,
            "sealed",
            "{way:?}: an absent key file is not an error"
        );
    }
    Ok(())
}

#[tokio::test]
async fn passphrase_mode_refuses_a_root_key_file() -> anyhow::Result<()> {
    const REFUSAL: &str = "seal.mode is passphrase but seal.root_key_file is set";
    for mode_way in WAYS {
        for key_way in WAYS {
            let sb = Sandbox::new()?;
            let key = sb.root_key("root.key")?;
            let log = sb
                .launch()
                .set(mode_way, "seal.mode", "passphrase")
                .set(key_way, "seal.root_key_file", &key)
                .refused()
                .await?;
            assert!(log.contains(REFUSAL), "{mode_way:?} {key_way:?}: {log}");
        }
    }
    // A key-file mode that wins over passphrase lower down uses the key file as usual.
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb
        .keyed(&key)
        .set(Way::File, "seal.mode", "passphrase")
        .set(Way::Env, "seal.mode", "key-file")
        .arg("--auto-init")
        .start()
        .await?;
    let status = server.detail(&sb.bootstrap(&key)?).await?;
    assert_eq!(status["seal_mode"], "key-file");
    drop(server);
    let server = sb
        .keyed(&key)
        .set(Way::Env, "seal.mode", "passphrase")
        .set(Way::Flag, "seal.mode", "key-file")
        .start()
        .await?;
    assert_eq!(server.state().await?, "unsealed");
    drop(server);
    let log = sb
        .keyed(&key)
        .set(Way::Flag, "seal.mode", "passphrase")
        .set(Way::Env, "seal.mode", "key-file")
        .refused()
        .await?;
    assert!(log.contains(REFUSAL), "the flag wins: {log}");
    Ok(())
}

#[tokio::test]
async fn unlock_manual_stays_sealed_across_restarts() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let admin = sb.passphrase_db("passphrase-file")?;
        for _ in 0..2 {
            let server = sb
                .launch()
                .set(way, "seal.unlock", "manual")
                .env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE)
                .start()
                .await?;
            let status = server.detail(&admin).await?;
            assert_eq!(
                (status["state"].as_str(), status["unlock_policy"].as_str()),
                (Some("sealed"), Some("manual")),
                "{way:?}: configured manual beats the stored passphrase-file policy"
            );
            assert_eq!(status["configured"], true);
            assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
            assert!(!sb.path("sekret.unlock-key").exists());
        }
    }
    Ok(())
}

#[tokio::test]
async fn unlock_passphrase_file_unlocks_at_every_start() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let admin = sb.passphrase_db("manual")?;
        for _ in 0..2 {
            let server = sb
                .launch()
                .set(way, "seal.unlock", "passphrase-file")
                .env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE)
                .start()
                .await?;
            let status = server.detail(&admin).await?;
            assert_eq!(
                (status["state"].as_str(), status["unlock_policy"].as_str()),
                (Some("unsealed"), Some("passphrase-file")),
                "{way:?}"
            );
            assert!(server.log().contains("unlocked at start"), "{way:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn unlock_remember_needs_one_manual_unlock() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let admin = sb.passphrase_db("manual")?;
        let server = sb.remembering().set(way, "seal.unlock", "remember").start().await?;
        assert_eq!(server.state().await?, "sealed", "{way:?}");
        // Only a policy that slipped in through the environment is called out.
        assert_eq!(
            server
                .log()
                .contains("remember unlock policy comes from SEKRET_UNLOCK in the environment"),
            way == Way::Env,
            "{way:?}: {}",
            server.log()
        );
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
        let file = sb.path("sekret.unlock-key");
        assert!(
            file.exists(),
            "{way:?}: the device key is in the configured remember file"
        );
        #[cfg(unix)]
        assert_eq!(mode_of(&file)?, 0o600);
        assert_eq!(server.detail(&admin).await?["remembered"], true);
        drop(server);
        for _ in 0..2 {
            let server = sb.remembering().set(way, "seal.unlock", "remember").start().await?;
            assert_eq!(server.state().await?, "unsealed", "{way:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn remember_file_sets_where_the_device_key_goes() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        sb.passphrase_db("manual")?;
        let file = sb.p("device.key");
        let launch = || {
            sb.launch()
                .default("seal.unlock", "remember")
                .set(way, "seal.remember_file", &file)
        };
        let server = launch().start().await?;
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
        #[cfg(unix)]
        assert_eq!(mode_of(Path::new(&file))?, 0o600, "{way:?}");
        assert!(!sb.path("sekret.unlock-key").exists(), "{way:?}");
        drop(server);
        let server = launch().start().await?;
        assert_eq!(server.state().await?, "unsealed", "{way:?}");
    }
    Ok(())
}

/// The epoch and root key fingerprints in a seal epoch mark.
fn mark_in(path: &Path) -> anyhow::Result<(i64, Vec<String>)> {
    let text = std::fs::read_to_string(path).with_context(|| format!("{}", path.display()))?;
    let mut words = text.split_whitespace().skip(1);
    let epoch = words.next().context("epoch")?.parse().context("epoch")?;
    Ok((epoch, words.filter(|w| *w != "migrated").map(String::from).collect()))
}

const FOREIGN_MARK: &str = "sekret-seal-epoch 1 0123456789abcdef\n";

async fn unseal_error(server: &Running) -> anyhow::Result<(StatusCode, Value)> {
    let (code, body) = server
        .call(
            Method::POST,
            "/api/v1/sys/unseal",
            Auth::None,
            Some(json!({"passphrase": PASSPHRASE})),
        )
        .await?;
    Ok((code, body["error"].clone()))
}

#[tokio::test]
async fn epoch_file_keeps_a_mark_the_server_checks() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        sb.passphrase_db("manual")?;
        let file = sb.p("marks.epoch");
        let launch = || sb.launch().set(way, "seal.epoch_file", &file);
        let server = launch().start().await?;
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK, "{way:?}");
        let (_, roots) = mark_in(Path::new(&file))?;
        assert_eq!(roots.len(), 1, "{way:?}: the mark names the root key");
        drop(server);
        // A mark naming another key refuses this database's own.
        std::fs::write(&file, FOREIGN_MARK).context("mark")?;
        let server = launch().start().await?;
        assert_eq!(
            unseal_error(&server).await?,
            (StatusCode::CONFLICT, json!("root_key_not_recognised")),
            "{way:?}"
        );
        drop(server);
        let missing = sb.p("missing/seal.epoch");
        let log = sb.launch().set(way, "seal.epoch_file", &missing).refused().await?;
        assert!(log.contains("cannot be created"), "{way:?}: {log}");
    }
    Ok(())
}

fn probe_epoch_file(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move {
        ensure!(server.unseal(PASSPHRASE).await? == StatusCode::OK, "unseal");
        let written: Vec<&str> = ["flag.epoch", "env.epoch", "file.epoch"]
            .into_iter()
            .filter(|name| server.dir.join(name).exists())
            .collect();
        Ok(match written.is_empty() {
            true => "none".into(),
            false => written.join(","),
        })
    })
}

#[tokio::test]
async fn precedence_seal_epoch_file() -> anyhow::Result<()> {
    precedence(Chain {
        key: "seal.epoch_file",
        flag: "flag.epoch",
        env: "env.epoch",
        file: "file.epoch",
        expect: ["flag.epoch", "env.epoch", "file.epoch", "none"],
        base: passphrase_base,
        probe: probe_epoch_file,
    })
    .await
}

/// A Postgres database has no file of its own to keep a mark beside, so without a remember file
/// or root key file the server and the admin commands need `seal.epoch_file`.
#[tokio::test]
async fn a_postgres_server_needs_an_epoch_file() -> anyhow::Result<()> {
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    let container = match Postgres::default().start().await {
        Ok(container) => container,
        Err(error) if std::env::var_os("SEKRET_REQUIRE_POSTGRES").is_none() => {
            eprintln!("skipping postgres test: {error}");
            return Ok(());
        }
        Err(error) => bail!("postgres container failed: {error}"),
    };
    let port = container.get_host_port_ipv4(5432).await.context("port")?;
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let sb = Sandbox::new()?;
    let pass = sb.passphrase_file()?;
    let mark = sb.p("seal.epoch");
    let admin = |command: &str, extra: &[&str], env: &[(&str, &str)]| {
        let mut args = vec!["admin", command, "--database-url", &url, "--passphrase-file", &pass];
        args.extend_from_slice(extra);
        sb.cli(&args, env, None)
    };

    let refused = admin("init", &[], &[])?;
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success() && stderr.contains("seal.epoch_file"),
        "{stderr}"
    );
    ok(admin("init", &["--epoch-file", &mark], &[])?)?;
    let (epoch, roots) = mark_in(Path::new(&mark))?;
    assert_eq!(roots.len(), 1);

    // The other admin commands find it through the environment and the configuration file.
    assert!(!admin("bootstrap", &[], &[])?.status.success());
    ok(admin("bootstrap", &[], &[("SEKRET_EPOCH_FILE", &mark)])?)?;
    let config = sb.write("admin.yaml", &format!("seal:\n  epoch_file: {mark}\n"))?;
    ok(admin("reset-epoch", &["--config", &config], &[])?)?;
    assert!(
        mark_in(Path::new(&mark))?.0 > epoch,
        "reset-epoch raised the configured mark"
    );

    let log = sb.launch().set(Way::Flag, "database.url", &url).refused().await?;
    assert!(log.contains("seal.epoch_file"), "{log}");
    for way in WAYS {
        let server = sb
            .launch()
            .set(Way::Flag, "database.url", &url)
            .set(way, "seal.epoch_file", &mark)
            .start()
            .await?;
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK, "{way:?}");
    }
    std::fs::write(&mark, FOREIGN_MARK).context("mark")?;
    let server = sb
        .launch()
        .set(Way::Flag, "database.url", &url)
        .set(Way::Env, "seal.epoch_file", &mark)
        .start()
        .await?;
    assert_eq!(
        unseal_error(&server).await?,
        (StatusCode::CONFLICT, json!("root_key_not_recognised"))
    );
    Ok(())
}

#[tokio::test]
async fn remember_file_problems_leave_the_server_sealed() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let admin = sb.passphrase_db("remember")?;
    let file = sb.path("sekret.unlock-key");
    let server = sb.remembering().start().await?;
    assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
    drop(server);
    assert_eq!(sb.remembering().start().await?.state().await?, "unsealed");

    // Missing: sealed, says why, and the next manual unlock writes a fresh file.
    std::fs::remove_file(&file).context("remove")?;
    let server = sb.remembering().start().await?;
    assert_eq!(server.state().await?, "sealed");
    assert_eq!(server.detail(&admin).await?["remembered"], false);
    assert!(
        server.log().contains("not unlocking from the remember file"),
        "{}",
        server.log()
    );
    assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
    assert!(file.exists());
    drop(server);
    assert_eq!(sb.remembering().start().await?.state().await?, "unsealed");

    // A device key from another server does not open this one.
    let other = Sandbox::new()?;
    other.passphrase_db("remember")?;
    let server = other.remembering().start().await?;
    assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
    drop(server);
    std::fs::copy(other.path("sekret.unlock-key"), &file).context("copy")?;
    let server = sb.remembering().start().await?;
    assert_eq!(server.state().await?, "sealed");
    assert!(
        server.log().contains("does not belong to this server"),
        "{}",
        server.log()
    );
    assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
    drop(server);
    assert_eq!(sb.remembering().start().await?.state().await?, "unsealed");

    // A symlink, even to the right key, is not followed.
    #[cfg(unix)]
    {
        let real = sb.path("elsewhere.key");
        std::fs::rename(&file, &real).context("move")?;
        std::os::unix::fs::symlink(&real, &file).context("symlink")?;
        let before = std::fs::read(&real).context("read")?;
        let server = sb.remembering().start().await?;
        assert_eq!(server.state().await?, "sealed");
        assert!(
            server.log().contains("not unlocking from the remember file"),
            "{}",
            server.log()
        );
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
        let replaced = std::fs::symlink_metadata(&file).context("meta")?;
        assert!(
            replaced.file_type().is_file(),
            "the symlink is replaced by a fresh file"
        );
        assert_eq!(
            std::fs::read(&real).context("read")?,
            before,
            "the link target is untouched"
        );
        drop(server);
        assert_eq!(sb.remembering().start().await?.state().await?, "unsealed");
    }
    Ok(())
}

#[tokio::test]
async fn unlock_passphrase_file_is_read_from_each_source() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        sb.passphrase_db("manual")?;
        let pass = sb.passphrase_file()?;
        let server = sb
            .launch()
            .default("seal.unlock", "passphrase-file")
            .set(way, "seal.passphrase_file", &pass)
            .start()
            .await?;
        assert_eq!(server.state().await?, "unsealed", "{way:?}");
    }
    let sb = Sandbox::new()?;
    sb.passphrase_db("passphrase-file")?;
    let server = sb.launch().env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE).start().await?;
    assert_eq!(server.state().await?, "unsealed", "the stored policy and the variable");
    drop(server);

    // The file wins over the variable.
    let wrong = sb.write("wrong-pass", &format!("{WRONG_PASSPHRASE}\n"))?;
    let pass = sb.passphrase_file()?;
    let server = sb
        .launch()
        .set(Way::Flag, "seal.passphrase_file", &pass)
        .env("SEKRET_UNLOCK_PASSPHRASE", WRONG_PASSPHRASE)
        .start()
        .await?;
    assert_eq!(server.state().await?, "unsealed");
    drop(server);
    let server = sb
        .launch()
        .set(Way::Flag, "seal.passphrase_file", &wrong)
        .env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE)
        .start()
        .await?;
    assert_eq!(server.state().await?, "sealed");
    Ok(())
}

#[tokio::test]
async fn passphrase_file_policy_failures_stay_sealed_and_say_why() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    sb.passphrase_db("passphrase-file")?;

    let server = sb.launch().start().await?;
    assert_eq!(server.state().await?, "sealed");
    assert!(server.log().contains("no passphrase file"), "{}", server.log());
    drop(server);

    let wrong = sb.write("wrong-pass", &format!("{WRONG_PASSPHRASE}\n"))?;
    let server = sb
        .launch()
        .set(Way::Flag, "seal.passphrase_file", &wrong)
        .start()
        .await?;
    assert_eq!(server.state().await?, "sealed");
    assert!(server.log().contains("did not open the root key"), "{}", server.log());
    drop(server);

    let missing = sb.p("missing-pass");
    let server = sb
        .launch()
        .set(Way::Flag, "seal.passphrase_file", &missing)
        .start()
        .await?;
    assert_eq!(server.state().await?, "sealed");
    assert!(server.log().contains("missing-pass"), "{}", server.log());
    assert_eq!(
        server.unseal(PASSPHRASE).await?,
        StatusCode::OK,
        "a person can still unlock it"
    );
    Ok(())
}

#[tokio::test]
async fn unlock_policy_in_configuration_overrides_the_database() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let admin = sb.passphrase_db("manual")?;
    let server = sb
        .launch()
        .set(Way::File, "seal.unlock", "passphrase-file")
        .env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE)
        .start()
        .await?;
    let status = server.detail(&admin).await?;
    assert_eq!(status["state"], "unsealed");
    assert_eq!(status["configured"], true);
    let (code, body) = server
        .call(
            Method::PUT,
            "/api/v1/sys/unlock-policy",
            Auth::Bearer(&admin),
            Some(json!({"policy": "manual"})),
        )
        .await?;
    assert_eq!(code, StatusCode::CONFLICT, "{body}");
    drop(server);

    // Unset in configuration, the stored policy applies and an admin may change it.
    let server = sb.launch().env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE).start().await?;
    let status = server.detail(&admin).await?;
    assert_eq!(
        (status["state"].as_str(), status["configured"].as_bool()),
        (Some("sealed"), Some(false))
    );
    assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
    let (code, body) = server
        .call(
            Method::PUT,
            "/api/v1/sys/unlock-policy",
            Auth::Bearer(&admin),
            Some(json!({"policy": "passphrase-file", "passphrase": PASSPHRASE})),
        )
        .await?;
    assert_eq!(code, StatusCode::OK, "{body}");
    drop(server);
    let server = sb.launch().env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE).start().await?;
    assert_eq!(server.state().await?, "unsealed", "the changed stored policy applies");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// setup.*
// ---------------------------------------------------------------------------------------------

/// The setup code the server logged.
fn logged_code(server: &Running) -> anyhow::Result<String> {
    let log = server.log();
    let line = log
        .lines()
        .find(|l| l.contains("setup code: "))
        .with_context(|| format!("no setup code in\n{log}"))?;
    Ok(line
        .rsplit("setup code: ")
        .next()
        .unwrap_or_default()
        .trim()
        .to_string())
}

async fn init_over_api(server: &Running, code: &str) -> anyhow::Result<(StatusCode, Value)> {
    server
        .call(
            Method::POST,
            "/api/v1/sys/init",
            Auth::None,
            Some(json!({"setup_code": code, "mode": "passphrase", "passphrase": PASSPHRASE})),
        )
        .await
}

#[tokio::test]
async fn setup_web_turns_api_setup_off() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let server = sb.launch().set(way, "setup.web", "false").start().await?;
        let status = server.status().await?;
        assert_eq!(
            (status["state"].as_str(), status["web_setup"].as_bool()),
            (Some("uninitialised"), Some(false)),
            "{way:?}"
        );
        // With nowhere to use it, no setup code is made or shown.
        assert!(logged_code(&server).is_err(), "{way:?}");
        assert!(server.log().contains("web setup is off"), "{way:?}");
        let (status, body) = init_over_api(&server, "AAAA-AAAA-AAAA").await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{way:?}");
        assert_eq!(body["error"], "setup_disabled");
    }
    let sb = Sandbox::new()?;
    let server = sb.launch().start().await?;
    assert_eq!(server.status().await?["web_setup"], true);
    let code = logged_code(&server)?;
    assert!(server.log().contains("/setup or with `sekret sys init`"));
    let (status, body) = init_over_api(&server, &code).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test]
async fn setup_web_off_with_auto_init_still_sets_up() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.p("root.key");
    let server = sb
        .launch()
        .set(Way::File, "setup.web", "false")
        .set(Way::File, "setup.auto_init", "true")
        .set(Way::File, "seal.mode", "key-file")
        .set(Way::File, "seal.root_key_file", &key)
        .start()
        .await?;
    let status = server.status().await?;
    assert_eq!(
        (status["state"].as_str(), status["web_setup"].as_bool()),
        (Some("unsealed"), Some(false))
    );
    let (code, _) = init_over_api(&server, "AAAA-AAAA-AAAA").await?;
    assert_eq!(code, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn auto_init_sets_up_key_file_mode() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.p("root.key");
        let launch = || {
            sb.launch()
                .default("seal.mode", "key-file")
                .default("seal.root_key_file", &key)
                .set(way, "setup.auto_init", "true")
        };
        let server = launch().start().await?;
        assert_eq!(server.state().await?, "unsealed", "{way:?}");
        assert!(server.log().contains("initialised automatically"), "{way:?}");
        #[cfg(unix)]
        assert_eq!(mode_of(Path::new(&key))?, 0o600, "{way:?}: the generated root key");
        drop(server);
        let server = launch().start().await?;
        assert_eq!(server.state().await?, "unsealed", "{way:?}: the key file is reused");
        assert!(!server.log().contains("initialised automatically"), "{way:?}");
    }
    let sb = Sandbox::new()?;
    let server = sb.launch().set(Way::Flag, "setup.auto_init", "false").start().await?;
    assert_eq!(server.state().await?, "uninitialised");
    Ok(())
}

#[tokio::test]
async fn auto_init_in_passphrase_mode_follows_each_unlock_policy() -> anyhow::Result<()> {
    // (policy, the state after a restart)
    for (policy, after_restart) in [
        ("manual", "sealed"),
        ("passphrase-file", "unsealed"),
        ("remember", "unsealed"),
    ] {
        let sb = Sandbox::new()?;
        // Only the passphrase-file policy takes the first passphrase from the unlock passphrase.
        let pass = sb.passphrase_file()?;
        let launch = || {
            let launch = sb
                .remembering()
                .set(Way::Flag, "setup.auto_init", "true")
                .set(Way::Flag, "seal.unlock", policy)
                .env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE);
            match policy {
                "passphrase-file" => launch,
                _ => launch.set(Way::Flag, "setup.passphrase_file", &pass),
            }
        };
        let server = launch().start().await?;
        let status = server.detail(&sb.bootstrap_passphrase()?).await?;
        assert_eq!(
            (status["state"].as_str(), status["seal_mode"].as_str()),
            (Some("unsealed"), Some("passphrase")),
            "{policy}: passphrase mode is the default"
        );
        assert_eq!(sb.path("sekret.unlock-key").exists(), policy == "remember", "{policy}");
        drop(server);
        let server = launch().start().await?;
        assert_eq!(server.state().await?, after_restart, "{policy}");
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK, "{policy}");
    }
    let sb = Sandbox::new()?;
    let log = sb.launch().set(Way::Env, "setup.auto_init", "true").refused().await?;
    assert!(log.contains("needs setup.passphrase_file"), "{log}");
    // The unlock passphrase is not a setup passphrase under a policy that would not keep it.
    for policy in ["manual", "remember"] {
        let sb = Sandbox::new()?;
        let log = sb
            .remembering()
            .set(Way::Flag, "setup.auto_init", "true")
            .set(Way::Flag, "seal.unlock", policy)
            .env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE)
            .refused()
            .await?;
        assert!(log.contains("needs setup.passphrase_file"), "{policy}: {log}");
    }
    Ok(())
}

#[tokio::test]
async fn setup_passphrase_file_is_the_first_passphrase() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let pass = sb.passphrase_file()?;
        let launch = || sb.launch().default("setup.auto_init", "true");
        let server = launch().set(way, "setup.passphrase_file", &pass).start().await?;
        let admin = sb.bootstrap_passphrase()?;
        assert_eq!(server.detail(&admin).await?["seal_mode"], "passphrase", "{way:?}");
        drop(server);
        std::fs::remove_file(&pass).context("delete the bootstrap file")?;
        let server = launch().start().await?;
        assert_eq!(server.state().await?, "sealed", "{way:?}: never used to unlock");
        assert_eq!(server.unseal(WRONG_PASSPHRASE).await?, StatusCode::UNAUTHORIZED);
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK, "{way:?}");
    }
    let sb = Sandbox::new()?;
    let weak = sb.write("weak", "password1234\n")?;
    let log = sb
        .launch()
        .default("setup.auto_init", "true")
        .set(Way::Flag, "setup.passphrase_file", &weak)
        .refused()
        .await?;
    assert!(log.to_lowercase().contains("passphrase"), "{log}");
    assert!(!log.contains("password1234"), "the passphrase is never logged");
    Ok(())
}

#[tokio::test]
async fn setup_admin_token_file_holds_a_working_token() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.p("root.key");
        let token_file = sb.p("admin-token");
        let launch = || {
            sb.launch()
                .default("setup.auto_init", "true")
                .default("seal.mode", "key-file")
                .default("seal.root_key_file", &key)
                .set(way, "setup.admin_token_file", &token_file)
        };
        let server = launch().start().await?;
        #[cfg(unix)]
        assert_eq!(mode_of(Path::new(&token_file))?, 0o600, "{way:?}");
        let token = std::fs::read_to_string(&token_file).context("token")?;
        let (_, me) = server.get("/api/v1/me", Auth::Bearer(token.trim())).await?;
        assert_eq!(me["name"], "bootstrap-admin", "{way:?}");
        drop(server);
        let server = launch().start().await?;
        assert_eq!(server.state().await?, "unsealed");
        assert_eq!(
            std::fs::read_to_string(&token_file).context("token")?,
            token,
            "{way:?}: only the start that sets up writes a token"
        );
    }
    let sb = Sandbox::new()?;
    let key = sb.p("root.key");
    let server = sb
        .launch()
        .default("setup.auto_init", "true")
        .default("seal.mode", "key-file")
        .default("seal.root_key_file", &key)
        .start()
        .await?;
    assert!(server.log().contains("initialised automatically"));
    assert!(!server.log().contains("break-glass"), "no file, no token");
    Ok(())
}

#[tokio::test]
async fn setup_code_file_holds_the_logged_code() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let file = sb.p("setup-code");
        let server = sb.launch().set(way, "setup.code_file", &file).start().await?;
        #[cfg(unix)]
        assert_eq!(mode_of(Path::new(&file))?, 0o600, "{way:?}");
        let written = std::fs::read_to_string(&file).context("code file")?;
        assert_eq!(written.trim(), logged_code(&server)?, "{way:?}");
        assert_eq!(
            init_over_api(&server, "AAAA-AAAA-AAAA").await?.0,
            StatusCode::UNAUTHORIZED
        );
        let (code, body) = init_over_api(&server, written.trim()).await?;
        assert_eq!(code, StatusCode::OK, "{way:?}: {body}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The configuration file itself
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn bad_configuration_files_are_refused_with_the_reason() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let cases = [
        ("server:\n  listn: 127.0.0.1:1\n", "listn"),
        ("servers:\n  listen: 127.0.0.1:1\n", "servers"),
        // Values are not echoed back, so a password in the file never reaches the log.
        ("database:\n  snapshots_to_keep: lots\n", "line 2"),
        ("server:\n  listen: [1, 2]\n", "line 2"),
        ("seal:\n  unlock: sometimes\n", "sometimes"),
        ("setup:\n  web: maybe\n", "true/false"),
        ("setup:\n  web: yes\n", "true/false"),
    ];
    for (text, needle) in cases {
        let log = sb.launch().raw_config(text).refused().await?;
        assert!(log.contains(needle), "{text:?} should mention {needle}: {log}");
        assert!(log.contains("config-"), "{text:?} should name the file: {log}");
    }
    let missing = sb
        .launch()
        .arg(&format!("--config={}", sb.p("nope.yaml")))
        .refused()
        .await?;
    assert!(missing.contains("nope.yaml"), "{missing}");
    Ok(())
}

#[tokio::test]
async fn an_empty_configuration_file_means_the_defaults() -> anyhow::Result<()> {
    for text in ["", "# nothing set\n"] {
        let sb = Sandbox::new()?;
        let server = sb.launch().raw_config(text).start().await?;
        let status = server.status().await?;
        assert_eq!(status["state"], "uninitialised");
        assert_eq!(status["web_setup"], true);
        let (code, _) = server.cli_start().await?;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "nothing but setup until set up");
    }
    Ok(())
}

#[tokio::test]
async fn print_config_loads_back_as_a_configuration() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let printed = ok(sb.cli(&["server", "--print-config"], &[], None)?)?;
    // Only the listen address is overridden; the printed public URL and database are used.
    let server = sb
        .launch()
        .without("server.public_url")
        .without("database.url")
        .raw_config(&printed)
        .start()
        .await?;
    let status = server.status().await?;
    assert_eq!(status["state"], "uninitialised");
    assert_eq!(status["web_setup"], true);
    assert!(
        server.log().contains("https://sekret.example.com/setup"),
        "{}",
        server.log()
    );
    assert!(sb.path("sekret.db").exists(), "the relative default database path");
    Ok(())
}

/// The public URL a key-file server started with these config sources reports.
async fn public_url_with_configs(sb: &Sandbox, flag: Option<&str>, env: Option<&str>) -> anyhow::Result<String> {
    let mut launch = sb.keyed(&sb.p("root.key")).without("server.public_url");
    if let Some(path) = flag {
        launch = launch.arg(&format!("--config={path}"));
    }
    if let Some(path) = env {
        launch = launch.env("SEKRET_CONFIG", path);
    }
    let server = launch.start().await?;
    probe_public_url(&server).await
}

#[tokio::test]
async fn config_flag_beats_sekret_config() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    sb.root_key("root.key")?;
    let flag = sb.write("flag.yaml", "server:\n  public_url: https://flag.example\n")?;
    let env = sb.write("env.yaml", "server:\n  public_url: https://env.example\n")?;
    assert_eq!(
        public_url_with_configs(&sb, Some(&flag), Some(&env)).await?,
        "https://flag.example"
    );
    assert_eq!(
        public_url_with_configs(&sb, None, Some(&env)).await?,
        "https://env.example"
    );
    Ok(())
}

#[tokio::test]
async fn admin_commands_read_the_configuration_file() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).start().await?;
    let config = sb.write(
        "admin.yaml",
        &format!("database:\n  url: {}\nseal:\n  root_key_file: {key}\n", sb.db()),
    )?;
    for env in [vec![], vec![("SEKRET_CONFIG", config.as_str())]] {
        let args: Vec<&str> = if env.is_empty() {
            vec!["admin", "bootstrap", "--config", &config]
        } else {
            vec!["admin", "bootstrap"]
        };
        let token = ok(sb.cli(&args, &env, None)?)?;
        let (_, me) = server.get("/api/v1/me", Auth::Bearer(token.trim())).await?;
        assert_eq!(me["name"], "bootstrap-admin");
    }
    let token = ok(sb.cli(
        &["admin", "bootstrap"],
        &[("SEKRET_DATABASE_URL", &sb.db()), ("SEKRET_ROOT_KEY_FILE", &key)],
        None,
    )?)?;
    let (code, _) = server.get("/api/v1/me", Auth::Bearer(token.trim())).await?;
    assert_eq!(code, StatusCode::OK);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Precedence: flag over environment over file over default
// ---------------------------------------------------------------------------------------------

type Probe = for<'a> fn(&'a Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>>;

/// One option set to a different value in each place.
struct Chain {
    key: &'static str,
    flag: &'static str,
    env: &'static str,
    file: &'static str,
    /// What the probe reports for each winner: flag, environment, file, default.
    expect: [&'static str; 4],
    /// Prepares the sandbox and returns the base launch.
    base: fn(&Sandbox) -> anyhow::Result<Launch<'_>>,
    probe: Probe,
}

fn keyed_base(sb: &Sandbox) -> anyhow::Result<Launch<'_>> {
    let key = sb.root_key("root.key")?;
    Ok(sb.keyed(&key))
}

fn passphrase_base(sb: &Sandbox) -> anyhow::Result<Launch<'_>> {
    sb.passphrase_db("manual")?;
    Ok(sb.launch().env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE))
}

fn uninitialised_base(sb: &Sandbox) -> anyhow::Result<Launch<'_>> {
    Ok(sb.launch())
}

fn tls_base(sb: &Sandbox) -> anyhow::Result<Launch<'_>> {
    pki(sb)?;
    let key = sb.root_key("root.key")?;
    Ok(sb
        .keyed(&key)
        .https(tls_client(sb, Some("client"))?)
        .default("tls.cert_file", &sb.p("server.pem"))
        .default("tls.key_file", &sb.p("server-key.pem"))
        .default("tls.client_ca_file", &sb.p("ca.pem")))
}

fn probe_public_url(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move {
        let (_, body) = server.cli_start().await?;
        let link = body["verification_url"].as_str().context("link")?;
        Ok(link.split("/cli-login").next().unwrap_or_default().to_string())
    })
}

fn probe_snapshots(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move {
        let admin = ok(Command::new(BIN)
            .args(["admin", "bootstrap", "--database-url"])
            .arg(format!("sqlite://{}", server.dir.join("sekret.db").display()))
            .arg("--root-key-file")
            .arg(server.dir.join("root.key"))
            .env_clear()
            .output()
            .context("bootstrap")?)?;
        Ok(snapshots_after_writes(server, admin.trim(), 5).await?.to_string())
    })
}

fn probe_rate(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move { Ok(allowed_in_a_row(server, 6).await?.to_string()) })
}

fn probe_unlock(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move {
        let status = server.detail(&admin_token_for(&server.dir)?).await?;
        Ok(format!(
            "{} {} {}",
            status["unlock_policy"].as_str().unwrap_or_default(),
            status["configured"],
            status["state"].as_str().unwrap_or_default()
        ))
    })
}

fn probe_web_setup(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move { Ok(server.status().await?["web_setup"].to_string()) })
}

fn probe_client_auth(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move {
        let ca = std::fs::read(server.dir.join("ca.pem")).context("ca")?;
        let anonymous = reqwest::Client::builder()
            .tls_certs_only(reqwest::Certificate::from_pem_bundle(&ca).context("ca bundle")?)
            .no_proxy()
            .build()
            .context("client")?;
        Ok(if reaches(&anonymous, &server.url).await {
            "optional".into()
        } else {
            "required".into()
        })
    })
}

fn probe_listen(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move {
        let address = listening_address(&server.log()).context("listening line")?;
        Ok(address.port().to_string())
    })
}

/// What a start with nothing set reports when the option has no default and the server refuses.
const REFUSED: &str = "refused";

/// Starts the server four times: flag, environment and file all set; environment and file;
/// file only; nothing. The probe must see the winner each time.
async fn precedence(chain: Chain) -> anyhow::Result<()> {
    let layers: [&[Way]; 4] = [
        &[Way::Flag, Way::Env, Way::File],
        &[Way::Env, Way::File],
        &[Way::File],
        &[],
    ];
    for (ways, expected) in layers.iter().zip(chain.expect) {
        let sb = Sandbox::new()?;
        let mut launch = (chain.base)(&sb)?;
        if ways.is_empty() {
            launch = launch.without(chain.key);
        }
        for way in ways.iter() {
            let value = match way {
                Way::Flag => chain.flag,
                Way::Env => chain.env,
                Way::File => chain.file,
            };
            launch = launch.set(*way, chain.key, value);
        }
        if expected == REFUSED {
            launch.refused().await?;
            continue;
        }
        let server = launch.start().await?;
        let seen = (chain.probe)(&server).await?;
        assert_eq!(seen, expected, "{} set by {ways:?}", chain.key);
    }
    Ok(())
}

#[tokio::test]
async fn precedence_server_public_url() -> anyhow::Result<()> {
    precedence(Chain {
        key: "server.public_url",
        flag: "https://flag.example",
        env: "https://env.example",
        file: "https://file.example",
        expect: [
            "https://flag.example",
            "https://env.example",
            "https://file.example",
            REFUSED,
        ],
        base: keyed_base,
        probe: probe_public_url,
    })
    .await
}

#[tokio::test]
async fn precedence_server_listen() -> anyhow::Result<()> {
    let layers: [(&[Way], Way); 3] = [
        (&[Way::Flag, Way::Env, Way::File], Way::Flag),
        (&[Way::Env, Way::File], Way::Env),
        (&[Way::File], Way::File),
    ];
    for (ways, winner) in layers {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let (server, expected) = start_listen_layer(&sb, &key, ways, winner).await?;
        assert_eq!(probe_listen(&server).await?, expected.to_string(), "{ways:?}");
    }
    Ok(())
}

/// Starts with `server.listen` set in each of `ways` to a port of its own. The test keeps every
/// losing port bound, so a server that chose one could not start; only the winner's is freed.
async fn start_listen_layer(sb: &Sandbox, key: &str, ways: &[Way], winner: Way) -> anyhow::Result<(Running, u16)> {
    for _ in 0..PORT_ATTEMPTS {
        let mut launch = sb.keyed(key);
        let mut losers = Vec::new();
        let mut expected = None;
        for way in ways {
            let held = HeldPort::new().context("hold port")?;
            let port = held.port().context("held port")?;
            launch = launch.set(*way, "server.listen", &format!("127.0.0.1:{port}"));
            if *way == winner {
                expected = Some(port);
                launch = launch.hold(held);
            } else {
                losers.push(held);
            }
        }
        let expected = expected.context("the winner is one of the ways")?;
        match launch.start().await {
            Ok(running) => return Ok((running, expected)),
            Err(error) if lost_port(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    bail!("the server could not bind in {PORT_ATTEMPTS} attempts; it may be choosing a losing port")
}

#[tokio::test]
async fn precedence_database_snapshots_to_keep() -> anyhow::Result<()> {
    precedence(Chain {
        key: "database.snapshots_to_keep",
        flag: "2",
        env: "3",
        file: "4",
        expect: ["2", "3", "4", "5"],
        base: keyed_base,
        probe: probe_snapshots,
    })
    .await
}

#[tokio::test]
async fn precedence_auth_login_rate_per_minute() -> anyhow::Result<()> {
    precedence(Chain {
        key: "auth.login_rate_per_minute",
        flag: "2",
        env: "3",
        file: "4",
        expect: ["2", "3", "4", "6"],
        base: keyed_base,
        probe: probe_rate,
    })
    .await
}

fn probe_connections(server: &Running) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
    Box::pin(async move { Ok(connections_served(server, 6).await?.to_string()) })
}

#[tokio::test]
async fn precedence_server_max_connections() -> anyhow::Result<()> {
    precedence(Chain {
        key: "server.max_connections",
        flag: "2",
        env: "3",
        file: "4",
        expect: ["2", "3", "4", "6"],
        base: keyed_base,
        probe: probe_connections,
    })
    .await
}

#[tokio::test]
async fn precedence_tls_client_auth() -> anyhow::Result<()> {
    precedence(Chain {
        key: "tls.client_auth",
        flag: "optional",
        env: "required",
        file: "optional",
        expect: ["optional", "required", "optional", "required"],
        base: tls_base,
        probe: probe_client_auth,
    })
    .await
}

#[tokio::test]
async fn precedence_seal_unlock() -> anyhow::Result<()> {
    precedence(Chain {
        key: "seal.unlock",
        flag: "manual",
        env: "passphrase-file",
        file: "remember",
        expect: [
            "manual true sealed",
            "passphrase-file true unsealed",
            "remember true sealed",
            "manual false sealed",
        ],
        base: passphrase_base,
        probe: probe_unlock,
    })
    .await
}

#[tokio::test]
async fn precedence_setup_web() -> anyhow::Result<()> {
    precedence(Chain {
        key: "setup.web",
        flag: "false",
        env: "true",
        file: "false",
        expect: ["false", "true", "false", "true"],
        base: uninitialised_base,
        probe: probe_web_setup,
    })
    .await
}

#[tokio::test]
async fn precedence_oidc_client_id() -> anyhow::Result<()> {
    let issuer = Issuer::start().await?;
    let layers: [(&[Way], &str); 4] = [
        (&[Way::Flag, Way::Env, Way::File], "from-flag"),
        (&[Way::Env, Way::File], "from-env"),
        (&[Way::File], "from-file"),
        (&[], "sekret"),
    ];
    for (ways, expected) in layers {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let mut launch = sb.keyed(&key).oidc(&issuer)?;
        for way in ways {
            let value = match way {
                Way::Flag => "from-flag",
                Way::Env => "from-env",
                Way::File => "from-file",
            };
            launch = launch.set(*way, "oidc.client_id", value);
        }
        let server = launch.start().await?;
        let login = begin_login(&server).await?;
        assert_eq!(query_param(&login.authorize, "client_id")?, expected, "{ways:?}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// File permissions
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn backups_written_by_the_cli_are_owner_only() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).start().await?;
    let admin = sb.bootstrap(&key)?;
    server.create_project(&admin, "app").await?;
    let env = [("SEKRET_URL", server.url.as_str()), ("SEKRET_TOKEN", admin.as_str())];
    ok(sb.cli(&["sys", "backup", "-o", "nightly.skb"], &env, None)?)?;
    assert_eq!(mode_of(&sb.path("nightly.skb"))?, 0o600);
    let backup = std::fs::read(sb.path("nightly.skb")).context("backup")?;
    assert!(backup.starts_with(b"SKB1"));
    drop(server);

    let restored = format!("sqlite://{}", sb.p("restored.db"));
    ok(sb.cli(
        &[
            "admin",
            "restore",
            "--backup",
            "nightly.skb",
            "--database-url",
            &restored,
            "--root-key-file",
            &key,
        ],
        &[],
        None,
    )?)?;
    assert_eq!(mode_of(&sb.path("restored.db"))?, 0o600, "the restored database");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn root_keys_written_on_the_host_are_owner_only() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    sb.passphrase_db("manual")?;
    let pass = sb.passphrase_file()?;
    ok(sb.cli(
        &[
            "admin",
            "set-seal-mode",
            "key-file",
            "--database-url",
            &sb.db(),
            "--root-key-file",
            &sb.p("written.key"),
            "--passphrase-file",
            &pass,
        ],
        &[],
        None,
    )?)?;
    assert_eq!(mode_of(&sb.path("written.key"))?, 0o600);
    let server = sb.keyed(&sb.p("written.key")).start().await?;
    let admin = sb.bootstrap(&sb.p("written.key"))?;
    assert_eq!(server.detail(&admin).await?["seal_mode"], "key-file");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Upgrading from the release before sealing
// ---------------------------------------------------------------------------------------------

fn migrations_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../sekret-store/migrations/sqlite")
}

async fn sqlite_pool(path: &Path) -> anyhow::Result<sqlx::SqlitePool> {
    // Rollback journal rather than WAL, so the file can be copied once the pool is closed.
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete);
    sqlx::SqlitePool::connect_with(options).await.context("sqlite")
}

/// Applies only the migrations up to and including `last`, as an older release would have.
async fn migrate_up_to(path: &Path, last: i64) -> anyhow::Result<()> {
    let pool = sqlite_pool(path).await?;
    let mut migrator = sqlx::migrate::Migrator::new(migrations_dir())
        .await
        .context("migrations")?;
    let earlier: Vec<_> = migrator
        .migrations
        .iter()
        .filter(|m| m.version <= last)
        .cloned()
        .collect();
    migrator.migrations = std::borrow::Cow::Owned(earlier);
    migrator.run(&pool).await.context("migrate")?;
    pool.close().await;
    Ok(())
}

async fn schema(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let pool = sqlite_pool(path).await?;
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
            .fetch_all(&pool)
            .await
            .context("schema")?;
    let versions: Vec<(i64,)> = sqlx::query_as("SELECT version FROM _sqlx_migrations ORDER BY version")
        .fetch_all(&pool)
        .await
        .context("versions")?;
    pool.close().await;
    let mut out: Vec<(String, String)> = rows.into_iter().map(|(n, s)| (n, s.unwrap_or_default())).collect();
    out.push(("migrations".into(), format!("{versions:?}")));
    Ok(out)
}

#[tokio::test]
async fn a_database_from_before_sealing_keeps_working_in_key_file_mode() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;

    // The schema an older release leaves behind, from migrations 0001 to 0004 only.
    let reference = sb.path("reference.db");
    migrate_up_to(&reference, 4).await?;
    let old_schema = schema(&reference).await?;
    assert!(!old_schema.iter().any(|(name, _)| name == "seal_config"));

    // Data written by the server, then the sealing migration taken out again.
    let server = sb.keyed(&key).start().await?;
    let admin = sb.bootstrap(&key)?;
    server.create_project(&admin, "app").await?;
    server.write_secret(&admin, "DB_URL", "postgres://kept").await?;
    drop(server);
    let db = sb.path("sekret.db");
    let pool = sqlite_pool(&db).await?;
    sqlx::query("DROP TABLE seal_config")
        .execute(&pool)
        .await
        .context("drop")?;
    sqlx::query("ALTER TABLE access_tokens DROP COLUMN auth_time")
        .execute(&pool)
        .await
        .context("drop column")?;
    sqlx::query("ALTER TABLE login_states DROP COLUMN max_age")
        .execute(&pool)
        .await
        .context("drop column")?;
    for column in ["requested_from_ip", "user_agent"] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE cli_logins DROP COLUMN {column}"
        )))
        .execute(&pool)
        .await
        .context("drop column")?;
    }
    sqlx::query("DROP INDEX access_tokens_sealed_hash")
        .execute(&pool)
        .await
        .context("drop index")?;
    for (table, column) in [
        ("access_tokens", "mac"),
        ("access_tokens", "sealed_hash"),
        ("client_secrets", "mac"),
        ("identity_auth_methods", "mac"),
        ("cli_logins", "approval_mac"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!("ALTER TABLE {table} DROP COLUMN {column}")))
            .execute(&pool)
            .await
            .context("drop column")?;
    }
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version >= 5")
        .execute(&pool)
        .await
        .context("forget")?;
    pool.close().await;
    assert_eq!(
        schema(&db).await?,
        old_schema,
        "the downgraded database matches the old schema"
    );
    std::fs::copy(&db, sb.path("no-key.db")).context("copy")?;
    std::fs::copy(&db, sb.path("passphrase.db")).context("copy")?;

    // Without the key it refuses, and so it does with passphrase mode configured.
    let log = sb
        .launch()
        .set(Way::Flag, "database.url", &sb.db_named("no-key.db"))
        .refused()
        .await?;
    assert!(log.contains("needs its root key file"), "{log}");
    let log = sb
        .keyed(&key)
        .set(Way::Flag, "database.url", &sb.db_named("passphrase.db"))
        .set(Way::Flag, "seal.mode", "passphrase")
        .refused()
        .await?;
    assert!(log.contains("set-seal-mode"), "{log}");

    // With the key it upgrades in key-file mode and the data is readable. The token minted above
    // was stored in this version's keyed form, which no older release wrote, so a new one is used.
    let server = sb.keyed(&key).start().await?;
    let admin = sb.bootstrap(&key)?;
    let status = server.detail(&admin).await?;
    assert_eq!(
        (status["state"].as_str(), status["seal_mode"].as_str()),
        (Some("unsealed"), Some("key-file"))
    );
    let (code, secret) = server.read_secret(&admin, "DB_URL").await?;
    assert_eq!(
        (code, secret["value"].as_str()),
        (StatusCode::OK, Some("postgres://kept"))
    );
    drop(server);
    assert!(schema(&db).await?.iter().any(|(name, _)| name == "seal_config"));

    // An empty old-schema database upgrades too.
    let empty = Sandbox::new()?;
    migrate_up_to(&empty.path("sekret.db"), 4).await?;
    let key = empty.root_key("root.key")?;
    let server = empty.keyed(&key).start().await?;
    assert_eq!(server.detail(&empty.bootstrap(&key)?).await?["seal_mode"], "key-file");
    Ok(())
}

/// The release before sealing, when it is installed. Set SEKRET_PREVIOUS_BIN to point elsewhere.
fn previous_release() -> Option<PathBuf> {
    let path = std::env::var_os("SEKRET_PREVIOUS_BIN")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".local/bin/sekret")))?;
    if !path.exists() {
        return None;
    }
    let help = Command::new(&path).args(["sys", "--help"]).output().ok()?;
    // A binary that knows `sys` already has sealing, so it is not the release before it.
    (!help.status.success()).then_some(path)
}

/// The address in the previous release's `sekret listening address=...` line.
fn previous_listening_address(log: &str) -> Option<SocketAddr> {
    log.lines()
        .filter(|line| line.contains("sekret listening"))
        .find_map(|line| line.split_once("address=")?.1.split_whitespace().next()?.parse().ok())
}

#[tokio::test]
async fn data_written_by_the_previous_release_stays_readable() -> anyhow::Result<()> {
    let Some(previous) = previous_release() else {
        eprintln!(
            "skipping: no pre-sealing sekret binary at ~/.local/bin/sekret or SEKRET_PREVIOUS_BIN; \
             download v1.0.0 from the GitHub release to run this test"
        );
        return Ok(());
    };
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let log = sb.path("previous.log");
    let mut old = Command::new(&previous)
        .args(["server", "--listen", "127.0.0.1:0", "--public-url", "http://127.0.0.1"])
        .args(["--database-url", &sb.db(), "--root-key-file", &key])
        .current_dir(sb.dir.path())
        .env_clear()
        .env("SEKRET_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).context("previous log")?)
        .spawn()
        .context("previous release")?;
    let deadline = Instant::now() + START_TIMEOUT;
    let address = loop {
        if let Some(address) = previous_listening_address(&read_log(&log)) {
            break address;
        }
        if let Some(status) = old.try_wait().context("wait")? {
            bail!("previous release exited with {status}:\n{}", read_log(&log));
        }
        if Instant::now() >= deadline {
            let _ = old.kill();
            let _ = old.wait();
            bail!("previous release did not start:\n{}", read_log(&log));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let url = format!("http://{address}");
    let client = plain_client()?;
    while Instant::now() < deadline && !reaches(&client, &url).await {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let admin = Command::new(&previous)
        .args([
            "admin",
            "bootstrap",
            "--database-url",
            &sb.db(),
            "--root-key-file",
            &key,
        ])
        .output()
        .context("previous bootstrap")?;
    let admin = ok(admin)?.trim().to_string();
    let send = |method: Method, path: &str, body: Value| {
        client
            .request(method, format!("{url}{path}"))
            .bearer_auth(&admin)
            .json(&body)
            .send()
    };
    let created = send(Method::POST, "/api/v1/projects", json!({"slug": "app", "name": "App"}))
        .await
        .context("create")?;
    assert!(created.status().is_success(), "{}", created.status());
    let written = send(
        Method::POST,
        "/api/v1/projects/app/environments/dev/secrets/batch",
        json!({"upserts": [{"key": "OLD", "value": "from-v1"}]}),
    )
    .await
    .context("write")?;
    assert!(written.status().is_success(), "{}", written.status());
    old.kill().ok();
    old.wait().ok();

    let server = sb.keyed(&key).start().await?;
    assert_eq!(server.detail(&admin).await?["seal_mode"], "key-file");
    let (code, secret) = server.read_secret(&admin, "OLD").await?;
    assert_eq!((code, secret["value"].as_str()), (StatusCode::OK, Some("from-v1")));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Options added by the first security audit
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn seal_remember_secret_file_is_needed_to_unlock_from_the_remember_file() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        sb.passphrase_db("remember")?;
        let secret = sb.write("remember-secret", "xX0cbCqZ2IpCHTTEMxOxIhogaYMr4nufQk3TEU8lrgY=\n")?;
        let with_secret = || sb.remembering().set(way, "seal.remember_secret_file", &secret);
        let server = with_secret().start().await?;
        assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK, "{way:?}");
        drop(server);
        assert_eq!(with_secret().start().await?.state().await?, "unsealed", "{way:?}");
        let without = sb.remembering().start().await?;
        assert_eq!(
            without.state().await?,
            "sealed",
            "{way:?}: the disk alone is not enough"
        );
        assert!(without.log().contains("remember secret"), "{way:?}: {}", without.log());
        drop(without);
        let short = sb.write("short", "too short\n")?;
        let log = sb
            .remembering()
            .set(way, "seal.remember_secret_file", &short)
            .refused()
            .await?;
        assert!(log.contains("at least 32"), "{way:?}: {log}");
        let guessable = sb.write("guessable", &format!("{}\n", "r".repeat(40)))?;
        let log = sb
            .remembering()
            .set(way, "seal.remember_secret_file", &guessable)
            .refused()
            .await?;
        assert!(log.contains("too easy to guess"), "{way:?}: {log}");
    }
    let sb = Sandbox::new()?;
    sb.passphrase_db("remember")?;
    let log = sb
        .remembering()
        .env("SEKRET_REMEMBER_SECRET", &"e".repeat(40))
        .refused()
        .await?;
    assert!(log.contains("too easy to guess"), "{log}");
    let value = "jMvJGjs1rlsZhRRrc5VnYCIQg/Hbw1zYRqMi5us1Xmw=".to_string();
    let server = sb.remembering().env("SEKRET_REMEMBER_SECRET", &value).start().await?;
    assert_eq!(server.unseal(PASSPHRASE).await?, StatusCode::OK);
    drop(server);
    let server = sb.remembering().env("SEKRET_REMEMBER_SECRET", &value).start().await?;
    assert_eq!(
        server.state().await?,
        "unsealed",
        "the value itself works from the environment"
    );
    Ok(())
}

#[tokio::test]
async fn backup_temp_dir_is_where_backups_are_staged() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let staging = sb.p("staging");
        let server = sb.keyed(&key).set(way, "backup.temp_dir", &staging).start().await?;
        let admin = sb.bootstrap(&key)?;
        let (code, _) = server
            .call(Method::POST, "/api/v1/sys/backup", Auth::Bearer(&admin), None)
            .await?;
        assert_eq!(code, StatusCode::OK, "{way:?}");
        assert!(
            sb.path("staging").is_dir(),
            "{way:?}: the directory is made on first use"
        );
        #[cfg(unix)]
        assert_eq!(mode_of(&sb.path("staging"))?, 0o700, "{way:?}");
    }
    Ok(())
}

/// Another user who can swap the staging directory could read or plant the database snapshot.
#[cfg(unix)]
#[tokio::test]
async fn backup_temp_dir_others_can_swap_is_refused() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let open = sb.path("open");
        std::fs::create_dir(&open).context("dir")?;
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        let below = open.join("private");
        std::fs::create_dir(&below).context("dir")?;
        std::fs::set_permissions(&below, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        for dir in [sb.p("open"), below.display().to_string(), sb.p("open/not-yet")] {
            let log = sb.keyed(&key).set(way, "backup.temp_dir", &dir).refused().await?;
            assert!(
                log.contains("backup.temp_dir") && log.contains("not safe for staging"),
                "{way:?} {dir}: {log}"
            );
        }
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).context("chmod")?;
        let sticky = sb
            .keyed(&key)
            .set(way, "backup.temp_dir", &sb.p("open"))
            .start()
            .await?;
        drop(sticky);
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).context("chmod")?;
        let server = sb
            .keyed(&key)
            .set(way, "backup.temp_dir", &below.display().to_string())
            .start()
            .await?;
        let admin = sb.bootstrap(&key)?;
        let (code, _) = server
            .call(Method::POST, "/api/v1/sys/backup", Auth::Bearer(&admin), None)
            .await?;
        assert_eq!(code, StatusCode::OK, "{way:?}");
    }
    Ok(())
}

#[tokio::test]
async fn auth_cli_login_max_auth_age_must_be_positive() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let log = sb
            .keyed(&key)
            .set(way, "auth.cli_login_max_auth_age", "0")
            .refused()
            .await?;
        assert!(log.contains("cli_login_max_auth_age"), "{way:?}: {log}");
        let server = sb
            .keyed(&key)
            .set(way, "auth.cli_login_max_auth_age", "900")
            .start()
            .await?;
        assert!(
            server.log().contains("auth.cli_login_max_auth_age") && server.log().contains("900"),
            "{way:?}: the startup log reports it"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The second security audit
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn server_unix_socket_unseals_on_the_host() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        sb.passphrase_db("manual")?;
        let pass = sb.passphrase_file()?;
        let socket = sb.p("sekret.sock");
        for _ in 0..2 {
            let server = sb.launch().set(way, "server.unix_socket", &socket).start().await?;
            assert_eq!(server.state().await?, "sealed", "{way:?}");
            #[cfg(unix)]
            assert_eq!(mode_of(&sb.path("sekret.sock"))?, 0o600, "{way:?}");
            let unsealed = sb.cli(
                &["sys", "unseal", "--socket", &socket, "--passphrase-file", &pass],
                &[],
                None,
            )?;
            assert!(ok(unsealed)?.contains("unsealed"), "{way:?}");
            assert_eq!(server.state().await?, "unsealed", "{way:?}");
            // A restart finds the old socket file and replaces it.
        }
    }
    for way in WAYS {
        let sb = Sandbox::new()?;
        sb.passphrase_db("manual")?;
        let socket = sb.p("group.sock");
        let server = sb
            .launch()
            .set(Way::Flag, "server.unix_socket", &socket)
            .set(way, "server.unix_socket_mode", "0660")
            .start()
            .await?;
        #[cfg(unix)]
        assert_eq!(mode_of(&sb.path("group.sock"))?, 0o660, "{way:?}");
        drop(server);
        let log = sb
            .launch()
            .set(Way::Flag, "server.unix_socket", &socket)
            .set(way, "server.unix_socket_mode", "0777")
            .refused()
            .await?;
        assert!(log.contains("0600 or 0660"), "{way:?}: {log}");
    }
    Ok(())
}

/// Removing a variable from the environment leaves its value in `/proc/<pid>/environ`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn secrets_from_the_environment_are_wiped_from_the_process() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    sb.passphrase_db("passphrase-file")?;
    let remember = "cJX/vpMVpBxjSDbMhicakdkcJMocZMmeEPyCOuUhips=".to_string();
    let server = sb
        .remembering()
        .env("SEKRET_UNLOCK_PASSPHRASE", PASSPHRASE)
        .env("SEKRET_REMEMBER_SECRET", &remember)
        .start()
        .await?;
    assert_eq!(server.state().await?, "unsealed", "the values were still read");
    let environ = std::fs::read(format!("/proc/{}/environ", server.child.id())).context("environ")?;
    let has = |needle: &[u8]| environ.windows(needle.len()).any(|w| w == needle);
    assert!(!has(PASSPHRASE.as_bytes()), "the unlock passphrase is gone");
    assert!(!has(remember.as_bytes()), "the remember secret is gone");
    assert!(has(b"SEKRET_LOG=info"), "the rest of the environment is untouched");
    Ok(())
}

#[tokio::test]
async fn setup_code_file_never_truncates_another_file() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let log = sb
        .launch()
        .set(Way::Flag, "setup.code_file", &sb.p("sekret.db"))
        .refused()
        .await?;
    assert!(log.contains("same file as the database"), "{log}");
    let precious = sb.write("precious", "keep me\n")?;
    std::fs::hard_link(&precious, sb.path("code")).context("link")?;
    for way in WAYS {
        let log = sb.launch().set(way, "setup.code_file", &sb.p("code")).refused().await?;
        assert!(log.contains("not a file sekret wrote"), "{way:?}: {log}");
    }
    assert_eq!(std::fs::read_to_string(&precious).context("read")?, "keep me\n");
    Ok(())
}

#[tokio::test]
async fn admin_commands_that_rewrite_keys_refuse_while_a_server_runs() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let new = sb.root_key("new.key")?;
    let server = sb.keyed(&key).start().await?;
    let admin = sb.bootstrap(&key)?;
    server.create_project(&admin, "app").await?;
    server.write_secret(&admin, "A", "kept").await?;
    let db = sb.db();
    let rotate = || {
        sb.cli(
            &[
                "admin",
                "rotate-root-key",
                "--database-url",
                &db,
                "--root-key-file",
                &key,
                "--new-root-key-file",
                &new,
            ],
            &[],
            None,
        )
    };
    let refused = rotate()?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("another sekret server"));
    let refused = sb.cli(
        &[
            "admin",
            "set-seal-mode",
            "passphrase",
            "--database-url",
            &db,
            "--root-key-file",
            &key,
            "--passphrase-file",
            &sb.passphrase_file()?,
        ],
        &[],
        None,
    )?;
    assert!(String::from_utf8_lossy(&refused.stderr).contains("another sekret server"));
    let (code, secret) = server.read_secret(&admin, "A").await?;
    assert_eq!((code, secret["value"].as_str()), (StatusCode::OK, Some("kept")));
    drop(server);

    ok(rotate()?)?;
    let server = sb.keyed(&new).start().await?;
    let (code, secret) = server.read_secret(&admin, "A").await?;
    assert_eq!((code, secret["value"].as_str()), (StatusCode::OK, Some("kept")));
    let (_, audit) = server.get("/api/v1/audit?limit=200", Auth::Bearer(&admin)).await?;
    let entries = audit["entries"].as_array().context("entries")?;
    for action in ["admin.bootstrap", "admin.rotate_root_key"] {
        assert!(
            entries.iter().any(|e| e["action"] == action && e["ip"] == "local"),
            "{action} is audited from the host"
        );
    }
    Ok(())
}

#[tokio::test]
async fn overriding_security_settings_from_the_environment_is_warned_about() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb
        .keyed(&key)
        .set(Way::File, "auth.default_org_role", "org-member")
        .env("SEKRET_DEFAULT_ORG_ROLE", "org-admin")
        .set_list(Way::File, "server.trusted_proxies", &["10.0.0.1/32"])
        .env("SEKRET_TRUSTED_PROXIES", "10.0.0.0/8")
        .start()
        .await?;
    let log = server.log();
    for expected in [
        "auth.default_org_role in the configuration file is overridden by an environment variable",
        "server.trusted_proxies in the configuration file is overridden by an environment variable",
        "makes everyone who can sign in an organisation admin",
        "setting=\"auth.default_org_role\"",
    ] {
        assert!(log.contains(expected), "{expected} missing from {log}");
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn key_files_others_can_read_are_warned_about() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).context("chmod")?;
    let server = sb.keyed(&key).start().await?;
    assert!(server.log().contains("other users can read it"), "{}", server.log());
    drop(server);
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    let server = sb.keyed(&key).start().await?;
    assert!(!server.log().contains("other users can read it"), "{}", server.log());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn files_holding_a_database_password_or_in_open_directories_are_warned_about() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    // The flag's SQLite database wins, but the file still holds the password.
    let with_password = "database:\n  url: postgres://sekret:hunter2@db.invalid/sekret\n";
    let server = sb.keyed(&key).raw_config(with_password).start().await?;
    let log = server.log();
    assert!(
        log.contains("the configuration file, which holds a database password,") && log.contains(READABLE_BY_OTHERS),
        "{log}"
    );
    assert!(!log.contains("hunter2"), "{log}");
    drop(server);
    let server = sb
        .keyed(&key)
        .raw_config("database:\n  snapshots_to_keep: 5\n")
        .start()
        .await?;
    assert!(!server.log().contains("the configuration file"), "{}", server.log());
    drop(server);

    let open = sb.path("open");
    std::fs::create_dir(&open).context("mkdir")?;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
    let moved = open.join("root.key");
    std::fs::rename(&key, &moved).context("move key")?;
    std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    let moved = moved.display().to_string();
    for way in WAYS {
        let log = sb.launch().set(way, "seal.root_key_file", &moved).refused().await?;
        assert!(
            log.contains("writable by every user, so anyone can replace it") && log.contains("refusing to start"),
            "{way:?}: {log}"
        );
        let server = sb
            .launch()
            .set(way, "seal.root_key_file", &moved)
            .arg("--allow-shared-config")
            .start()
            .await?;
        assert!(
            server
                .log()
                .contains("writable by every user, so anyone can replace it"),
            "{way:?}: allowed, it is a warning: {}",
            server.log()
        );
    }
    Ok(())
}

const READABLE_BY_OTHERS: &str = "other users can read it";

#[tokio::test]
async fn restore_clears_what_an_interrupted_restore_left() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let server = sb.keyed(&key).start().await?;
    let admin = sb.bootstrap(&key)?;
    server.create_project(&admin, "app").await?;
    let backup = server
        .client
        .post(format!("{}/api/v1/sys/backup", server.url))
        .bearer_auth(&admin)
        .send()
        .await
        .context("backup")?
        .bytes()
        .await
        .context("bytes")?;
    std::fs::write(sb.path("backup.skb"), &backup).context("save")?;
    drop(server);
    std::fs::create_dir(sb.path(".restored.db.restore-abc")).context("stale dir")?;
    std::fs::write(sb.path(".restored.db.restore-abc/restored.db"), b"half").context("stale")?;
    std::fs::write(sb.path(".restored.db.restore-123"), b"half").context("stale file")?;
    ok(sb.cli(
        &[
            "admin",
            "restore",
            "--backup",
            &sb.p("backup.skb"),
            "--database-url",
            &sb.db_named("restored.db"),
            "--root-key-file",
            &key,
        ],
        &[],
        None,
    )?)?;
    assert!(!sb.path(".restored.db.restore-abc").exists());
    assert!(!sb.path(".restored.db.restore-123").exists());
    assert!(sb.path("restored.db").is_file());
    let leftovers: Vec<String> = std::fs::read_dir(sb.dir.path())
        .context("list")?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".restore-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The third security audit: admin commands, the database lock and configuration
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn database_url_file_chooses_the_database() -> anyhow::Result<()> {
    for way in WAYS {
        let sb = Sandbox::new()?;
        let key = sb.root_key("root.key")?;
        let db = sb.db_named("from-file.db");
        let url_file = sb.write("db-url", &format!("{db}\n"))?;
        let server = sb
            .keyed(&key)
            .without("database.url")
            .set(way, "database.url_file", &url_file)
            .start()
            .await?;
        let admin = sb.bootstrap_on(&db, &key)?;
        server.create_project(&admin, "app").await?;
        assert!(sb.path("from-file.db").exists(), "{way:?}");
        assert!(!sb.path("sekret.db").exists(), "{way:?}");
        assert!(
            server.log().contains("setting=\"database.url_file\""),
            "{way:?}: {}",
            server.log()
        );
        assert!(!server.log().contains(&db), "the URL itself is not logged: {way:?}");
    }
    Ok(())
}

/// A password on the command line is readable by every local user for the server's whole life.
#[tokio::test]
async fn a_database_password_in_a_flag_is_warned_about() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    const WARNING: &str = "--database-url carries a password";
    // Nothing listens on port 1; the settings are reported before the database is opened.
    let with_password = "postgres://sekret:hunter2@127.0.0.1:1/sekret";
    for way in WAYS {
        let log = sb.keyed(&key).set(way, "database.url", with_password).refused().await?;
        assert_eq!(log.contains(WARNING), way == Way::Flag, "{way:?}: {log}");
        assert!(!log.contains("hunter2"), "{way:?}: the password is never logged");
    }
    let server = sb.keyed(&key).set(Way::Flag, "database.url", &sb.db()).start().await?;
    assert!(!server.log().contains(WARNING), "no password, no warning");
    drop(server);
    let in_file = sb.write("pw-url", &format!("{with_password}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&in_file, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    }
    let log = sb
        .keyed(&key)
        .without("database.url")
        .set(Way::Flag, "database.url_file", &in_file)
        .refused()
        .await?;
    assert!(!log.contains(WARNING), "a URL file is the fix: {log}");
    Ok(())
}

/// Whoever can change the configuration file decides who signs in as an admin.
#[cfg(unix)]
#[tokio::test]
async fn a_configuration_file_others_can_change_is_refused() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let config = sb.write("own.yaml", "auth:\n  default_org_role: org-member\n")?;
    const WARNING: &str = "whoever can change it decides who signs in";
    for mode in [0o600, 0o644] {
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(mode)).context("chmod")?;
        let server = sb.keyed(&key).arg(&format!("--config={config}")).start().await?;
        assert!(!server.log().contains(WARNING), "{mode:o}: {}", server.log());
    }
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
    let log = sb.keyed(&key).arg(&format!("--config={config}")).refused().await?;
    assert!(log.contains(WARNING) && log.contains("refusing to start"), "{log}");
    let server = sb
        .keyed(&key)
        .arg(&format!("--config={config}"))
        .arg("--allow-shared-config")
        .start()
        .await?;
    assert!(
        server.log().contains(WARNING),
        "allowed, it is a warning: {}",
        server.log()
    );
    drop(server);
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    let server = sb.keyed(&key).env("SEKRET_CONFIG", &config).start().await?;
    assert!(!server.log().contains(WARNING), "{}", server.log());
    drop(server);
    // A directory anyone can write to lets them replace the file.
    let open = sb.path("open");
    std::fs::create_dir(&open).context("dir")?;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
    let replaceable = open.join("sekret.yaml");
    std::fs::write(&replaceable, "auth:\n  default_org_role: org-member\n").context("write")?;
    std::fs::set_permissions(&replaceable, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    let log = sb
        .keyed(&key)
        .env("SEKRET_CONFIG", &replaceable.display().to_string())
        .refused()
        .await?;
    assert!(log.contains(WARNING), "{log}");
    // So does one further up, by swapping the private directory below it.
    let nested = open.join("conf");
    std::fs::create_dir(&nested).context("dir")?;
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    let deep = nested.join("sekret.yaml");
    std::fs::write(&deep, "auth:\n  default_org_role: org-member\n").context("write")?;
    std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
    let deep = deep.display().to_string();
    let log = sb.keyed(&key).arg(&format!("--config={deep}")).refused().await?;
    assert!(log.contains(WARNING) && log.contains("is below"), "{log}");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).context("chmod")?;
    let server = sb.keyed(&key).arg(&format!("--config={deep}")).start().await?;
    assert!(!server.log().contains(WARNING), "{}", server.log());
    Ok(())
}

#[tokio::test]
async fn database_url_and_url_file_follow_the_usual_precedence() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let in_file = sb.write("db-url", &format!("{}\n", sb.db_named("from-file.db")))?;
    // A URL flag beats a URL file from the environment, and the loser is named.
    let server = sb
        .keyed(&key)
        .without("database.url")
        .set(Way::Flag, "database.url", &sb.db_named("from-flag.db"))
        .set(Way::Env, "database.url_file", &in_file)
        .start()
        .await?;
    assert!(sb.path("from-flag.db").exists());
    assert!(!sb.path("from-file.db").exists());
    assert!(
        server
            .log()
            .contains("database.url_file from the environment is ignored"),
        "{}",
        server.log()
    );
    drop(server);
    // A URL file in the environment beats a URL in the configuration file.
    let server = sb
        .keyed(&key)
        .without("database.url")
        .set(Way::File, "database.url", &sb.db_named("from-yaml.db"))
        .set(Way::Env, "database.url_file", &in_file)
        .start()
        .await?;
    assert!(sb.path("from-file.db").exists());
    assert!(!sb.path("from-yaml.db").exists());
    drop(server);
    // Both at the same level is a mistake.
    let log = sb
        .keyed(&key)
        .without("database.url")
        .set(Way::File, "database.url", &sb.db_named("a.db"))
        .set(Way::File, "database.url_file", &in_file)
        .refused()
        .await?;
    assert!(log.contains("both set"), "{log}");
    let empty = sb.write("empty-url", "\n")?;
    let log = sb
        .keyed(&key)
        .without("database.url")
        .set(Way::Flag, "database.url_file", &empty)
        .refused()
        .await?;
    assert!(log.contains("is empty"), "{log}");
    // Admin commands read it too.
    let flags = [
        "admin",
        "bootstrap",
        "--database-url-file",
        in_file.as_str(),
        "--root-key-file",
        key.as_str(),
    ];
    assert!(!ok(sb.cli(&flags, &[], None)?)?.trim().is_empty());
    Ok(())
}

/// A Postgres URL in the environment carries its password; it must not stay readable there.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_database_url_is_wiped_from_the_environment() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let db = sb.db_named("secret-path.db");
    let server = sb
        .keyed(&key)
        .without("database.url")
        .env("SEKRET_DATABASE_URL", &db)
        .start()
        .await?;
    assert!(sb.path("secret-path.db").exists(), "the value was still used");
    let environ = std::fs::read(format!("/proc/{}/environ", server.child.id())).context("environ")?;
    let has = |needle: &[u8]| environ.windows(needle.len()).any(|w| w == needle);
    assert!(!has(db.as_bytes()), "the database URL is gone");
    assert!(
        server.log().contains("from=\"environment\""),
        "its origin is still reported: {}",
        server.log()
    );
    Ok(())
}

/// Rewinds the newest applied migration, as a database last opened by the previous release.
async fn rewind_schema(path: &Path) -> anyhow::Result<(i64, i64)> {
    use sqlx::{ConnectOptions, Row};
    let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .connect()
        .await
        .context("open")?;
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = (SELECT MAX(version) FROM _sqlx_migrations)")
        .execute(&mut conn)
        .await
        .context("rewind")?;
    let row = sqlx::query("SELECT COUNT(*) AS n, MAX(version) AS v FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .context("count")?;
    Ok((row.try_get("n").context("n")?, row.try_get("v").context("v")?))
}

async fn applied_migrations(path: &Path) -> anyhow::Result<(i64, i64)> {
    use sqlx::{ConnectOptions, Row};
    let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .connect()
        .await
        .context("open")?;
    let row = sqlx::query("SELECT COUNT(*) AS n, MAX(version) AS v FROM _sqlx_migrations")
        .fetch_one(&mut conn)
        .await
        .context("count")?;
    Ok((row.try_get("n").context("n")?, row.try_get("v").context("v")?))
}

/// The demonstrated attack: `admin bootstrap`, which runs beside a live server, migrated the
/// database of an older running server underneath it.
#[tokio::test]
async fn bootstrap_never_migrates_a_database_of_another_version() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    drop(sb.keyed(&key).start().await?);
    let before = rewind_schema(&sb.path("sekret.db")).await?;
    let output = sb.cli(
        &[
            "admin",
            "bootstrap",
            "--database-url",
            &sb.db(),
            "--root-key-file",
            &key,
        ],
        &[],
        None,
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("schema"), "{stderr}");
    assert_eq!(
        applied_migrations(&sb.path("sekret.db")).await?,
        before,
        "nothing was migrated"
    );
    // A newer schema than the binary knows is refused the same way.
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    drop(sb.keyed(&key).start().await?);
    {
        use sqlx::ConnectOptions;
        let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(sb.path("sekret.db"))
            .connect()
            .await
            .context("open")?;
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
             VALUES (99999, 'from the future', TRUE, x'00', 0)",
        )
        .execute(&mut conn)
        .await
        .context("future migration")?;
    }
    let output = sb.cli(
        &[
            "admin",
            "bootstrap",
            "--database-url",
            &sb.db(),
            "--root-key-file",
            &key,
        ],
        &[],
        None,
    )?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("schema"));
    Ok(())
}

/// The demonstrated attack: the lock was keyed on the path as given, so an admin command reached
/// a live database through a symlink and re-keyed it under the running server.
#[cfg(unix)]
#[tokio::test]
async fn admin_commands_cannot_reach_a_live_database_by_another_name() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let new_key = sb.root_key("new.key")?;
    let server = sb.keyed(&key).start().await?;
    let admin = sb.bootstrap(&key)?;
    std::os::unix::fs::symlink(sb.path("sekret.db"), sb.path("link.db")).context("symlink")?;
    std::fs::hard_link(sb.path("sekret.db"), sb.path("hard.db")).context("hard link")?;
    for name in ["link.db", "hard.db"] {
        let output = sb.cli(
            &[
                "admin",
                "rotate-root-key",
                "--database-url",
                &sb.db_named(name),
                "--root-key-file",
                &key,
                "--new-root-key-file",
                &new_key,
            ],
            &[],
            None,
        )?;
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(!output.status.success(), "{name}: {stderr}");
        assert!(stderr.contains("another sekret server"), "{name}: {stderr}");
    }
    server.create_project(&admin, "still-writable").await?;
    Ok(())
}

#[tokio::test]
async fn admin_commands_leave_no_stray_database_behind_a_wrong_path() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let missing = sb.db_named("missing.db");
    let new_key = sb.root_key("new.key")?;
    let commands: [&[&str]; 3] = [
        &[
            "admin",
            "bootstrap",
            "--database-url",
            &missing,
            "--root-key-file",
            &key,
        ],
        &[
            "admin",
            "rotate-root-key",
            "--database-url",
            &missing,
            "--root-key-file",
            &key,
            "--new-root-key-file",
            &new_key,
        ],
        &[
            "admin",
            "set-seal-mode",
            "passphrase",
            "--database-url",
            &missing,
            "--root-key-file",
            &key,
        ],
    ];
    for command in commands {
        let output = sb.cli(command, &[], None)?;
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(!output.status.success(), "{command:?}");
        assert!(stderr.contains("no database"), "{command:?}: {stderr}");
        assert!(!sb.path("missing.db").exists(), "{command:?}");
        assert!(!sb.path("missing.db.lock").exists(), "{command:?}");
    }
    Ok(())
}

#[tokio::test]
async fn admin_token_lifetimes_are_bounded_to_a_day() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    drop(sb.keyed(&key).start().await?);
    let bootstrap = |ttl: &str| {
        sb.cli(
            &[
                "admin",
                "bootstrap",
                "--database-url",
                &sb.db(),
                "--root-key-file",
                &key,
                "--ttl",
                ttl,
            ],
            &[],
            None,
        )
    };
    for refused in ["0", "-5", "86401", "31536000"] {
        assert!(!bootstrap(refused)?.status.success(), "{refused}");
    }
    assert!(bootstrap("86400")?.status.success());
    let output = sb.cli(
        &[
            "admin",
            "init",
            "--database-url",
            &sb.db_named("other.db"),
            "--key-file-mode",
            "--root-key-file",
            &sb.p("other.key"),
            "--ttl",
            "90000",
        ],
        &[],
        None,
    )?;
    assert!(!output.status.success());
    assert!(!sb.path("other.db").exists(), "refused before anything is created");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn the_unseal_socket_needs_a_private_directory() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new()?;
    sb.passphrase_db("manual")?;
    let shared = sb.path("shared");
    std::fs::create_dir(&shared).context("dir")?;
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
    let socket = shared.join("sekret.sock").display().to_string();
    let log = sb
        .launch()
        .set(Way::Flag, "server.unix_socket", &socket)
        .refused()
        .await?;
    assert!(log.contains("must not be writable"), "{log}");

    // The CLI refuses a socket someone else could have planted there.
    let planted = std::os::unix::net::UnixListener::bind(&socket).context("bind")?;
    let pass = sb.passphrase_file()?;
    let output = sb.cli(
        &["sys", "unseal", "--socket", &socket, "--passphrase-file", &pass],
        &[],
        None,
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("can be written by other users"), "{stderr}");
    drop(planted);
    Ok(())
}

/// A group member could swap the socket in a group-writable directory, sticky bit or not.
#[cfg(unix)]
#[tokio::test]
async fn the_unseal_socket_refuses_a_group_writable_directory() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for mode in [0o770, 0o1770] {
        let sb = Sandbox::new()?;
        sb.passphrase_db("manual")?;
        let shared = sb.path("shared");
        std::fs::create_dir(&shared).context("dir")?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(mode)).context("chmod")?;
        let socket = shared.join("sekret.sock").display().to_string();
        let log = sb
            .launch()
            .set(Way::Flag, "server.unix_socket", &socket)
            .refused()
            .await?;
        assert!(log.contains("writable by its group"), "{mode:o}: {log}");

        let planted = std::os::unix::net::UnixListener::bind(&socket).context("bind")?;
        let pass = sb.passphrase_file()?;
        let output = sb.cli(
            &["sys", "unseal", "--socket", &socket, "--passphrase-file", &pass],
            &[],
            None,
        )?;
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains("written by its group"), "{mode:o}: {stderr}");
        drop(planted);
    }
    Ok(())
}

/// Someone who can rearrange a directory further up can swap in a private directory of their
/// own, with a socket and listener that all agree on their uid.
#[cfg(unix)]
#[tokio::test]
async fn the_unseal_socket_refuses_a_directory_below_one_others_can_write() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new()?;
    sb.passphrase_db("manual")?;
    let shared = sb.path("shared");
    let own = shared.join("sekret");
    std::fs::create_dir_all(&own).context("dir")?;
    std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
    let socket = own.join("sekret.sock").display().to_string();
    let log = sb
        .launch()
        .set(Way::Flag, "server.unix_socket", &socket)
        .refused()
        .await?;
    assert!(log.contains("not safe") && log.contains("shared"), "{log}");

    let planted = std::os::unix::net::UnixListener::bind(&socket).context("bind")?;
    let pass = sb.passphrase_file()?;
    let output = sb.cli(
        &["sys", "unseal", "--socket", &socket, "--passphrase-file", &pass],
        &[],
        None,
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("shared") && stderr.contains("other users"), "{stderr}");
    drop(planted);
    Ok(())
}

/// `--socket-owner` and `SEKRET_SOCKET_OWNER` name the user the socket must belong to besides
/// root and the caller. The flag beats the variable, and neither matters without `--socket`.
#[cfg(unix)]
#[tokio::test]
async fn socket_owner_names_whose_socket_is_trusted() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    sb.passphrase_db("manual")?;
    let socket = sb.p("sekret.sock");
    let server = sb
        .launch()
        .set(Way::Flag, "server.unix_socket", &socket)
        .start()
        .await?;
    let status = |args: &[&str], env: &[(&str, &str)]| -> anyhow::Result<Output> {
        let mut argv = vec!["sys", "status"];
        argv.extend_from_slice(args);
        sb.cli(&argv, env, None)
    };
    let unknown = "no-such-sekret-user";
    // An owner that cannot be looked up stops the command before anything is sent.
    for (args, env) in [
        (vec!["--socket", &socket, "--socket-owner", unknown], vec![]),
        (vec!["--socket", &socket], vec![("SEKRET_SOCKET_OWNER", unknown)]),
    ] {
        let output = status(&args, &env)?;
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert_eq!(output.status.code(), Some(1), "{args:?} {env:?}: {stderr}");
        assert!(stderr.contains("no user called"), "{stderr}");
    }
    // The socket is the caller's own, so naming root or the caller is accepted.
    let output = status(&["--socket", &socket, "--socket-owner", "root"], &[])?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "sealed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = status(
        &["--socket", &socket, "--socket-owner", "0"],
        &[("SEKRET_SOCKET_OWNER", unknown)],
    )?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "the flag wins over the variable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = status(&["--server", &server.url], &[("SEKRET_SOCKET_OWNER", unknown)])?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "without --socket the owner is not used: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// A restart that overlaps the old server waits for its lock rather than failing.
#[tokio::test]
async fn a_starting_server_waits_for_the_database_lock() -> anyhow::Result<()> {
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let first = sb.keyed(&key).start().await?;
    let release = async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(first);
    };
    let (second, ()) = tokio::join!(sb.keyed(&key).start(), release);
    let second = second?;
    assert!(second.log().contains("waiting"), "{}", second.log());
    assert_eq!(second.state().await?, "unsealed");
    Ok(())
}

/// When Postgres drops the lock's session, a second server could take over; this one stops.
#[tokio::test]
async fn a_server_that_loses_its_postgres_lock_stops() -> anyhow::Result<()> {
    use sqlx::Connection;
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    let container = match Postgres::default().start().await {
        Ok(container) => container,
        Err(error) if std::env::var_os("SEKRET_REQUIRE_POSTGRES").is_none() => {
            eprintln!("skipping postgres test: {error}");
            return Ok(());
        }
        Err(error) => bail!("postgres container failed: {error}"),
    };
    let port = container.get_host_port_ipv4(5432).await.context("port")?;
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let sb = Sandbox::new()?;
    let key = sb.root_key("root.key")?;
    let mut server = sb.keyed(&key).set(Way::Flag, "database.url", &url).start().await?;
    let mut conn = sqlx::PgConnection::connect(&url).await.context("connect")?;
    sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory'")
        .execute(&mut conn)
        .await
        .context("terminate")?;
    let deadline = Instant::now() + Duration::from_secs(40);
    let status = loop {
        if let Some(status) = server.child.try_wait().context("wait")? {
            break status;
        }
        ensure!(Instant::now() < deadline, "the server kept running:\n{}", server.log());
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert!(!status.success());
    assert!(
        server.log().contains("no longer holds the database lock"),
        "{}",
        server.log()
    );
    Ok(())
}
