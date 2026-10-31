use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

pub const PROJECT_FILE: &str = ".sekret.toml";

/// Defaults read from the nearest `.sekret.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectFile {
    pub server: Option<String>,
    pub project: Option<String>,
    pub environment: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredToken {
    pub token: String,
    pub expires_at: i64,
}

/// Tokens saved by `sekret login`, keyed by server URL.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(default)]
    pub servers: BTreeMap<String, StoredToken>,
}

/// Why a project file found on the way up is not used, or `None` when it is trusted. `owners` are
/// the owners of the file and, for a symlink, of the link too; `dir_mode` is its directory's mode.
pub fn distrust_reason(owners: &[u32], dir_mode: u32, me: u32) -> Option<&'static str> {
    if owners.iter().any(|owner| *owner != me) {
        return Some("it belongs to another user");
    }
    if dir_mode & 0o002 != 0 {
        return Some("its directory is writable by every user");
    }
    None
}

#[cfg(unix)]
fn untrusted(path: &Path) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    let (Ok(link), Ok(target)) = (path.symlink_metadata(), path.metadata()) else {
        return Some("it cannot be inspected");
    };
    let dir = path.parent().unwrap_or(Path::new("."));
    let Ok(dir_meta) = dir.metadata() else {
        return Some("its directory cannot be inspected");
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    distrust_reason(&[link.uid(), target.uid()], dir_meta.mode(), me)
}

#[cfg(not(unix))]
fn untrusted(_path: &Path) -> Option<&'static str> {
    None
}

/// The nearest `.sekret.toml` this user owns, skipping ones planted by someone else with a warning.
pub fn find_project_file(start: &Path, warnings: &mut Vec<String>) -> Option<PathBuf> {
    for candidate in start.ancestors().map(|dir| dir.join(PROJECT_FILE)) {
        if !candidate.is_file() {
            continue;
        }
        let Some(reason) = untrusted(&candidate) else {
            return Some(candidate);
        };
        warnings.push(format!("ignoring {} because {reason}", candidate.display()));
    }
    None
}

/// Reads a small text file, following symlinks and refusing anything that is not a regular file.
pub fn read_text(path: &Path) -> anyhow::Result<String> {
    let bytes = sekret_server::files::read_limited(path, sekret_server::files::TEXT_FILE_LIMIT)
        .with_context(|| format!("reading {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    Ok(text.to_string())
}

/// The project file and where it was found.
pub fn load_project_file(start: &Path, warnings: &mut Vec<String>) -> anyhow::Result<(ProjectFile, Option<PathBuf>)> {
    let Some(path) = find_project_file(start, warnings) else {
        return Ok((ProjectFile::default(), None));
    };
    let text = read_text(&path)?;
    let file = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok((file, Some(path)))
}

pub fn credentials_path() -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join("sekret").join("credentials.toml"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("sekret")
        .join("credentials.toml"))
}

pub fn load_credentials(path: &Path) -> anyhow::Result<Credentials> {
    if !path.exists() {
        return Ok(Credentials::default());
    }
    let text = zeroize::Zeroizing::new(read_text(path)?);
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Writes the credentials file readable only by the current user, in a directory only they can
/// enter, through a new file under a random name that is then renamed into place.
pub fn save_credentials(path: &Path, credentials: &Credentials) -> anyhow::Result<()> {
    let dir = path.parent().context("credentials path has no parent")?;
    sekret_server::files::create_private_dir(dir).with_context(|| format!("creating {}", dir.display()))?;
    let text = zeroize::Zeroizing::new(toml::to_string(credentials)?);
    sekret_server::files::write_private_atomic(path, text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// Everything a client command needs, after flags, environment and project file are merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub server: String,
    pub token: Option<String>,
    pub project: Option<String>,
    pub environment: Option<String>,
    pub path: String,
    /// The server came from a flag or `SEKRET_URL`, or is one `sekret login` saved a token for,
    /// rather than only from a project file that anyone could have written.
    pub server_confirmed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub server: Option<String>,
    pub token: Option<String>,
    pub project: Option<String>,
    pub environment: Option<String>,
    pub path: Option<String>,
}

/// Flags (which already include environment variables via clap) win over the project file,
/// and the stored login is used when no token was given.
pub fn resolve(
    overrides: Overrides,
    file: ProjectFile,
    credentials: &Credentials,
    now: i64,
) -> anyhow::Result<Resolved> {
    let from_flag = overrides.server.is_some();
    let Some(server) = overrides.server.or(file.server) else {
        bail!("no server configured; pass --server, set SEKRET_URL or add `server` to {PROJECT_FILE}");
    };
    let server = server.trim_end_matches('/').to_string();
    let server_confirmed = from_flag || credentials.servers.contains_key(&server);
    if overrides.token.is_some() && !server_confirmed {
        bail!(
            "{server} comes only from {PROJECT_FILE}, so the token from --token or SEKRET_TOKEN is not sent to it; \
             pass --server or set SEKRET_URL to confirm the server"
        );
    }
    let token = overrides.token.or_else(|| {
        credentials
            .servers
            .get(&server)
            .filter(|stored| stored.expires_at > now)
            .map(|stored| stored.token.clone())
    });
    Ok(Resolved {
        server,
        token,
        project: overrides.project.or(file.project),
        environment: overrides.environment.or(file.environment),
        path: overrides.path.or(file.path).unwrap_or_else(|| "/".into()),
        server_confirmed,
    })
}

fn is_loopback(host: &url::Url) -> bool {
    match host.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Plain `http://` is only for this machine unless explicitly allowed, because tokens and secret
/// values would cross the network unencrypted.
pub fn check_transport(server: &str, allow_insecure_http: bool) -> anyhow::Result<()> {
    let url = url::Url::parse(server).with_context(|| format!("the server URL {server} is not valid"))?;
    if url.scheme() != "http" || allow_insecure_http || is_loopback(&url) {
        return Ok(());
    }
    bail!("{server} is plain http; use https, or pass --allow-insecure-http if you accept sending tokens unencrypted")
}

/// Whether `link` is on the same scheme, host and port as `server`.
pub fn same_origin(server: &str, link: &str) -> bool {
    match (url::Url::parse(server), url::Url::parse(link)) {
        (Ok(server), Ok(link)) => server.origin() == link.origin(),
        _ => false,
    }
}

impl Resolved {
    pub fn require_project(&self) -> anyhow::Result<(String, String)> {
        let project = self
            .project
            .clone()
            .context("no project; pass --project or set it in .sekret.toml")?;
        let environment = self
            .environment
            .clone()
            .context("no environment; pass --env or set it in .sekret.toml")?;
        Ok((project, environment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn stored(token: &str, expires_at: i64) -> Credentials {
        let mut c = Credentials::default();
        c.servers.insert(
            "https://sekret.example.com".into(),
            StoredToken {
                token: token.into(),
                expires_at,
            },
        );
        c
    }

    #[test]
    fn flags_beat_project_file_and_stored_login_is_used() -> anyhow::Result<()> {
        let file = ProjectFile {
            server: Some("https://sekret.example.com/".into()),
            project: Some("app".into()),
            environment: Some("dev".into()),
            path: None,
        };
        let resolved = resolve(
            Overrides {
                environment: Some("prod".into()),
                ..Default::default()
            },
            file,
            &stored("t", 100),
            50,
        )
        .context("resolve")?;
        assert_eq!(resolved.server, "https://sekret.example.com");
        assert_eq!(resolved.environment.as_deref(), Some("prod"));
        assert_eq!(resolved.project.as_deref(), Some("app"));
        assert_eq!(resolved.token.as_deref(), Some("t"));
        assert_eq!(resolved.path, "/");
        Ok(())
    }

    #[test]
    fn expired_stored_tokens_are_ignored() -> anyhow::Result<()> {
        let overrides = Overrides {
            server: Some("https://sekret.example.com".into()),
            ..Default::default()
        };
        let resolved = resolve(overrides, ProjectFile::default(), &stored("t", 10), 50).context("resolve")?;
        assert_eq!(resolved.token, None);
        Ok(())
    }

    #[test]
    fn missing_server_is_an_error() {
        assert!(resolve(Overrides::default(), ProjectFile::default(), &Credentials::default(), 0).is_err());
    }

    #[test]
    fn project_file_is_found_in_parent_directories() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        std::fs::write(
            dir.path().join(PROJECT_FILE),
            "server = \"https://s\"\nproject = \"p\"\n",
        )
        .context("write")?;
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).context("mkdir")?;
        let mut warnings = Vec::new();
        let (file, found) = load_project_file(&nested, &mut warnings).context("load")?;
        assert_eq!(file.project.as_deref(), Some("p"));
        assert_eq!(found, Some(dir.path().join(PROJECT_FILE)));
        assert!(warnings.is_empty());
        std::fs::write(dir.path().join(PROJECT_FILE), "unknown = 1\n").context("write")?;
        assert!(load_project_file(&nested, &mut warnings).is_err());
        Ok(())
    }

    #[test]
    fn project_files_from_other_users_or_open_directories_are_distrusted() {
        assert_eq!(distrust_reason(&[1000, 1000], 0o755, 1000), None);
        assert!(distrust_reason(&[1001, 1000], 0o755, 1000).is_some(), "a planted file");
        assert!(
            distrust_reason(&[1000, 0], 0o755, 1000).is_some(),
            "a symlink to another user's file"
        );
        assert!(distrust_reason(&[1000], 0o777, 1000).is_some());
        assert!(
            distrust_reason(&[1000], 0o1777, 1000).is_some(),
            "sticky directories such as /tmp too"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_project_file_in_a_world_writable_directory_is_skipped() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().context("dir")?;
        std::fs::write(dir.path().join(PROJECT_FILE), "project = \"mine\"\n").context("write")?;
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).context("mkdir")?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        std::fs::write(shared.join(PROJECT_FILE), "server = \"http://evil.test\"\n").context("plant")?;
        let mut warnings = Vec::new();
        let (file, found) = load_project_file(&shared, &mut warnings).context("load")?;
        assert_eq!(
            file.project.as_deref(),
            Some("mine"),
            "the parent's file is used instead"
        );
        assert_eq!(file.server, None);
        assert_eq!(found, Some(dir.path().join(PROJECT_FILE)));
        assert!(
            warnings.iter().any(|w| w.contains("writable by every user")),
            "{warnings:?}"
        );
        Ok(())
    }

    #[test]
    fn a_flag_token_is_never_sent_to_a_server_only_the_project_file_names() -> anyhow::Result<()> {
        let hostile = ProjectFile {
            server: Some("https://evil.test".into()),
            ..Default::default()
        };
        let with_token = Overrides {
            token: Some("skt_secret".into()),
            ..Default::default()
        };
        let refused = resolve(with_token.clone(), hostile.clone(), &Credentials::default(), 0);
        assert!(refused.is_err_and(|e| e.to_string().contains("not sent")));
        // Confirming the server with a flag or SEKRET_URL is enough.
        let confirmed = Overrides {
            server: Some("https://evil.test".into()),
            ..with_token.clone()
        };
        assert!(resolve(confirmed, hostile, &Credentials::default(), 0)?.server_confirmed);
        // So is having logged in to it.
        let known = ProjectFile {
            server: Some("https://sekret.example.com".into()),
            ..Default::default()
        };
        let resolved = resolve(with_token, known.clone(), &stored("t", 100), 0)?;
        assert_eq!(resolved.token.as_deref(), Some("skt_secret"));
        assert!(resolved.server_confirmed);
        // Without a flag token, the stored login only ever goes to its own server.
        let unknown = ProjectFile {
            server: Some("https://evil.test".into()),
            ..Default::default()
        };
        let resolved = resolve(Overrides::default(), unknown, &stored("t", 100), 0)?;
        assert_eq!(resolved.token, None);
        assert!(!resolved.server_confirmed);
        Ok(())
    }

    #[test]
    fn plain_http_is_only_for_loopback_unless_allowed() {
        for local in [
            "http://127.0.0.1:8080",
            "http://localhost:1",
            "http://[::1]:9",
            "https://x.test",
        ] {
            assert!(check_transport(local, false).is_ok(), "{local}");
        }
        assert!(check_transport("http://sekret.example.com", false).is_err());
        assert!(check_transport("http://192.168.1.10", false).is_err());
        assert!(check_transport("http://sekret.example.com", true).is_ok());
    }

    #[test]
    fn origins_compare_scheme_host_and_port() {
        assert!(same_origin("https://s.test", "https://s.test/cli-login?code=A"));
        assert!(!same_origin("https://s.test", "https://evil.test/cli-login"));
        assert!(!same_origin("https://s.test", "http://s.test/cli-login"));
        assert!(!same_origin("https://s.test", "https://s.test:8443/cli-login"));
        assert!(!same_origin("https://s.test", "not a url"));
    }

    #[test]
    fn oversized_project_files_are_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let big = format!("project = \"{}\"\n", "a".repeat(2 * 1024 * 1024));
        std::fs::write(dir.path().join(PROJECT_FILE), big).context("write")?;
        assert!(load_project_file(dir.path(), &mut Vec::new()).is_err());
        Ok(())
    }

    #[test]
    fn credentials_round_trip_with_private_permissions() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("sekret").join("credentials.toml");
        save_credentials(&path, &stored("abc", 5)).context("save")?;
        assert_eq!(load_credentials(&path).context("load")?, stored("abc", 5));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).context("meta")?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let parent = path.parent().context("parent")?;
            let dir_mode = std::fs::metadata(parent).context("meta")?.permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
        // A file planted at the old fixed temporary name is neither followed nor left behind.
        let planted = path.with_extension("tmp");
        std::fs::write(&planted, "planted").context("plant")?;
        save_credentials(&path, &stored("def", 6)).context("save again")?;
        assert_eq!(load_credentials(&path).context("load")?, stored("def", 6));
        assert_eq!(std::fs::read_to_string(&planted).context("read")?, "planted");
        Ok(())
    }
}
