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

pub fn find_project_file(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|dir| dir.join(PROJECT_FILE))
        .find(|candidate| candidate.is_file())
}

pub fn load_project_file(start: &Path) -> anyhow::Result<ProjectFile> {
    let Some(path) = find_project_file(start) else {
        return Ok(ProjectFile::default());
    };
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
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
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Writes the credentials file readable only by the current user.
pub fn save_credentials(path: &Path, credentials: &Credentials) -> anyhow::Result<()> {
    let dir = path.parent().context("credentials path has no parent")?;
    std::fs::create_dir_all(dir)?;
    let text = toml::to_string(credentials)?;
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Everything a client command needs, after flags, environment and project file are merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub server: String,
    pub token: Option<String>,
    pub project: Option<String>,
    pub environment: Option<String>,
    pub path: String,
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
    let Some(server) = overrides.server.or(file.server) else {
        bail!("no server configured; pass --server, set SEKRET_URL or add `server` to {PROJECT_FILE}");
    };
    let server = server.trim_end_matches('/').to_string();
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
    })
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
    fn flags_beat_project_file_and_stored_login_is_used() {
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
        .expect("resolve");
        assert_eq!(resolved.server, "https://sekret.example.com");
        assert_eq!(resolved.environment.as_deref(), Some("prod"));
        assert_eq!(resolved.project.as_deref(), Some("app"));
        assert_eq!(resolved.token.as_deref(), Some("t"));
        assert_eq!(resolved.path, "/");
    }

    #[test]
    fn expired_stored_tokens_are_ignored() {
        let overrides = Overrides {
            server: Some("https://sekret.example.com".into()),
            ..Default::default()
        };
        let resolved = resolve(overrides, ProjectFile::default(), &stored("t", 10), 50).expect("resolve");
        assert_eq!(resolved.token, None);
    }

    #[test]
    fn missing_server_is_an_error() {
        assert!(resolve(Overrides::default(), ProjectFile::default(), &Credentials::default(), 0).is_err());
    }

    #[test]
    fn project_file_is_found_in_parent_directories() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join(PROJECT_FILE),
            "server = \"https://s\"\nproject = \"p\"\n",
        )
        .expect("write");
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).expect("mkdir");
        let file = load_project_file(&nested).expect("load");
        assert_eq!(file.project.as_deref(), Some("p"));
        std::fs::write(dir.path().join(PROJECT_FILE), "unknown = 1\n").expect("write");
        assert!(load_project_file(&nested).is_err());
    }

    #[test]
    fn credentials_round_trip_with_private_permissions() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("sekret").join("credentials.toml");
        save_credentials(&path, &stored("abc", 5)).expect("save");
        assert_eq!(load_credentials(&path).expect("load"), stored("abc", 5));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
