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
    /// Blocked variable names that `run`, `env use` and export load anyway, once the person has
    /// confirmed this exact list for this file.
    pub allow: Vec<String>,
    /// Where the file was found.
    #[serde(skip)]
    pub location: Option<PathBuf>,
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
    /// `allow` lists the person confirmed, keyed by the project file's path. A changed list needs
    /// confirming again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub confirmed_allow: BTreeMap<String, Vec<String>>,
}

/// The sorted, de-duplicated form an `allow` list is confirmed and compared in.
pub fn normalised_allow(names: &[String]) -> Vec<String> {
    let set: std::collections::BTreeSet<&String> = names.iter().collect();
    set.into_iter().cloned().collect()
}

impl Credentials {
    pub fn allow_confirmed(&self, file: &Path, names: &[String]) -> bool {
        self.confirmed_allow
            .get(&file.display().to_string())
            .is_some_and(|confirmed| *confirmed == normalised_allow(names))
    }

    pub fn confirm_allow(&mut self, file: &Path, names: &[String]) {
        self.confirmed_allow
            .insert(file.display().to_string(), normalised_allow(names));
    }
}

/// Owner, group and permission bits of a file or directory, as `stat` reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ownership {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// The user running the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Me {
    pub uid: u32,
    pub gid: u32,
}

impl Me {
    /// With user private groups (the usual `umask 002` setups) a person's primary group shares
    /// their user id and holds only them, so it writing to a file is them writing to it.
    fn group_is_private(self, gid: u32) -> bool {
        gid == self.gid && gid == self.uid
    }

    fn group_can_write(self, item: Ownership) -> bool {
        item.mode & 0o020 != 0 && !self.group_is_private(item.gid)
    }
}

/// Why a project file found on the way up is not used, or `None` when it is trusted. `owners` are
/// the owners of the opened file and, for a symlink, of the link too. Root may own the directory,
/// since root can change anything anyway.
pub fn distrust_reason(owners: &[u32], dir: Ownership, me: Me) -> Option<&'static str> {
    if owners.iter().any(|owner| *owner != me.uid) {
        return Some("it belongs to another user");
    }
    if dir.uid != me.uid && dir.uid != 0 {
        return Some("its directory belongs to another user");
    }
    if dir.mode & 0o002 != 0 {
        return Some("its directory is writable by every user");
    }
    if me.group_can_write(dir) {
        return Some("its directory is writable by its group");
    }
    None
}

#[cfg(unix)]
fn current_user() -> Me {
    // SAFETY: geteuid and getegid have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    Me { uid, gid }
}

#[cfg(unix)]
fn ownership(meta: &std::fs::Metadata) -> Ownership {
    use std::os::unix::fs::MetadataExt;
    Ownership {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
    }
}

/// Opens a file once, without blocking on a FIFO, and returns it with the metadata of the open
/// handle, so what is checked is what gets read.
fn open_checked(path: &Path) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok((file, meta))
}

fn read_open(file: std::fs::File, path: &Path) -> anyhow::Result<String> {
    use std::io::Read;
    let limit = sekret_server::files::TEXT_FILE_LIMIT;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > limit {
        bail!("{} is larger than {limit} bytes", path.display());
    }
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    Ok(text.to_string())
}

/// The project file opened for reading if this user may trust it, else why not.
#[cfg(unix)]
fn open_trusted(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::MetadataExt;
    let link = path
        .symlink_metadata()
        .map_err(|_| "it cannot be inspected".to_string())?;
    let (file, meta) = open_checked(path).map_err(|e| format!("it cannot be opened: {e}"))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let dir_meta = dir
        .metadata()
        .map_err(|_| "its directory cannot be inspected".to_string())?;
    if let Some(reason) = distrust_reason(&[link.uid(), meta.uid()], ownership(&dir_meta), current_user()) {
        return Err(reason.to_string());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_trusted(path: &Path) -> Result<std::fs::File, String> {
    open_checked(path)
        .map(|(file, _)| file)
        .map_err(|e| format!("it cannot be opened: {e}"))
}

/// The nearest `.sekret.toml` this user may trust, opened, skipping ones planted by someone else
/// with a warning. Each candidate is checked on the open handle that is then read.
pub fn find_project_file(start: &Path, warnings: &mut Vec<String>) -> Option<(PathBuf, std::fs::File)> {
    for candidate in start.ancestors().map(|dir| dir.join(PROJECT_FILE)) {
        if candidate.symlink_metadata().is_err() {
            continue;
        }
        match open_trusted(&candidate) {
            Ok(file) => return Some((candidate, file)),
            Err(reason) => warnings.push(format!("ignoring {} because {reason}", candidate.display())),
        }
    }
    None
}

/// Reads a small text file, following symlinks and refusing anything that is not a regular file.
pub fn read_text(path: &Path) -> anyhow::Result<String> {
    let (file, _) = open_checked(path).with_context(|| format!("reading {}", path.display()))?;
    read_open(file, path)
}

/// The project file and where it was found.
pub fn load_project_file(start: &Path, warnings: &mut Vec<String>) -> anyhow::Result<(ProjectFile, Option<PathBuf>)> {
    let Some((path, opened)) = find_project_file(start, warnings) else {
        return Ok((ProjectFile::default(), None));
    };
    let text = read_open(opened, &path)?;
    let mut file: ProjectFile = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    file.location = Some(std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone()));
    Ok((file, Some(path)))
}

/// `$XDG_CONFIG_HOME/sekret/credentials.toml`, or under `~/.config`. A relative
/// `XDG_CONFIG_HOME` is ignored, as the XDG specification says.
pub fn credentials_path() -> anyhow::Result<PathBuf> {
    credentials_path_from(std::env::var_os("XDG_CONFIG_HOME"), std::env::var_os("HOME"))
}

pub fn credentials_path_from(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> anyhow::Result<PathBuf> {
    let base = match xdg_config_home.map(PathBuf::from).filter(|dir| dir.is_absolute()) {
        Some(dir) => dir,
        None => PathBuf::from(home.context("HOME is not set")?).join(".config"),
    };
    Ok(base.join("sekret").join("credentials.toml"))
}

/// Why the credentials file must not be used, from its own and its directory's owner and mode.
/// Anyone else who can change it could point a saved login at their own server.
pub fn credentials_refusal(file: Ownership, dir: Ownership, me: Me) -> Option<&'static str> {
    if file.uid != me.uid {
        return Some("it belongs to another user");
    }
    if file.mode & 0o002 != 0 || me.group_can_write(file) {
        return Some("other users can change it; run `chmod 600` on it");
    }
    if dir.uid != me.uid {
        return Some("its directory belongs to another user");
    }
    if dir.mode & 0o002 != 0 || me.group_can_write(dir) {
        return Some("other users can change its directory; run `chmod 700` on it");
    }
    None
}

/// Whether anyone but this user can read the file.
fn others_can_read(file: Ownership, me: Me) -> bool {
    file.mode & 0o004 != 0 || (file.mode & 0o040 != 0 && !me.group_is_private(file.gid))
}

/// The saved logins. A credentials file other users can read is used with a warning; one they
/// can change, or that is not this user's, is refused.
pub fn load_credentials(path: &Path, warnings: &mut Vec<String>) -> anyhow::Result<Credentials> {
    if path.symlink_metadata().is_err() {
        return Ok(Credentials::default());
    }
    let (file, meta) = open_checked(path).with_context(|| format!("reading {}", path.display()))?;
    #[cfg(unix)]
    {
        let dir = path.parent().unwrap_or(Path::new("."));
        let dir_meta = dir
            .metadata()
            .with_context(|| format!("inspecting {}", dir.display()))?;
        let (file_owner, dir_owner, me) = (ownership(&meta), ownership(&dir_meta), current_user());
        if let Some(reason) = credentials_refusal(file_owner, dir_owner, me) {
            bail!("not using {} because {reason}", path.display());
        }
        if others_can_read(file_owner, me) {
            warnings.push(format!(
                "{} can be read by other users, who could take your tokens; run `chmod 600` on it",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (&meta, &warnings);
    let text = zeroize::Zeroizing::new(read_open(file, path)?);
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

/// How the person chose the server, which decides what may be sent to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSource {
    /// `--server` or `SEKRET_URL`.
    Explicit,
    /// Only the project file names it, but `sekret login` saved a token for it.
    LoggedIn,
    /// Only the project file names it, and anyone who could write that file chose it.
    ProjectFile,
}

/// Everything a client command needs, after flags, environment and project file are merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub server: String,
    pub token: Option<String>,
    pub project: Option<String>,
    pub environment: Option<String>,
    pub path: String,
    pub source: ServerSource,
    /// Blocked variable names the project file allows, once confirmed.
    pub allow: Vec<String>,
    /// The project file's `allow` list while it is not yet confirmed, with the file's path.
    pub unconfirmed_allow: Option<(PathBuf, Vec<String>)>,
    /// The project file chose the project or environment, rather than a flag or variable.
    pub chosen_by_file: Option<PathBuf>,
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
    let source = if from_flag {
        ServerSource::Explicit
    } else if credentials.servers.contains_key(&server) {
        ServerSource::LoggedIn
    } else {
        ServerSource::ProjectFile
    };
    // A saved login is for its own token only; it does not vouch for the server to other credentials.
    if overrides.token.is_some() && source != ServerSource::Explicit {
        bail!(
            "{} comes only from {PROJECT_FILE}, so the token from --token or SEKRET_TOKEN is not sent to it; \
             pass --server or set SEKRET_URL to confirm the server",
            sekret_client::terminal_safe(&server)
        );
    }
    let token = overrides.token.or_else(|| {
        credentials
            .servers
            .get(&server)
            .filter(|stored| stored.expires_at > now)
            .map(|stored| stored.token.clone())
    });
    let chosen_by_file = ((overrides.project.is_none() && file.project.is_some())
        || (overrides.environment.is_none() && file.environment.is_some()))
    .then(|| file.location.clone().unwrap_or_else(|| PathBuf::from(PROJECT_FILE)));
    // A cloned repository's file must not unblock names on its own say-so.
    let (allow, unconfirmed_allow) = match &file.location {
        _ if file.allow.is_empty() => (Vec::new(), None),
        Some(location) if credentials.allow_confirmed(location, &file.allow) => (file.allow, None),
        location => (
            Vec::new(),
            Some((
                location.clone().unwrap_or_else(|| PathBuf::from(PROJECT_FILE)),
                normalised_allow(&file.allow),
            )),
        ),
    };
    Ok(Resolved {
        server,
        token,
        project: overrides.project.or(file.project),
        environment: overrides.environment.or(file.environment),
        path: overrides.path.or(file.path).unwrap_or_else(|| "/".into()),
        source,
        allow,
        unconfirmed_allow,
        chosen_by_file,
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
    /// Named by a flag or `SEKRET_URL`, or confirmed by the person at `sekret login`.
    pub fn server_confirmed(&self) -> bool {
        self.source != ServerSource::ProjectFile
    }

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
            ..Default::default()
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

    const ME: Me = Me { uid: 1000, gid: 1000 };
    /// A group shared with other people, such as `users`.
    const SHARED: u32 = 100;

    fn dir(uid: u32, mode: u32) -> Ownership {
        Ownership { uid, gid: SHARED, mode }
    }

    #[test]
    fn project_files_from_other_users_or_open_directories_are_distrusted() {
        assert_eq!(distrust_reason(&[1000, 1000], dir(1000, 0o755), ME), None);
        assert_eq!(
            distrust_reason(&[1000], dir(0, 0o755), ME),
            None,
            "root may own the directory"
        );
        assert!(
            distrust_reason(&[1001, 1000], dir(1000, 0o755), ME).is_some(),
            "a planted file"
        );
        assert!(
            distrust_reason(&[1000, 0], dir(1000, 0o755), ME).is_some(),
            "a symlink to another user's file"
        );
        assert!(distrust_reason(&[1000], dir(1000, 0o777), ME).is_some());
        assert!(
            distrust_reason(&[1000], dir(1000, 0o1777), ME).is_some(),
            "sticky directories such as /tmp too"
        );
        assert_eq!(
            distrust_reason(&[1000], dir(1000, 0o775), ME),
            Some("its directory is writable by its group")
        );
        let private = Ownership {
            gid: 1000,
            ..dir(1000, 0o775)
        };
        assert_eq!(
            distrust_reason(&[1000], private, ME),
            None,
            "umask 002 with a private group writes only as this user"
        );
        assert!(
            distrust_reason(&[1000], private, Me { uid: 1000, gid: 1001 }).is_some(),
            "a primary group that is not the user's own is shared"
        );
        assert_eq!(
            distrust_reason(&[1000], dir(1001, 0o755), ME),
            Some("its directory belongs to another user"),
            "its owner could swap the file"
        );
    }

    /// A supplementary group of the current user that is not their private one, to stand in for a
    /// group shared with others.
    #[cfg(unix)]
    fn shared_group() -> anyhow::Result<Option<u32>> {
        let output = std::process::Command::new("id").arg("-G").output().context("id")?;
        let me = current_user();
        Ok(String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .filter_map(|g| g.parse::<u32>().ok())
            .find(|g| !me.group_is_private(*g)))
    }

    #[cfg(unix)]
    #[test]
    fn a_project_file_in_a_group_writable_directory_is_skipped() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let Some(group) = shared_group()? else {
            return Ok(());
        };
        let top = tempfile::tempdir().context("dir")?;
        std::fs::set_permissions(top.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let shared = top.path().join("shared");
        std::fs::create_dir(&shared).context("mkdir")?;
        std::os::unix::fs::chown(&shared, None, Some(group)).context("chgrp")?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o770)).context("chmod")?;
        std::fs::write(shared.join(PROJECT_FILE), "server = \"http://evil.test\"\n").context("plant")?;
        let mut warnings = Vec::new();
        let (file, found) = load_project_file(&shared, &mut warnings).context("load")?;
        assert_eq!(file.server, None);
        assert_eq!(found, None);
        assert!(
            warnings.iter().any(|w| w.contains("writable by its group")),
            "{warnings:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_as_the_project_file_is_skipped_without_hanging() -> anyhow::Result<()> {
        let top = tempfile::tempdir().context("dir")?;
        let path = top.path().join(PROJECT_FILE);
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .context("mkfifo")?;
        anyhow::ensure!(status.success(), "mkfifo failed");
        let mut warnings = Vec::new();
        let (_, found) = load_project_file(top.path(), &mut warnings).context("load")?;
        assert_eq!(found, None);
        assert!(
            warnings.iter().any(|w| w.contains("not a regular file")),
            "{warnings:?}"
        );
        Ok(())
    }

    #[test]
    fn a_relative_xdg_config_home_is_ignored() -> anyhow::Result<()> {
        let path = credentials_path_from(Some("rel/config".into()), Some("/home/me".into()))?;
        assert_eq!(path, PathBuf::from("/home/me/.config/sekret/credentials.toml"));
        let path = credentials_path_from(Some("/xdg".into()), Some("/home/me".into()))?;
        assert_eq!(path, PathBuf::from("/xdg/sekret/credentials.toml"));
        let path = credentials_path_from(Some("".into()), Some("/home/me".into()))?;
        assert_eq!(path, PathBuf::from("/home/me/.config/sekret/credentials.toml"));
        assert!(credentials_path_from(Some("rel".into()), None).is_err());
        Ok(())
    }

    #[test]
    fn credentials_others_can_change_are_refused() {
        let me = ME.uid;
        assert_eq!(credentials_refusal(dir(me, 0o600), dir(me, 0o700), ME), None);
        assert_eq!(
            credentials_refusal(dir(me, 0o644), dir(me, 0o755), ME),
            None,
            "readable is only warned about"
        );
        assert!(others_can_read(dir(me, 0o640), ME));
        assert!(!others_can_read(dir(me, 0o600), ME));
        assert!(credentials_refusal(dir(1001, 0o600), dir(me, 0o700), ME).is_some());
        assert!(credentials_refusal(dir(me, 0o620), dir(me, 0o700), ME).is_some());
        assert!(credentials_refusal(dir(me, 0o602), dir(me, 0o700), ME).is_some());
        assert!(credentials_refusal(dir(me, 0o600), dir(1001, 0o700), ME).is_some());
        assert!(credentials_refusal(dir(me, 0o600), dir(me, 0o770), ME).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn loose_credentials_files_are_warned_about_or_refused() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let top = tempfile::tempdir().context("dir")?;
        let path = top.path().join("sekret").join("credentials.toml");
        save_credentials(&path, &stored("abc", 5)).context("save")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).context("chmod")?;
        let mut warnings = Vec::new();
        assert_eq!(load_credentials(&path, &mut warnings)?, stored("abc", 5));
        assert!(
            warnings.iter().any(|w| w.contains("read by other users")),
            "{warnings:?}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
        let refused = load_credentials(&path, &mut Vec::new());
        assert!(refused.is_err_and(|e| e.to_string().contains("can change it")));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
        let parent = path.parent().context("parent")?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        let refused = load_credentials(&path, &mut Vec::new());
        assert!(refused.is_err_and(|e| e.to_string().contains("its directory")));
        Ok(())
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
        let resolved = resolve(confirmed, hostile, &Credentials::default(), 0)?;
        assert_eq!(resolved.source, ServerSource::Explicit);
        assert!(resolved.server_confirmed());
        // A saved login only vouches for its own token: once an attacker's server had been logged
        // in to, it would otherwise collect every SEKRET_TOKEN too.
        let known = ProjectFile {
            server: Some("https://sekret.example.com".into()),
            ..Default::default()
        };
        let refused = resolve(with_token, known.clone(), &stored("t", 100), 0);
        assert!(refused.is_err_and(|e| e.to_string().contains("not sent")));
        let resolved = resolve(Overrides::default(), known, &stored("t", 100), 0)?;
        assert_eq!(resolved.token.as_deref(), Some("t"));
        assert_eq!(resolved.source, ServerSource::LoggedIn);
        assert!(resolved.server_confirmed());
        // Without a flag token, the stored login only ever goes to its own server.
        let unknown = ProjectFile {
            server: Some("https://evil.test".into()),
            ..Default::default()
        };
        let resolved = resolve(Overrides::default(), unknown, &stored("t", 100), 0)?;
        assert_eq!(resolved.token, None);
        assert_eq!(resolved.source, ServerSource::ProjectFile);
        assert!(!resolved.server_confirmed());
        Ok(())
    }

    #[test]
    fn the_project_file_allows_blocked_names_only_once_confirmed() -> anyhow::Result<()> {
        let mut file: ProjectFile =
            toml::from_str("server = \"https://s\"\nallow = [\"KUBECONFIG\", \"GIT_PAGER\"]\n")?;
        let location = PathBuf::from("/repo/.sekret.toml");
        file.location = Some(location.clone());
        let resolved = resolve(Overrides::default(), file.clone(), &Credentials::default(), 0)?;
        assert!(
            resolved.allow.is_empty(),
            "a cloned file cannot unblock names by itself"
        );
        assert_eq!(
            resolved.unconfirmed_allow,
            Some((location.clone(), vec!["GIT_PAGER".into(), "KUBECONFIG".into()]))
        );

        let mut credentials = Credentials::default();
        credentials.confirm_allow(
            &location,
            &["KUBECONFIG".into(), "GIT_PAGER".into(), "KUBECONFIG".into()],
        );
        let resolved = resolve(Overrides::default(), file.clone(), &credentials, 0)?;
        assert_eq!(resolved.allow, ["KUBECONFIG", "GIT_PAGER"]);
        assert_eq!(resolved.unconfirmed_allow, None);

        // A longer list, or the same list in another file, needs confirming again.
        let mut grown = file.clone();
        grown.allow.push("LD_PRELOAD".into());
        assert!(resolve(Overrides::default(), grown, &credentials, 0)?.allow.is_empty());
        let mut elsewhere = file;
        elsewhere.location = Some("/other/.sekret.toml".into());
        assert!(
            resolve(Overrides::default(), elsewhere, &credentials, 0)?
                .allow
                .is_empty()
        );

        let text = toml::to_string(&credentials)?;
        let read: Credentials = toml::from_str(&text)?;
        assert!(read.allow_confirmed(&location, &["GIT_PAGER".into(), "KUBECONFIG".into()]));
        let old: Credentials = toml::from_str("[servers]\n")?;
        assert!(old.confirmed_allow.is_empty(), "older credentials files still load");
        Ok(())
    }

    #[test]
    fn a_project_or_environment_from_the_file_is_flagged() -> anyhow::Result<()> {
        let mut file: ProjectFile =
            toml::from_str("server = \"https://s\"\nproject = \"p\"\nenvironment = \"prod\"\n")?;
        file.location = Some("/repo/.sekret.toml".into());
        let from_file = resolve(Overrides::default(), file.clone(), &Credentials::default(), 0)?;
        assert_eq!(from_file.chosen_by_file, Some(PathBuf::from("/repo/.sekret.toml")));
        let chosen = Overrides {
            project: Some("p".into()),
            environment: Some("dev".into()),
            ..Default::default()
        };
        let flagged = resolve(chosen, file, &Credentials::default(), 0)?;
        assert_eq!(flagged.chosen_by_file, None);
        Ok(())
    }

    #[test]
    fn a_loaded_project_file_records_where_it_is() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        }
        std::fs::write(dir.path().join(PROJECT_FILE), "allow = [\"KUBECONFIG\"]\n").context("write")?;
        let mut warnings = Vec::new();
        let (file, _) = load_project_file(dir.path(), &mut warnings)?;
        let expected = std::fs::canonicalize(dir.path().join(PROJECT_FILE))?;
        assert_eq!(file.location, Some(expected), "{warnings:?}");
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
        let mut warnings = Vec::new();
        assert_eq!(
            load_credentials(&path, &mut warnings).context("load")?,
            stored("abc", 5)
        );
        assert!(warnings.is_empty(), "{warnings:?}");
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
        assert_eq!(
            load_credentials(&path, &mut warnings).context("load")?,
            stored("def", 6)
        );
        assert_eq!(std::fs::read_to_string(&planted).context("read")?, "planted");
        Ok(())
    }
}
