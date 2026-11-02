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
    /// `allow` lists the person confirmed, keyed by [`AllowScope::key`]. A changed list, or the
    /// same list loading from another server, project, environment or path, needs confirming again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub confirmed_allow: BTreeMap<String, Vec<String>>,
    /// Project and environment choices made by a project file that the person confirmed, keyed
    /// by [`ChoiceScope::key`].
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub confirmed_choices: std::collections::BTreeSet<String>,
}

/// A project file picking where `run`, `env use` and `export` load secrets from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChoiceScope {
    pub file: PathBuf,
    pub server: String,
    pub project: String,
    pub environment: String,
}

impl ChoiceScope {
    /// A JSON array, so no value can be crafted to collide with another scope.
    pub fn key(&self) -> String {
        serde_json::json!([
            self.file.display().to_string(),
            self.server,
            self.project,
            self.environment
        ])
        .to_string()
    }

    /// `project/environment` on `server`, safe to show at a terminal.
    pub fn describe(&self) -> String {
        format!(
            "{}/{} on {}",
            sekret_client::terminal_safe(&self.project),
            sekret_client::terminal_safe(&self.environment),
            sekret_client::terminal_safe(&self.server)
        )
        .replace(['\n', '\t'], " ")
    }
}

/// What a project file's `allow` list is confirmed for: the file, and where secrets load from.
/// Who can write secrets differs between projects and environments, so so does the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowScope {
    pub file: PathBuf,
    pub server: String,
    pub project: String,
    pub environment: String,
    pub path: String,
}

impl AllowScope {
    /// A JSON array, so no value can be crafted to collide with another scope.
    pub fn key(&self) -> String {
        serde_json::json!([
            self.file.display().to_string(),
            self.server,
            self.project,
            self.environment,
            self.path
        ])
        .to_string()
    }

    /// `project/environment` at `path` on `server`, safe to show at a terminal.
    pub fn describe(&self) -> String {
        format!(
            "{}/{} (path {}) on {}",
            sekret_client::terminal_safe(&self.project),
            sekret_client::terminal_safe(&self.environment),
            sekret_client::terminal_safe(&self.path),
            sekret_client::terminal_safe(&self.server)
        )
        .replace(['\n', '\t'], " ")
    }
}

/// The sorted, de-duplicated form an `allow` list is confirmed and compared in.
pub fn normalised_allow(names: &[String]) -> Vec<String> {
    let set: std::collections::BTreeSet<&String> = names.iter().collect();
    set.into_iter().cloned().collect()
}

impl Credentials {
    pub fn allow_confirmed(&self, scope: &AllowScope, names: &[String]) -> bool {
        self.confirmed_allow
            .get(&scope.key())
            .is_some_and(|confirmed| *confirmed == normalised_allow(names))
    }

    pub fn confirm_allow(&mut self, scope: &AllowScope, names: &[String]) {
        self.confirmed_allow.insert(scope.key(), normalised_allow(names));
    }

    pub fn choice_confirmed(&self, scope: &ChoiceScope) -> bool {
        self.confirmed_choices.contains(&scope.key())
    }

    pub fn confirm_choice(&mut self, scope: &ChoiceScope) {
        self.confirmed_choices.insert(scope.key());
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
    /// Nobody else is listed in the primary group or has it as their own.
    pub private_group: bool,
}

impl Me {
    /// With user private groups (the usual `umask 002` setups) a person's primary group holds
    /// only them, so it writing to a file is them writing to it.
    fn group_is_private(self, gid: u32) -> bool {
        self.private_group && gid == self.gid
    }

    /// With an ACL, group write may grant other users, so no group counts as private.
    #[cfg(unix)]
    fn unless_acl(self, acl: bool) -> Self {
        if !acl {
            return self;
        }
        Self {
            gid: self.uid.wrapping_add(1),
            ..self
        }
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

/// Why a project file others could edit is not used, since an edit could point `run` at another
/// project or environment.
pub fn file_writers(file: Ownership, me: Me) -> Option<&'static str> {
    if file.mode & 0o002 != 0 {
        return Some("it is writable by every user");
    }
    if me.group_can_write(file) {
        return Some("it is writable by its group");
    }
    None
}

#[cfg(unix)]
fn current_user() -> Me {
    // SAFETY: geteuid and getegid have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let private_group = match (
        std::fs::read_to_string("/etc/group"),
        std::fs::read_to_string("/etc/passwd"),
    ) {
        (Ok(group), Ok(passwd)) => crate::settings::group_holds_only(&group, &passwd, gid, uid),
        _ => false,
    };
    Me {
        uid,
        gid,
        private_group,
    }
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
        .with_context(|| format!("reading {}", shown(path)))?;
    if bytes.len() as u64 > limit {
        bail!("{} is larger than {limit} bytes", shown(path));
    }
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{} is not UTF-8", shown(path)))?;
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
    let me = current_user();
    if let Some(reason) = distrust_reason(&[link.uid(), meta.uid()], ownership(&dir_meta), me)
        .or_else(|| file_writers(ownership(&meta), me))
    {
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

/// TOML errors quote the offending line, so escape sequences in the file are made harmless.
fn parse_toml<T: serde::de::DeserializeOwned>(text: &str, path: &Path) -> anyhow::Result<T> {
    toml::from_str(text).map_err(|e| {
        anyhow::anyhow!(
            "parsing {}: {}",
            sekret_client::terminal_safe(&path.display().to_string()),
            sekret_client::terminal_safe(&e.to_string())
        )
    })
}

/// The project file and where it was found.
pub fn load_project_file(start: &Path, warnings: &mut Vec<String>) -> anyhow::Result<(ProjectFile, Option<PathBuf>)> {
    let Some((path, opened)) = find_project_file(start, warnings) else {
        return Ok((ProjectFile::default(), None));
    };
    let text = read_open(opened, &path)?;
    let mut file: ProjectFile = parse_toml(&text, &path)?;
    file.location = Some(std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone()));
    Ok((file, Some(path)))
}

/// `$XDG_CONFIG_HOME/sekret`, or `~/.config/sekret`. A relative `XDG_CONFIG_HOME` is ignored, as
/// the XDG specification says.
pub fn config_dir_from(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> anyhow::Result<PathBuf> {
    let base = match xdg_config_home.map(PathBuf::from).filter(|dir| dir.is_absolute()) {
        Some(dir) => dir,
        None => {
            let home = PathBuf::from(home.context("HOME is not set")?);
            // A relative HOME would make the config whatever the current directory holds, such as
            // a cloned repository.
            if !home.is_absolute() {
                bail!("HOME is not an absolute path; set it, or set XDG_CONFIG_HOME to one");
            }
            home.join(".config")
        }
    };
    Ok(base.join("sekret"))
}

fn config_dir() -> anyhow::Result<PathBuf> {
    config_dir_from(std::env::var_os("XDG_CONFIG_HOME"), std::env::var_os("HOME"))
}

/// `$XDG_CONFIG_HOME/sekret/credentials.toml`, or under `~/.config`.
pub fn credentials_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("credentials.toml"))
}

pub const USER_CONFIG_FILE: &str = "config.toml";

/// `$XDG_CONFIG_HOME/sekret/config.toml`, or under `~/.config`.
pub fn user_config_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(USER_CONFIG_FILE))
}

/// The user's own defaults, used when no flag, environment variable or project file sets them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserConfig {
    pub server: Option<String>,
    /// Relative paths are taken from the config file's directory.
    pub ca_file: Option<PathBuf>,
    /// Where the file is looked for, whether or not it exists.
    #[serde(skip)]
    pub location: Option<PathBuf>,
}

/// Why a file this user relies on for whom to trust must not be used: the user config and the CA
/// file it names. Root may own either, as for a config provisioned from `/etc/skel`, since root
/// can change anything anyway. The directories leading to it are checked by [`swappable_dir`].
pub fn owned_file_refusal(file: Ownership, me: Me) -> Option<&'static str> {
    if file.uid != me.uid && file.uid != 0 {
        return Some("it belongs to another user");
    }
    if file.mode & 0o002 != 0 || me.group_can_write(file) {
        return Some("other users can change it");
    }
    None
}

fn shown(path: &Path) -> String {
    sekret_client::terminal_safe(&path.display().to_string())
}

/// Whether another user could swap an entry of `dir` for their own: it is theirs, or they may
/// write to it and no sticky bit stops them renaming this user's entries.
pub fn swappable_dir(dir: Ownership, me: Me) -> bool {
    let sticky = dir.mode & 0o1000 != 0;
    (dir.uid != me.uid && dir.uid != 0) || (!sticky && (dir.mode & 0o002 != 0 || me.group_can_write(dir)))
}

/// Opens a regular file without following a final symlink or blocking on a FIFO.
#[cfg(unix)]
fn open_nofollow(path: &Path) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok((file, meta))
}

/// Reads a file this user relies on to decide whom to trust: the user config and the CA file it
/// names. The path is resolved one name at a time, checking every directory that holds a name on
/// the way, symlinks included, and then the open handle itself is checked, so no one else can
/// redirect the lookup or swap the file between the check and the read. Returns where the file
/// really is and its text.
#[cfg(unix)]
pub fn read_trusted(path: &Path, what: &str) -> anyhow::Result<(PathBuf, String)> {
    let me = current_user();
    let refuse = |reason: &str| anyhow::anyhow!("not using {what} {} because {reason}", shown(path));
    let real = match walk_checked(path, me) {
        Ok(real) => real,
        Err(Walk::Refused(reason)) => return Err(refuse(&reason)),
        Err(Walk::Failed(e)) => return Err(e).with_context(|| format!("reading {what} {}", shown(path))),
    };
    // Checked before opening, so a link to a device never opens it.
    let kind = std::fs::symlink_metadata(&real).with_context(|| format!("inspecting {what} {}", shown(path)))?;
    if !kind.is_file() {
        return Err(refuse("it is not a regular file"));
    }
    let (file, meta) = open_nofollow(&real).with_context(|| format!("reading {what} {}", shown(path)))?;
    if let Some(reason) = owned_file_refusal(ownership(&meta), me.unless_acl(fd_has_acl(&file))) {
        return Err(refuse(reason));
    }
    let text = read_open(file, &real)?;
    Ok((real, text))
}

#[cfg(unix)]
enum Walk {
    Refused(String),
    Failed(std::io::Error),
}

#[cfg(unix)]
impl From<std::io::Error> for Walk {
    fn from(e: std::io::Error) -> Self {
        Self::Failed(e)
    }
}

/// The kernel's protected_symlinks rule, which a walk that opens the resolved path never meets:
/// in a sticky directory anyone may create a name, so only a link this user, root or the
/// directory's owner made may be followed.
pub fn link_may_be_followed(link_owner: u32, dir_owner: u32, me: Me) -> bool {
    link_owner == me.uid || link_owner == 0 || link_owner == dir_owner
}

/// Follows `path` from the root one name at a time, as the kernel would, refusing as soon as a
/// directory holding a name on the way, the target of a symlink included, is one another user
/// could change. Returns the path with every link resolved.
#[cfg(unix)]
fn walk_checked(path: &Path, me: Me) -> Result<PathBuf, Walk> {
    use std::collections::VecDeque;
    use std::path::Component;
    const MAX_LINKS: usize = 40;
    if !path.is_absolute() {
        return Err(Walk::Refused("it is not an absolute path".into()));
    }
    let mut pending: VecDeque<std::ffi::OsString> = VecDeque::new();
    let queue = |pending: &mut VecDeque<std::ffi::OsString>, path: &Path| {
        let names: Vec<_> = path
            .components()
            .filter_map(|part| match part {
                Component::Normal(name) => Some(name.to_os_string()),
                Component::ParentDir => Some("..".into()),
                _ => None,
            })
            .collect();
        for name in names.into_iter().rev() {
            pending.push_front(name);
        }
    };
    queue(&mut pending, path);
    let mut current = PathBuf::from("/");
    let mut links = 0;
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            current.pop();
            continue;
        }
        let meta = current.metadata()?;
        if swappable_dir(ownership(&meta), me.unless_acl(has_acl(&current))) {
            return Err(Walk::Refused(format!(
                "others can change {}, which leads to it",
                shown(&current)
            )));
        }
        let next = current.join(&name);
        let entry = std::fs::symlink_metadata(&next)?;
        if !entry.file_type().is_symlink() {
            current = next;
            continue;
        }
        if !link_may_be_followed(ownership(&entry).uid, ownership(&meta).uid, me) {
            return Err(Walk::Refused(format!(
                "{} is a symbolic link another user made",
                shown(&next)
            )));
        }
        links += 1;
        if links > MAX_LINKS {
            return Err(Walk::Refused(format!(
                "it passes through more than {MAX_LINKS} symbolic links"
            )));
        }
        let target = std::fs::read_link(&next)?;
        if target.is_absolute() {
            current = PathBuf::from("/");
        }
        queue(&mut pending, &target);
    }
    Ok(current)
}

/// Whether a POSIX access ACL is set, in which case the group bits are the mask over named users
/// and groups, not the group alone.
#[cfg(target_os = "linux")]
fn has_acl(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return true;
    };
    // SAFETY: both strings are NUL-terminated, and a null buffer of size 0 only asks for the size.
    let size = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    size > 0
}

#[cfg(target_os = "linux")]
fn fd_has_acl(file: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: the descriptor is open for the life of `file`, and a null buffer of size 0 only
    // asks for the size.
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    size > 0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn has_acl(_: &Path) -> bool {
    false
}

#[cfg(all(unix, not(target_os = "linux")))]
fn fd_has_acl(_: &std::fs::File) -> bool {
    false
}

#[cfg(not(unix))]
pub fn read_trusted(path: &Path, what: &str) -> anyhow::Result<(PathBuf, String)> {
    let real = std::fs::canonicalize(path).with_context(|| format!("reading {what} {}", shown(path)))?;
    let text = read_text(&real)?;
    Ok((real, text))
}

/// Parse errors give the line and a fixed explanation, never the parser's own message, which can
/// quote keys and values, and a value typed into the wrong file may be a secret.
fn parse_user_config(text: &str, path: &Path) -> anyhow::Result<UserConfig> {
    toml::from_str(text).map_err(|e| {
        let line = e
            .span()
            .and_then(|span| text.get(..span.start))
            .map(|before| before.matches('\n').count() + 1);
        let at = line.map(|line| format!(" line {line}")).unwrap_or_default();
        anyhow::anyhow!(
            "parsing {}{at}: not a valid user config, which may set only `server` and `ca_file`, both as quoted \
             strings",
            shown(path)
        )
    })
}

/// The user config, or the defaults when there is none. A file someone else owns or can change
/// is refused rather than skipped, because it chooses which server receives this user's tokens.
/// The CA file it names is checked the same way when it is read.
pub fn load_user_config(path: &Path) -> anyhow::Result<UserConfig> {
    let missing = UserConfig {
        location: Some(path.to_path_buf()),
        ..UserConfig::default()
    };
    match path.symlink_metadata() {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(missing),
        Err(e) => return Err(e).with_context(|| format!("reading the user config {}", shown(path))),
    }
    let (real, text) = read_trusted(path, "the user config")?;
    let mut config = parse_user_config(&text, path)?;
    if config.server.as_deref().is_some_and(|server| server.trim().is_empty()) {
        bail!("{}: `server` is empty", shown(path));
    }
    if let Some(ca) = config.ca_file.take() {
        if ca.as_os_str().is_empty() {
            bail!("{}: `ca_file` is empty", shown(path));
        }
        config.ca_file = Some(match real.parent() {
            Some(dir) if ca.is_relative() => dir.join(ca),
            _ => ca,
        });
    }
    config.location = missing.location;
    Ok(config)
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
    parse_toml(&text, path)
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
    /// `--server`, `SEKRET_URL` or the user config, all of which only this user can set.
    Explicit,
    /// Only the project file names it, but `sekret login` saved a token for it.
    LoggedIn,
    /// Only the project file names it, and anyone who could write that file chose it.
    ProjectFile,
}

/// The extra CA to trust and where it was named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaFile {
    /// `--ca-file` or `SEKRET_CA_FILE`, read as given.
    Given(PathBuf),
    /// `ca_file` in the user config, read only if no one else can change it.
    UserConfig(PathBuf),
}

impl CaFile {
    pub fn read(&self) -> anyhow::Result<String> {
        match self {
            Self::Given(path) => read_text(path),
            Self::UserConfig(path) => read_trusted(path, "the CA file").map(|(_, text)| text),
        }
    }
}

/// Everything a client command needs, after flags, environment, project file and user config are
/// merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub server: String,
    pub token: Option<String>,
    pub ca_file: Option<CaFile>,
    pub project: Option<String>,
    pub environment: Option<String>,
    pub path: String,
    pub source: ServerSource,
    /// Blocked variable names the project file allows, once confirmed.
    pub allow: Vec<String>,
    /// The project file's `allow` list while it is not yet confirmed for where secrets load from.
    pub unconfirmed_allow: Option<(AllowScope, Vec<String>)>,
    /// The project file chose the project or environment, rather than a flag or variable.
    pub chosen_by_file: Option<PathBuf>,
    /// That choice, while the person has not yet confirmed it.
    pub unconfirmed_choice: Option<ChoiceScope>,
    /// The nearest trusted project file, which `env use` records in the shell.
    pub project_file: Option<PathBuf>,
    /// Why the project or environment `env use` left in this shell must not be used here.
    pub stale_shell: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub server: Option<String>,
    pub token: Option<String>,
    /// From `--project`; `env_project` holds `SEKRET_PROJECT`.
    pub project: Option<String>,
    /// From `--env`; `env_environment` holds `SEKRET_ENVIRONMENT`.
    pub environment: Option<String>,
    pub env_project: Option<String>,
    pub env_environment: Option<String>,
    /// [`LOADED_FILE_VAR`]: set by `env use` to the project file it loaded under, empty for none.
    pub loaded_file: Option<String>,
    pub path: Option<String>,
    /// From `--ca-file` or `SEKRET_CA_FILE`.
    pub ca_file: Option<PathBuf>,
    /// The user config, the lowest priority of all.
    pub user: UserConfig,
}

/// Records which project file the last `env use` ran under, so another one can tell the shell's
/// `SEKRET_PROJECT` and `SEKRET_ENVIRONMENT` were not meant for it.
pub const LOADED_FILE_VAR: &str = "SEKRET_LOADED_FILE";

/// Refuses a project or environment that `env use` exported under a different project file, when
/// the nearer file here names another one. Values set by hand or by CI are not checked.
fn stale_shell_choice(overrides: &Overrides, file: &ProjectFile) -> Option<String> {
    let loaded_in = overrides.loaded_file.as_deref()?;
    let here = file
        .location
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    if loaded_in == here {
        return None;
    }
    let here = sekret_client::terminal_safe(&here);
    let clash = |flag: &Option<String>, env: &Option<String>, in_file: &Option<String>, name: &str| {
        let (None, Some(env), Some(in_file)) = (flag, env, in_file) else {
            return None;
        };
        (env != in_file).then(|| {
            format!(
                "{name} is {} in this shell but {here} says {}",
                sekret_client::terminal_safe(env),
                sekret_client::terminal_safe(in_file)
            )
        })
    };
    let clashes: Vec<String> = [
        clash(
            &overrides.project,
            &overrides.env_project,
            &file.project,
            "SEKRET_PROJECT",
        ),
        clash(
            &overrides.environment,
            &overrides.env_environment,
            &file.environment,
            "SEKRET_ENVIRONMENT",
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    if clashes.is_empty() {
        return None;
    }
    let shown_from = if loaded_in.is_empty() {
        "no project file".to_string()
    } else {
        sekret_client::terminal_safe(loaded_in)
    };
    Some(
        format!(
            "{}; these were loaded by `sekret-env` under {shown_from}, so not using them here. Run `sekret-env off` \
             to use this folder's file, or pass --project and --env to choose",
            clashes.join(" and ")
        )
        .replace(['\n', '\t'], " "),
    )
}

/// The order in which settings are taken, highest first, shown in `--help` and kept in step with
/// [`resolve`].
pub const SETTINGS_ORDER: &str = "\
Settings are taken from the first of these that sets them:
  1. command-line flags (--server, --ca-file, --project, --env, --path, --token)
  2. environment variables (SEKRET_URL, SEKRET_CA_FILE, SEKRET_PROJECT, SEKRET_ENVIRONMENT,
     SEKRET_PATH, SEKRET_TOKEN)
  3. the nearest .sekret.toml in this directory or a parent (server, project, environment, path,
     allow)
  4. the user config, $XDG_CONFIG_HOME/sekret/config.toml or ~/.config/sekret/config.toml
     (server, ca_file)
An empty value for the server, token, project, environment or path, as a flag or a variable, counts
as unset; an empty CA file is an error. The token, when neither --token nor SEKRET_TOKEN is set, is
the one `sekret login` saved for the chosen server. SEKRET_PROJECT and SEKRET_ENVIRONMENT left by
`sekret-env` under a different .sekret.toml are refused rather than used.";

/// Flags (which already include environment variables via clap) win over the project file, which
/// wins over the user config. The stored login is used when no token was given.
pub fn resolve(
    overrides: Overrides,
    file: ProjectFile,
    credentials: &Credentials,
    now: i64,
) -> anyhow::Result<Resolved> {
    let stale_shell = stale_shell_choice(&overrides, &file);
    let trimmed = |server: String| server.trim_end_matches('/').to_string();
    let user_server = overrides.user.server.clone().map(trimmed);
    let (server, source) = match (overrides.server, file.server, overrides.user.server) {
        (Some(server), _, _) => (trimmed(server), ServerSource::Explicit),
        (None, Some(server), _) => {
            let server = trimmed(server);
            // The user named this server themselves, so a project file agreeing changes nothing.
            let source = if user_server.as_ref() == Some(&server) {
                ServerSource::Explicit
            } else if credentials.servers.contains_key(&server) {
                ServerSource::LoggedIn
            } else {
                ServerSource::ProjectFile
            };
            (server, source)
        }
        (None, None, Some(server)) => (trimmed(server), ServerSource::Explicit),
        (None, None, None) => {
            let user_config = overrides
                .user
                .location
                .as_deref()
                .map(shown)
                .unwrap_or_else(|| format!("~/.config/sekret/{USER_CONFIG_FILE}"));
            bail!(
                "no server configured; pass --server, set SEKRET_URL, or add `server` to {PROJECT_FILE} or to \
                 {user_config}"
            )
        }
    };
    let ca_file = overrides
        .ca_file
        .map(CaFile::Given)
        .or(overrides.user.ca_file.map(CaFile::UserConfig));
    // A saved login is for its own token only; it does not vouch for the server to other credentials.
    if overrides.token.is_some() && source != ServerSource::Explicit {
        bail!(
            "{} comes only from {PROJECT_FILE}, so the token from --token or SEKRET_TOKEN is not sent to it; \
             pass --server, set SEKRET_URL or set `server` in the user config to confirm the server",
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
    let flag_or_env_project = overrides.project.or(overrides.env_project);
    let flag_or_env_environment = overrides.environment.or(overrides.env_environment);
    let chosen_by_file = ((flag_or_env_project.is_none() && file.project.is_some())
        || (flag_or_env_environment.is_none() && file.environment.is_some()))
    .then(|| file.location.clone().unwrap_or_else(|| PathBuf::from(PROJECT_FILE)));
    let project = flag_or_env_project.or(file.project);
    let environment = flag_or_env_environment.or(file.environment);
    let path = overrides.path.or(file.path).unwrap_or_else(|| "/".into());
    // Nor may it pick, say, prod for a cloned repository's build scripts without a yes.
    let unconfirmed_choice = chosen_by_file
        .as_ref()
        .map(|chosen| ChoiceScope {
            file: chosen.clone(),
            server: server.clone(),
            project: project.clone().unwrap_or_default(),
            environment: environment.clone().unwrap_or_default(),
        })
        .filter(|scope| file.location.is_none() || !credentials.choice_confirmed(scope));
    // A cloned repository's file must not unblock names on its own say-so.
    let scope = AllowScope {
        file: file.location.clone().unwrap_or_else(|| PathBuf::from(PROJECT_FILE)),
        server: server.clone(),
        project: project.clone().unwrap_or_default(),
        environment: environment.clone().unwrap_or_default(),
        path: path.clone(),
    };
    let (allow, unconfirmed_allow) = if file.allow.is_empty() {
        (Vec::new(), None)
    } else if file.location.is_some() && credentials.allow_confirmed(&scope, &file.allow) {
        (file.allow, None)
    } else {
        (Vec::new(), Some((scope, normalised_allow(&file.allow))))
    };
    Ok(Resolved {
        server,
        token,
        ca_file,
        project,
        environment,
        path,
        source,
        allow,
        unconfirmed_allow,
        chosen_by_file,
        unconfirmed_choice,
        project_file: file.location,
        stale_shell,
    })
}

/// Plain `http://` is only for this machine unless explicitly allowed, because tokens and secret
/// values would cross the network unencrypted. Plain http never goes through a proxy.
pub fn check_transport(server: &str, allow_insecure_http: bool) -> anyhow::Result<()> {
    // The URL parser would percent-encode these, but the raw string is what gets shown.
    if server.contains(['\n', '\t', '\r']) || sekret_client::terminal_safe(server) != server {
        bail!(
            "the server URL {} holds control or direction characters",
            sekret_client::terminal_safe(server).escape_debug()
        );
    }
    let url = url::Url::parse(server).with_context(|| format!("the server URL {server} is not valid"))?;
    if url.scheme() != "http" || allow_insecure_http || sekret_client::is_loopback(&url) {
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
    /// Named by a flag, `SEKRET_URL` or the user config, or confirmed by the person at `sekret login`.
    pub fn server_confirmed(&self) -> bool {
        self.source != ServerSource::ProjectFile
    }

    /// The project, unless it came from a shell loaded for another project file.
    pub fn checked_project(&self) -> anyhow::Result<Option<String>> {
        if let Some(reason) = &self.stale_shell {
            bail!("{reason}");
        }
        Ok(self.project.clone())
    }

    pub fn require_project(&self) -> anyhow::Result<(String, String)> {
        if let Some(reason) = &self.stale_shell {
            bail!("{reason}");
        }
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

    const ME: Me = Me {
        uid: 1000,
        gid: 1000,
        private_group: true,
    };
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
            distrust_reason(&[1000], private, Me { gid: 1001, ..ME }).is_some(),
            "a primary group that is not the user's own is shared"
        );
        assert!(
            distrust_reason(
                &[1000],
                private,
                Me {
                    private_group: false,
                    ..ME
                }
            )
            .is_some(),
            "a group with the user's id that holds someone else is shared"
        );
        assert_eq!(
            distrust_reason(&[1000], dir(1001, 0o755), ME),
            Some("its directory belongs to another user"),
            "its owner could swap the file"
        );
    }

    #[test]
    fn project_files_others_can_edit_are_distrusted() {
        assert_eq!(file_writers(dir(1000, 0o644), ME), None);
        assert_eq!(file_writers(dir(1000, 0o600), ME), None);
        assert_eq!(file_writers(dir(1000, 0o666), ME), Some("it is writable by every user"));
        assert_eq!(file_writers(dir(1000, 0o664), ME), Some("it is writable by its group"));
        let private = Ownership {
            gid: 1000,
            ..dir(1000, 0o664)
        };
        assert_eq!(file_writers(private, ME), None, "a private group is only this user");
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
        let path = config_dir_from(Some("rel/config".into()), Some("/home/me".into()))?;
        assert_eq!(path, PathBuf::from("/home/me/.config/sekret"));
        let path = config_dir_from(Some("/xdg".into()), Some("/home/me".into()))?;
        assert_eq!(path, PathBuf::from("/xdg/sekret"));
        let path = config_dir_from(Some("".into()), Some("/home/me".into()))?;
        assert_eq!(path, PathBuf::from("/home/me/.config/sekret"));
        assert!(config_dir_from(Some("rel".into()), None).is_err());
        for home in ["", ".", "home/me"] {
            assert!(
                config_dir_from(None, Some(home.into())).is_err(),
                "a relative HOME ({home:?}) would read the current directory's config"
            );
        }
        Ok(())
    }

    /// A private config directory holding `config.toml` with `text`.
    #[cfg(unix)]
    fn user_config_with(text: &str) -> anyhow::Result<(tempfile::TempDir, PathBuf)> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().context("dir")?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let path = dir.path().join(USER_CONFIG_FILE);
        std::fs::write(&path, text).context("write")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
        Ok((dir, path))
    }

    #[cfg(unix)]
    #[test]
    fn the_user_config_reads_server_and_ca_file() -> anyhow::Result<()> {
        let (dir, path) = user_config_with("server = \"https://sekret.lab/\"\nca_file = \"root.pem\"\n")?;
        let config = load_user_config(&path)?;
        assert_eq!(config.server.as_deref(), Some("https://sekret.lab/"));
        let real_dir = std::fs::canonicalize(dir.path()).context("canonical")?;
        assert_eq!(config.ca_file, Some(real_dir.join("root.pem")), "relative to the file");
        assert_eq!(config.location.as_deref(), Some(path.as_path()));
        let (_dir, path) = user_config_with("ca_file = \"/absent/root.pem\"\n")?;
        assert_eq!(
            load_user_config(&path)?.ca_file,
            Some(PathBuf::from("/absent/root.pem")),
            "a missing CA file is left for the read to report"
        );
        let missing = dir.path().join("absent.toml");
        let config = load_user_config(&missing)?;
        assert_eq!((config.server, config.ca_file), (None, None));
        assert_eq!(config.location, Some(missing));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn the_user_config_refuses_unknown_keys_and_an_empty_server() -> anyhow::Result<()> {
        let (_dir, path) = user_config_with("project = \"app\"\n")?;
        let refused = load_user_config(&path).err().context("project is not a user setting")?;
        assert!(
            format!("{refused:#}").contains("may set only `server` and `ca_file`"),
            "{refused:#}"
        );
        let (_dir, path) = user_config_with("server = \"  \"\n")?;
        assert!(load_user_config(&path).is_err());
        let (_dir, path) = user_config_with("ca_file = \"\"\n")?;
        assert!(load_user_config(&path).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_parse_error_names_the_line_but_never_quotes_the_file() -> anyhow::Result<()> {
        let cases = [
            ("server = \"https://sekret.lab\"\ntoken = \"skt_SECRET\"\n", "line 2"),
            ("skt_SECRET = \"x\"\n", "line 1"),
            ("[skt_SECRET]\n", "line 1"),
            ("server = 12345678\n", "line 1"),
            ("server = skt_SECRET\n", "line 1"),
        ];
        for (text, line) in cases {
            let (_dir, path) = user_config_with(text)?;
            let message = format!("{:#}", load_user_config(&path).err().context("invalid")?);
            assert!(message.contains(line), "{message}");
            for leak in ["SECRET", "12345678", "token"] {
                assert!(!message.contains(leak), "{message}");
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_user_config_that_cannot_be_inspected_is_an_error_not_absent() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if current_user().uid == 0 {
            return Ok(());
        }
        let (dir, path) = user_config_with("server = \"https://sekret.lab\"\n")?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000)).context("chmod")?;
        let result = load_user_config(&path);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn a_directory_above_is_safe_only_if_others_cannot_swap_its_entries() {
        let at = |uid: u32, mode: u32| Ownership { uid, gid: SHARED, mode };
        assert!(!swappable_dir(at(ME.uid, 0o700), ME));
        assert!(!swappable_dir(at(0, 0o755), ME));
        assert!(!swappable_dir(at(0, 0o1777), ME), "a sticky /tmp is fine");
        assert!(swappable_dir(at(0, 0o777), ME), "world-writable without the sticky bit");
        assert!(swappable_dir(at(0, 0o775), ME), "writable by a shared group");
        assert!(swappable_dir(at(1001, 0o755), ME), "another user's");
        assert!(
            !swappable_dir(at(0, 0o1775), ME),
            "a sticky, group-writable store such as /nix/store"
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_directory_along_a_chain_of_links_is_checked() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let (real, _) = user_config_with("server = \"https://sekret.lab\"\n")?;
        let middle = tempfile::tempdir().context("middle")?;
        let home = tempfile::tempdir().context("home")?;
        for dir in [middle.path(), home.path()] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        }
        let second = middle.path().join("second.toml");
        std::os::unix::fs::symlink(real.path().join(USER_CONFIG_FILE), &second).context("link")?;
        let first = home.path().join(USER_CONFIG_FILE);
        std::os::unix::fs::symlink(&second, &first).context("link")?;
        assert!(load_user_config(&first).is_ok());
        std::fs::set_permissions(middle.path(), std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        let refused = format!("{:#}", load_user_config(&first).err().context("open middle link")?);
        assert!(refused.contains("which leads to it"), "{refused}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_partway_along_the_path_is_checked() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        // ~/.config/sekret -> shared/r/sekret, where r is a symlink inside a directory others
        // can change, so they could re-point r at any config of yours.
        let (real, _) = user_config_with("server = \"https://sekret.lab\"\n")?;
        let shared = tempfile::tempdir().context("shared")?;
        std::os::unix::fs::symlink(real.path().parent().context("parent")?, shared.path().join("r")).context("r")?;
        let home = tempfile::tempdir().context("home")?;
        let name = real.path().file_name().context("name")?;
        std::os::unix::fs::symlink(shared.path().join("r").join(name), home.path().join("sekret")).context("link")?;
        let path = home.path().join("sekret").join(USER_CONFIG_FILE);
        for dir in [shared.path(), home.path()] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        }
        assert!(load_user_config(&path).is_ok());
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        let refused = format!("{:#}", load_user_config(&path).err().context("open shared")?);
        assert!(refused.contains("which leads to it"), "{refused}");
        Ok(())
    }

    #[test]
    fn a_link_another_user_planted_in_a_shared_directory_is_not_followed() {
        let tmp_owner = 0;
        assert!(link_may_be_followed(ME.uid, tmp_owner, ME));
        assert!(link_may_be_followed(0, tmp_owner, ME));
        assert!(!link_may_be_followed(1001, tmp_owner, ME), "planted in /tmp");
        assert!(link_may_be_followed(1001, 1001, ME), "in a directory that user owns");
    }

    #[cfg(unix)]
    #[test]
    fn dot_dot_after_a_link_is_taken_from_where_the_link_leads() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let (real, _) = user_config_with("server = \"https://sekret.lab\"\n")?;
        let top = tempfile::tempdir().context("top")?;
        std::fs::set_permissions(top.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let deep = top.path().join("a").join("b");
        std::fs::create_dir_all(&deep).context("deep")?;
        std::os::unix::fs::symlink(&deep, top.path().join("lnk")).context("absolute link")?;
        std::os::unix::fs::symlink("a/b", top.path().join("rel")).context("relative link")?;
        let name = real.path().file_name().context("name")?;
        std::os::unix::fs::symlink(real.path(), top.path().join("a").join(name)).context("config link")?;
        for via in ["lnk", "rel"] {
            let path = top.path().join(via).join("..").join(name).join(USER_CONFIG_FILE);
            let config = load_user_config(&path).with_context(|| format!("through {via}"))?;
            assert_eq!(config.server.as_deref(), Some("https://sekret.lab"));
        }
        let looped = top.path().join("loop");
        std::os::unix::fs::symlink(&looped, &looped).context("loop")?;
        let refused = format!("{:#}", read_trusted(&looped, "the CA file").err().context("loop")?);
        assert!(refused.contains("symbolic links"), "{refused}");
        let above_root = PathBuf::from("/../../")
            .join(real.path().strip_prefix("/")?)
            .join(USER_CONFIG_FILE);
        assert!(load_user_config(&above_root).is_ok(), "`..` at / stays at /");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_chain_of_more_than_forty_links_is_refused() -> anyhow::Result<()> {
        let (real, _) = user_config_with("server = \"https://sekret.lab\"\n")?;
        let mut target = real.path().join(USER_CONFIG_FILE);
        for hop in 0..41 {
            let link = real.path().join(format!("hop{hop}"));
            std::os::unix::fs::symlink(&target, &link).context("link")?;
            target = link;
        }
        let refused = format!("{:#}", load_user_config(&target).err().context("41 links")?);
        assert!(refused.contains("more than 40 symbolic links"), "{refused}");
        let within = real.path().join("hop39");
        assert!(load_user_config(&within).is_ok(), "40 links are fine");
        Ok(())
    }

    /// Grants `uid` rwx on `dir` by writing the access ACL xattr directly, as `setfacl -m u:<uid>:rwx`
    /// would on a 0770 directory, so the test needs no `acl` package.
    #[cfg(target_os = "linux")]
    fn grant_user_rwx(dir: &Path, uid: u32) -> anyhow::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        const UNDEFINED: u32 = u32::MAX;
        // posix_acl_xattr: a version header, then (tag, perm, id) entries sorted by tag.
        let entries: [(u16, u16, u32); 5] = [
            (0x01, 7, UNDEFINED), // owner
            (0x02, 7, uid),       // named user
            (0x04, 7, UNDEFINED), // owning group
            (0x10, 7, UNDEFINED), // mask
            (0x20, 0, UNDEFINED), // other
        ];
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            acl.extend(tag.to_le_bytes());
            acl.extend(perm.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).context("path")?;
        // SAFETY: both strings are NUL-terminated and the value pointer and length describe `acl`.
        let result = unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        anyhow::ensure!(result == 0, "setxattr: {}", std::io::Error::last_os_error());
        Ok(())
    }

    /// Needs a filesystem with POSIX ACLs.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_acl_on_a_directory_along_the_path_is_seen() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let (real, path) = user_config_with("server = \"https://sekret.lab\"\n")?;
        std::fs::set_permissions(real.path(), std::fs::Permissions::from_mode(0o770)).context("chmod")?;
        let me = current_user();
        if me.uid != me.gid {
            return Ok(());
        }
        assert!(load_user_config(&path).is_ok(), "a private group may write");
        grant_user_rwx(real.path(), 65534)?;
        let refused = format!("{:#}", load_user_config(&path).err().context("directory ACL")?);
        assert!(refused.contains("which leads to it"), "{refused}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_relative_path_is_never_trusted() {
        let refused = read_trusted(Path::new("config.toml"), "the user config");
        assert!(refused.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_device_is_refused_without_opening_it() -> anyhow::Result<()> {
        let home = tempfile::tempdir().context("home")?;
        let link = home.path().join("root.pem");
        std::os::unix::fs::symlink("/dev/null", &link).context("link")?;
        let refused = format!("{:#}", CaFile::UserConfig(link).read().err().context("device")?);
        assert!(refused.contains("not a regular file"), "{refused}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_above_others_can_change_is_refused() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let top = tempfile::tempdir().context("top")?;
        let config_dir = top.path().join("sekret");
        std::fs::create_dir(&config_dir).context("mkdir")?;
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let path = config_dir.join(USER_CONFIG_FILE);
        std::fs::write(&path, "server = \"https://sekret.lab\"\n").context("write")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
        std::fs::set_permissions(top.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        assert!(load_user_config(&path).is_ok());
        std::fs::set_permissions(top.path(), std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        let refused = format!("{:#}", load_user_config(&path).err().context("open parent")?);
        assert!(refused.contains("which leads to it"), "{refused}");
        std::fs::set_permissions(top.path(), std::fs::Permissions::from_mode(0o1777)).context("chmod")?;
        assert!(load_user_config(&path).is_ok(), "sticky");
        Ok(())
    }

    #[test]
    fn root_may_own_the_user_config_and_its_ca_but_no_one_else() {
        let mine = Ownership {
            uid: ME.uid,
            gid: ME.gid,
            mode: 0o600,
        };
        let root = Ownership {
            uid: 0,
            gid: 0,
            mode: 0o644,
        };
        let other = Ownership { uid: 1001, ..root };
        assert_eq!(owned_file_refusal(mine, ME), None);
        assert_eq!(owned_file_refusal(root, ME), None);
        assert!(owned_file_refusal(other, ME).is_some());
        let shared_group = Ownership {
            mode: 0o664,
            gid: SHARED,
            ..root
        };
        assert!(owned_file_refusal(shared_group, ME).is_some());
        let private_group = Ownership { mode: 0o660, ..mine };
        assert_eq!(owned_file_refusal(private_group, ME), None);
        assert!(
            owned_file_refusal(private_group, ME.unless_acl(true)).is_some(),
            "with an ACL, group write may name other users"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_ca_file_others_can_change_is_refused() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = user_config_with("ca_file = \"root.pem\"\n")?;
        let ca = dir.path().join("root.pem");
        std::fs::write(&ca, "pem").context("ca")?;
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o644)).context("chmod")?;
        let named = CaFile::UserConfig(load_user_config(&path)?.ca_file.context("ca_file")?);
        assert_eq!(named.read()?, "pem");
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
        let refused = format!("{:#}", named.read().err().context("writable CA")?);
        assert!(refused.contains("the CA file"), "{refused}");
        // The same file named by --ca-file is read as given.
        assert_eq!(CaFile::Given(ca).read()?, "pem");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_config_is_checked_and_read_where_it_really_is() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let (real, _) = user_config_with("server = \"https://sekret.lab\"\nca_file = \"root.pem\"\n")?;
        let home = tempfile::tempdir().context("home")?;
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let linked_dir = home.path().join("sekret");
        std::os::unix::fs::symlink(real.path(), &linked_dir).context("link")?;
        let config = load_user_config(&linked_dir.join(USER_CONFIG_FILE))?;
        let real_dir = std::fs::canonicalize(real.path()).context("canonical")?;
        assert_eq!(config.ca_file, Some(real_dir.join("root.pem")));

        std::fs::set_permissions(real.path(), std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        assert!(
            load_user_config(&linked_dir.join(USER_CONFIG_FILE)).is_err(),
            "the real directory is the one checked"
        );
        std::fs::set_permissions(real.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let link = home.path().join(USER_CONFIG_FILE);
        std::os::unix::fs::symlink(real.path().join(USER_CONFIG_FILE), &link).context("file link")?;
        assert!(load_user_config(&link).is_ok());
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        let refused = format!("{:#}", load_user_config(&link).err().context("open link directory")?);
        assert!(refused.contains("which leads to it"), "{refused}");
        Ok(())
    }

    #[test]
    fn a_project_file_naming_the_users_own_server_keeps_it_trusted() -> anyhow::Result<()> {
        let overrides = Overrides {
            token: Some("skt_env".into()),
            ..with_user(Some("https://user.test"), None)
        };
        let same = ProjectFile {
            server: Some("https://user.test/".into()),
            ..Default::default()
        };
        let resolved = resolve(overrides.clone(), same, &Credentials::default(), 0)?;
        assert_eq!(resolved.source, ServerSource::Explicit);
        let other = ProjectFile {
            server: Some("https://other.test".into()),
            ..Default::default()
        };
        assert!(resolve(overrides, other, &Credentials::default(), 0).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_user_config_others_can_change_is_refused() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = user_config_with("server = \"https://sekret.lab\"\n")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
        let refused = load_user_config(&path).err().context("world-writable file")?;
        assert!(
            format!("{refused:#}").contains("other users can change it"),
            "{refused:#}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).context("chmod")?;
        assert!(load_user_config(&path).is_ok(), "readable by others is fine");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).context("chmod")?;
        assert!(
            load_user_config(&path).is_err(),
            "a world-writable directory is refused"
        );
        Ok(())
    }

    fn with_user(server: Option<&str>, ca_file: Option<&str>) -> Overrides {
        Overrides {
            user: UserConfig {
                server: server.map(Into::into),
                ca_file: ca_file.map(PathBuf::from),
                location: None,
            },
            ..Default::default()
        }
    }

    #[test]
    fn the_user_config_is_the_lowest_priority() -> anyhow::Result<()> {
        let user = with_user(Some("https://user.test/"), Some("/user.pem"));
        let resolved = resolve(user.clone(), ProjectFile::default(), &Credentials::default(), 0)?;
        assert_eq!(resolved.server, "https://user.test");
        let from_user = Some(CaFile::UserConfig("/user.pem".into()));
        assert_eq!(resolved.ca_file, from_user);

        let file = ProjectFile {
            server: Some("https://file.test".into()),
            ..Default::default()
        };
        let resolved = resolve(user.clone(), file.clone(), &Credentials::default(), 0)?;
        assert_eq!(resolved.server, "https://file.test", "the project file wins");
        assert_eq!(resolved.source, ServerSource::ProjectFile);
        assert_eq!(resolved.ca_file, from_user, "it sets no CA");

        let flags = Overrides {
            server: Some("https://flag.test".into()),
            ca_file: Some("/flag.pem".into()),
            ..user
        };
        let resolved = resolve(flags, file, &Credentials::default(), 0)?;
        assert_eq!(resolved.server, "https://flag.test");
        assert_eq!(resolved.ca_file, Some(CaFile::Given("/flag.pem".into())));
        Ok(())
    }

    #[test]
    fn a_server_from_the_user_config_is_trusted_with_tokens() -> anyhow::Result<()> {
        let overrides = Overrides {
            token: Some("skt_env".into()),
            ..with_user(Some("https://user.test"), None)
        };
        let resolved = resolve(overrides, ProjectFile::default(), &Credentials::default(), 0)?;
        assert_eq!(resolved.source, ServerSource::Explicit);
        assert!(resolved.server_confirmed());
        assert_eq!(resolved.token.as_deref(), Some("skt_env"));
        Ok(())
    }

    #[test]
    fn a_missing_server_names_every_place_to_set_one() {
        let refused = resolve(Overrides::default(), ProjectFile::default(), &Credentials::default(), 0);
        let message = refused.map(|_| String::new()).unwrap_or_else(|e| e.to_string());
        for place in ["--server", "SEKRET_URL", PROJECT_FILE, "~/.config/sekret/config.toml"] {
            assert!(message.contains(place), "{message}");
        }
    }

    #[test]
    fn the_help_lists_the_order_resolve_follows() {
        let at = |needle: &str| SETTINGS_ORDER.find(needle);
        let order = [
            at("command-line flags"),
            at("environment variables"),
            at(PROJECT_FILE),
            at("~/.config/sekret/config.toml"),
        ];
        assert!(order.iter().all(Option::is_some), "{SETTINGS_ORDER}");
        assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{SETTINGS_ORDER}");
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

    #[cfg(unix)]
    #[test]
    fn a_project_file_others_can_edit_is_skipped() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let top = tempfile::tempdir().context("dir")?;
        std::fs::set_permissions(top.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let path = top.path().join(PROJECT_FILE);
        std::fs::write(&path, "environment = \"prod\"\n").context("write")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).context("chmod")?;
        let mut warnings = Vec::new();
        let (file, found) = load_project_file(top.path(), &mut warnings).context("load")?;
        assert_eq!(file.environment, None);
        assert_eq!(found, None);
        assert!(
            warnings.iter().any(|w| w.contains("it is writable by every user")),
            "{warnings:?}"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).context("chmod")?;
        let mut warnings = Vec::new();
        let (file, found) = load_project_file(top.path(), &mut warnings).context("load")?;
        assert_eq!(file.environment.as_deref(), Some("prod"));
        assert_eq!(found, Some(path));
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
        let mut file: ProjectFile = toml::from_str(
            "server = \"https://s\"\nproject = \"app\"\nenvironment = \"dev\"\nallow = [\"KUBECONFIG\", \"GIT_PAGER\"]\n",
        )?;
        let location = PathBuf::from("/repo/.sekret.toml");
        file.location = Some(location.clone());
        let scope = AllowScope {
            file: location.clone(),
            server: "https://s".into(),
            project: "app".into(),
            environment: "dev".into(),
            path: "/".into(),
        };
        let resolved = resolve(Overrides::default(), file.clone(), &Credentials::default(), 0)?;
        assert!(
            resolved.allow.is_empty(),
            "a cloned file cannot unblock names by itself"
        );
        assert_eq!(
            resolved.unconfirmed_allow,
            Some((scope.clone(), vec!["GIT_PAGER".into(), "KUBECONFIG".into()]))
        );

        let mut credentials = Credentials::default();
        credentials.confirm_allow(&scope, &["KUBECONFIG".into(), "GIT_PAGER".into(), "KUBECONFIG".into()]);
        let resolved = resolve(Overrides::default(), file.clone(), &credentials, 0)?;
        assert_eq!(resolved.allow, ["KUBECONFIG", "GIT_PAGER"]);
        assert_eq!(resolved.unconfirmed_allow, None);

        // A longer list, or the same list in another file, needs confirming again.
        let mut grown = file.clone();
        grown.allow.push("LD_PRELOAD".into());
        assert!(resolve(Overrides::default(), grown, &credentials, 0)?.allow.is_empty());
        let mut elsewhere = file.clone();
        elsewhere.location = Some("/other/.sekret.toml".into());
        assert!(
            resolve(Overrides::default(), elsewhere, &credentials, 0)?
                .allow
                .is_empty()
        );

        let text = toml::to_string(&credentials)?;
        let read: Credentials = toml::from_str(&text)?;
        assert!(read.allow_confirmed(&scope, &["GIT_PAGER".into(), "KUBECONFIG".into()]));
        let old: Credentials = toml::from_str("[servers]\n")?;
        assert!(old.confirmed_allow.is_empty(), "older credentials files still load");
        let path_keyed: Credentials =
            toml::from_str("[confirmed_allow]\n\"/repo/.sekret.toml\" = [\"GIT_PAGER\", \"KUBECONFIG\"]\n")?;
        assert!(
            resolve(Overrides::default(), file, &path_keyed, 0)?.allow.is_empty(),
            "a yes saved before scopes were recorded is asked again"
        );
        Ok(())
    }

    #[test]
    fn a_confirmed_allow_list_does_not_follow_a_change_of_project_environment_path_or_server() -> anyhow::Result<()> {
        let mut file: ProjectFile = toml::from_str(
            "server = \"https://s\"\nproject = \"app\"\nenvironment = \"dev\"\nallow = [\"NODE_OPTIONS\"]\n",
        )?;
        file.location = Some("/repo/.sekret.toml".into());
        let mut credentials = Credentials::default();
        let confirmed = resolve(Overrides::default(), file.clone(), &credentials, 0)?
            .unconfirmed_allow
            .context("unconfirmed at first")?;
        credentials.confirm_allow(&confirmed.0, &confirmed.1);
        assert_eq!(
            resolve(Overrides::default(), file.clone(), &credentials, 0)?.allow,
            ["NODE_OPTIONS"]
        );

        let edited = |text: &str| -> anyhow::Result<ProjectFile> {
            let mut changed: ProjectFile = toml::from_str(text)?;
            changed.location = file.location.clone();
            Ok(changed)
        };
        let changed_files = [
            "server = \"https://s\"\nproject = \"sandbox\"\nenvironment = \"dev\"\nallow = [\"NODE_OPTIONS\"]\n",
            "server = \"https://s\"\nproject = \"app\"\nenvironment = \"prod\"\nallow = [\"NODE_OPTIONS\"]\n",
            "server = \"https://s\"\nproject = \"app\"\nenvironment = \"dev\"\npath = \"/open\"\nallow = [\"NODE_OPTIONS\"]\n",
            "server = \"https://other\"\nproject = \"app\"\nenvironment = \"dev\"\nallow = [\"NODE_OPTIONS\"]\n",
        ];
        for text in changed_files {
            let resolved = resolve(Overrides::default(), edited(text)?, &credentials, 0)?;
            assert!(resolved.allow.is_empty(), "{text}");
            assert!(resolved.unconfirmed_allow.is_some(), "{text}");
        }
        let switched = Overrides {
            environment: Some("staging".into()),
            ..Default::default()
        };
        assert!(
            resolve(switched, file, &credentials, 0)?.allow.is_empty(),
            "a flag or variable choosing another environment asks again too"
        );
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
        assert_eq!(flagged.unconfirmed_choice, None);
        Ok(())
    }

    #[test]
    fn a_project_file_choice_is_confirmed_per_file_server_project_and_environment() -> anyhow::Result<()> {
        let mut file: ProjectFile =
            toml::from_str("server = \"https://s\"\nproject = \"payments\"\nenvironment = \"prod\"\n")?;
        file.location = Some("/repo/.sekret.toml".into());
        let mut credentials = Credentials::default();
        let scope = resolve(Overrides::default(), file.clone(), &credentials, 0)?
            .unconfirmed_choice
            .context("a cloned file's choice starts unconfirmed")?;
        assert_eq!(
            scope,
            ChoiceScope {
                file: "/repo/.sekret.toml".into(),
                server: "https://s".into(),
                project: "payments".into(),
                environment: "prod".into(),
            }
        );
        credentials.confirm_choice(&scope);
        let read: Credentials = toml::from_str(&toml::to_string(&credentials)?)?;
        assert_eq!(
            resolve(Overrides::default(), file.clone(), &read, 0)?.unconfirmed_choice,
            None,
            "the saved yes is used next time"
        );

        let env_only = Overrides {
            environment: Some("dev".into()),
            ..Default::default()
        };
        assert!(
            resolve(env_only, file.clone(), &read, 0)?.unconfirmed_choice.is_some(),
            "the file still picks the project, now for another environment"
        );
        let edited = [
            ("/repo/.sekret.toml", "https://other", "payments", "prod"),
            ("/repo/.sekret.toml", "https://s", "billing", "prod"),
            ("/repo/.sekret.toml", "https://s", "payments", "staging"),
            ("/other/.sekret.toml", "https://s", "payments", "prod"),
        ];
        for (location, server, project, environment) in edited {
            let mut changed: ProjectFile = toml::from_str(&format!(
                "server = \"{server}\"\nproject = \"{project}\"\nenvironment = \"{environment}\"\n"
            ))?;
            changed.location = Some(location.into());
            let resolved = resolve(Overrides::default(), changed, &read, 0)?;
            assert!(
                resolved.unconfirmed_choice.is_some(),
                "{location} {server} {project} {environment}"
            );
        }
        let env_vars = Overrides {
            env_project: Some("payments".into()),
            env_environment: Some("prod".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve(env_vars, file, &Credentials::default(), 0)?.unconfirmed_choice,
            None,
            "SEKRET_PROJECT and SEKRET_ENVIRONMENT are the person's choice"
        );
        let old: Credentials = toml::from_str("[servers]\n")?;
        assert!(old.confirmed_choices.is_empty(), "older credentials files still load");
        Ok(())
    }

    fn repo_b() -> anyhow::Result<ProjectFile> {
        let mut file: ProjectFile = toml::from_str("server = \"https://s\"\nproject = \"b\"\nenvironment = \"dev\"\n")?;
        file.location = Some("/repo-b/.sekret.toml".into());
        Ok(file)
    }

    /// What `sekret-env prod` in repository A leaves in the shell.
    fn shell_from_a(loaded_file: &str) -> Overrides {
        Overrides {
            env_project: Some("a".into()),
            env_environment: Some("prod".into()),
            loaded_file: Some(loaded_file.into()),
            ..Default::default()
        }
    }

    #[test]
    fn a_shell_loaded_for_another_project_file_does_not_override_this_one() -> anyhow::Result<()> {
        let stale = resolve(
            shell_from_a("/repo-a/.sekret.toml"),
            repo_b()?,
            &Credentials::default(),
            0,
        )?;
        let reason = stale.stale_shell.clone().context("the clash is reported")?;
        assert!(
            reason.contains("SEKRET_PROJECT is a") && reason.contains("says b"),
            "{reason}"
        );
        assert!(reason.contains("SEKRET_ENVIRONMENT is prod") && reason.contains("sekret-env off"));
        let refused = stale.require_project().err().context("run and export are refused")?;
        assert!(refused.to_string().contains("/repo-a/.sekret.toml"), "{refused}");
        assert!(stale.checked_project().is_err(), "policy changes are refused too");

        let none = resolve(shell_from_a(""), repo_b()?, &Credentials::default(), 0)?;
        assert!(
            none.stale_shell
                .as_deref()
                .is_some_and(|r| r.contains("no project file")),
            "loaded outside any repository, then moved into one"
        );
        Ok(())
    }

    #[test]
    fn a_shell_choice_is_kept_where_it_was_made_or_when_chosen_by_flag() -> anyhow::Result<()> {
        let same = resolve(
            shell_from_a("/repo-b/.sekret.toml"),
            repo_b()?,
            &Credentials::default(),
            0,
        )?;
        assert_eq!(same.stale_shell, None, "sekret-env prod inside B keeps prod");
        assert_eq!(same.require_project()?, ("a".to_string(), "prod".to_string()));

        let mut flagged = shell_from_a("/repo-a/.sekret.toml");
        flagged.project = Some("a".into());
        flagged.environment = Some("prod".into());
        let flagged = resolve(flagged, repo_b()?, &Credentials::default(), 0)?;
        assert_eq!(flagged.stale_shell, None, "flags are a deliberate choice");
        assert_eq!(flagged.require_project()?, ("a".to_string(), "prod".to_string()));

        let mut by_hand = shell_from_a("/repo-a/.sekret.toml");
        by_hand.loaded_file = None;
        let by_hand = resolve(by_hand, repo_b()?, &Credentials::default(), 0)?;
        assert_eq!(by_hand.stale_shell, None, "variables set by hand or by CI still win");
        assert_eq!(by_hand.require_project()?, ("a".to_string(), "prod".to_string()));

        let mut agreeing = repo_b()?;
        agreeing.project = Some("a".into());
        agreeing.environment = None;
        let agreeing = resolve(
            shell_from_a("/repo-a/.sekret.toml"),
            agreeing,
            &Credentials::default(),
            0,
        )?;
        assert_eq!(agreeing.stale_shell, None, "nothing in the file is overridden");

        let outside = resolve(
            shell_from_a("/repo-a/.sekret.toml"),
            ProjectFile {
                server: Some("https://s".into()),
                ..Default::default()
            },
            &Credentials::default(),
            0,
        )?;
        assert_eq!(outside.stale_shell, None, "no project file here to override");
        Ok(())
    }

    #[test]
    fn project_file_parse_errors_carry_no_escape_sequences() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        }
        std::fs::write(
            dir.path().join(PROJECT_FILE),
            "project = 5 # \u{1b}]52;c;cm0gLXJmIH4=\u{7}\u{1b}]0;PWNED\u{7}\u{1b}[2J\n",
        )
        .context("write")?;
        let error = load_project_file(dir.path(), &mut Vec::new())
            .err()
            .context("a bad file is refused")?;
        let shown = format!("{error:#}");
        assert!(shown.contains("parsing"), "{shown}");
        assert!(!shown.contains('\u{1b}') && !shown.contains('\u{7}'), "{shown:?}");
        Ok(())
    }

    #[test]
    fn credentials_parse_errors_carry_no_escape_sequences() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("sekret").join("credentials.toml");
        save_credentials(&path, &Credentials::default()).context("save")?;
        std::fs::write(&path, "servers = 5 # \u{1b}]0;PWNED\u{7}\n").context("write")?;
        let error = load_credentials(&path, &mut Vec::new())
            .err()
            .context("a bad file is refused")?;
        let shown = format!("{error:#}");
        assert!(!shown.contains('\u{1b}') && !shown.contains('\u{7}'), "{shown:?}");
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
    fn a_server_holding_control_or_direction_characters_is_refused() {
        for server in [
            "https://x.test/\u{1b}[2J",
            "https://x.test/a\nb",
            "https://x.test/\u{9b}31m",
            "https://x.test/\u{202e}evil",
        ] {
            let refused = check_transport(server, false).err().map(|e| format!("{e:#}"));
            assert!(
                refused.as_deref().is_some_and(|e| e.contains("control or direction")),
                "{server:?}: {refused:?}"
            );
            assert!(refused.is_some_and(|e| !e.contains('\u{1b}') && !e.contains('\u{202e}')));
        }
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
