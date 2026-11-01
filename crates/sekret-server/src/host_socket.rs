//! A Unix socket on the host that serves only status and unseal. Access is decided by the
//! socket file's permissions, so the network's rate limits and back-off do not apply to it.

use std::path::{Path, PathBuf};

use crate::StartupError;
use crate::config::UnixSocketSettings;
use crate::state::AppState;

/// Why a socket's directory is unsafe: anyone who can write to it can swap the socket for one
/// of their own and collect the passphrases sent to it.
fn directory_problem(dir_uid: u32, dir_mode: u32, server_uid: u32) -> Option<&'static str> {
    if dir_uid != server_uid {
        return Some("must be owned by the user sekret runs as");
    }
    if dir_mode & 0o002 != 0 {
        return Some("must not be writable by other users");
    }
    if dir_mode & 0o020 != 0 {
        return Some("must not be writable by its group; share the socket through its group instead");
    }
    None
}

pub fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// A directory on the way to a socket, and the owner of the entry in it that the path goes
/// through next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub dir: PathBuf,
    pub dir_uid: u32,
    pub dir_mode: u32,
    pub entry_uid: u32,
}

/// Why someone outside `trusted` could swap what lies below this directory, and so plant a
/// socket of their own further down. A sticky directory such as `/tmp` is safe as long as the
/// entry in it belongs to a trusted user.
pub fn ancestor_problem(ancestor: &Ancestor, trusted: &[u32]) -> Option<&'static str> {
    if !trusted.contains(&ancestor.dir_uid) {
        return Some("belongs to another user, who could replace what is in it");
    }
    if ancestor.dir_mode & 0o022 == 0 {
        return None;
    }
    if ancestor.dir_mode & 0o1000 == 0 {
        return Some("can be written by other users, who could replace what is in it");
    }
    if !trusted.contains(&ancestor.entry_uid) {
        return Some("is shared, and the entry in it belongs to another user");
    }
    None
}

/// `dir` and every directory above it, both as written and with symlinks resolved, each with
/// the owner of the entry below it.
#[cfg(unix)]
pub fn ancestors(dir: &Path) -> std::io::Result<Vec<Ancestor>> {
    use std::os::unix::fs::MetadataExt;
    let written = std::path::absolute(dir)?;
    let real = std::fs::canonicalize(dir)?;
    let mut found = Vec::new();
    for start in [written, real] {
        let mut entry = start.as_path();
        while let Some(parent) = entry.parent() {
            let parent_meta = std::fs::metadata(parent)?;
            let entry_meta = std::fs::symlink_metadata(entry)?;
            found.push(Ancestor {
                dir: parent.to_path_buf(),
                dir_uid: parent_meta.uid(),
                dir_mode: parent_meta.mode(),
                entry_uid: entry_meta.uid(),
            });
            entry = parent;
        }
    }
    Ok(found)
}

/// The first directory above `dir` that lets someone outside `trusted` replace `dir`, as a
/// sentence, or `None` when there is none.
#[cfg(unix)]
pub fn untrusted_ancestor(dir: &Path, trusted: &[u32]) -> std::io::Result<Option<String>> {
    Ok(ancestors(dir)?.iter().find_map(|ancestor| {
        ancestor_problem(ancestor, trusted).map(|why| format!("{} {why}", ancestor.dir.display()))
    }))
}

#[cfg(unix)]
fn check_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = parent_of(path);
    let meta = std::fs::metadata(parent)?;
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
    let server_uid = unsafe { libc::geteuid() };
    if let Some(problem) = directory_problem(meta.uid(), meta.mode(), server_uid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("the socket's directory {} {problem}", parent.display()),
        ));
    }
    let Some(why) = untrusted_ancestor(parent, &[0, server_uid])? else {
        return Ok(());
    };
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "the socket's directory {} sits below a directory that is not safe: {why}",
            parent.display()
        ),
    ))
}

#[cfg(unix)]
fn listen(socket: &UnixSocketSettings) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let path = &socket.path;
    check_directory(path)?;
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && !meta.file_type().is_socket()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a socket; not replacing it", path.display()),
        ));
    }
    // Bound inside a fresh owner-only directory and only moved into place once its mode is set,
    // so nobody can connect in between, whatever the process umask.
    let staging = tempfile::Builder::new()
        .prefix(".sekret-socket-")
        .tempdir_in(parent_of(path))?;
    let temp = staging.path().join("unseal.sock");
    let listener = tokio::net::UnixListener::bind(&temp)?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(socket.mode))?;
    std::fs::rename(&temp, path)?;
    Ok(listener)
}

#[cfg(not(unix))]
fn listen(_socket: &UnixSocketSettings) -> std::io::Result<tokio::net::UnixListener> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix sockets need a Unix host",
    ))
}

/// Starts serving on the socket in the background.
pub fn spawn(state: AppState, socket: &UnixSocketSettings) -> Result<(), StartupError> {
    let listener = listen(socket).map_err(|e| StartupError::Init(format!("{}: {e}", socket.path.display())))?;
    let path = socket.path.clone();
    tracing::info!(path = %path.display(), mode = format!("{:o}", socket.mode), "unseal socket ready");
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, crate::api::host_router(state)).await {
            tracing::error!(%error, path = %path.display(), "the unseal socket stopped");
        }
    });
    Ok(())
}

/// Removes the socket file at shutdown, if it is still a socket.
pub fn remove(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
            let _ = std::fs::remove_file(path);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_private_directory_owned_by_the_server_may_hold_the_socket() {
        assert_eq!(directory_problem(1000, 0o40700, 1000), None);
        assert_eq!(directory_problem(1000, 0o40750, 1000), None);
        assert!(
            directory_problem(0, 0o40755, 1000).is_some(),
            "someone else's directory"
        );
        assert!(directory_problem(1000, 0o40777, 1000).is_some(), "writable by anyone");
        assert!(directory_problem(1000, 0o41777, 1000).is_some(), "like /tmp");
    }

    #[test]
    fn a_group_writable_directory_is_refused_even_with_the_sticky_bit() {
        assert_eq!(directory_problem(1000, 0o42750, 1000), None, "setgid is fine");
        for mode in [0o40770, 0o41770, 0o42770, 0o40730] {
            assert!(directory_problem(1000, mode, 1000).is_some(), "{mode:o}");
        }
    }

    fn ancestor(dir_uid: u32, dir_mode: u32, entry_uid: u32) -> Ancestor {
        Ancestor {
            dir: "/srv".into(),
            dir_uid,
            dir_mode,
            entry_uid,
        }
    }

    #[test]
    fn ancestors_others_could_rearrange_are_refused() {
        let trusted = [0, 990];
        assert_eq!(ancestor_problem(&ancestor(0, 0o40755, 0), &trusted), None, "/ or /run");
        assert_eq!(ancestor_problem(&ancestor(990, 0o40700, 990), &trusted), None);
        assert_eq!(
            ancestor_problem(&ancestor(0, 0o41777, 990), &trusted),
            None,
            "a sticky /tmp whose entry is the server's"
        );
        assert!(
            ancestor_problem(&ancestor(0, 0o40775, 990), &trusted).is_some(),
            "the audit's group-writable /srv/shared"
        );
        assert!(ancestor_problem(&ancestor(0, 0o40777, 990), &trusted).is_some());
        assert!(
            ancestor_problem(&ancestor(0, 0o41777, 2000), &trusted).is_some(),
            "another user's directory in /tmp"
        );
        assert!(
            ancestor_problem(&ancestor(2000, 0o40755, 990), &trusted).is_some(),
            "a directory another user owns can be rearranged by them"
        );
    }

    #[cfg(unix)]
    #[test]
    fn listen_refuses_a_directory_below_one_others_can_write() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let shared = tempfile::tempdir()?;
        let own = shared.path().join("sekret");
        std::fs::create_dir(&own)?;
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700))?;
        let path = own.join("unseal.sock");
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o700))?;
        check_directory(&path)?;
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o777))?;
        let error = check_directory(&path)
            .err()
            .ok_or_else(|| anyhow::anyhow!("expected refusal"))?;
        assert!(error.to_string().contains("not safe"), "{error}");
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o1777))?;
        check_directory(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_judged_by_both_its_link_and_its_target() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir()?;
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700))?;
        let open = base.path().join("open");
        let target = open.join("real");
        std::fs::create_dir_all(&target)?;
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))?;
        let safe = base.path().join("safe");
        std::fs::create_dir(&safe)?;
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o700))?;
        let link = safe.join("link");
        std::os::unix::fs::symlink(&target, &link)?;
        // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
        let me = unsafe { libc::geteuid() };
        let found = untrusted_ancestor(&link, &[0, me])?.unwrap_or_default();
        assert!(
            found.contains("open"),
            "the target sits in a world-writable directory: {found}"
        );
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755))?;
        assert_eq!(untrusted_ancestor(&link, &[0, me])?, None);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn listen_refuses_a_group_writable_directory() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770))?;
        let path = dir.path().join("unseal.sock");
        let error = check_directory(&path)
            .err()
            .ok_or_else(|| anyhow::anyhow!("expected refusal"))?;
        assert!(error.to_string().contains("group"), "{error}");
        assert!(!path.exists());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750))?;
        check_directory(&path)?;
        Ok(())
    }
}
