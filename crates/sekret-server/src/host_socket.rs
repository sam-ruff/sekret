//! A Unix socket on the host that serves only status and unseal. Access is decided by the
//! socket file's permissions, so the network's rate limits and back-off do not apply to it.

use std::path::Path;

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

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

#[cfg(unix)]
fn check_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = parent_of(path);
    let meta = std::fs::metadata(parent)?;
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
    let server_uid = unsafe { libc::geteuid() };
    let Some(problem) = directory_problem(meta.uid(), meta.mode(), server_uid) else {
        return Ok(());
    };
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("the socket's directory {} {problem}", parent.display()),
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
