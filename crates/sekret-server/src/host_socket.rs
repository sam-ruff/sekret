//! A Unix socket on the host that serves only status and unseal. Access is decided by the
//! socket file's permissions, so the network's rate limits and back-off do not apply to it.

use std::path::Path;

use crate::StartupError;
use crate::config::UnixSocketSettings;
use crate::state::AppState;

#[cfg(unix)]
fn listen(socket: &UnixSocketSettings) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let path = &socket.path;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket; not replacing it", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    // Bound under a temporary name and only moved into place once its mode is set, so nobody
    // can connect in between.
    let mut temp = path.as_os_str().to_os_string();
    temp.push(format!(".{}.tmp", std::process::id()));
    let temp = std::path::PathBuf::from(temp);
    let _ = std::fs::remove_file(&temp);
    let listener = tokio::net::UnixListener::bind(&temp)?;
    let placed = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(socket.mode))
        .and_then(|()| std::fs::rename(&temp, path));
    if let Err(error) = placed {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
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
