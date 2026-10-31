//! Checks a host socket before a passphrase or setup code is sent to it, so a socket planted by
//! another user cannot collect them.

use std::path::Path;

use anyhow::{Context, bail};

/// What the checks look at, gathered from the file system and the connected server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketFacts {
    pub socket_uid: u32,
    pub dir_uid: u32,
    pub dir_mode: u32,
    /// The user of the process listening, where the platform reports it.
    pub peer_uid: Option<u32>,
    pub me: u32,
}

/// Why the socket cannot be trusted, or `None` when it can.
pub fn problem(facts: &SocketFacts) -> Option<&'static str> {
    if facts.dir_mode & 0o002 != 0 {
        return Some("its directory can be written by other users, who could replace it");
    }
    // Outside its group, only the directory's owner and root can create entries in it.
    let trusted_dir = facts.dir_uid == facts.me || facts.dir_uid == 0;
    if !trusted_dir && facts.socket_uid != facts.dir_uid {
        return Some("it belongs to a different user from its directory");
    }
    match facts.peer_uid {
        Some(peer) if peer != facts.socket_uid && peer != 0 => {
            Some("the process listening on it is not the socket's owner")
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn peer_uid(path: &Path) -> anyhow::Result<Option<u32>> {
    use std::os::unix::io::AsRawFd;
    let stream =
        std::os::unix::net::UnixStream::connect(path).with_context(|| format!("connecting to {}", path.display()))?;
    let mut credentials = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor belongs to `stream`, which outlives the call, and the kernel writes
    // at most `length` bytes into `credentials`, which is exactly that size.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &mut length,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("reading the socket's peer");
    }
    Ok(Some(credentials.uid))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(_path: &Path) -> anyhow::Result<Option<u32>> {
    Ok(None)
}

/// Refuses a socket that someone other than the server's user could have put there.
#[cfg(unix)]
pub fn check(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let socket = std::fs::symlink_metadata(path).with_context(|| format!("{}", path.display()))?;
    if !socket.file_type().is_socket() {
        bail!("{} is not a socket", path.display());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = std::fs::metadata(parent).with_context(|| format!("{}", parent.display()))?;
    let facts = SocketFacts {
        socket_uid: socket.uid(),
        dir_uid: dir.uid(),
        dir_mode: dir.mode(),
        peer_uid: peer_uid(path)?,
        // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
        me: unsafe { libc::geteuid() },
    };
    if let Some(why) = problem(&facts) {
        bail!("not sending anything to {}: {why}", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn check(_path: &Path) -> anyhow::Result<()> {
    bail!("host sockets need a Unix host")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> SocketFacts {
        SocketFacts {
            socket_uid: 990,
            dir_uid: 990,
            dir_mode: 0o40750,
            peer_uid: Some(990),
            me: 1000,
        }
    }

    #[test]
    fn a_socket_in_the_server_users_private_directory_is_trusted() {
        assert_eq!(problem(&facts()), None);
        let mine = SocketFacts {
            socket_uid: 1000,
            dir_uid: 1000,
            peer_uid: Some(1000),
            ..facts()
        };
        assert_eq!(problem(&mine), None);
        let root_dir = SocketFacts {
            dir_uid: 0,
            dir_mode: 0o40755,
            ..facts()
        };
        assert_eq!(problem(&root_dir), None, "a root-owned /run style directory");
    }

    #[test]
    fn sockets_others_could_have_planted_are_refused() {
        let shared = SocketFacts {
            dir_uid: 0,
            dir_mode: 0o41777,
            ..facts()
        };
        assert!(problem(&shared).is_some(), "a world-writable directory like /tmp");
        let foreign = SocketFacts {
            socket_uid: 2000,
            ..facts()
        };
        assert!(
            problem(&foreign).is_some(),
            "someone else's socket in the server's directory"
        );
        let impostor = SocketFacts {
            peer_uid: Some(2000),
            ..facts()
        };
        assert!(problem(&impostor).is_some(), "another user listening behind the file");
        let unknown_peer = SocketFacts {
            peer_uid: None,
            ..facts()
        };
        assert_eq!(problem(&unknown_peer), None, "platforms without peer credentials");
    }
}
