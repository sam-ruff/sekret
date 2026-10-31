//! Checks a host socket before a passphrase or setup code is sent to it, so a socket planted by
//! another user cannot collect them. The connection that was checked is the one used afterwards.

use std::path::Path;

use anyhow::{Context, bail};

/// What the checks look at, gathered from the file system and the connected server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketFacts {
    pub socket_uid: u32,
    pub dir_uid: u32,
    pub dir_mode: u32,
    /// The user of the process listening on the connection that will carry the request.
    pub peer_uid: u32,
}

/// Why the socket cannot be trusted, or `None` when it can.
///
/// The server refuses to listen anywhere but a directory it owns that nobody else can write to,
/// so the directory's owner is the server's user: the socket and its listener must both be theirs.
pub fn problem(facts: &SocketFacts) -> Option<&'static str> {
    if facts.dir_mode & 0o002 != 0 {
        return Some("its directory can be written by other users, who could replace it");
    }
    if facts.dir_mode & 0o020 != 0 {
        return Some("its directory can be written by its group, whose members could replace it");
    }
    if facts.socket_uid != facts.dir_uid {
        return Some("it belongs to a different user from its directory");
    }
    if facts.peer_uid != facts.socket_uid {
        return Some("the process listening on it is not the socket's owner");
    }
    None
}

#[cfg(unix)]
fn file_facts(path: &Path) -> anyhow::Result<(std::fs::Metadata, std::fs::Metadata)> {
    use std::os::unix::fs::FileTypeExt;
    let socket = std::fs::symlink_metadata(path).with_context(|| format!("{}", path.display()))?;
    if !socket.file_type().is_socket() {
        bail!("{} is not a socket", path.display());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = std::fs::metadata(parent).with_context(|| format!("{}", parent.display()))?;
    Ok((socket, dir))
}

/// Connects to the socket and returns the connection once it passes the checks. Callers send
/// over this stream rather than reconnecting by path, which could reach a different listener.
#[cfg(unix)]
pub async fn connect(path: &Path) -> anyhow::Result<tokio::net::UnixStream> {
    use std::os::unix::fs::MetadataExt;
    let (before, dir) = file_facts(path)?;
    let stream = tokio::net::UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to {}", path.display()))?;
    let peer = stream.peer_cred().context("reading the user listening on the socket")?;
    // A swap between the first look and the connection shows up as a different file.
    let (after, _) = file_facts(path)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        bail!(
            "not sending anything to {}: it was replaced while connecting",
            path.display()
        );
    }
    let facts = SocketFacts {
        socket_uid: after.uid(),
        dir_uid: dir.uid(),
        dir_mode: dir.mode(),
        peer_uid: peer.uid(),
    };
    if let Some(why) = problem(&facts) {
        bail!("not sending anything to {}: {why}", path.display());
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> SocketFacts {
        SocketFacts {
            socket_uid: 990,
            dir_uid: 990,
            dir_mode: 0o40750,
            peer_uid: 990,
        }
    }

    #[test]
    fn a_socket_in_the_server_users_private_directory_is_trusted() {
        assert_eq!(problem(&facts()), None);
        let root = SocketFacts {
            socket_uid: 0,
            dir_uid: 0,
            dir_mode: 0o40755,
            peer_uid: 0,
        };
        assert_eq!(problem(&root), None, "a server running as root in its own directory");
        let setgid = SocketFacts {
            dir_mode: 0o42750,
            ..facts()
        };
        assert_eq!(
            problem(&setgid),
            None,
            "a setgid directory that shares the socket's group"
        );
    }

    #[test]
    fn sockets_others_could_have_planted_are_refused() {
        let shared = SocketFacts {
            dir_uid: 0,
            dir_mode: 0o41777,
            socket_uid: 0,
            peer_uid: 0,
        };
        assert!(problem(&shared).is_some(), "a world-writable directory like /tmp");
        let foreign = SocketFacts {
            socket_uid: 2000,
            peer_uid: 2000,
            ..facts()
        };
        assert!(
            problem(&foreign).is_some(),
            "someone else's socket in the server's directory"
        );
        let impostor = SocketFacts {
            peer_uid: 2000,
            ..facts()
        };
        assert!(problem(&impostor).is_some(), "another user listening behind the file");
    }

    #[test]
    fn group_writable_directories_are_refused_even_with_the_sticky_bit() {
        for mode in [0o40770, 0o41770, 0o42770, 0o40730] {
            let group = SocketFacts {
                dir_mode: mode,
                ..facts()
            };
            assert!(problem(&group).is_some(), "{mode:o}");
        }
        // The audit's case: a root-owned group-writable directory with a member's socket in it.
        let planted = SocketFacts {
            socket_uid: 2000,
            dir_uid: 0,
            dir_mode: 0o40770,
            peer_uid: 2000,
        };
        assert!(problem(&planted).is_some());
    }

    #[test]
    fn a_socket_not_owned_by_its_directory_owner_is_refused_even_in_a_root_directory() {
        let other = SocketFacts {
            socket_uid: 2000,
            dir_uid: 0,
            dir_mode: 0o40755,
            peer_uid: 2000,
        };
        assert!(problem(&other).is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_checked_connection_is_returned_and_others_are_refused() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().context("dir")?;
        // The default mode follows the umask, which may leave the group able to write.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let path = dir.path().join("unseal.sock");
        let _listener = tokio::net::UnixListener::bind(&path).context("bind")?;
        let stream = connect(&path).await?;
        assert!(stream.peer_cred().is_ok());

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).context("chmod")?;
        let error = connect(&path).await.err().context("expected refusal")?;
        assert!(error.to_string().contains("group"), "{error}");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let file = dir.path().join("plain");
        std::fs::write(&file, b"x").context("write")?;
        assert!(connect(&file).await.is_err(), "not a socket");
        Ok(())
    }
}
