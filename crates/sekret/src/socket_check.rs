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

/// Users the socket may belong to: root, the person running the CLI, and the server's user when
/// they name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owners {
    pub me: u32,
    pub expected: Option<u32>,
}

impl Owners {
    fn allow(self, uid: u32) -> bool {
        uid == 0 || uid == self.me || self.expected == Some(uid)
    }

    /// Who may own the directories above the socket: the allowed owners and the socket's owner.
    fn trusted_above(self, socket_uid: u32) -> Vec<u32> {
        let mut trusted = vec![0, self.me, socket_uid];
        trusted.extend(self.expected);
        trusted
    }
}

/// Why the socket cannot be trusted, or `None` when it can.
///
/// The server refuses to listen anywhere but a directory it owns that nobody else can write to,
/// so the directory's owner is the server's user: the socket and its listener must both be theirs,
/// and that user must be one the person expects.
pub fn problem(facts: &SocketFacts, owners: Owners) -> Option<&'static str> {
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
    if !owners.allow(facts.socket_uid) {
        return Some(
            "it belongs to a user other than root, you or the one named with --socket-owner; pass \
             --socket-owner USER, or set SEKRET_SOCKET_OWNER, naming the user sekret runs as",
        );
    }
    None
}

/// The user id for a name or a number, as `--socket-owner` takes it.
#[cfg(unix)]
pub fn user_id(name: &str) -> anyhow::Result<u32> {
    if let Ok(uid) = name.parse::<u32>() {
        return Ok(uid);
    }
    let c_name = std::ffi::CString::new(name).context("a user name cannot hold a NUL byte")?;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to live memory of the stated size for the whole call.
    let code = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    // Some C libraries report a missing user with one of these rather than a null result.
    let missing = [0, libc::ENOENT, libc::ESRCH, libc::EBADF, libc::EPERM].contains(&code);
    if !missing {
        bail!(
            "looking up the user {name:?}: {}",
            std::io::Error::from_raw_os_error(code)
        );
    }
    if result.is_null() {
        bail!("there is no user called {name:?}");
    }
    // SAFETY: getpwnam_r succeeded, so `result` points at the filled-in `entry`.
    Ok(unsafe { (*result).pw_uid })
}

#[cfg(not(unix))]
pub fn user_id(_name: &str) -> anyhow::Result<u32> {
    bail!("host sockets need a Unix host")
}

#[cfg(unix)]
fn file_facts(path: &Path) -> anyhow::Result<(std::fs::Metadata, std::fs::Metadata)> {
    use std::os::unix::fs::FileTypeExt;
    let socket = std::fs::symlink_metadata(path).with_context(|| format!("{}", path.display()))?;
    if !socket.file_type().is_socket() {
        bail!("{} is not a socket", path.display());
    }
    let parent = sekret_server::host_socket::parent_of(path);
    let dir = std::fs::metadata(parent).with_context(|| format!("{}", parent.display()))?;
    Ok((socket, dir))
}

/// Connects to the socket and returns the connection once it passes the checks. Callers send
/// over this stream rather than reconnecting by path, which could reach a different listener.
#[cfg(unix)]
pub async fn connect(path: &Path, expected_owner: Option<u32>) -> anyhow::Result<tokio::net::UnixStream> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
    let owners = Owners {
        me: unsafe { libc::geteuid() },
        expected: expected_owner,
    };
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
    if let Some(why) = problem(&facts, owners) {
        bail!("not sending anything to {}: {why}", path.display());
    }
    // Whoever can rearrange a directory further up can swap in a directory of their own.
    let parent = sekret_server::host_socket::parent_of(path);
    let above = sekret_server::host_socket::untrusted_ancestor(parent, &owners.trusted_above(facts.socket_uid))
        .with_context(|| format!("checking the directories above {}", path.display()))?;
    if let Some(why) = above {
        bail!("not sending anything to {}: {why}", path.display());
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Owners = Owners {
        me: 1000,
        expected: None,
    };
    const SERVER: Owners = Owners {
        me: 1000,
        expected: Some(990),
    };

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
        assert_eq!(problem(&facts(), SERVER), None);
        let root = SocketFacts {
            socket_uid: 0,
            dir_uid: 0,
            dir_mode: 0o40755,
            peer_uid: 0,
        };
        assert_eq!(
            problem(&root, ME),
            None,
            "a server running as root in its own directory"
        );
        let setgid = SocketFacts {
            dir_mode: 0o42750,
            ..facts()
        };
        assert_eq!(
            problem(&setgid, SERVER),
            None,
            "a setgid directory that shares the socket's group"
        );
        let mine = SocketFacts {
            socket_uid: 1000,
            dir_uid: 1000,
            peer_uid: 1000,
            ..facts()
        };
        assert_eq!(problem(&mine, ME), None, "a server the person runs themselves");
    }

    #[test]
    fn a_consistent_socket_of_an_unexpected_user_is_refused() {
        // The audit's case: socket, directory and listener all belong to the planter.
        let why = problem(&facts(), ME).unwrap_or_default();
        assert!(why.contains("--socket-owner"), "{why}");
        let other = Owners {
            me: 1000,
            expected: Some(991),
        };
        assert!(problem(&facts(), other).is_some(), "the named owner is someone else");
    }

    #[test]
    fn sockets_others_could_have_planted_are_refused() {
        let shared = SocketFacts {
            dir_uid: 0,
            dir_mode: 0o41777,
            socket_uid: 0,
            peer_uid: 0,
        };
        assert!(problem(&shared, ME).is_some(), "a world-writable directory like /tmp");
        let foreign = SocketFacts {
            socket_uid: 2000,
            peer_uid: 2000,
            ..facts()
        };
        assert!(
            problem(&foreign, SERVER).is_some(),
            "someone else's socket in the server's directory"
        );
        let impostor = SocketFacts {
            peer_uid: 2000,
            ..facts()
        };
        assert!(
            problem(&impostor, SERVER).is_some(),
            "another user listening behind the file"
        );
    }

    #[test]
    fn group_writable_directories_are_refused_even_with_the_sticky_bit() {
        for mode in [0o40770, 0o41770, 0o42770, 0o40730] {
            let group = SocketFacts {
                dir_mode: mode,
                ..facts()
            };
            assert!(problem(&group, SERVER).is_some(), "{mode:o}");
        }
        let planted = SocketFacts {
            socket_uid: 2000,
            dir_uid: 0,
            dir_mode: 0o40770,
            peer_uid: 2000,
        };
        assert!(problem(&planted, SERVER).is_some());
    }

    #[test]
    fn a_socket_not_owned_by_its_directory_owner_is_refused_even_in_a_root_directory() {
        let other = SocketFacts {
            socket_uid: 2000,
            dir_uid: 0,
            dir_mode: 0o40755,
            peer_uid: 2000,
        };
        assert!(problem(&other, SERVER).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn owners_are_named_or_numbered() -> anyhow::Result<()> {
        assert_eq!(user_id("root")?, 0);
        assert_eq!(user_id("990")?, 990);
        assert!(user_id("no-such-sekret-user").is_err());
        assert!(user_id("bad\0name").is_err());
        Ok(())
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
        let stream = connect(&path, None).await?;
        assert!(stream.peer_cred().is_ok());

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).context("chmod")?;
        let error = connect(&path, None).await.err().context("expected refusal")?;
        assert!(error.to_string().contains("group"), "{error}");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let file = dir.path().join("plain");
        std::fs::write(&file, b"x").context("write")?;
        assert!(connect(&file, None).await.is_err(), "not a socket");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_below_a_directory_others_can_write_is_refused() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let shared = tempfile::tempdir().context("dir")?;
        let own = shared.path().join("sekret");
        std::fs::create_dir(&own).context("mkdir")?;
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        let path = own.join("unseal.sock");
        let _listener = tokio::net::UnixListener::bind(&path).context("bind")?;

        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o775)).context("chmod")?;
        let error = connect(&path, None).await.err().context("expected refusal")?;
        assert!(error.to_string().contains("other users"), "{error}");

        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o1777)).context("chmod")?;
        connect(&path, None)
            .await
            .context("a sticky directory whose entry is ours is fine")?;
        std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o700)).context("chmod")?;
        connect(&path, None).await?;
        Ok(())
    }
}
