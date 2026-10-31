//! Reading and writing key material on disk: owner-only permissions, bounded reads and no
//! symlinks where they are not wanted.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// The most a key, passphrase or secret file may hold.
pub const SECRET_FILE_LIMIT: u64 = 4096;
/// The most a configuration or PEM file may hold.
pub const TEXT_FILE_LIMIT: u64 = 1024 * 1024;

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}

/// Opens for reading without blocking on a FIFO, optionally refusing a symlink at the last step.
fn reading(follow_symlinks: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let nofollow = if follow_symlinks { 0 } else { libc::O_NOFOLLOW };
        options.custom_flags(libc::O_NONBLOCK | nofollow);
    }
    #[cfg(not(unix))]
    let _ = follow_symlinks;
    options
}

fn read_bounded(path: &Path, limit: u64, follow_symlinks: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    let file = reading(follow_symlinks).open(path)?;
    // Checked on the open handle, so a swap after the check cannot change what is read.
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    let mut contents = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("larger than {limit} bytes"),
        ));
    }
    Ok(contents)
}

/// Reads a regular file of at most `limit` bytes, following symlinks, because Kubernetes mounts
/// secrets through them.
pub fn read_limited(path: &Path, limit: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    read_bounded(path, limit, true)
}

/// Reads a key file of at most [`SECRET_FILE_LIMIT`] bytes, refusing a symlink at its final
/// component and anything that is not a regular file.
pub fn read_private(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    read_bounded(path, SECRET_FILE_LIMIT, false)
}

/// Flushes the directory entry, so a new file survives a power cut.
pub fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn write_all(mut file: File, contents: &[u8]) -> io::Result<()> {
    file.write_all(contents)?;
    file.sync_all()
}

/// Creates `path` with mode 0600, failing if anything, including a symlink, is already there.
pub fn write_new_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let file = private_options().write(true).create_new(true).open(path)?;
    if let Err(error) = write_all(file, contents) {
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    sync_parent(path)
}

/// Creates or replaces `path` with mode 0600, refusing to write through a symlink.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let file = private_options().write(true).create(true).truncate(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    write_all(file, contents)
}

fn random_suffix() -> io::Result<String> {
    let mut bytes = [0u8; 8];
    sekret_core::crypto::fill_random(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(hex::encode(bytes))
}

/// Writes a new owner-only file under a random name beside `path`, then renames it into place,
/// so readers never see a partial file and nothing can be planted at the temporary name.
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".{}.tmp", random_suffix()?));
    let temp = path.with_file_name(temp_name);
    write_new_private(&temp, contents)?;
    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    sync_parent(path)
}

/// Creates `path` and its missing parents with mode 0700.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Removes `path`; a file that is already gone is not an error.
pub fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Removes a remember file, but only a regular file the size of a device key, so a misconfigured
/// path can never delete something else. A symlink there is removed itself, never its target.
pub fn remove_device_key_file(path: &Path) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if meta.file_type().is_symlink() {
        return remove_if_present(path);
    }
    if !meta.is_file() || !sekret_core::seal::DeviceKey::plausible_file_len(meta.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} does not look like a remember file; not deleting it", path.display()),
        ));
    }
    remove_if_present(path)
}

/// Whether a new file could be created at `path`: nothing is there and the directory is writable.
pub fn can_create(path: &Path) -> io::Result<()> {
    if path.symlink_metadata().is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", path.display()),
        ));
    }
    let parent: PathBuf = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let probe = parent.join(format!(".sekret-probe-{}", random_suffix()?));
    write_new_private(&probe, b"")?;
    remove_if_present(&probe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn new_private_files_are_owner_only_and_never_overwritten() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("key");
        write_new_private(&path, b"one").context("write")?;
        assert!(write_new_private(&path, b"two").is_err());
        assert_eq!(read_private(&path).context("read")?.as_slice(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).context("meta")?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        write_private(&path, b"three").context("overwrite")?;
        assert_eq!(read_private(&path).context("read")?.as_slice(), b"three");
        remove_if_present(&path).context("remove")?;
        remove_if_present(&path).context("remove again")?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let target = dir.path().join("target");
        std::fs::write(&target, b"elsewhere").context("target")?;
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).context("link")?;
        assert!(read_private(&link).is_err());
        assert!(write_private(&link, b"x").is_err());
        assert!(write_new_private(&link, b"x").is_err());
        assert_eq!(std::fs::read(&target).context("read")?, b"elsewhere");
        assert_eq!(read_limited(&link, 100).context("follow")?.as_slice(), b"elsewhere");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn devices_fifos_and_oversized_files_are_refused() -> anyhow::Result<()> {
        assert!(read_limited(Path::new("/dev/zero"), SECRET_FILE_LIMIT).is_err());
        assert!(read_private(Path::new("/dev/zero")).is_err());
        let dir = tempfile::tempdir().context("dir")?;
        let fifo = dir.path().join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .context("mkfifo")?;
        if status.success() {
            assert!(read_private(&fifo).is_err());
            assert!(read_limited(&fifo, 10).is_err());
        }
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'a'; 4097]).context("big")?;
        assert!(read_private(&big).is_err());
        std::fs::write(&big, vec![b'a'; 4096]).context("big")?;
        assert_eq!(read_private(&big).context("read")?.len(), 4096);
        Ok(())
    }

    #[test]
    fn atomic_writes_replace_and_leave_no_temporary_files() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("credentials.toml");
        write_private_atomic(&path, b"one").context("first")?;
        write_private_atomic(&path, b"two").context("second")?;
        assert_eq!(std::fs::read(&path).context("read")?, b"two");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .context("list")?
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names.len(), 1);
        Ok(())
    }

    #[test]
    fn only_plausible_remember_files_are_deleted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let keep = dir.path().join("database.db");
        std::fs::write(&keep, vec![0u8; 8192]).context("db")?;
        assert!(remove_device_key_file(&keep).is_err());
        assert!(keep.exists());
        let key = dir.path().join("unlock.key");
        std::fs::write(&key, format!("{}\n", "A".repeat(44))).context("key")?;
        remove_device_key_file(&key).context("remove")?;
        assert!(!key.exists());
        remove_device_key_file(&key).context("already gone")?;
        assert!(remove_device_key_file(dir.path()).is_err());
        Ok(())
    }

    #[test]
    fn can_create_checks_absence_and_writability() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("token");
        can_create(&path).context("free")?;
        std::fs::write(&path, b"x").context("write")?;
        assert!(can_create(&path).is_err());
        assert!(can_create(&dir.path().join("missing/token")).is_err());
        Ok(())
    }
}
