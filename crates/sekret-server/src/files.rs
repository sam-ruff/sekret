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

/// A file this process created, identified so it is only ever deleted while unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    pub path: PathBuf,
    device: u64,
    inode: u64,
    len: u64,
}

#[cfg(unix)]
fn identity(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn identity(_meta: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// Whether the process user owns the file described by `meta`.
#[cfg(unix)]
fn owned_by_us(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    meta.uid() == unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn owned_by_us(_meta: &std::fs::Metadata) -> bool {
    true
}

/// Creates `path` with mode 0600 and records what was written. A stale file of ours from an
/// earlier start is replaced; anything else there, such as a hard link to another file, a
/// symlink or someone else's file, is refused rather than truncated.
pub fn write_new_recorded(path: &Path, contents: &[u8]) -> io::Result<WrittenFile> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let ours = meta.is_file() && owned_by_us(&meta) && hard_links(&meta) == 1;
        if !ours {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a file sekret wrote; remove it or choose another path",
                    path.display()
                ),
            ));
        }
        remove_if_present(path)?;
    }
    write_new_private(path, contents)?;
    let meta = std::fs::symlink_metadata(path)?;
    let (device, inode) = identity(&meta);
    Ok(WrittenFile {
        path: path.to_path_buf(),
        device,
        inode,
        len: meta.len(),
    })
}

#[cfg(unix)]
fn hard_links(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(not(unix))]
fn hard_links(_meta: &std::fs::Metadata) -> u64 {
    1
}

/// Deletes a file written by [`write_new_recorded`] only if it is still the same file with the
/// same size; anything swapped in at the path is left alone.
pub fn remove_if_unchanged(written: &WrittenFile) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(&written.path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let same = meta.is_file() && identity(&meta) == (written.device, written.inode) && meta.len() == written.len;
    if !same {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} changed since sekret wrote it; not deleting it",
                written.path.display()
            ),
        ));
    }
    remove_if_present(&written.path)
}

/// Why a file holding key material or a passphrase is exposed: readable by the group or others,
/// or owned by another user. Symlinks are followed, as Kubernetes mounts secrets through them.
pub fn exposure(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "{} has mode {mode:o}, so other users can read it; run chmod 600 on it",
                path.display()
            ));
        }
    }
    if !owned_by_us(&meta) {
        return Some(format!(
            "{} is owned by another user, who can read or replace it",
            path.display()
        ));
    }
    None
}

const EPOCH_PREFIX: &str = "sekret-seal-epoch";
const MIGRATED: &str = "migrated";
/// More than a rotation in progress ever records.
const MAX_MARK_ROOTS: usize = 2;

/// An epoch mark: the highest seal configuration epoch seen, and the fingerprints of the root
/// keys the database may be under. Marks written before fingerprints were recorded name none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochMark {
    pub epoch: i64,
    pub roots: Vec<String>,
    /// A configuration recorded here had run the one-off migrations, so none may run again.
    pub migrated: bool,
}

fn is_fingerprint(text: &str) -> bool {
    (8..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// An epoch out of range was written by someone else, so the mark reads as damaged.
fn parse_mark(text: &str) -> Option<EpochMark> {
    let mut words = text.split_ascii_whitespace();
    if words.next()? != EPOCH_PREFIX {
        return None;
    }
    let epoch = words.next()?.parse().ok()?;
    if !sekret_core::seal::plausible_epoch(epoch) {
        return None;
    }
    let mut roots: Vec<String> = words.map(str::to_string).collect();
    let migrated = roots.last().is_some_and(|word| word == MIGRATED);
    if migrated {
        roots.pop();
    }
    if roots.len() > MAX_MARK_ROOTS || !roots.iter().all(|r| is_fingerprint(r)) {
        return None;
    }
    Some(EpochMark { epoch, roots, migrated })
}

/// The mark in a mark file, if there is one.
pub fn read_mark(path: &Path) -> io::Result<Option<EpochMark>> {
    let bytes = match read_private(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let text = std::str::from_utf8(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    parse_mark(text)
        .map(Some)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not an epoch mark"))
}

/// The epoch recorded in a mark file, if there is a readable one.
pub fn read_epoch(path: &Path) -> io::Result<Option<i64>> {
    Ok(read_mark(path)?.map(|mark| mark.epoch))
}

/// Replaces the mark file, owner-only and synced to disk.
pub fn write_mark(path: &Path, mark: &EpochMark) -> io::Result<()> {
    if mark.roots.len() > MAX_MARK_ROOTS || !mark.roots.iter().all(|r| is_fingerprint(r)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a root key fingerprint",
        ));
    }
    if !sekret_core::seal::plausible_epoch(mark.epoch) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the seal epoch is out of range",
        ));
    }
    let mut text = format!("{EPOCH_PREFIX} {}", mark.epoch);
    for root in &mark.roots {
        text.push(' ');
        text.push_str(root);
    }
    if mark.migrated {
        text.push(' ');
        text.push_str(MIGRATED);
    }
    text.push('\n');
    write_private_atomic(path, text.as_bytes())
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

    #[cfg(unix)]
    #[test]
    fn a_hard_link_at_a_written_path_is_never_truncated_or_deleted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let database = dir.path().join("sekret.db");
        std::fs::write(&database, b"SQLite format 3\0precious").context("db")?;
        let code = dir.path().join("setup-code");
        std::fs::hard_link(&database, &code).context("link")?;
        assert!(write_new_recorded(&code, b"ABCD-EFGH-JKMN\n").is_err());
        assert_eq!(std::fs::read(&database).context("read")?, b"SQLite format 3\0precious");
        let link = dir.path().join("code-link");
        std::os::unix::fs::symlink(&database, &link).context("symlink")?;
        assert!(write_new_recorded(&link, b"x").is_err());
        Ok(())
    }

    #[test]
    fn written_files_are_only_removed_while_unchanged() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("setup-code");
        std::fs::write(&path, b"stale code from an earlier start").context("stale")?;
        let written = write_new_recorded(&path, b"ABCD-EFGH-JKMN\n").context("write")?;
        assert_eq!(std::fs::read(&path).context("read")?, b"ABCD-EFGH-JKMN\n");
        remove_if_unchanged(&written).context("remove")?;
        assert!(!path.exists());
        remove_if_unchanged(&written).context("already gone")?;

        let written = write_new_recorded(&path, b"ABCD-EFGH-JKMN\n").context("write")?;
        std::fs::remove_file(&path).context("swap out")?;
        std::fs::write(&path, b"ABCD-EFGH-JKMN\n").context("swap in")?;
        assert!(remove_if_unchanged(&written).is_err(), "another file at the same path");
        assert!(path.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exposed_key_files_are_reported_through_symlinks() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().context("dir")?;
        let key = dir.path().join("root.key");
        std::fs::write(&key, b"k").context("key")?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).context("chmod")?;
        assert_eq!(exposure(&key), None);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).context("chmod")?;
        let link = dir.path().join("mounted");
        std::os::unix::fs::symlink(&key, &link).context("symlink")?;
        assert!(
            exposure(&link).is_some_and(|w| w.contains("644")),
            "the target is checked"
        );
        assert_eq!(exposure(&dir.path().join("missing")), None);
        Ok(())
    }

    #[test]
    fn epoch_marks_round_trip() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("sekret.db.epoch");
        assert_eq!(read_epoch(&path).context("absent")?, None);
        let mark = EpochMark {
            epoch: 7,
            roots: vec!["0123456789abcdef".into()],
            migrated: false,
        };
        write_mark(&path, &mark).context("write")?;
        assert_eq!(read_epoch(&path).context("read")?, Some(7));
        assert_eq!(read_mark(&path).context("read")?, Some(mark));
        let migrated = EpochMark {
            epoch: 8,
            roots: vec!["0123456789abcdef".into()],
            migrated: true,
        };
        write_mark(&path, &migrated).context("write")?;
        assert_eq!(
            std::fs::read_to_string(&path).context("text")?,
            "sekret-seal-epoch 8 0123456789abcdef migrated\n"
        );
        assert_eq!(read_mark(&path).context("read")?, Some(migrated));
        std::fs::write(&path, b"garbage").context("garbage")?;
        assert!(read_epoch(&path).is_err());
        Ok(())
    }

    #[test]
    fn marks_with_an_implausible_epoch_read_as_damaged() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("sekret.db.epoch");
        let ceiling = sekret_core::seal::MAX_SEAL_EPOCH;
        for epoch in [i64::MAX, ceiling, -1] {
            std::fs::write(&path, format!("sekret-seal-epoch {epoch}\n")).context("write")?;
            assert!(read_mark(&path).is_err(), "{epoch}");
            let mark = EpochMark {
                epoch,
                roots: Vec::new(),
                migrated: false,
            };
            assert!(write_mark(&path, &mark).is_err(), "{epoch}");
        }
        std::fs::write(&path, format!("sekret-seal-epoch {}\n", ceiling - 1)).context("write")?;
        assert_eq!(read_epoch(&path).context("read")?, Some(ceiling - 1));
        Ok(())
    }

    #[test]
    fn marks_from_before_fingerprints_still_read() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("sekret.db.epoch");
        std::fs::write(&path, b"sekret-seal-epoch 12\n").context("old")?;
        assert_eq!(
            read_mark(&path).context("read")?,
            Some(EpochMark {
                epoch: 12,
                roots: Vec::new(),
                migrated: false,
            })
        );
        let rotating = EpochMark {
            epoch: 13,
            roots: vec!["0123456789abcdef".into(), "fedcba9876543210".into()],
            migrated: true,
        };
        write_mark(&path, &rotating).context("write")?;
        assert_eq!(read_mark(&path).context("read")?, Some(rotating));
        Ok(())
    }

    #[test]
    fn malformed_fingerprints_make_a_mark_unreadable() -> anyhow::Result<()> {
        let dir = tempfile::tempdir().context("dir")?;
        let path = dir.path().join("sekret.db.epoch");
        for bad in [
            "sekret-seal-epoch 3 not-hex\n",
            "sekret-seal-epoch 3 aaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbb cccccccccccccccc\n",
            "sekret-seal-epoch\n",
            "sekret-seal-epochs 3\n",
            "sekret-seal-epoch 3 migrated migrated\n",
            "sekret-seal-epoch 3 migrated aaaaaaaaaaaaaaaa\n",
        ] {
            std::fs::write(&path, bad).context("write")?;
            assert!(read_mark(&path).is_err(), "{bad}");
        }
        let injected = EpochMark {
            epoch: 1,
            roots: vec!["aa\nsekret-seal-epoch 0".into()],
            migrated: false,
        };
        assert!(write_mark(&path, &injected).is_err());
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
