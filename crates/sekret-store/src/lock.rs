//! One writer per database: the server holds this lock for its whole life, and admin commands
//! that write take it too, refusing to run while it is held.

use std::path::PathBuf;

use sqlx::Connection;

use crate::{StoreError, StoreResult, sqlite_file};

/// The advisory lock key on Postgres, the same for every sekret process.
const POSTGRES_LOCK_KEY: i64 = 0x5e_6b_72_65_74_00_00_01;

/// Held while alive; dropping it releases the lock.
pub enum InstanceLock {
    /// An in-memory database, which nothing else can open.
    Private,
    /// An exclusive `flock` on `<db>.lock`, released when the file closes.
    File(std::fs::File),
    /// A session-level advisory lock on a connection kept open for the purpose.
    Postgres(sqlx::AnyConnection),
}

impl std::fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InstanceLock::Private => "InstanceLock::Private",
            InstanceLock::File(_) => "InstanceLock::File",
            InstanceLock::Postgres(_) => "InstanceLock::Postgres",
        })
    }
}

fn held() -> StoreError {
    StoreError::Unsupported("another sekret server or admin command is using this database; stop it first".into())
}

/// The lock file beside a SQLite database.
pub fn lock_file(database: &std::path::Path) -> PathBuf {
    let mut name = database.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

#[cfg(unix)]
fn lock_sqlite(path: &std::path::Path) -> StoreResult<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| StoreError::Database(format!("{}: {e}", path.display())))?;
    // SAFETY: the descriptor belongs to `file`, which outlives the call.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        return Err(held());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn lock_sqlite(path: &std::path::Path) -> StoreResult<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| StoreError::Database(format!("{}: {e}", path.display())))
}

impl InstanceLock {
    /// Takes the lock without waiting, or fails when another process holds it.
    pub async fn acquire(database_url: &str) -> StoreResult<Self> {
        if database_url.starts_with("postgres") {
            sqlx::any::install_default_drivers();
            let mut conn = sqlx::AnyConnection::connect(database_url).await?;
            let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(POSTGRES_LOCK_KEY)
                .fetch_one(&mut conn)
                .await?;
            if !row.0 {
                return Err(held());
            }
            return Ok(InstanceLock::Postgres(conn));
        }
        match sqlite_file(database_url) {
            Some(path) => Ok(InstanceLock::File(lock_sqlite(&lock_file(&path))?)),
            None => Ok(InstanceLock::Private),
        }
    }

    pub fn is_held_error(error: &StoreError) -> bool {
        matches!(error, StoreError::Unsupported(message) if message.starts_with("another sekret server"))
    }
}
