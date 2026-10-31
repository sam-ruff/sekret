//! One writer per database: the server holds this lock for its whole life, and admin commands
//! that write take it too, refusing to run while it is held.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sqlx::Connection;

use crate::{StoreError, StoreResult, sqlite_file};

/// The advisory lock key on Postgres, the same for every sekret process.
const POSTGRES_LOCK_KEY: i64 = 0x5e_6b_72_65_74_00_00_01;
/// How often a waiting start tries the lock again.
const RETRY_EVERY: Duration = Duration::from_millis(500);
/// How long a check of a held lock may take before the lock counts as lost.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// Postgres closes the lock's session this soon after the sekret host stops answering, so a
/// replacement server is not locked out by a dead one.
const KEEPALIVES: [&str; 3] = [
    "SET tcp_keepalives_idle = 30",
    "SET tcp_keepalives_interval = 10",
    "SET tcp_keepalives_count = 3",
];

/// Held while alive; dropping it releases the lock.
pub enum InstanceLock {
    /// An in-memory database, which nothing else can open.
    Private,
    /// Exclusive `flock`s on `<canonical db>.lock` and on the database file itself, so a
    /// symlinked or hard-linked path to the same database meets the same lock.
    File {
        sidecar: std::fs::File,
        database: Option<std::fs::File>,
        path: PathBuf,
    },
    /// A session-level advisory lock on a connection kept open for the purpose.
    Postgres(Box<sqlx::PgConnection>),
}

impl std::fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InstanceLock::Private => "InstanceLock::Private",
            InstanceLock::File { .. } => "InstanceLock::File",
            InstanceLock::Postgres(_) => "InstanceLock::Postgres",
        })
    }
}

fn held() -> StoreError {
    StoreError::Unsupported("another sekret server or admin command is using this database; stop it first".into())
}

fn lost(why: impl std::fmt::Display) -> StoreError {
    StoreError::Database(format!("the database lock was lost: {why}"))
}

/// Where `path` really is: relative paths are taken from the working directory and the nearest
/// existing ancestor is resolved through any symlinks, so a file that does not exist yet still
/// compares correctly with one that does.
pub fn canonical_path(path: &Path) -> PathBuf {
    let absolute = match std::env::current_dir() {
        Ok(cwd) if path.is_relative() => cwd.join(path),
        _ => path.to_path_buf(),
    };
    let mut missing = Vec::new();
    let mut current = absolute.as_path();
    loop {
        if let Ok(real) = std::fs::canonicalize(current) {
            return missing.iter().rev().fold(real, |acc, part| acc.join(part));
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name.to_os_string());
                current = parent;
            }
            _ => return absolute,
        }
    }
}

/// The lock file beside a SQLite database, named after its canonical path.
pub fn lock_file(database: &Path) -> PathBuf {
    let mut name = canonical_path(database).into_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

#[cfg(unix)]
fn try_flock(file: &std::fs::File) -> StoreResult<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: the descriptor belongs to `file`, which outlives the call.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        return Err(held());
    }
    Ok(())
}

#[cfg(not(unix))]
fn try_flock(_file: &std::fs::File) -> StoreResult<()> {
    Ok(())
}

fn open_sidecar(path: &Path) -> StoreResult<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|e| StoreError::Database(format!("{}: {e}", path.display())))
}

/// The database file itself, created owner-only when `create` and missing, so every later
/// path to it meets the lock. Opened read-only otherwise: the lock is all it is for.
fn open_database(path: &Path, create: bool) -> StoreResult<Option<std::fs::File>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    if create {
        options.write(true).create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StoreError::Database(format!("{}: {error}", path.display()))),
    }
}

fn lock_sqlite(database: &Path, create: bool) -> StoreResult<InstanceLock> {
    let path = canonical_path(database);
    let sidecar = open_sidecar(&lock_file(&path))?;
    try_flock(&sidecar)?;
    let database = open_database(&path, create)?;
    if let Some(file) = &database {
        try_flock(file)?;
    }
    Ok(InstanceLock::File {
        sidecar,
        database,
        path,
    })
}

async fn lock_postgres(database_url: &str) -> StoreResult<InstanceLock> {
    let mut conn = sqlx::PgConnection::connect(database_url).await?;
    for statement in KEEPALIVES {
        if let Err(error) = sqlx::query(statement).execute(&mut conn).await {
            tracing::warn!(%error, statement, "could not set a keepalive on the database lock's connection");
        }
    }
    let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
        .bind(POSTGRES_LOCK_KEY)
        .fetch_one(&mut conn)
        .await?;
    if !row.0 {
        return Err(held());
    }
    Ok(InstanceLock::Postgres(Box::new(conn)))
}

/// Whether this session still holds the advisory lock. A pooler that hands the session to
/// someone else, or a restarted database, shows up here as a lost lock.
async fn postgres_still_held(conn: &mut sqlx::PgConnection) -> StoreResult<bool> {
    let high = (POSTGRES_LOCK_KEY >> 32) & 0xffff_ffff;
    let low = POSTGRES_LOCK_KEY & 0xffff_ffff;
    let row: (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() \
         AND granted AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 1)",
    )
    .bind(high)
    .bind(low)
    .fetch_one(conn)
    .await?;
    Ok(row.0)
}

#[cfg(unix)]
fn same_file(file: &std::fs::File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(open), Ok(named)) = (file.metadata(), std::fs::symlink_metadata(path)) else {
        return false;
    };
    (open.dev(), open.ino()) == (named.dev(), named.ino())
}

#[cfg(not(unix))]
fn same_file(_file: &std::fs::File, _path: &Path) -> bool {
    true
}

impl InstanceLock {
    /// Takes the lock without waiting, or fails when another process holds it.
    pub async fn acquire(database_url: &str) -> StoreResult<Self> {
        if database_url.starts_with("postgres") {
            return lock_postgres(database_url).await;
        }
        match sqlite_file(database_url) {
            Some(path) => lock_sqlite(&path, database_url.contains("mode=rwc")),
            None => Ok(InstanceLock::Private),
        }
    }

    /// Takes the lock, trying again for up to `wait` while another process holds it, so a
    /// restart can overlap briefly with the server it replaces.
    pub async fn acquire_within(database_url: &str, wait: Duration) -> StoreResult<Self> {
        let deadline = Instant::now() + wait;
        let mut announced = false;
        loop {
            match Self::acquire(database_url).await {
                Err(error) if Self::is_held_error(&error) && Instant::now() < deadline => {
                    if !announced {
                        tracing::info!(
                            seconds = wait.as_secs(),
                            "the database is locked by another process; waiting"
                        );
                        announced = true;
                    }
                    tokio::time::sleep(RETRY_EVERY).await;
                }
                outcome => return outcome,
            }
        }
    }

    /// Confirms the lock is still held: the Postgres session is alive and owns the advisory
    /// lock, or the SQLite file at the path is still the one locked.
    pub async fn check(&mut self) -> StoreResult<()> {
        match self {
            InstanceLock::Private => Ok(()),
            InstanceLock::File { database, path, .. } => match database {
                Some(file) if !same_file(file, path) => Err(lost(format!("{} was replaced", path.display()))),
                _ => Ok(()),
            },
            InstanceLock::Postgres(conn) => {
                match tokio::time::timeout(CHECK_TIMEOUT, postgres_still_held(conn)).await {
                    Ok(Ok(true)) => Ok(()),
                    Ok(Ok(false)) => Err(lost("this session no longer holds the advisory lock")),
                    Ok(Err(error)) => Err(lost(error)),
                    Err(_) => Err(lost("the database did not answer")),
                }
            }
        }
    }

    pub fn is_held_error(error: &StoreError) -> bool {
        matches!(error, StoreError::Unsupported(message) if message.starts_with("another sekret server"))
    }
}
