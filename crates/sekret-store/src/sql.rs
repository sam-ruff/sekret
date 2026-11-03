use std::path::{Path, PathBuf};

use async_trait::async_trait;
use sekret_core::seal::{KdfParams, SealFlags, SealMode, UnlockPolicy, WrappedRootKey};
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Connection, Row};

use crate::models::*;
use crate::{INTEGRITY_KEY_META, Store, StoreError, StoreResult};

/// [`Store`] over sqlx's `Any` driver. SQL is kept portable between SQLite and Postgres.
#[derive(Clone)]
pub struct SqlStore {
    pool: AnyPool,
    postgres: bool,
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::Database(db) if db.is_unique_violation() || db.is_foreign_key_violation() => {
                StoreError::Conflict
            }
            sqlx::Error::RowNotFound => StoreError::NotFound,
            _ => StoreError::Database(error.to_string()),
        }
    }
}

impl From<sqlx::migrate::MigrateError> for StoreError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        StoreError::Database(error.to_string())
    }
}

fn corrupt(error: serde_json::Error) -> StoreError {
    StoreError::Corrupt(error.to_string())
}

fn to_json<T: serde::Serialize>(value: &T) -> StoreResult<String> {
    serde_json::to_string(value).map_err(corrupt)
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> StoreResult<T> {
    serde_json::from_str(text).map_err(corrupt)
}

fn flag(value: bool) -> i64 {
    i64::from(value)
}

fn get_flag(row: &AnyRow, column: &str) -> StoreResult<bool> {
    Ok(row.try_get::<i64, _>(column)? != 0)
}

fn principal(row: &AnyRow, column: &str) -> StoreResult<PrincipalKind> {
    let raw: String = row.try_get(column)?;
    PrincipalKind::parse(&raw).ok_or_else(|| StoreError::Corrupt(format!("unknown principal kind {raw}")))
}

fn user_from(row: &AnyRow) -> StoreResult<User> {
    Ok(User {
        id: row.try_get("id")?,
        subject: row.try_get("subject")?,
        email: row.try_get("email")?,
        name: row.try_get("name")?,
        groups: from_json(&row.try_get::<String, _>("groups")?)?,
        disabled: get_flag(row, "disabled")?,
        created_at: row.try_get("created_at")?,
        last_login_at: row.try_get("last_login_at")?,
    })
}

fn identity_from(row: &AnyRow) -> StoreResult<Identity> {
    Ok(Identity {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        token_ttl: row.try_get("token_ttl")?,
        token_max_ttl: row.try_get("token_max_ttl")?,
        trusted_cidrs: from_json(&row.try_get::<String, _>("trusted_cidrs")?)?,
        disabled: get_flag(row, "disabled")?,
        created_at: row.try_get("created_at")?,
    })
}

fn auth_method_from(row: &AnyRow) -> StoreResult<AuthMethod> {
    Ok(AuthMethod {
        identity_id: row.try_get("identity_id")?,
        kind: row.try_get("kind")?,
        config: from_json(&row.try_get::<String, _>("config")?)?,
        created_at: row.try_get("created_at")?,
        mac: row.try_get("mac")?,
    })
}

fn client_secret_from(row: &AnyRow) -> StoreResult<ClientSecret> {
    Ok(ClientSecret {
        id: row.try_get("id")?,
        identity_id: row.try_get("identity_id")?,
        description: row.try_get("description")?,
        secret_hash: row.try_get("secret_hash")?,
        prefix: row.try_get("prefix")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        uses_remaining: row.try_get("uses_remaining")?,
        revoked: get_flag(row, "revoked")?,
        last_used_at: row.try_get("last_used_at")?,
        mac: row.try_get("mac")?,
    })
}

fn token_from(row: &AnyRow) -> StoreResult<AccessToken> {
    Ok(AccessToken {
        id: row.try_get("id")?,
        token_hash: row.try_get("token_hash")?,
        kind: row.try_get("kind")?,
        principal_kind: principal(row, "principal_kind")?,
        principal_id: row.try_get("principal_id")?,
        description: row.try_get("description")?,
        source: row.try_get("source")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        max_expires_at: row.try_get("max_expires_at")?,
        revoked: get_flag(row, "revoked")?,
        last_used_at: row.try_get("last_used_at")?,
        auth_time: row.try_get("auth_time")?,
        mac: row.try_get("mac")?,
        sealed_hash: row.try_get("sealed_hash")?,
    })
}

fn project_from(row: &AnyRow) -> StoreResult<Project> {
    Ok(Project {
        id: row.try_get("id")?,
        slug: row.try_get("slug")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        wrapped_key: row.try_get("wrapped_key")?,
        created_at: row.try_get("created_at")?,
        logo_updated_at: row.try_get("logo_updated_at")?,
        secret_policy: row.try_get("secret_policy")?,
        secret_access: get_flag(row, "secret_access")?,
    })
}

fn grant_from(row: &AnyRow) -> StoreResult<SecretGrant> {
    Ok(SecretGrant {
        secret_id: row.try_get("secret_id")?,
        principal_kind: principal(row, "principal_kind")?,
        principal_id: row.try_get("principal_id")?,
        actions: from_json(&row.try_get::<String, _>("actions")?)?,
        created_at: row.try_get("created_at")?,
    })
}

fn role_from(row: &AnyRow) -> StoreResult<Role> {
    Ok(Role {
        id: row.try_get("id")?,
        project_id: row.try_get("project_id")?,
        slug: row.try_get("slug")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        rules: from_json(&row.try_get::<String, _>("rules")?)?,
        created_at: row.try_get("created_at")?,
    })
}

fn membership_from(row: &AnyRow) -> StoreResult<Membership> {
    Ok(Membership {
        project_id: row.try_get("project_id")?,
        principal_kind: principal(row, "principal_kind")?,
        principal_id: row.try_get("principal_id")?,
        role_slug: row.try_get("role_slug")?,
        created_at: row.try_get("created_at")?,
    })
}

fn environment_from(row: &AnyRow) -> StoreResult<Environment> {
    Ok(Environment {
        id: row.try_get("id")?,
        project_id: row.try_get("project_id")?,
        slug: row.try_get("slug")?,
        name: row.try_get("name")?,
        position: row.try_get("position")?,
        created_at: row.try_get("created_at")?,
    })
}

const SECRET_COLUMNS: &str = "s.id, s.project_id, s.environment_id, s.path, s.key, s.current_version, s.deleted, \
     s.created_at, s.updated_at, s.policy, s.restricted, s.access_epoch, v.version, v.value, v.comment, v.tags, v.deleted AS v_deleted, v.actor, \
     v.created_at AS v_created_at, v.generated";

const SECRET_JOIN: &str =
    "FROM secrets s JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version";

fn version_from(
    row: &AnyRow,
    secret_id: String,
    deleted_column: &str,
    created_column: &str,
) -> StoreResult<SecretVersion> {
    Ok(SecretVersion {
        secret_id,
        version: row.try_get("version")?,
        value: row.try_get("value")?,
        comment: row.try_get("comment")?,
        tags: from_json(&row.try_get::<String, _>("tags")?)?,
        deleted: get_flag(row, deleted_column)?,
        actor: row.try_get("actor")?,
        created_at: row.try_get(created_column)?,
        generated: get_flag(row, "generated")?,
    })
}

fn secret_with_version_from(row: &AnyRow) -> StoreResult<SecretWithVersion> {
    let secret = Secret {
        id: row.try_get("id")?,
        project_id: row.try_get("project_id")?,
        environment_id: row.try_get("environment_id")?,
        path: row.try_get("path")?,
        key: row.try_get("key")?,
        current_version: row.try_get("current_version")?,
        deleted: get_flag(row, "deleted")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        policy: row.try_get("policy")?,
        restricted: get_flag(row, "restricted")?,
        access_epoch: row.try_get("access_epoch")?,
    };
    let version = version_from(row, secret.id.clone(), "v_deleted", "v_created_at")?;
    Ok(SecretWithVersion { secret, version })
}

fn snapshot_from(row: &AnyRow) -> StoreResult<Snapshot> {
    Ok(Snapshot {
        id: row.try_get("id")?,
        environment_id: row.try_get("environment_id")?,
        entries: from_json(&row.try_get::<String, _>("entries")?)?,
        reason: row.try_get("reason")?,
        actor: row.try_get("actor")?,
        created_at: row.try_get("created_at")?,
    })
}

fn audit_from(row: &AnyRow) -> StoreResult<AuditEntry> {
    Ok(AuditEntry {
        id: row.try_get("id")?,
        created_at: row.try_get("created_at")?,
        actor_kind: row.try_get("actor_kind")?,
        actor_id: row.try_get("actor_id")?,
        actor_name: row.try_get("actor_name")?,
        action: row.try_get("action")?,
        project_id: row.try_get("project_id")?,
        environment: row.try_get("environment")?,
        path: row.try_get("path")?,
        secret_key: row.try_get("secret_key")?,
        detail: from_json(&row.try_get::<String, _>("detail")?)?,
        ip: row.try_get("ip")?,
        restricted: get_flag(row, "restricted")?,
    })
}

fn cli_login_from(row: &AnyRow) -> StoreResult<CliLogin> {
    Ok(CliLogin {
        device_code_hash: row.try_get("device_code_hash")?,
        user_code: row.try_get("user_code")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        approved_user_id: row.try_get("approved_user_id")?,
        consumed: get_flag(row, "consumed")?,
        requested_from_ip: row.try_get("requested_from_ip")?,
        user_agent: row.try_get("user_agent")?,
    })
}

/// Only ever given SQL assembled from constants and numbered placeholders, never user input.
fn audited(sql: String) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(sql)
}

enum SqlParam {
    Text(String),
    Int(i64),
}

/// WHERE clauses with numbered placeholders, bound in order.
#[derive(Default)]
struct Filter {
    clauses: Vec<String>,
    params: Vec<SqlParam>,
}

impl Filter {
    fn bind(&mut self, param: SqlParam) -> String {
        self.params.push(param);
        format!("${}", self.params.len())
    }

    fn equals(&mut self, column: &str, value: Option<&String>) {
        let Some(value) = value else {
            return;
        };
        let p = self.bind(SqlParam::Text(value.clone()));
        self.clauses.push(format!("{column} = {p}"));
    }

    fn where_clause(&self) -> String {
        if self.clauses.is_empty() {
            return "1 = 1".into();
        }
        self.clauses.join(" AND ")
    }

    fn apply<'q>(
        self,
        mut query: sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments>,
    ) -> sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments> {
        for param in self.params {
            query = match param {
                SqlParam::Text(value) => query.bind(value),
                SqlParam::Int(value) => query.bind(value),
            };
        }
        query
    }
}

/// A LIKE pattern that matches `text` literally, with `\` as the escape character.
fn like_literal(text: &str) -> String {
    text.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

fn audit_filter(query: &AuditQuery) -> Filter {
    let mut filter = Filter::default();
    filter.equals("project_id", query.project_id.as_ref());
    filter.equals("actor_id", query.actor_id.as_ref());
    filter.equals("actor_kind", query.actor_kind.as_ref());
    filter.equals("environment", query.environment.as_ref());
    filter.equals("secret_key", query.key.as_ref());
    if let Some(action) = query.action.as_deref().filter(|a| !a.is_empty()) {
        let p = filter.bind(SqlParam::Text(format!("{}%", like_literal(action))));
        filter.clauses.push(format!("action LIKE {p} ESCAPE '\\'"));
    }
    if let Some(path) = query.path.as_deref().filter(|p| !p.is_empty()) {
        let p = filter.bind(SqlParam::Text(format!("{}%", like_literal(path))));
        filter.clauses.push(format!("COALESCE(path, '') LIKE {p} ESCAPE '\\'"));
    }
    if let Some(since) = query.since {
        let p = filter.bind(SqlParam::Int(since));
        filter.clauses.push(format!("created_at >= {p}"));
    }
    if let Some(until) = query.until {
        let p = filter.bind(SqlParam::Int(until));
        filter.clauses.push(format!("created_at <= {p}"));
    }
    if let Some(visible) = &query.restricted_visible {
        let mut allowed = Vec::with_capacity(visible.len());
        for (environment, path, key) in visible {
            let (e, p, k) = (
                filter.bind(SqlParam::Text(environment.clone())),
                filter.bind(SqlParam::Text(path.clone())),
                filter.bind(SqlParam::Text(key.clone())),
            );
            allowed.push(format!(
                "(COALESCE(environment, '') = {e} AND COALESCE(path, '') = {p} AND COALESCE(secret_key, '') = {k})"
            ));
        }
        let clause = if allowed.is_empty() {
            "restricted = 0".to_string()
        } else {
            format!(
                "(restricted = 0 OR (action NOT IN ('secret.access', 'secret.write-refused') AND ({})))",
                allowed.join(" OR ")
            )
        };
        filter.clauses.push(clause);
    }
    if let Some(search) = query.search.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let p = filter.bind(SqlParam::Text(format!("%{}%", like_literal(&search.to_lowercase()))));
        let actors = ["action", "actor_name", "actor_id", "ip"];
        let secrets = [
            "COALESCE(environment, '')",
            "COALESCE(path, '')",
            "COALESCE(secret_key, '')",
        ];
        let mut columns = actors.to_vec();
        if !query.search_actors_only {
            columns.extend(secrets);
        }
        let any: Vec<String> = columns
            .iter()
            .map(|c| format!("LOWER({c}) LIKE {p} ESCAPE '\\'"))
            .collect();
        filter.clauses.push(format!("({})", any.join(" OR ")));
    }
    filter
}

fn seal_config_from(row: &AnyRow) -> StoreResult<SealConfig> {
    let raw_mode: String = row.try_get("mode")?;
    let mode =
        SealMode::parse(&raw_mode).ok_or_else(|| StoreError::Corrupt(format!("unknown seal mode {raw_mode}")))?;
    let raw_policy: String = row.try_get("unlock_policy")?;
    let unlock_policy = UnlockPolicy::parse(&raw_policy)
        .ok_or_else(|| StoreError::Corrupt(format!("unknown unlock policy {raw_policy}")))?;
    let ciphertext: Option<Vec<u8>> = row.try_get("wrapped_root_key")?;
    let salt: Option<Vec<u8>> = row.try_get("kdf_salt")?;
    let params: Option<String> = row.try_get("kdf_params")?;
    let wrapped = match (ciphertext, salt, params) {
        (Some(ciphertext), Some(salt), Some(params)) => Some(WrappedRootKey {
            salt,
            params: from_json::<KdfParams>(&params)?,
            ciphertext,
        }),
        (None, None, None) => None,
        _ => return Err(StoreError::Corrupt("partial wrapped root key".into())),
    };
    let bits: i64 = row.try_get("flags")?;
    let flags = SealFlags::from_bits(bits).ok_or_else(|| StoreError::Corrupt(format!("unknown seal flags {bits}")))?;
    Ok(SealConfig {
        flags,
        mode,
        wrapped,
        unlock_policy,
        remembered: row.try_get("remembered_root_key")?,
        epoch: row.try_get("epoch")?,
        mac: row.try_get("config_mac")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// The columns of a seal configuration, ready to bind.
struct SealColumns {
    mode: &'static str,
    ciphertext: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    params: Option<String>,
    policy: &'static str,
}

fn seal_columns(config: &SealConfig) -> StoreResult<SealColumns> {
    let wrapped = config.wrapped.as_ref();
    Ok(SealColumns {
        mode: config.mode.as_str(),
        ciphertext: wrapped.map(|w| w.ciphertext.clone()),
        salt: wrapped.map(|w| w.salt.clone()),
        params: wrapped.map(|w| to_json(&w.params)).transpose()?,
        policy: config.unlock_policy.as_str(),
    })
}

/// Rewrites what holds a replaced seal configuration on Postgres.
const VACUUM_SEAL: &str = "VACUUM FULL seal_config";
/// Rewrites everything a root key replacement re-encrypts on Postgres.
const VACUUM_REKEY: &str = "VACUUM FULL seal_config, projects, secret_versions, identity_auth_methods";

const UPDATE_SEAL: &str = "UPDATE seal_config SET mode = $1, wrapped_root_key = $2, kdf_salt = $3, kdf_params = $4, \
                           unlock_policy = $5, remembered_root_key = $6, updated_at = $7, epoch = $8, config_mac = $9, \
                           flags = $10 WHERE id = 1";

fn update_seal(config: &SealConfig) -> StoreResult<sqlx::query::Query<'static, sqlx::Any, sqlx::any::AnyArguments>> {
    let columns = seal_columns(config)?;
    Ok(sqlx::query(UPDATE_SEAL)
        .bind(columns.mode)
        .bind(columns.ciphertext)
        .bind(columns.salt)
        .bind(columns.params)
        .bind(columns.policy)
        .bind(config.remembered.clone())
        .bind(config.updated_at)
        .bind(config.epoch)
        .bind(config.mac.clone())
        .bind(config.flags.bits()))
}

fn collect<T>(rows: Vec<AnyRow>, map: fn(&AnyRow) -> StoreResult<T>) -> StoreResult<Vec<T>> {
    rows.iter().map(map).collect()
}

/// The file behind a SQLite URL, or `None` for Postgres and in-memory databases.
pub fn sqlite_file(url: &str) -> Option<PathBuf> {
    let rest = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:"))?;
    let path = rest.split('?').next().unwrap_or_default();
    if path.is_empty() || path.contains(":memory:") || url.contains("mode=memory") {
        return None;
    }
    Some(PathBuf::from(path))
}

/// Creates the database file owner-only before SQLite does, tightens one that is readable by
/// others, and warns about a parent directory others can write to.
fn prepare_sqlite_file(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => tighten(path)?,
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if let Ok(meta) = std::fs::metadata(parent)
            && meta.permissions().mode() & 0o022 != 0
        {
            tracing::warn!(
                directory = %parent.display(),
                "the database directory can be written by other users; restrict it to the sekret user"
            );
        }
    }
    Ok(())
}

/// Makes an existing database, WAL or shared-memory file owner-only.
fn tighten(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return Ok(());
        };
        if !meta.is_file() || meta.permissions().mode() & 0o077 == 0 {
            return Ok(());
        }
        tracing::warn!(path = %path.display(), "made the database file readable by its owner only");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Custom organisation roles called backup-reader before migrating; zero on a fresh or migrated database.
async fn custom_backup_reader_roles(pool: &AnyPool) -> i64 {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM roles WHERE project_id = '' AND slug = 'backup-reader'")
        .fetch_one(pool)
        .await;
    row.ok().and_then(|r| r.try_get::<i64, _>("n").ok()).unwrap_or(0)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// How [`SqlStore::open`] treats the database it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Open {
    /// Creates a SQLite file when the URL says `mode=rwc`, and applies migrations.
    Create,
    /// Only an existing database, with migrations applied. For commands that hold the instance lock.
    Migrate,
    /// Only an existing database already at this binary's schema, changed in no way. For commands
    /// that run beside a live server, which a migration could break.
    Exact,
}

fn migrator(postgres: bool) -> sqlx::migrate::Migrator {
    if postgres {
        sqlx::migrate!("./migrations/postgres")
    } else {
        sqlx::migrate!("./migrations/sqlite")
    }
}

/// The URL with SQLite's `mode=rwc` turned into `mode=rw`, so opening never creates a file.
pub fn without_create(url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let params: Vec<&str> = query
        .split('&')
        .map(|param| if param == "mode=rwc" { "mode=rw" } else { param })
        .collect();
    format!("{base}?{}", params.join("&"))
}

/// Refuses a database whose applied migrations differ from the ones this binary carries.
async fn check_schema(pool: &AnyPool, postgres: bool) -> StoreResult<()> {
    let expected: Vec<i64> = migrator(postgres).iter().map(|m| m.version).collect();
    let rows = sqlx::query("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(pool)
        .await
        .map_err(|_| StoreError::Unsupported("this is not a sekret database, or it was never started".into()))?;
    let applied = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("version"))
        .collect::<Result<Vec<_>, _>>()?;
    if applied == expected {
        return Ok(());
    }
    let shown = |versions: &[i64]| versions.last().map_or_else(|| "none".to_string(), i64::to_string);
    Err(StoreError::Unsupported(format!(
        "the database schema is at migration {} but this sekret {} expects {}; run the command with the \
         sekret version the server runs, or upgrade the server first",
        shown(&applied),
        sekret_core::VERSION,
        shown(&expected)
    )))
}

impl SqlStore {
    /// Connects and applies migrations. Accepts `sqlite://...`, `sqlite::memory:` or `postgres://...`.
    pub async fn connect(url: &str) -> StoreResult<Self> {
        Self::open(url, Open::Create).await
    }

    pub async fn open(url: &str, how: Open) -> StoreResult<Self> {
        sqlx::any::install_default_drivers();
        let postgres = url.starts_with("postgres");
        let in_memory = url.contains(":memory:") || url.contains("mode=memory");
        let file = if postgres { None } else { sqlite_file(url) };
        let url = match how {
            Open::Create => url.to_string(),
            Open::Migrate | Open::Exact => without_create(url),
        };
        let url = url.as_str();
        if let Some(path) = &file {
            match how {
                Open::Create if url.contains("mode=rwc") => {
                    prepare_sqlite_file(path).map_err(|e| StoreError::Database(format!("{}: {e}", path.display())))?
                }
                Open::Create => {}
                Open::Migrate | Open::Exact => {
                    if std::fs::symlink_metadata(path).is_err() {
                        return Err(StoreError::Database(format!("{}: no database there", path.display())));
                    }
                }
            }
        }
        // An in-memory SQLite database exists per connection, so it must not be pooled.
        let max = if in_memory {
            1
        } else if postgres {
            16
        } else {
            8
        };
        let pool = AnyPoolOptions::new()
            .max_connections(max)
            .min_connections(u32::from(in_memory))
            .after_connect(move |conn, _| {
                Box::pin(async move {
                    // Overwrites freed pages, so an old seal configuration does not linger in the file.
                    if !postgres {
                        sqlx::query("PRAGMA secure_delete = ON").execute(&mut *conn).await?;
                        // A checkpoint then shrinks the write-ahead log to nothing rather than
                        // leaving old pages in a file that is merely reused.
                        sqlx::query("PRAGMA journal_size_limit = 0").execute(&mut *conn).await?;
                    }
                    Ok(())
                })
            })
            .connect(url)
            .await?;
        if how == Open::Exact {
            check_schema(&pool, postgres).await?;
            return Ok(Self { pool, postgres });
        }
        let before = custom_backup_reader_roles(&pool).await;
        if !postgres && !in_memory {
            sqlx::query("PRAGMA journal_mode = WAL").execute(&pool).await?;
        }
        migrator(postgres).run(&pool).await?;
        let store = Self { pool, postgres };
        // Migration 0006 renames it when backup-reader-custom is free; this covers the rest.
        if let Some(slug) = store.rename_custom_role("backup-reader").await? {
            tracing::warn!(
                slug,
                "a custom organisation role used the slug backup-reader, which is now built in; \
                 it was renamed along with its bindings"
            );
        } else if before > 0 {
            tracing::warn!(
                "a custom organisation role used the slug backup-reader, which is now built in; \
                 it was renamed to backup-reader-custom along with its bindings"
            );
        }
        if let Some(path) = &file {
            for suffix in ["", "-wal", "-shm"] {
                tighten(&sibling(path, suffix)).map_err(|e| StoreError::Database(e.to_string()))?;
            }
        }
        Ok(store)
    }

    /// Moves a custom organisation role off a slug that is now built in, to the first free of
    /// `<slug>-custom`, `<slug>-custom-2` and so on, with its bindings. Returns the new slug
    /// when anything changed.
    async fn rename_custom_role(&self, slug: &str) -> StoreResult<Option<String>> {
        let mut tx = self.pool.begin().await?;
        let exists = sqlx::query("SELECT 1 FROM roles WHERE project_id = '' AND slug = $1")
            .bind(slug)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !exists {
            return Ok(None);
        }
        let mut target = format!("{slug}-custom");
        for n in 2.. {
            let taken = sqlx::query("SELECT 1 FROM roles WHERE project_id = '' AND slug = $1")
                .bind(&target)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
            if !taken {
                break;
            }
            target = format!("{slug}-custom-{n}");
        }
        sqlx::query("UPDATE org_bindings SET role_slug = $1 WHERE role_slug = $2")
            .bind(&target)
            .bind(slug)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE roles SET slug = $1 WHERE project_id = '' AND slug = $2")
            .bind(&target)
            .bind(slug)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(target))
    }

    /// Folds the write-ahead log back into the database and truncates it, so pages holding a
    /// replaced key or value do not linger beside the database. On Postgres, runs `vacuum`
    /// instead, so the dead rows holding old wraps and ciphertexts go with the old table files.
    /// Postgres keeps its own write-ahead log and archives; see the security docs for that.
    async fn scrub_log(&self, vacuum: &'static str) {
        if self.postgres {
            self.rewrite_tables(vacuum).await;
            return;
        }
        for _ in 0..5 {
            match sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .fetch_one(&self.pool)
                .await
            {
                Ok(row) if row.try_get::<i64, _>(0).unwrap_or(1) == 0 => return,
                Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                Err(error) => {
                    tracing::warn!(%error, "could not checkpoint the write-ahead log");
                    return;
                }
            }
        }
        tracing::warn!("the write-ahead log is busy, so old pages stay in it until the next checkpoint");
    }

    /// Best effort: it needs to own the tables, and briefly locks them.
    async fn rewrite_tables(&self, vacuum: &'static str) {
        if let Err(error) = sqlx::raw_sql(vacuum).execute(&self.pool).await {
            tracing::warn!(
                %error,
                "could not rewrite the tables after replacing keys, so old copies stay in dead rows until Postgres \
                 reuses the space; run VACUUM FULL on them as their owner"
            );
        }
    }

    /// `select` holding the rows it reads until the transaction ends. SQLite already runs one
    /// writer at a time, and has no such clause.
    fn locking(&self, select: &'static str) -> sqlx::AssertSqlSafe<String> {
        if self.postgres {
            return audited(format!("{select} FOR UPDATE"));
        }
        audited(select.to_string())
    }

    pub async fn ping(&self) -> StoreResult<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

#[async_trait]
impl Store for SqlStore {
    async fn get_meta(&self, key: &str) -> StoreResult<Option<String>> {
        let row = sqlx::query("SELECT value FROM meta WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.try_get("value")).transpose()?)
    }

    async fn set_meta(&self, key: &str, value: &str) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_meta(&self, key: &str, value: &str) -> StoreResult<bool> {
        let result = sqlx::query("INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING")
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn get_seal_config(&self) -> StoreResult<Option<SealConfig>> {
        let row = sqlx::query("SELECT * FROM seal_config WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(seal_config_from).transpose()
    }

    async fn init_seal_config(&self, config: SealConfig, fingerprint: &str) -> StoreResult<()> {
        let columns = seal_columns(&config)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO seal_config (id, mode, wrapped_root_key, kdf_salt, kdf_params, unlock_policy, \
             remembered_root_key, created_at, updated_at, epoch, config_mac, flags) \
             VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(columns.mode)
        .bind(columns.ciphertext)
        .bind(columns.salt)
        .bind(columns.params)
        .bind(columns.policy)
        .bind(config.remembered)
        .bind(config.created_at)
        .bind(config.updated_at)
        .bind(config.epoch)
        .bind(config.mac)
        .bind(config.flags.bits())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO meta (key, value) VALUES ('root_key_fingerprint', $1) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(fingerprint)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.scrub_log(VACUUM_SEAL).await;
        Ok(())
    }

    async fn update_seal_config(&self, config: SealConfig) -> StoreResult<()> {
        let result = update_seal(&config)?.execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        self.scrub_log(VACUUM_SEAL).await;
        Ok(())
    }

    async fn snapshot_to(&self, path: &str, seal: SealConfig) -> StoreResult<()> {
        if self.postgres {
            return Err(StoreError::Unsupported(
                "backups through the API need SQLite; use pg_dump for Postgres, whose secret values are already encrypted"
                    .into(),
            ));
        }
        // In-memory databases cannot be copied this way; they only exist in tests.
        sqlx::query("VACUUM INTO $1").bind(path).execute(&self.pool).await?;
        // The remembered wrap must never leave the host, so the copy gets the configuration it is
        // given and rewrites its pages. No journal, so the old row is not copied out on the way.
        let mut copy = sqlx::AnyConnection::connect(&format!("sqlite://{path}")).await?;
        sqlx::query("PRAGMA journal_mode = OFF").execute(&mut copy).await?;
        sqlx::query("PRAGMA secure_delete = ON").execute(&mut copy).await?;
        update_seal(&seal)?.execute(&mut copy).await?;
        sqlx::query("UPDATE seal_config SET remembered_root_key = NULL")
            .execute(&mut copy)
            .await?;
        sqlx::query("VACUUM").execute(&mut copy).await?;
        copy.close().await?;
        Ok(())
    }

    async fn upsert_user(&self, login: UserLogin) -> StoreResult<User> {
        let groups = to_json(&login.groups)?;
        sqlx::query(
            "INSERT INTO users (id, subject, email, name, groups, disabled, created_at, last_login_at) \
             VALUES ($1, $2, $3, $4, $5, 0, $6, $7) \
             ON CONFLICT (subject) DO UPDATE SET email = excluded.email, name = excluded.name, \
             groups = excluded.groups, last_login_at = excluded.last_login_at",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&login.subject)
        .bind(&login.email)
        .bind(&login.name)
        .bind(&groups)
        .bind(login.now)
        .bind(login.now)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query("SELECT * FROM users WHERE subject = $1")
            .bind(&login.subject)
            .fetch_one(&self.pool)
            .await?;
        user_from(&row)
    }

    async fn get_user(&self, id: &str) -> StoreResult<Option<User>> {
        let row = sqlx::query("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(user_from).transpose()
    }

    async fn list_users(&self) -> StoreResult<Vec<User>> {
        collect(
            sqlx::query("SELECT * FROM users ORDER BY email, name")
                .fetch_all(&self.pool)
                .await?,
            user_from,
        )
    }

    async fn set_user_disabled(&self, id: &str, disabled: bool) -> StoreResult<()> {
        let result = sqlx::query("UPDATE users SET disabled = $1 WHERE id = $2")
            .bind(flag(disabled))
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn create_identity(&self, identity: Identity) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO identities (id, name, description, token_ttl, token_max_ttl, trusted_cidrs, disabled, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&identity.id)
        .bind(&identity.name)
        .bind(&identity.description)
        .bind(identity.token_ttl)
        .bind(identity.token_max_ttl)
        .bind(to_json(&identity.trusted_cidrs)?)
        .bind(flag(identity.disabled))
        .bind(identity.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_identity(&self, id: &str) -> StoreResult<Option<Identity>> {
        let row = sqlx::query("SELECT * FROM identities WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(identity_from).transpose()
    }

    async fn list_identities(&self) -> StoreResult<Vec<Identity>> {
        collect(
            sqlx::query("SELECT * FROM identities ORDER BY name")
                .fetch_all(&self.pool)
                .await?,
            identity_from,
        )
    }

    async fn update_identity(&self, identity: Identity) -> StoreResult<()> {
        let result = sqlx::query(
            "UPDATE identities SET name = $1, description = $2, token_ttl = $3, token_max_ttl = $4, \
             trusted_cidrs = $5, disabled = $6 WHERE id = $7",
        )
        .bind(&identity.name)
        .bind(&identity.description)
        .bind(identity.token_ttl)
        .bind(identity.token_max_ttl)
        .bind(to_json(&identity.trusted_cidrs)?)
        .bind(flag(identity.disabled))
        .bind(&identity.id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn delete_identity(&self, id: &str) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM project_memberships WHERE principal_kind = 'identity' AND principal_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM org_bindings WHERE principal_kind = 'identity' AND principal_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM access_tokens WHERE principal_kind = 'identity' AND principal_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM client_secrets WHERE identity_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM identity_auth_methods WHERE identity_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM secret_grants WHERE principal_kind = 'identity' AND principal_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("DELETE FROM identities WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    async fn put_auth_method(&self, method: AuthMethod) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO identity_auth_methods (identity_id, kind, config, created_at, mac) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (identity_id, kind) DO UPDATE SET config = excluded.config, mac = excluded.mac",
        )
        .bind(&method.identity_id)
        .bind(&method.kind)
        .bind(to_json(&method.config)?)
        .bind(method.created_at)
        .bind(method.mac.clone())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_auth_method(&self, identity_id: &str, kind: &str) -> StoreResult<Option<AuthMethod>> {
        let row = sqlx::query("SELECT * FROM identity_auth_methods WHERE identity_id = $1 AND kind = $2")
            .bind(identity_id)
            .bind(kind)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(auth_method_from).transpose()
    }

    async fn list_auth_methods(&self, identity_id: &str) -> StoreResult<Vec<AuthMethod>> {
        let rows = sqlx::query("SELECT * FROM identity_auth_methods WHERE identity_id = $1 ORDER BY kind")
            .bind(identity_id)
            .fetch_all(&self.pool)
            .await?;
        collect(rows, auth_method_from)
    }

    async fn delete_auth_method(&self, identity_id: &str, kind: &str) -> StoreResult<()> {
        sqlx::query("DELETE FROM identity_auth_methods WHERE identity_id = $1 AND kind = $2")
            .bind(identity_id)
            .bind(kind)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_client_secret(&self, secret: ClientSecret) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO client_secrets (id, identity_id, description, secret_hash, prefix, created_at, expires_at, \
             uses_remaining, revoked, last_used_at, mac) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&secret.id)
        .bind(&secret.identity_id)
        .bind(&secret.description)
        .bind(&secret.secret_hash)
        .bind(&secret.prefix)
        .bind(secret.created_at)
        .bind(secret.expires_at)
        .bind(secret.uses_remaining)
        .bind(flag(secret.revoked))
        .bind(secret.last_used_at)
        .bind(secret.mac.clone())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn rekey_client_secret(&self, id: &str, old_hash: &str, new_hash: &str, mac: &str) -> StoreResult<bool> {
        let result =
            sqlx::query("UPDATE client_secrets SET secret_hash = $1, mac = $2 WHERE id = $3 AND secret_hash = $4")
                .bind(new_hash)
                .bind(mac)
                .bind(id)
                .bind(old_hash)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_unsigned_client_secrets(&self) -> StoreResult<Vec<ClientSecret>> {
        let rows = sqlx::query("SELECT * FROM client_secrets WHERE mac IS NULL AND revoked = 0 ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        collect(rows, client_secret_from)
    }

    async fn set_client_secret_mac(&self, id: &str, mac: &str) -> StoreResult<()> {
        sqlx::query("UPDATE client_secrets SET mac = $1 WHERE id = $2")
            .bind(mac)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_client_secrets(&self, identity_id: &str) -> StoreResult<Vec<ClientSecret>> {
        let rows = sqlx::query("SELECT * FROM client_secrets WHERE identity_id = $1 ORDER BY created_at DESC")
            .bind(identity_id)
            .fetch_all(&self.pool)
            .await?;
        collect(rows, client_secret_from)
    }

    async fn find_client_secret(&self, secret_hash: &str) -> StoreResult<Option<ClientSecret>> {
        let row = sqlx::query("SELECT * FROM client_secrets WHERE secret_hash = $1")
            .bind(secret_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(client_secret_from).transpose()
    }

    async fn consume_client_secret(&self, id: &str, now: i64) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE client_secrets SET last_used_at = $1, \
             uses_remaining = CASE WHEN uses_remaining IS NULL THEN NULL ELSE uses_remaining - 1 END \
             WHERE id = $2 AND revoked = 0 AND (uses_remaining IS NULL OR uses_remaining > 0)",
        )
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn revoke_client_secret(&self, identity_id: &str, id: &str) -> StoreResult<()> {
        let result = sqlx::query("UPDATE client_secrets SET revoked = 1 WHERE id = $1 AND identity_id = $2")
            .bind(id)
            .bind(identity_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn create_token(&self, token: AccessToken) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO access_tokens (id, token_hash, kind, principal_kind, principal_id, description, created_at, \
             expires_at, max_expires_at, revoked, last_used_at, source, auth_time, mac, sealed_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(&token.id)
        .bind(&token.token_hash)
        .bind(&token.kind)
        .bind(token.principal_kind.as_str())
        .bind(&token.principal_id)
        .bind(&token.description)
        .bind(token.created_at)
        .bind(token.expires_at)
        .bind(token.max_expires_at)
        .bind(flag(token.revoked))
        .bind(token.last_used_at)
        .bind(&token.source)
        .bind(token.auth_time)
        .bind(token.mac.clone())
        .bind(token.sealed_hash.clone())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_sealed_token(&self, sealed_hash: &str) -> StoreResult<Option<AccessToken>> {
        let row = sqlx::query("SELECT * FROM access_tokens WHERE sealed_hash = $1")
            .bind(sealed_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(token_from).transpose()
    }

    async fn rekey_token(&self, id: &str, old_hash: &str, new_hash: &str, mac: &str) -> StoreResult<bool> {
        let result =
            sqlx::query("UPDATE access_tokens SET token_hash = $1, mac = $2 WHERE id = $3 AND token_hash = $4")
                .bind(new_hash)
                .bind(mac)
                .bind(id)
                .bind(old_hash)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_unsigned_tokens(&self) -> StoreResult<Vec<AccessToken>> {
        let rows = sqlx::query("SELECT * FROM access_tokens WHERE mac IS NULL AND revoked = 0 ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        collect(rows, token_from)
    }

    async fn set_token_mac(&self, id: &str, mac: &str) -> StoreResult<()> {
        sqlx::query("UPDATE access_tokens SET mac = $1 WHERE id = $2")
            .bind(mac)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_unsigned_auth_methods(&self) -> StoreResult<Vec<AuthMethod>> {
        let rows = sqlx::query("SELECT * FROM identity_auth_methods WHERE mac IS NULL ORDER BY identity_id, kind")
            .fetch_all(&self.pool)
            .await?;
        collect(rows, auth_method_from)
    }

    async fn revoke_tokens_from_source(&self, source: &str) -> StoreResult<()> {
        if source.is_empty() {
            return Ok(());
        }
        sqlx::query("UPDATE access_tokens SET revoked = 1 WHERE source = $1")
            .bind(source)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn find_token(&self, token_hash: &str) -> StoreResult<Option<AccessToken>> {
        let row = sqlx::query("SELECT * FROM access_tokens WHERE token_hash = $1")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(token_from).transpose()
    }

    async fn touch_token(&self, id: &str, now: i64) -> StoreResult<()> {
        sqlx::query("UPDATE access_tokens SET last_used_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn extend_token(&self, id: &str, expires_at: i64) -> StoreResult<()> {
        sqlx::query("UPDATE access_tokens SET expires_at = $1 WHERE id = $2 AND revoked = 0 AND max_expires_at >= $3")
            .bind(expires_at)
            .bind(id)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_token(&self, id: &str) -> StoreResult<()> {
        sqlx::query("UPDATE access_tokens SET revoked = 1 WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revoke_principal_tokens(&self, kind: PrincipalKind, principal_id: &str) -> StoreResult<()> {
        sqlx::query("UPDATE access_tokens SET revoked = 1 WHERE principal_kind = $1 AND principal_id = $2")
            .bind(kind.as_str())
            .bind(principal_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_principal_tokens(&self, kind: PrincipalKind, principal_id: &str) -> StoreResult<Vec<AccessToken>> {
        let rows = sqlx::query(
            "SELECT * FROM access_tokens WHERE principal_kind = $1 AND principal_id = $2 ORDER BY created_at DESC",
        )
        .bind(kind.as_str())
        .bind(principal_id)
        .fetch_all(&self.pool)
        .await?;
        collect(rows, token_from)
    }

    async fn list_org_bindings(&self) -> StoreResult<Vec<Binding>> {
        let rows = sqlx::query("SELECT * FROM org_bindings ORDER BY principal_kind, principal_id")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(Binding {
                    principal_kind: principal(row, "principal_kind")?,
                    principal_id: row.try_get("principal_id")?,
                    role_slug: row.try_get("role_slug")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn add_org_binding(&self, binding: Binding) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO org_bindings (principal_kind, principal_id, role_slug, created_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT DO NOTHING",
        )
        .bind(binding.principal_kind.as_str())
        .bind(&binding.principal_id)
        .bind(&binding.role_slug)
        .bind(binding.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_org_binding(&self, kind: PrincipalKind, principal_id: &str, role_slug: &str) -> StoreResult<()> {
        sqlx::query("DELETE FROM org_bindings WHERE principal_kind = $1 AND principal_id = $2 AND role_slug = $3")
            .bind(kind.as_str())
            .bind(principal_id)
            .bind(role_slug)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_project(&self, project: Project, environments: Vec<Environment>) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO projects (id, slug, name, description, wrapped_key, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&project.id)
        .bind(&project.slug)
        .bind(&project.name)
        .bind(&project.description)
        .bind(&project.wrapped_key)
        .bind(project.created_at)
        .execute(&mut *tx)
        .await?;
        for env in environments {
            sqlx::query(
                "INSERT INTO environments (id, project_id, slug, name, position, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&env.id)
            .bind(&env.project_id)
            .bind(&env.slug)
            .bind(&env.name)
            .bind(env.position)
            .bind(env.created_at)
            .execute(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO folders (environment_id, path, created_at) VALUES ($1, '/', $2)")
                .bind(&env.id)
                .bind(env.created_at)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn get_project(&self, id_or_slug: &str) -> StoreResult<Option<Project>> {
        // An id match always wins over a slug that happens to equal it.
        let row = sqlx::query(
            "SELECT * FROM projects WHERE id = $1 OR slug = $2 \
             ORDER BY CASE WHEN id = $3 THEN 0 ELSE 1 END LIMIT 1",
        )
        .bind(id_or_slug)
        .bind(id_or_slug)
        .bind(id_or_slug)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(project_from).transpose()
    }

    async fn list_projects(&self) -> StoreResult<Vec<Project>> {
        collect(
            sqlx::query("SELECT * FROM projects ORDER BY name")
                .fetch_all(&self.pool)
                .await?,
            project_from,
        )
    }

    async fn set_project_logo(&self, project_id: &str, logo: Option<ProjectLogo>, now: i64) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM project_logos WHERE project_id = $1")
            .bind(project_id)
            .execute(&mut *tx)
            .await?;
        let updated_at = match logo {
            Some(logo) => {
                sqlx::query("INSERT INTO project_logos (project_id, content_type, data) VALUES ($1, $2, $3)")
                    .bind(project_id)
                    .bind(logo.content_type)
                    .bind(logo.data)
                    .execute(&mut *tx)
                    .await?;
                Some(now)
            }
            None => None,
        };
        let result = sqlx::query("UPDATE projects SET logo_updated_at = $1 WHERE id = $2")
            .bind(updated_at)
            .bind(project_id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    async fn set_project_policy(&self, project_id: &str, policy: Option<String>) -> StoreResult<()> {
        let result = sqlx::query("UPDATE projects SET secret_policy = $1 WHERE id = $2")
            .bind(policy)
            .bind(project_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_secret_policy(&self, secret_id: &str, policy: Option<String>) -> StoreResult<()> {
        let result = sqlx::query("UPDATE secrets SET policy = $1 WHERE id = $2")
            .bind(policy)
            .bind(secret_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn set_project_secret_access(&self, project_id: &str, enabled: bool) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        // Holding the project row orders this against restricting a secret in the same project.
        sqlx::query(self.locking("SELECT secret_access FROM projects WHERE id = $1"))
            .bind(project_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        if !enabled {
            let restricted: i64 =
                sqlx::query("SELECT COUNT(*) AS n FROM secrets WHERE project_id = $1 AND restricted = 1")
                    .bind(project_id)
                    .fetch_one(&mut *tx)
                    .await?
                    .try_get("n")?;
            if restricted > 0 {
                return Err(StoreError::Conflict);
            }
            // Lists left on open secrets would come back to life if the setting returned.
            sqlx::query("DELETE FROM secret_grants WHERE secret_id IN (SELECT id FROM secrets WHERE project_id = $1)")
                .bind(project_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE secrets SET access_epoch = access_epoch + 1 WHERE project_id = $1")
                .bind(project_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE projects SET secret_access = $1 WHERE id = $2")
            .bind(flag(enabled))
            .bind(project_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn count_restricted_secrets(&self, project_id: &str) -> StoreResult<i64> {
        Ok(
            sqlx::query("SELECT COUNT(*) AS n FROM secrets WHERE project_id = $1 AND restricted = 1")
                .bind(project_id)
                .fetch_one(&self.pool)
                .await?
                .try_get("n")?,
        )
    }

    async fn list_restricted_secrets(&self, project_id: &str) -> StoreResult<Vec<RestrictedSecret>> {
        let rows = sqlx::query(
            "SELECT s.id, e.slug, s.path, s.key, s.deleted, v.tags FROM secrets s \
             JOIN environments e ON e.id = s.environment_id \
             JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version \
             WHERE s.project_id = $1 AND s.restricted = 1 ORDER BY e.position, e.slug, s.path, s.key",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(RestrictedSecret {
                    secret_id: row.try_get("id")?,
                    environment: row.try_get("slug")?,
                    path: row.try_get("path")?,
                    key: row.try_get("key")?,
                    deleted: get_flag(row, "deleted")?,
                    tags: from_json(&row.try_get::<String, _>("tags")?)?,
                })
            })
            .collect()
    }

    async fn list_project_grants(&self, project_id: &str) -> StoreResult<Vec<SecretGrant>> {
        collect(
            sqlx::query(
                "SELECT g.* FROM secret_grants g JOIN secrets s ON s.id = g.secret_id WHERE s.project_id = $1 \
                 ORDER BY g.secret_id, g.principal_kind, g.principal_id",
            )
            .bind(project_id)
            .fetch_all(&self.pool)
            .await?,
            grant_from,
        )
    }

    async fn environment_access(&self, environment_id: &str) -> StoreResult<EnvironmentAccess> {
        // One statement, so the epochs and the entries come from the same moment.
        let rows = sqlx::query(
            "SELECT s.id AS sid, s.access_epoch, g.principal_kind, g.principal_id, g.actions, g.created_at \
             FROM secrets s LEFT JOIN secret_grants g ON g.secret_id = s.id \
             WHERE s.environment_id = $1 AND s.restricted = 1",
        )
        .bind(environment_id)
        .fetch_all(&self.pool)
        .await?;
        let mut access = EnvironmentAccess::default();
        for row in &rows {
            let secret_id: String = row.try_get("sid")?;
            access.epochs.insert(secret_id.clone(), row.try_get("access_epoch")?);
            let Some(actions) = row.try_get::<Option<String>, _>("actions")? else {
                continue;
            };
            let kind: String = row.try_get("principal_kind")?;
            access.grants.push(SecretGrant {
                secret_id,
                principal_kind: PrincipalKind::parse(&kind)
                    .ok_or_else(|| StoreError::Corrupt(format!("unknown principal kind {kind}")))?,
                principal_id: row.try_get("principal_id")?,
                actions: from_json(&actions)?,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(access)
    }

    async fn previous_snapshot(&self, snapshot: &Snapshot) -> StoreResult<Option<Snapshot>> {
        let row = sqlx::query(
            "SELECT * FROM snapshots WHERE environment_id = $1 AND (created_at < $2 OR (created_at = $3 AND id < $4)) \
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(&snapshot.environment_id)
        .bind(snapshot.created_at)
        .bind(snapshot.created_at)
        .bind(&snapshot.id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(snapshot_from).transpose()
    }

    async fn list_environment_grants(&self, environment_id: &str) -> StoreResult<Vec<SecretGrant>> {
        collect(
            sqlx::query(
                "SELECT g.* FROM secret_grants g JOIN secrets s ON s.id = g.secret_id WHERE s.environment_id = $1 \
                 ORDER BY g.secret_id, g.principal_kind, g.principal_id",
            )
            .bind(environment_id)
            .fetch_all(&self.pool)
            .await?,
            grant_from,
        )
    }

    async fn list_secret_grants(&self, secret_id: &str) -> StoreResult<Vec<SecretGrant>> {
        collect(
            sqlx::query("SELECT * FROM secret_grants WHERE secret_id = $1 ORDER BY principal_kind, principal_id")
                .bind(secret_id)
                .fetch_all(&self.pool)
                .await?,
            grant_from,
        )
    }

    async fn update_secret_access(&self, change: AccessChange) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        let project_id: String = sqlx::query("SELECT project_id FROM secrets WHERE id = $1")
            .bind(&change.secret_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?
            .try_get("project_id")?;
        let enabled = sqlx::query(self.locking("SELECT secret_access FROM projects WHERE id = $1"))
            .bind(&project_id)
            .fetch_one(&mut *tx)
            .await?;
        let widens = change.restricted == Some(true) || !change.grant.is_empty();
        if widens && !get_flag(&enabled, "secret_access")? {
            return Err(StoreError::Conflict);
        }
        if let Some(restricted) = change.restricted {
            sqlx::query("UPDATE secrets SET restricted = $1 WHERE id = $2")
                .bind(flag(restricted))
                .bind(&change.secret_id)
                .execute(&mut *tx)
                .await?;
        }
        if change.restricted == Some(false) {
            sqlx::query("DELETE FROM secret_grants WHERE secret_id = $1")
                .bind(&change.secret_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE secrets SET access_epoch = access_epoch + 1 WHERE id = $1")
            .bind(&change.secret_id)
            .execute(&mut *tx)
            .await?;
        for (kind, id) in &change.revoke {
            sqlx::query("DELETE FROM secret_grants WHERE secret_id = $1 AND principal_kind = $2 AND principal_id = $3")
                .bind(&change.secret_id)
                .bind(kind.as_str())
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        for grant in &change.grant {
            if grant.secret_id != change.secret_id {
                return Err(StoreError::Corrupt("a grant names another secret".into()));
            }
            sqlx::query("DELETE FROM secret_grants WHERE secret_id = $1 AND principal_kind = $2 AND principal_id = $3")
                .bind(&grant.secret_id)
                .bind(grant.principal_kind.as_str())
                .bind(&grant.principal_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO secret_grants (secret_id, principal_kind, principal_id, actions, created_at) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&grant.secret_id)
            .bind(grant.principal_kind.as_str())
            .bind(&grant.principal_id)
            .bind(to_json(&grant.actions)?)
            .bind(grant.created_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn get_project_logo(&self, project_id: &str) -> StoreResult<Option<ProjectLogo>> {
        let row = sqlx::query("SELECT content_type, data FROM project_logos WHERE project_id = $1")
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| {
            Ok(ProjectLogo {
                content_type: r.try_get("content_type")?,
                data: r.try_get("data")?,
            })
        })
        .transpose()
    }

    async fn update_project(&self, id: &str, name: &str, description: &str) -> StoreResult<()> {
        let result = sqlx::query("UPDATE projects SET name = $1, description = $2 WHERE id = $3")
            .bind(name)
            .bind(description)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn delete_project(&self, id: &str) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM project_logos WHERE project_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE project_id = $1)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM secret_grants WHERE secret_id IN (SELECT id FROM secrets WHERE project_id = $1)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM secrets WHERE project_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM snapshots WHERE environment_id IN (SELECT id FROM environments WHERE project_id = $1)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM folders WHERE environment_id IN (SELECT id FROM environments WHERE project_id = $1)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM environments WHERE project_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM project_memberships WHERE project_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM roles WHERE project_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    async fn list_encrypted_values(&self, project_id: &str) -> StoreResult<Vec<EncryptedValue>> {
        let rows = sqlx::query(
            "SELECT v.secret_id, v.version, v.value FROM secret_versions v JOIN secrets s ON s.id = v.secret_id \
             WHERE s.project_id = $1 AND v.value IS NOT NULL ORDER BY v.secret_id, v.version",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(EncryptedValue {
                    secret_id: row.try_get("secret_id")?,
                    version: row.try_get("version")?,
                    value: row.try_get("value")?,
                })
            })
            .collect()
    }

    async fn replace_wrapped_keys(&self, rekey: Rekey) -> StoreResult<()> {
        let Rekey {
            keys,
            values,
            auth_methods,
            fingerprint,
            seal,
            integrity_key,
            revoke_credentials,
        } = rekey;
        let mut tx = self.pool.begin().await?;
        if let Some(config) = seal {
            let result = update_seal(&config)?.execute(&mut *tx).await?;
            if result.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
        }
        for (id, key) in keys {
            sqlx::query("UPDATE projects SET wrapped_key = $1 WHERE id = $2")
                .bind(key)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        for value in values {
            let result = sqlx::query("UPDATE secret_versions SET value = $1 WHERE secret_id = $2 AND version = $3")
                .bind(value.value)
                .bind(&value.secret_id)
                .bind(value.version)
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() == 0 {
                return Err(StoreError::Conflict);
            }
        }
        for method in auth_methods {
            sqlx::query("UPDATE identity_auth_methods SET config = $1, mac = $2 WHERE identity_id = $3 AND kind = $4")
                .bind(to_json(&method.config)?)
                .bind(method.mac.clone())
                .bind(&method.identity_id)
                .bind(&method.kind)
                .execute(&mut *tx)
                .await?;
        }
        if let Some(wrapped) = integrity_key {
            sqlx::query(
                "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            )
            .bind(INTEGRITY_KEY_META)
            .bind(wrapped)
            .execute(&mut *tx)
            .await?;
        }
        if revoke_credentials {
            for statement in [
                "UPDATE access_tokens SET revoked = 1 WHERE revoked = 0",
                "UPDATE client_secrets SET revoked = 1 WHERE revoked = 0",
                "UPDATE cli_logins SET consumed = 1 WHERE consumed = 0",
            ] {
                sqlx::query(statement).execute(&mut *tx).await?;
            }
        }
        sqlx::query(
            "INSERT INTO meta (key, value) VALUES ('root_key_fingerprint', $1) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(&fingerprint)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.scrub_log(VACUUM_REKEY).await;
        Ok(())
    }

    async fn list_roles(&self, project_id: &str) -> StoreResult<Vec<Role>> {
        let rows = sqlx::query("SELECT * FROM roles WHERE project_id = $1 ORDER BY slug")
            .bind(project_id)
            .fetch_all(&self.pool)
            .await?;
        collect(rows, role_from)
    }

    async fn upsert_role(&self, role: Role) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO roles (id, project_id, slug, name, description, rules, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (project_id, slug) DO UPDATE SET name = excluded.name, description = excluded.description, \
             rules = excluded.rules",
        )
        .bind(&role.id)
        .bind(&role.project_id)
        .bind(&role.slug)
        .bind(&role.name)
        .bind(&role.description)
        .bind(to_json(&role.rules)?)
        .bind(role.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_role(&self, project_id: &str, slug: &str) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        if project_id.is_empty() {
            sqlx::query("DELETE FROM org_bindings WHERE role_slug = $1")
                .bind(slug)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query("DELETE FROM project_memberships WHERE project_id = $1 AND role_slug = $2")
                .bind(project_id)
                .bind(slug)
                .execute(&mut *tx)
                .await?;
        }
        let result = sqlx::query("DELETE FROM roles WHERE project_id = $1 AND slug = $2")
            .bind(project_id)
            .bind(slug)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    async fn list_memberships(&self, project_id: &str) -> StoreResult<Vec<Membership>> {
        let rows = sqlx::query(
            "SELECT * FROM project_memberships WHERE project_id = $1 ORDER BY principal_kind, principal_id",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await?;
        collect(rows, membership_from)
    }

    async fn memberships_for(&self, principals: Vec<(PrincipalKind, String)>) -> StoreResult<Vec<Membership>> {
        let mut out = Vec::new();
        for (kind, id) in principals {
            let rows = sqlx::query("SELECT * FROM project_memberships WHERE principal_kind = $1 AND principal_id = $2")
                .bind(kind.as_str())
                .bind(&id)
                .fetch_all(&self.pool)
                .await?;
            out.extend(collect(rows, membership_from)?);
        }
        Ok(out)
    }

    async fn add_membership(&self, membership: Membership) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO project_memberships (project_id, principal_kind, principal_id, role_slug, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&membership.project_id)
        .bind(membership.principal_kind.as_str())
        .bind(&membership.principal_id)
        .bind(&membership.role_slug)
        .bind(membership.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_membership(
        &self,
        project_id: &str,
        kind: PrincipalKind,
        principal_id: &str,
        role_slug: &str,
    ) -> StoreResult<()> {
        let result = sqlx::query(
            "DELETE FROM project_memberships WHERE project_id = $1 AND principal_kind = $2 AND principal_id = $3 \
             AND role_slug = $4",
        )
        .bind(project_id)
        .bind(kind.as_str())
        .bind(principal_id)
        .bind(role_slug)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn list_environments(&self, project_id: &str) -> StoreResult<Vec<Environment>> {
        let rows = sqlx::query("SELECT * FROM environments WHERE project_id = $1 ORDER BY position, slug")
            .bind(project_id)
            .fetch_all(&self.pool)
            .await?;
        collect(rows, environment_from)
    }

    async fn create_environment(&self, env: Environment) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO environments (id, project_id, slug, name, position, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&env.id)
        .bind(&env.project_id)
        .bind(&env.slug)
        .bind(&env.name)
        .bind(env.position)
        .bind(env.created_at)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO folders (environment_id, path, created_at) VALUES ($1, '/', $2)")
            .bind(&env.id)
            .bind(env.created_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn update_environment(&self, id: &str, name: &str, position: i64) -> StoreResult<()> {
        let result = sqlx::query("UPDATE environments SET name = $1, position = $2 WHERE id = $3")
            .bind(name)
            .bind(position)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn delete_environment(&self, id: &str) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        // Checked inside the transaction so a secret written meanwhile is not lost with its history.
        let live: i64 = sqlx::query("SELECT COUNT(*) AS n FROM secrets WHERE environment_id = $1 AND deleted = 0")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?
            .try_get("n")?;
        if live > 0 {
            return Err(StoreError::Conflict);
        }
        sqlx::query(
            "DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE environment_id = $1)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM secret_grants WHERE secret_id IN (SELECT id FROM secrets WHERE environment_id = $1)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM secrets WHERE environment_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM snapshots WHERE environment_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM folders WHERE environment_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    async fn list_folders(&self, environment_id: &str) -> StoreResult<Vec<Folder>> {
        let rows = sqlx::query("SELECT * FROM folders WHERE environment_id = $1 ORDER BY path")
            .bind(environment_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(Folder {
                    environment_id: row.try_get("environment_id")?,
                    path: row.try_get("path")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    async fn create_folder(&self, folder: Folder) -> StoreResult<()> {
        sqlx::query("INSERT INTO folders (environment_id, path, created_at) VALUES ($1, $2, $3)")
            .bind(&folder.environment_id)
            .bind(&folder.path)
            .bind(folder.created_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_folder(&self, environment_id: &str, path: &str) -> StoreResult<()> {
        let prefix = format!("{path}/");
        let mut tx = self.pool.begin().await?;
        let live: i64 = sqlx::query(
            "SELECT COUNT(*) AS n FROM secrets WHERE environment_id = $1 AND deleted = 0 \
             AND (path = $2 OR substr(path, 1, CAST($3 AS INTEGER)) = $4)",
        )
        .bind(environment_id)
        .bind(path)
        .bind(prefix.len() as i64)
        .bind(&prefix)
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
        if live > 0 {
            return Err(StoreError::Conflict);
        }
        let result = sqlx::query(
            "DELETE FROM folders WHERE environment_id = $1 AND (path = $2 OR substr(path, 1, CAST($3 AS INTEGER)) = $4)",
        )
        .bind(environment_id)
        .bind(path)
        .bind(prefix.len() as i64)
        .bind(&prefix)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    async fn list_secrets(
        &self,
        environment_id: &str,
        path: &str,
        recursive: bool,
        include_deleted: bool,
    ) -> StoreResult<Vec<SecretWithVersion>> {
        let deleted = if include_deleted { "" } else { " AND s.deleted = 0" };
        let rows = if recursive && path == "/" {
            sqlx::query(audited(format!(
                "SELECT {SECRET_COLUMNS} {SECRET_JOIN} WHERE s.environment_id = $1{deleted} ORDER BY s.path, s.key"
            )))
            .bind(environment_id)
            .fetch_all(&self.pool)
            .await?
        } else if recursive {
            let prefix = format!("{path}/");
            sqlx::query(audited(format!(
                "SELECT {SECRET_COLUMNS} {SECRET_JOIN} WHERE s.environment_id = $1 \
                 AND (s.path = $2 OR substr(s.path, 1, CAST($3 AS INTEGER)) = $4){deleted} ORDER BY s.path, s.key"
            )))
            .bind(environment_id)
            .bind(path)
            .bind(prefix.len() as i64)
            .bind(prefix)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(audited(format!(
                "SELECT {SECRET_COLUMNS} {SECRET_JOIN} WHERE s.environment_id = $1 AND s.path = $2{deleted} ORDER BY s.key"
            )))
            .bind(environment_id)
            .bind(path)
            .fetch_all(&self.pool)
            .await?
        };
        collect(rows, secret_with_version_from)
    }

    async fn get_secret(&self, environment_id: &str, path: &str, key: &str) -> StoreResult<Option<SecretWithVersion>> {
        let row = sqlx::query(audited(format!(
            "SELECT {SECRET_COLUMNS} {SECRET_JOIN} WHERE s.environment_id = $1 AND s.path = $2 AND s.key = $3"
        )))
        .bind(environment_id)
        .bind(path)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(secret_with_version_from).transpose()
    }

    async fn get_secret_by_id(&self, id: &str) -> StoreResult<Option<SecretWithVersion>> {
        let row = sqlx::query(audited(format!(
            "SELECT {SECRET_COLUMNS} {SECRET_JOIN} WHERE s.id = $1"
        )))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(secret_with_version_from).transpose()
    }

    async fn list_versions(&self, secret_id: &str, before: Option<i64>, limit: i64) -> StoreResult<Vec<SecretVersion>> {
        let rows = sqlx::query(
            "SELECT * FROM secret_versions WHERE secret_id = $1 AND version < $2 ORDER BY version DESC LIMIT $3",
        )
        .bind(secret_id)
        .bind(before.unwrap_or(i64::MAX))
        .bind(limit.max(0))
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| version_from(row, secret_id.to_string(), "deleted", "created_at"))
            .collect()
    }

    async fn get_version(&self, secret_id: &str, version: i64) -> StoreResult<Option<SecretVersion>> {
        let row = sqlx::query("SELECT * FROM secret_versions WHERE secret_id = $1 AND version = $2")
            .bind(secret_id)
            .bind(version)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref()
            .map(|r| version_from(r, secret_id.to_string(), "deleted", "created_at"))
            .transpose()
    }

    async fn write_secrets(&self, batch: WriteBatch) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        if batch.changes.iter().any(|c| c.restricted) {
            let project = sqlx::query(self.locking("SELECT secret_access FROM projects WHERE id = $1"))
                .bind(&batch.project_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?;
            if !get_flag(&project, "secret_access")? {
                return Err(StoreError::Conflict);
            }
        }
        for change in &batch.changes {
            let v = &change.version;
            if change.previous_version == 0 {
                sqlx::query(
                    "INSERT INTO secrets (id, project_id, environment_id, path, key, current_version, deleted, \
                     created_at, updated_at, restricted) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                )
                .bind(&change.secret_id)
                .bind(&batch.project_id)
                .bind(&batch.environment_id)
                .bind(&change.path)
                .bind(&change.key)
                .bind(v.version)
                .bind(flag(v.deleted))
                .bind(batch.now)
                .bind(batch.now)
                .bind(flag(change.restricted))
                .execute(&mut *tx)
                .await?;
            } else {
                let result = sqlx::query(
                    "UPDATE secrets SET current_version = $1, deleted = $2, updated_at = $3 \
                     WHERE id = $4 AND current_version = $5 AND environment_id = $6 AND access_epoch = $7",
                )
                .bind(v.version)
                .bind(flag(v.deleted))
                .bind(batch.now)
                .bind(&change.secret_id)
                .bind(change.previous_version)
                .bind(&batch.environment_id)
                .bind(change.access_epoch)
                .execute(&mut *tx)
                .await?;
                if result.rows_affected() != 1 {
                    return Err(StoreError::Conflict);
                }
                if change.restricted {
                    // Brought back restricted with an empty list, as a new restricted secret starts.
                    sqlx::query("UPDATE secrets SET restricted = 1, access_epoch = access_epoch + 1 WHERE id = $1")
                        .bind(&change.secret_id)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query("DELETE FROM secret_grants WHERE secret_id = $1")
                        .bind(&change.secret_id)
                        .execute(&mut *tx)
                        .await?;
                }
            }
            sqlx::query(
                "INSERT INTO secret_versions (secret_id, version, value, comment, tags, deleted, actor, created_at, \
                 generated) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(&change.secret_id)
            .bind(v.version)
            .bind(v.value.clone())
            .bind(&v.comment)
            .bind(to_json(&v.tags)?)
            .bind(flag(v.deleted))
            .bind(&v.actor)
            .bind(v.created_at)
            .bind(flag(v.generated))
            .execute(&mut *tx)
            .await?;
        }
        let rows = sqlx::query(
            "SELECT id, current_version FROM secrets WHERE environment_id = $1 AND deleted = 0 ORDER BY id",
        )
        .bind(&batch.environment_id)
        .fetch_all(&mut *tx)
        .await?;
        let entries = rows
            .iter()
            .map(|row| {
                Ok(SnapshotEntry {
                    secret_id: row.try_get("id")?,
                    version: row.try_get("current_version")?,
                })
            })
            .collect::<StoreResult<Vec<_>>>()?;
        sqlx::query(
            "INSERT INTO snapshots (id, environment_id, entries, reason, actor, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&batch.snapshot_id)
        .bind(&batch.environment_id)
        .bind(to_json(&entries)?)
        .bind(&batch.reason)
        .bind(&batch.actor)
        .bind(batch.now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn list_snapshots(&self, environment_id: &str, limit: i64) -> StoreResult<Vec<Snapshot>> {
        let rows =
            sqlx::query("SELECT * FROM snapshots WHERE environment_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2")
                .bind(environment_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?;
        collect(rows, snapshot_from)
    }

    async fn get_snapshot(&self, id: &str) -> StoreResult<Option<Snapshot>> {
        let row = sqlx::query("SELECT * FROM snapshots WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(snapshot_from).transpose()
    }

    async fn prune_snapshots(&self, environment_id: &str, keep: i64) -> StoreResult<()> {
        sqlx::query(
            "DELETE FROM snapshots WHERE environment_id = $1 AND id NOT IN \
             (SELECT id FROM snapshots WHERE environment_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3)",
        )
        .bind(environment_id)
        .bind(environment_id)
        .bind(keep)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_audit(&self, entry: AuditEntry) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO audit_log (id, created_at, actor_kind, actor_id, actor_name, action, project_id, environment, \
             path, secret_key, detail, ip, restricted) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(&entry.id)
        .bind(entry.created_at)
        .bind(&entry.actor_kind)
        .bind(&entry.actor_id)
        .bind(&entry.actor_name)
        .bind(&entry.action)
        .bind(entry.project_id.clone())
        .bind(entry.environment.clone())
        .bind(entry.path.clone())
        .bind(entry.secret_key.clone())
        .bind(to_json(&entry.detail)?)
        .bind(&entry.ip)
        .bind(flag(entry.restricted))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_audit(&self, query: AuditQuery) -> StoreResult<Vec<AuditEntry>> {
        let mut filter = audit_filter(&query);
        if let Some((created_at, id)) = &query.after {
            let op = if query.oldest_first { ">" } else { "<" };
            let a = filter.bind(SqlParam::Int(*created_at));
            let b = filter.bind(SqlParam::Int(*created_at));
            let c = filter.bind(SqlParam::Text(id.clone()));
            filter
                .clauses
                .push(format!("(created_at {op} {a} OR (created_at = {b} AND id {op} {c}))"));
        }
        let direction = if query.oldest_first { "ASC" } else { "DESC" };
        let limit = filter.bind(SqlParam::Int(query.limit.clamp(1, 500)));
        let sql = format!(
            "SELECT * FROM audit_log WHERE {} ORDER BY created_at {direction}, id {direction} LIMIT {limit}",
            filter.where_clause()
        );
        let rows = filter.apply(sqlx::query(audited(sql))).fetch_all(&self.pool).await?;
        collect(rows, audit_from)
    }

    async fn count_audit(&self, query: AuditQuery) -> StoreResult<i64> {
        let filter = audit_filter(&query);
        let sql = format!("SELECT COUNT(*) AS n FROM audit_log WHERE {}", filter.where_clause());
        let row = filter.apply(sqlx::query(audited(sql))).fetch_one(&self.pool).await?;
        Ok(row.try_get("n")?)
    }

    async fn put_login_state(&self, state: LoginState) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO login_states (state, nonce, pkce_verifier, return_to, created_at, max_age) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&state.state)
        .bind(&state.nonce)
        .bind(&state.pkce_verifier)
        .bind(&state.return_to)
        .bind(state.created_at)
        .bind(state.max_age)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_login_state(&self, state: &str) -> StoreResult<Option<LoginState>> {
        let row = sqlx::query("DELETE FROM login_states WHERE state = $1 RETURNING *")
            .bind(state)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(LoginState {
                state: row.try_get("state")?,
                nonce: row.try_get("nonce")?,
                pkce_verifier: row.try_get("pkce_verifier")?,
                return_to: row.try_get("return_to")?,
                created_at: row.try_get("created_at")?,
                max_age: row.try_get("max_age")?,
            })
        })
        .transpose()
    }

    async fn create_cli_login(&self, login: CliLogin) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO cli_logins (device_code_hash, user_code, created_at, expires_at, approved_user_id, consumed, \
             requested_from_ip, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&login.device_code_hash)
        .bind(&login.user_code)
        .bind(login.created_at)
        .bind(login.expires_at)
        .bind(login.approved_user_id.clone())
        .bind(flag(login.consumed))
        .bind(&login.requested_from_ip)
        .bind(&login.user_agent)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_cli_login(&self, user_code: &str, now: i64) -> StoreResult<Option<CliLogin>> {
        let row = sqlx::query("SELECT * FROM cli_logins WHERE user_code = $1 AND expires_at > $2 AND consumed = 0")
            .bind(user_code)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(cli_login_from).transpose()
    }

    async fn approve_cli_login(&self, user_code: &str, user_id: &str, now: i64, mac: &str) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE cli_logins SET approved_user_id = $1, approval_mac = $2 WHERE user_code = $3 AND expires_at > $4 \
             AND approved_user_id IS NULL AND consumed = 0",
        )
        .bind(user_id)
        .bind(mac)
        .bind(user_code)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn deny_cli_login(&self, user_code: &str, now: i64) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE cli_logins SET consumed = 1 WHERE user_code = $1 AND expires_at > $2 \
             AND approved_user_id IS NULL AND consumed = 0",
        )
        .bind(user_code)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn poll_cli_login(&self, device_code_hash: &str, now: i64) -> StoreResult<CliPoll> {
        let row = sqlx::query("SELECT * FROM cli_logins WHERE device_code_hash = $1")
            .bind(device_code_hash)
            .fetch_optional(&self.pool)
            .await?;
        let Some(login) = row.as_ref().map(cli_login_from).transpose()? else {
            return Ok(CliPoll::Gone);
        };
        if login.consumed || login.expires_at <= now {
            return Ok(CliPoll::Gone);
        }
        let Some(user_id) = login.approved_user_id else {
            return Ok(CliPoll::Pending);
        };
        let mac: Option<String> = row.as_ref().map(|r| r.try_get("approval_mac")).transpose()?.flatten();
        // Only one poller can claim the approval.
        let result = sqlx::query("UPDATE cli_logins SET consumed = 1 WHERE device_code_hash = $1 AND consumed = 0")
            .bind(device_code_hash)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() != 1 {
            return Ok(CliPoll::Gone);
        }
        Ok(CliPoll::Approved { user_id, mac })
    }

    async fn purge_expired(&self, now: i64) -> StoreResult<()> {
        sqlx::query("DELETE FROM access_tokens WHERE expires_at < $1")
            .bind(now - 86_400)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM login_states WHERE created_at < $1")
            .bind(now - 600)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM cli_logins WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
