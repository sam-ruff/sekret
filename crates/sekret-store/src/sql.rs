use async_trait::async_trait;
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row};

use crate::models::*;
use crate::{Store, StoreError, StoreResult};

/// [`Store`] over sqlx's `Any` driver. SQL is kept portable between SQLite and Postgres.
#[derive(Clone)]
pub struct SqlStore {
    pool: AnyPool,
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
     s.created_at, s.updated_at, s.policy, v.version, v.value, v.comment, v.tags, v.deleted AS v_deleted, v.actor, \
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
    if let Some(search) = query.search.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let p = filter.bind(SqlParam::Text(format!("%{}%", like_literal(&search.to_lowercase()))));
        let columns = [
            "action",
            "actor_name",
            "actor_id",
            "COALESCE(environment, '')",
            "COALESCE(path, '')",
            "COALESCE(secret_key, '')",
            "ip",
        ];
        let any: Vec<String> = columns
            .iter()
            .map(|c| format!("LOWER({c}) LIKE {p} ESCAPE '\\'"))
            .collect();
        filter.clauses.push(format!("({})", any.join(" OR ")));
    }
    filter
}

fn collect<T>(rows: Vec<AnyRow>, map: fn(&AnyRow) -> StoreResult<T>) -> StoreResult<Vec<T>> {
    rows.iter().map(map).collect()
}

impl SqlStore {
    /// Connects and applies migrations. Accepts `sqlite://...`, `sqlite::memory:` or `postgres://...`.
    pub async fn connect(url: &str) -> StoreResult<Self> {
        sqlx::any::install_default_drivers();
        let postgres = url.starts_with("postgres");
        let in_memory = url.contains(":memory:") || url.contains("mode=memory");
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
            .connect(url)
            .await?;
        if postgres {
            sqlx::migrate!("./migrations/postgres").run(&pool).await?;
        } else {
            if !in_memory {
                sqlx::query("PRAGMA journal_mode = WAL").execute(&pool).await?;
            }
            sqlx::migrate!("./migrations/sqlite").run(&pool).await?;
        }
        Ok(Self { pool })
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
            "INSERT INTO identity_auth_methods (identity_id, kind, config, created_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (identity_id, kind) DO UPDATE SET config = excluded.config",
        )
        .bind(&method.identity_id)
        .bind(&method.kind)
        .bind(to_json(&method.config)?)
        .bind(method.created_at)
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
             uses_remaining, revoked, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
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
             expires_at, max_expires_at, revoked, last_used_at, source) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
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
        .execute(&self.pool)
        .await?;
        Ok(())
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

    async fn replace_wrapped_keys(
        &self,
        keys: Vec<(String, Vec<u8>)>,
        auth_methods: Vec<AuthMethod>,
        fingerprint: &str,
    ) -> StoreResult<()> {
        let mut tx = self.pool.begin().await?;
        for (id, key) in keys {
            sqlx::query("UPDATE projects SET wrapped_key = $1 WHERE id = $2")
                .bind(key)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        for method in auth_methods {
            sqlx::query("UPDATE identity_auth_methods SET config = $1 WHERE identity_id = $2 AND kind = $3")
                .bind(to_json(&method.config)?)
                .bind(&method.identity_id)
                .bind(&method.kind)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "INSERT INTO meta (key, value) VALUES ('root_key_fingerprint', $1) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(fingerprint)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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

    async fn list_versions(&self, secret_id: &str) -> StoreResult<Vec<SecretVersion>> {
        let rows = sqlx::query("SELECT * FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC")
            .bind(secret_id)
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
        for change in &batch.changes {
            let v = &change.version;
            if change.previous_version == 0 {
                sqlx::query(
                    "INSERT INTO secrets (id, project_id, environment_id, path, key, current_version, deleted, \
                     created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
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
                .execute(&mut *tx)
                .await?;
            } else {
                let result = sqlx::query(
                    "UPDATE secrets SET current_version = $1, deleted = $2, updated_at = $3 \
                     WHERE id = $4 AND current_version = $5 AND environment_id = $6",
                )
                .bind(v.version)
                .bind(flag(v.deleted))
                .bind(batch.now)
                .bind(&change.secret_id)
                .bind(change.previous_version)
                .bind(&batch.environment_id)
                .execute(&mut *tx)
                .await?;
                if result.rows_affected() != 1 {
                    return Err(StoreError::Conflict);
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
             path, secret_key, detail, ip) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
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
            "INSERT INTO login_states (state, nonce, pkce_verifier, return_to, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&state.state)
        .bind(&state.nonce)
        .bind(&state.pkce_verifier)
        .bind(&state.return_to)
        .bind(state.created_at)
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
            })
        })
        .transpose()
    }

    async fn create_cli_login(&self, login: CliLogin) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO cli_logins (device_code_hash, user_code, created_at, expires_at, approved_user_id, consumed) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&login.device_code_hash)
        .bind(&login.user_code)
        .bind(login.created_at)
        .bind(login.expires_at)
        .bind(login.approved_user_id.clone())
        .bind(flag(login.consumed))
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

    async fn approve_cli_login(&self, user_code: &str, user_id: &str, now: i64) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE cli_logins SET approved_user_id = $1 WHERE user_code = $2 AND expires_at > $3 \
             AND approved_user_id IS NULL AND consumed = 0",
        )
        .bind(user_id)
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
        // Only one poller can claim the approval.
        let result = sqlx::query("UPDATE cli_logins SET consumed = 1 WHERE device_code_hash = $1 AND consumed = 0")
            .bind(device_code_hash)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() != 1 {
            return Ok(CliPoll::Gone);
        }
        Ok(CliPoll::Approved(user_id))
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
