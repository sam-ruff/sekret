//! Persistence for sekret behind the [`Store`] trait, with a sqlx implementation for SQLite and Postgres.

mod lock;
pub mod models;
mod sql;

use async_trait::async_trait;
pub use lock::{InstanceLock, canonical_path, lock_file};
pub use models::*;
pub use sql::{Open, SqlStore, sqlite_file, without_create};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("record already exists or was changed concurrently")]
    Conflict,
    #[error("record not found")]
    NotFound,
    #[error("stored data is corrupt: {0}")]
    Corrupt(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("{0}")]
    Unsupported(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// The meta key holding the integrity key, wrapped under the root key.
pub const INTEGRITY_KEY_META: &str = "integrity_key";

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait Store: Send + Sync {
    async fn get_meta(&self, key: &str) -> StoreResult<Option<String>>;
    async fn set_meta(&self, key: &str, value: &str) -> StoreResult<()>;
    /// Sets `key` only when it has no value yet. False when one was already there.
    async fn insert_meta(&self, key: &str, value: &str) -> StoreResult<bool>;

    async fn get_seal_config(&self) -> StoreResult<Option<SealConfig>>;
    /// Records the seal configuration and root key fingerprint together. `Conflict` if already initialised.
    async fn init_seal_config(&self, config: SealConfig, fingerprint: &str) -> StoreResult<()>;
    /// `NotFound` before initialisation.
    async fn update_seal_config(&self, config: SealConfig) -> StoreResult<()>;
    /// Writes a consistent copy of the database to `path` with `seal` as its seal configuration,
    /// never carrying a remembered unlock. SQLite only; `Unsupported` on Postgres.
    async fn snapshot_to(&self, path: &str, seal: SealConfig) -> StoreResult<()>;

    async fn upsert_user(&self, login: UserLogin) -> StoreResult<User>;
    async fn get_user(&self, id: &str) -> StoreResult<Option<User>>;
    async fn list_users(&self) -> StoreResult<Vec<User>>;
    async fn set_user_disabled(&self, id: &str, disabled: bool) -> StoreResult<()>;

    async fn create_identity(&self, identity: Identity) -> StoreResult<()>;
    async fn get_identity(&self, id: &str) -> StoreResult<Option<Identity>>;
    async fn list_identities(&self) -> StoreResult<Vec<Identity>>;
    async fn update_identity(&self, identity: Identity) -> StoreResult<()>;
    async fn delete_identity(&self, id: &str) -> StoreResult<()>;

    async fn put_auth_method(&self, method: AuthMethod) -> StoreResult<()>;
    async fn get_auth_method(&self, identity_id: &str, kind: &str) -> StoreResult<Option<AuthMethod>>;
    async fn list_auth_methods(&self, identity_id: &str) -> StoreResult<Vec<AuthMethod>>;
    async fn delete_auth_method(&self, identity_id: &str, kind: &str) -> StoreResult<()>;

    async fn create_client_secret(&self, secret: ClientSecret) -> StoreResult<()>;
    async fn list_client_secrets(&self, identity_id: &str) -> StoreResult<Vec<ClientSecret>>;
    async fn find_client_secret(&self, secret_hash: &str) -> StoreResult<Option<ClientSecret>>;
    /// Records a use, decrementing any remaining-use counter. False when no use is left.
    async fn consume_client_secret(&self, id: &str, now: i64) -> StoreResult<bool>;
    async fn revoke_client_secret(&self, identity_id: &str, id: &str) -> StoreResult<()>;
    /// Moves a client secret from `old_hash` to `new_hash` with a new MAC. False when it is no
    /// longer stored under `old_hash`.
    async fn rekey_client_secret(&self, id: &str, old_hash: &str, new_hash: &str, mac: &str) -> StoreResult<bool>;
    /// Client secrets with no MAC, from before the integrity key.
    async fn list_unsigned_client_secrets(&self) -> StoreResult<Vec<ClientSecret>>;
    async fn set_client_secret_mac(&self, id: &str, mac: &str) -> StoreResult<()>;

    async fn create_token(&self, token: AccessToken) -> StoreResult<()>;
    async fn find_token(&self, token_hash: &str) -> StoreResult<Option<AccessToken>>;
    /// The token stored with this plain hash, for the routes open while sealed.
    async fn find_sealed_token(&self, sealed_hash: &str) -> StoreResult<Option<AccessToken>>;
    /// As [`Store::rekey_client_secret`], for an access token.
    async fn rekey_token(&self, id: &str, old_hash: &str, new_hash: &str, mac: &str) -> StoreResult<bool>;
    /// Unrevoked access tokens with no MAC, from before the integrity key.
    async fn list_unsigned_tokens(&self) -> StoreResult<Vec<AccessToken>>;
    async fn set_token_mac(&self, id: &str, mac: &str) -> StoreResult<()>;
    /// Auth methods with no MAC, from before the integrity key.
    async fn list_unsigned_auth_methods(&self) -> StoreResult<Vec<AuthMethod>>;
    async fn touch_token(&self, id: &str, now: i64) -> StoreResult<()>;
    async fn extend_token(&self, id: &str, expires_at: i64) -> StoreResult<()>;
    async fn revoke_token(&self, id: &str) -> StoreResult<()>;
    async fn revoke_principal_tokens(&self, kind: PrincipalKind, principal_id: &str) -> StoreResult<()>;
    async fn revoke_tokens_from_source(&self, source: &str) -> StoreResult<()>;
    async fn list_principal_tokens(&self, kind: PrincipalKind, principal_id: &str) -> StoreResult<Vec<AccessToken>>;

    async fn list_org_bindings(&self) -> StoreResult<Vec<Binding>>;
    async fn add_org_binding(&self, binding: Binding) -> StoreResult<()>;
    async fn remove_org_binding(&self, kind: PrincipalKind, principal_id: &str, role_slug: &str) -> StoreResult<()>;

    /// Creates the project with its environments in one transaction.
    async fn create_project(&self, project: Project, environments: Vec<Environment>) -> StoreResult<()>;
    async fn get_project(&self, id_or_slug: &str) -> StoreResult<Option<Project>>;
    async fn list_projects(&self) -> StoreResult<Vec<Project>>;
    /// Replaces the project's logo, or removes it with `None`.
    async fn set_project_logo(&self, project_id: &str, logo: Option<ProjectLogo>, now: i64) -> StoreResult<()>;
    async fn get_project_logo(&self, project_id: &str) -> StoreResult<Option<ProjectLogo>>;
    async fn set_project_policy(&self, project_id: &str, policy: Option<String>) -> StoreResult<()>;
    async fn set_secret_policy(&self, secret_id: &str, policy: Option<String>) -> StoreResult<()>;
    /// Turns per-secret access on or off. Turning it off is a `Conflict` while any secret in the
    /// project is restricted, so no restriction is ever dropped silently, and otherwise clears
    /// every access list in the project.
    async fn set_project_secret_access(&self, project_id: &str, enabled: bool) -> StoreResult<()>;
    /// Restricted secrets in the project, deleted ones included.
    async fn count_restricted_secrets(&self, project_id: &str) -> StoreResult<i64>;
    /// Restricted secrets in the project, deleted ones included, without their values.
    async fn list_restricted_secrets(&self, project_id: &str) -> StoreResult<Vec<RestrictedSecret>>;
    /// Every access list entry on secrets in the environment.
    async fn list_environment_grants(&self, environment_id: &str) -> StoreResult<Vec<SecretGrant>>;
    /// The restricted secrets in the environment with their access epochs, and their entries,
    /// read together so a write can be held to the lists it was judged by.
    async fn environment_access(&self, environment_id: &str) -> StoreResult<EnvironmentAccess>;
    /// The snapshot taken just before this one in its environment.
    async fn previous_snapshot(&self, snapshot: &Snapshot) -> StoreResult<Option<Snapshot>>;
    /// Every access list entry on secrets in the project.
    async fn list_project_grants(&self, project_id: &str) -> StoreResult<Vec<SecretGrant>>;
    async fn list_secret_grants(&self, secret_id: &str) -> StoreResult<Vec<SecretGrant>>;
    /// Applies one secret's access changes atomically and moves its access epoch on.
    /// Restricting is a `Conflict` when the project setting is off, and unrestricting clears the
    /// list before any grants in the same change.
    async fn update_secret_access(&self, change: AccessChange) -> StoreResult<()>;
    async fn update_project(&self, id: &str, name: &str, description: &str) -> StoreResult<()>;
    async fn delete_project(&self, id: &str) -> StoreResult<()>;
    /// Every stored secret value in the project, history included.
    async fn list_encrypted_values(&self, project_id: &str) -> StoreResult<Vec<EncryptedValue>>;
    /// Swaps every root-key-dependent value in one transaction: project keys, secret values,
    /// re-sealed auth method configs, the fingerprint and, when given, the seal configuration.
    async fn replace_wrapped_keys(&self, rekey: Rekey) -> StoreResult<()>;

    async fn list_roles(&self, project_id: &str) -> StoreResult<Vec<Role>>;
    async fn upsert_role(&self, role: Role) -> StoreResult<()>;
    async fn delete_role(&self, project_id: &str, slug: &str) -> StoreResult<()>;

    async fn list_memberships(&self, project_id: &str) -> StoreResult<Vec<Membership>>;
    async fn memberships_for(&self, principals: Vec<(PrincipalKind, String)>) -> StoreResult<Vec<Membership>>;
    async fn add_membership(&self, membership: Membership) -> StoreResult<()>;
    async fn remove_membership(
        &self,
        project_id: &str,
        kind: PrincipalKind,
        principal_id: &str,
        role_slug: &str,
    ) -> StoreResult<()>;

    async fn list_environments(&self, project_id: &str) -> StoreResult<Vec<Environment>>;
    async fn create_environment(&self, environment: Environment) -> StoreResult<()>;
    async fn update_environment(&self, id: &str, name: &str, position: i64) -> StoreResult<()>;
    async fn delete_environment(&self, id: &str) -> StoreResult<()>;

    async fn list_folders(&self, environment_id: &str) -> StoreResult<Vec<Folder>>;
    async fn create_folder(&self, folder: Folder) -> StoreResult<()>;
    async fn delete_folder(&self, environment_id: &str, path: &str) -> StoreResult<()>;

    /// Secrets in `path`, or beneath it when `recursive`, with their current version.
    async fn list_secrets(
        &self,
        environment_id: &str,
        path: &str,
        recursive: bool,
        include_deleted: bool,
    ) -> StoreResult<Vec<SecretWithVersion>>;
    async fn get_secret(&self, environment_id: &str, path: &str, key: &str) -> StoreResult<Option<SecretWithVersion>>;
    async fn get_secret_by_id(&self, id: &str) -> StoreResult<Option<SecretWithVersion>>;
    /// Up to `limit` versions, newest first, older than `before` when given.
    async fn list_versions(&self, secret_id: &str, before: Option<i64>, limit: i64) -> StoreResult<Vec<SecretVersion>>;
    async fn get_version(&self, secret_id: &str, version: i64) -> StoreResult<Option<SecretVersion>>;
    /// Applies every change and records an environment snapshot atomically.
    async fn write_secrets(&self, batch: WriteBatch) -> StoreResult<()>;

    async fn list_snapshots(&self, environment_id: &str, limit: i64) -> StoreResult<Vec<Snapshot>>;
    async fn get_snapshot(&self, id: &str) -> StoreResult<Option<Snapshot>>;
    async fn prune_snapshots(&self, environment_id: &str, keep: i64) -> StoreResult<()>;

    async fn insert_audit(&self, entry: AuditEntry) -> StoreResult<()>;
    async fn list_audit(&self, query: AuditQuery) -> StoreResult<Vec<AuditEntry>>;
    /// Entries matching the query's filters, ignoring `after` and `limit`.
    async fn count_audit(&self, query: AuditQuery) -> StoreResult<i64>;

    async fn put_login_state(&self, state: LoginState) -> StoreResult<()>;
    async fn take_login_state(&self, state: &str) -> StoreResult<Option<LoginState>>;

    async fn create_cli_login(&self, login: CliLogin) -> StoreResult<()>;
    async fn get_cli_login(&self, user_code: &str, now: i64) -> StoreResult<Option<CliLogin>>;
    /// `mac` authenticates the approval, and is handed back by [`Store::poll_cli_login`].
    async fn approve_cli_login(&self, user_code: &str, user_id: &str, now: i64, mac: &str) -> StoreResult<bool>;
    /// Consumes a pending, unapproved login so its poller is told it has gone.
    async fn deny_cli_login(&self, user_code: &str, now: i64) -> StoreResult<bool>;
    async fn poll_cli_login(&self, device_code_hash: &str, now: i64) -> StoreResult<CliPoll>;

    async fn purge_expired(&self, now: i64) -> StoreResult<()>;
}
