use sekret_core::permissions::{Action, Rule};
use sekret_core::seal::{SealFlags, SealMode, UnlockPolicy, WrappedRootKey};
use serde::{Deserialize, Serialize};

/// How the root key is protected. `wrapped` is set only in passphrase mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealConfig {
    pub mode: SealMode,
    pub wrapped: Option<WrappedRootKey>,
    pub unlock_policy: UnlockPolicy,
    /// The root key wrapped under the device key in the remember file.
    pub remembered: Option<Vec<u8>>,
    /// Goes up with every change, and is covered by `mac`.
    pub epoch: i64,
    /// Authenticates the row under a key derived from the root key; absent on databases from
    /// before it existed.
    pub mac: Option<Vec<u8>>,
    /// Covered by `mac`.
    pub flags: SealFlags,
    pub created_at: i64,
    pub updated_at: i64,
}

/// One stored secret value, as written under its project's data key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedValue {
    pub secret_id: String,
    pub version: i64,
    pub value: Vec<u8>,
}

/// Everything that changes when the root key is replaced, written in one transaction.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Rekey {
    /// `(project id, wrapped data key)`.
    pub keys: Vec<(String, Vec<u8>)>,
    /// Values re-encrypted under the projects' new data keys.
    pub values: Vec<EncryptedValue>,
    pub auth_methods: Vec<AuthMethod>,
    pub fingerprint: String,
    pub seal: Option<SealConfig>,
    /// The integrity key wrapped under the new root key, replacing the stored one.
    pub integrity_key: Option<String>,
    /// Revoke every token and client secret and close every pending CLI login, for a new
    /// integrity key under which none of them verify.
    pub revoke_credentials: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String,
    /// `issuer|sub`, stable across email changes.
    pub subject: String,
    pub email: String,
    pub name: String,
    pub groups: Vec<String>,
    pub disabled: bool,
    pub created_at: i64,
    pub last_login_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLogin {
    pub subject: String,
    pub email: String,
    pub name: String,
    pub groups: Vec<String>,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub description: String,
    pub token_ttl: i64,
    pub token_max_ttl: i64,
    pub trusted_cidrs: Vec<String>,
    pub disabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthMethod {
    pub identity_id: String,
    pub kind: String,
    pub config: serde_json::Value,
    pub created_at: i64,
    /// Authenticates the identity, kind and configuration under the integrity key.
    pub mac: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSecret {
    pub id: String,
    pub identity_id: String,
    pub description: String,
    pub secret_hash: String,
    /// First characters of the secret, shown so people can tell secrets apart.
    pub prefix: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub uses_remaining: Option<i64>,
    pub revoked: bool,
    pub last_used_at: Option<i64>,
    /// Authenticates the row's fixed fields under the integrity key.
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalKind {
    User,
    Group,
    Identity,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PrincipalKind::User => "user",
            PrincipalKind::Group => "group",
            PrincipalKind::Identity => "identity",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(PrincipalKind::User),
            "group" => Some(PrincipalKind::Group),
            "identity" => Some(PrincipalKind::Identity),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    pub id: String,
    pub token_hash: String,
    /// `session`, `cli`, `machine` or `admin`.
    pub kind: String,
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    pub description: String,
    /// The credential this token was minted from, such as `client-secret:<id>`; empty when none.
    pub source: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub max_expires_at: i64,
    pub revoked: bool,
    pub last_used_at: Option<i64>,
    /// When the person last authenticated with the identity provider, for browser sessions.
    pub auth_time: Option<i64>,
    /// Authenticates the row's fixed fields under the integrity key.
    pub mac: Option<String>,
    /// SHA-256 of the token, for the routes open while sealed, which grant nothing.
    pub sealed_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    pub role_slug: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub project_id: String,
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    pub role_slug: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub wrapped_key: Vec<u8>,
    pub created_at: i64,
    /// When a logo was last set; `None` when the project has none.
    pub logo_updated_at: Option<i64>,
    /// Default generation and rotation policy as JSON; `None` is off.
    pub secret_policy: Option<String>,
    /// Secrets in this project may be restricted to their own access lists.
    pub secret_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectLogo {
    pub content_type: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: String,
    /// Empty for organisation roles.
    pub project_id: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<Rule>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    pub id: String,
    pub project_id: String,
    pub slug: String,
    pub name: String,
    pub position: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub environment_id: String,
    pub path: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub id: String,
    pub project_id: String,
    pub environment_id: String,
    pub path: String,
    pub key: String,
    pub current_version: i64,
    pub deleted: bool,
    pub created_at: i64,
    pub updated_at: i64,
    /// This secret's own policy override as JSON; `None` follows the project.
    pub policy: Option<String>,
    /// Only the principals on its access list, and admins, may reach it.
    pub restricted: bool,
}

/// One entry on a secret's access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretGrant {
    pub secret_id: String,
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    pub actions: Vec<Action>,
    pub created_at: i64,
}

/// Changes to one secret's access, applied together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessChange {
    pub secret_id: String,
    /// Restricting needs the project setting on, checked in the same transaction.
    pub restricted: Option<bool>,
    /// Added, or replacing the actions of an existing entry for the same principal.
    pub grant: Vec<SecretGrant>,
    pub revoke: Vec<(PrincipalKind, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVersion {
    pub secret_id: String,
    pub version: i64,
    /// Ciphertext; absent for a deletion marker.
    pub value: Option<Vec<u8>>,
    pub comment: String,
    pub tags: Vec<String>,
    pub deleted: bool,
    pub actor: String,
    pub created_at: i64,
    /// The value was generated by sekret, so rotation may replace it.
    pub generated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretWithVersion {
    pub secret: Secret,
    pub version: SecretVersion,
}

/// One change inside an atomic write. `previous_version` is 0 for a new secret and is used as
/// an optimistic lock for existing ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretChange {
    pub secret_id: String,
    pub path: String,
    pub key: String,
    pub previous_version: i64,
    pub version: SecretVersion,
    /// Restricts the secret in the same write, which needs the project setting on. False leaves
    /// an existing secret's flag as it is.
    pub restricted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBatch {
    pub project_id: String,
    pub environment_id: String,
    pub changes: Vec<SecretChange>,
    pub snapshot_id: String,
    pub reason: String,
    pub actor: String,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub secret_id: String,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    pub environment_id: String,
    pub entries: Vec<SnapshotEntry>,
    pub reason: String,
    pub actor: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub id: String,
    pub created_at: i64,
    pub actor_kind: String,
    pub actor_id: String,
    pub actor_name: String,
    pub action: String,
    pub project_id: Option<String>,
    pub environment: Option<String>,
    pub path: Option<String>,
    pub secret_key: Option<String>,
    pub detail: serde_json::Value,
    pub ip: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditQuery {
    pub project_id: Option<String>,
    /// Case-insensitive substring over action, actor, environment, path, key and address.
    pub search: Option<String>,
    /// Limit `search` to the action, actor and address, for readers who may not see every
    /// environment, folder and key.
    pub search_actors_only: bool,
    /// Prefix, so `secret.` matches every secret action.
    pub action: Option<String>,
    pub actor_id: Option<String>,
    pub actor_kind: Option<String>,
    pub environment: Option<String>,
    pub key: Option<String>,
    /// Folder prefix.
    pub path: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub oldest_first: bool,
    /// Continue after this `(created_at, id)` in the chosen order.
    pub after: Option<(i64, String)>,
    pub limit: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginState {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    pub created_at: i64,
    /// Set when the sign-in asked the provider for a fresh authentication within this many seconds.
    pub max_age: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliLogin {
    pub device_code_hash: String,
    pub user_code: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub approved_user_id: Option<String>,
    pub consumed: bool,
    /// The client address that started the login.
    pub requested_from_ip: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliPoll {
    Pending,
    /// `mac` authenticates the approval under the integrity key; absent on approvals from before.
    Approved {
        user_id: String,
        mac: Option<String>,
    },
    Gone,
}
