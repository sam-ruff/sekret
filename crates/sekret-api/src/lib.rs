//! Request and response types shared by the sekret server, CLI and operator.

use std::collections::BTreeMap;

pub use sekret_core::VERSION;
pub use sekret_core::claims::ClaimBindings;
pub use sekret_core::permissions::{Action, Conditions, Effect, Rule, Subject};
pub use sekret_core::rotation::{Charset, Generator, PolicyOverride, SecretPolicy};
pub use sekret_core::seal::{PassphraseStrength, SealMode, SealState, UnlockPolicy, UnsealedBy};
pub use sekret_core::validate::is_invisible_format;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
    /// zxcvbn's feedback, with `weak_passphrase`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strength: Option<PassphraseStrength>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LogoutResponse {
    /// The provider's end-session URL to send the browser to, when it has one.
    pub logout_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuthConfig {
    pub oidc_enabled: bool,
    pub login_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalKind {
    User,
    Group,
    Identity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Me {
    pub kind: PrincipalKind,
    pub id: String,
    pub name: String,
    pub email: String,
    pub groups: Vec<String>,
    /// Organisation-level rules, so clients can hide actions that would be refused.
    pub org_rules: Vec<Rule>,
    /// Organisation role slugs held, including those implied by configuration.
    #[serde(default)]
    pub org_roles: Vec<String>,
    /// Holds `org-admin`, the same check the system routes make.
    #[serde(default)]
    pub is_org_admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    /// Seconds until expiry.
    pub expires_in: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JwtLoginRequest {
    pub identity_id: String,
    /// The OIDC or Kubernetes service account token.
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UniversalLoginRequest {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CliStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CliPollRequest {
    pub device_code: String,
}

/// The code the person typed from their own terminal; a code carried in a link is not enough.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CliApproveRequest {
    pub code: String,
}

/// A CLI login waiting for approval, so the person can tell whether they started it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PendingCliLogin {
    /// Never set by this server: the person must type the whole code from their terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_hint: Option<String>,
    /// The client address that started the login, as the server saw it.
    pub requested_from_ip: String,
    /// Reported by the requester, so it can be faked.
    pub user_agent: String,
    /// Whether the requester's address matches the address of the browser asking. Behind shared
    /// NAT this can be true for someone else, and a VPN can make it false for the same person.
    pub same_address: bool,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
}

/// A CLI login to refuse; the code is typed or carried from the approval page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CliDenyRequest {
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Project {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub created_at: i64,
    /// Versioned URL of the project's logo, absent when it has none.
    #[serde(default)]
    pub logo_url: Option<String>,
    /// Secrets here may be restricted to their own access lists.
    #[serde(default)]
    pub secret_access: bool,
}

/// The project's per-secret access setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretAccessSetting {
    pub enabled: bool,
    /// Every restricted secret in the project the caller's roles let them see, deleted ones
    /// included. The setting cannot be turned off while any secret is restricted.
    pub restricted: Vec<RestrictedSecret>,
    /// Restricted secrets in the project, including any the caller's roles hide.
    pub restricted_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RestrictedSecret {
    pub environment: String,
    pub path: String,
    pub key: String,
    pub deleted: bool,
    /// Entries on its access list.
    pub grants: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SetSecretAccessSetting {
    pub enabled: bool,
}

/// One entry on a secret's access list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretGrant {
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    /// A user's verified email, or their display name when they have none; an identity's name;
    /// the group name for groups.
    pub principal_name: String,
    /// Always includes `read`; at most `read`, `read-value`, `edit` and `delete`.
    pub actions: Vec<Action>,
    pub created_at: i64,
}

/// Who may reach a secret beyond its role rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretAccess {
    /// Only principals on `grants`, project admins and organisation admins may reach it, and
    /// only as far as their roles also allow. Off, the list has no effect.
    pub restricted: bool,
    pub grants: Vec<SecretGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GrantRequest {
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    /// Any of `read`, `read-value`, `edit` and `delete`; `read` is always added.
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PrincipalRef {
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
}

/// Changes to one secret's access, applied together.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretAccessChange {
    /// Restricting needs the project setting on.
    #[serde(default)]
    pub restricted: Option<bool>,
    /// Entries to add, or to replace the actions of for a principal already listed.
    #[serde(default)]
    pub grant: Vec<GrantRequest>,
    #[serde(default)]
    pub revoke: Vec<PrincipalRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateProject {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Environments to create; defaults to development, staging and production.
    #[serde(default)]
    pub environments: Option<Vec<CreateEnvironment>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateProject {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Environment {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateEnvironment {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub position: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateEnvironment {
    pub name: String,
    pub position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Folder {
    pub path: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateFolder {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Secret {
    pub id: String,
    pub environment: String,
    pub path: String,
    pub key: String,
    /// Absent when the caller may see the key but not its value, or did not ask for values.
    pub value: Option<String>,
    pub value_hidden: bool,
    pub version: i64,
    pub comment: String,
    pub tags: Vec<String>,
    pub updated_at: i64,
    pub updated_by: String,
    /// The current value was generated by sekret, so rotation may replace it.
    #[serde(default)]
    pub generated: bool,
    /// When automatic rotation will next replace the value; absent when rotation does not apply.
    #[serde(default)]
    pub next_rotation_at: Option<i64>,
    /// Only principals on its access list, and admins, may reach it.
    #[serde(default)]
    pub restricted: bool,
    /// For a restricted secret, what its list grants the caller; absent when the list does not
    /// bind them, because the secret is open or they are an admin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted: Option<Vec<Action>>,
}

/// Request to fill a secret with a newly generated value, creating it if needed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GenerateSecret {
    /// Overrides the secret's policy generator for this value only.
    #[serde(default)]
    pub generator: Option<Generator>,
    #[serde(default)]
    pub comment: String,
    /// See [`SecretUpsert::restricted`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted: Option<bool>,
}

/// A secret's own policy setting together with what actually applies to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretPolicyView {
    pub setting: PolicyOverride,
    pub effective: SecretPolicy,
    pub generated: bool,
    pub next_rotation_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretList {
    pub secrets: Vec<Secret>,
    pub folders: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SetSecret {
    pub value: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// See [`SecretUpsert::restricted`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretUpsert {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// `true` creates the secret restricted, with an empty access list, so it is never open
    /// even for a moment; that needs a project admin and the project setting on. A deleted
    /// secret can be brought back restricted the same way. Otherwise, for a secret that already
    /// exists it must match whether it is restricted, which only the access route changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BatchWrite {
    #[serde(default = "root_path")]
    pub path: String,
    #[serde(default)]
    pub upserts: Vec<SecretUpsert>,
    #[serde(default)]
    pub deletes: Vec<String>,
}

fn root_path() -> String {
    "/".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BatchResult {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: Vec<String>,
    pub snapshot_id: Option<String>,
    /// The keys that asked for `restricted: true` and are restricted after this write. A client
    /// should treat a key missing here as open, since a server that predates per-secret access
    /// ignores the request.
    #[serde(default)]
    pub restricted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecretVersion {
    pub version: i64,
    pub value: Option<String>,
    pub value_hidden: bool,
    pub deleted: bool,
    pub comment: String,
    pub tags: Vec<String>,
    pub actor: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RollbackRequest {
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RawSecret {
    pub path: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RawSecrets {
    pub project: String,
    pub environment: String,
    pub secrets: Vec<RawSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OverviewRow {
    pub path: String,
    pub key: String,
    /// Environment slug to version, absent where the key is missing.
    pub environments: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Overview {
    pub environments: Vec<Environment>,
    pub rows: Vec<OverviewRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Snapshot {
    pub id: String,
    pub reason: String,
    pub actor: String,
    pub created_at: i64,
    pub secret_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SnapshotChange {
    pub path: String,
    pub key: String,
    pub kind: SnapshotChangeKind,
    pub snapshot_version: Option<i64>,
    pub current_version: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SnapshotDetail {
    pub snapshot: Snapshot,
    /// What restoring this snapshot would change.
    pub changes: Vec<SnapshotChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RestoreRequest {
    /// Restrict the restore to this folder and everything beneath it.
    #[serde(default = "root_path")]
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Membership {
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    /// Display name for users and identities; the group name for groups.
    pub principal_name: String,
    pub role: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AddMembership {
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Role {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub builtin: bool,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PutRole {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProjectPermissions {
    pub rules: Vec<Rule>,
    /// The caller is a project or organisation admin, so manages per-secret access and is
    /// exempt from access lists, though not from their own rules.
    #[serde(default)]
    pub manages_secret_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub groups: Vec<String>,
    pub disabled: bool,
    pub created_at: i64,
    pub last_login_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateUser {
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OrgBinding {
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    pub principal_name: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AddOrgBinding {
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub description: String,
    pub token_ttl: i64,
    pub token_max_ttl: i64,
    pub trusted_cidrs: Vec<String>,
    pub disabled: bool,
    pub created_at: i64,
    pub auth_methods: Vec<AuthMethodKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateIdentity {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub token_ttl: Option<i64>,
    #[serde(default)]
    pub token_max_ttl: Option<i64>,
    #[serde(default)]
    pub trusted_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UpdateIdentity {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub token_ttl: i64,
    pub token_max_ttl: i64,
    #[serde(default)]
    pub trusted_cidrs: Vec<String>,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethodKind {
    Oidc,
    Kubernetes,
    Universal,
}

impl AuthMethodKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethodKind::Oidc => "oidc",
            AuthMethodKind::Kubernetes => "kubernetes",
            AuthMethodKind::Universal => "universal",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "oidc" => Some(AuthMethodKind::Oidc),
            "kubernetes" => Some(AuthMethodKind::Kubernetes),
            "universal" => Some(AuthMethodKind::Universal),
            _ => None,
        }
    }
}

/// Machine login using JWTs from any OIDC issuer, such as GitHub Actions or Keycloak service accounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OidcAuthConfig {
    pub issuer: String,
    /// Overrides discovery when the issuer does not publish `.well-known/openid-configuration`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    pub bindings: ClaimBindings,
    /// Longest token accepted, from `iat` to `exp`, in seconds; 3600 when left out, and at most
    /// ten years. Tokens without `iat` are refused.
    #[serde(default = "default_max_token_lifetime")]
    #[schema(minimum = 1, maximum = 315_360_000)]
    pub max_token_lifetime: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum KubernetesMode {
    /// Ask the cluster's TokenReview API, authenticating with `reviewer_jwt` or, without one, the presented token.
    TokenReview,
    /// Verify the service account JWT against the cluster's signing keys.
    Jwks,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct KubernetesAuthConfig {
    pub mode: KubernetesMode,
    /// API server URL, required for TokenReview.
    #[serde(default)]
    pub host: Option<String>,
    /// PEM CA bundle for the API server.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// Token of a service account bound to `system:auth-delegator`. Write-only: reads return
    /// `[redacted]`, and sending that value back keeps the stored token.
    #[serde(default)]
    pub reviewer_jwt: Option<String>,
    /// Service account issuer, required for JWKS mode.
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Inline JWKS document, as returned by `kubectl get --raw /openid/v1/jwks`.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// Globs over namespaces.
    pub namespaces: Vec<String>,
    /// Globs over service account names.
    pub service_accounts: Vec<String>,
    #[serde(default = "default_k8s_audiences")]
    pub audiences: Vec<String>,
    /// Longest service account token accepted, from `iat` to `exp`, in seconds; 3600 when left
    /// out, and at most ten years. Tokens without `iat` are refused. In TokenReview mode it
    /// applies to tokens whose claims can be read.
    #[serde(default = "default_max_token_lifetime")]
    #[schema(minimum = 1, maximum = 315_360_000)]
    pub max_token_lifetime: i64,
}

/// Stands in for a stored credential in responses.
pub const REDACTED_CREDENTIAL: &str = "[redacted]";

/// A cluster admin could otherwise mint a year-long token, which in JWKS mode outlives deleting
/// its service account.
pub const DEFAULT_MAX_TOKEN_LIFETIME: i64 = 3600;

fn default_max_token_lifetime() -> i64 {
    DEFAULT_MAX_TOKEN_LIFETIME
}

fn default_k8s_audiences() -> Vec<String> {
    vec!["sekret".into()]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuthMethodConfig {
    Oidc(OidcAuthConfig),
    Kubernetes(KubernetesAuthConfig),
    Universal,
}

impl AuthMethodConfig {
    pub fn kind(&self) -> AuthMethodKind {
        match self {
            AuthMethodConfig::Oidc(_) => AuthMethodKind::Oidc,
            AuthMethodConfig::Kubernetes(_) => AuthMethodKind::Kubernetes,
            AuthMethodConfig::Universal => AuthMethodKind::Universal,
        }
    }
}

/// The longest lifetime, in seconds, that a client secret or a Kubernetes token limit may be
/// given: ten years.
pub const MAX_LIFETIME: i64 = 10 * 365 * 86_400;
/// The most uses a client secret may be limited to.
pub const MAX_CLIENT_SECRET_USES: i64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreateClientSecret {
    #[serde(default)]
    pub description: String,
    /// Seconds until the secret stops working, at most ten years; never when absent.
    #[serde(default)]
    #[schema(minimum = 1, maximum = 315_360_000)]
    pub ttl: Option<i64>,
    #[serde(default)]
    #[schema(minimum = 1, maximum = 1_000_000_000)]
    pub max_uses: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ClientSecret {
    pub id: String,
    pub description: String,
    pub prefix: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub uses_remaining: Option<i64>,
    pub revoked: bool,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CreatedClientSecret {
    pub client_id: String,
    /// Shown once; only a hash is stored.
    pub client_secret: String,
    pub secret: ClientSecret,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AuditPage {
    pub entries: Vec<AuditEntry>,
    /// Entries matching the filters across all pages.
    pub total: i64,
    /// Pass back as `cursor` for the next page; absent on the last page.
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    #[default]
    Desc,
    Asc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UserPage {
    pub items: Vec<User>,
    pub total: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IdentityPage {
    pub items: Vec<Identity>,
    pub total: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
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

/// `GET /sys/status` answers without authentication, so monitoring can alert on a sealed server,
/// and then fills in only `state`, `web_setup` and `version`, plus what configuration has decided
/// while uninitialised. `GET /sys/status/detail` fills in every field for organisation admins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SysStatus {
    pub state: SealState,
    /// Once initialised, the stored mode. Before that, the mode the configuration requires, if any.
    pub seal_mode: Option<SealMode>,
    /// How the server is unlocked after a start; passphrase mode only. Before setup, the policy
    /// the configuration sets, if any.
    pub unlock_policy: Option<UnlockPolicy>,
    /// The unlock policy comes from server configuration and cannot be changed through the API.
    pub configured: bool,
    /// A remembered unlock is in place, so the next start unlocks itself. Sealing by hand does not
    /// clear it; forget the unlock for that.
    pub remembered: bool,
    /// The configuration sets `seal.remember_file`, so the remember policy can be chosen. Shown
    /// before setup and to organisation admins.
    #[serde(default)]
    pub remember_available: bool,
    /// How the root key got into memory, while unsealed. `key-file` with a passphrase `seal_mode`
    /// means a root key file overrode the passphrase.
    #[serde(default)]
    pub unsealed_by: Option<UnsealedBy>,
    /// First-boot setup is offered through the API and web interface.
    pub web_setup: bool,
    pub version: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InitRequest {
    /// The one-time code from the server log.
    #[schema(value_type = String)]
    pub setup_code: Zeroizing<String>,
    pub mode: SealMode,
    /// Required in passphrase mode; at least 12 characters.
    #[schema(value_type = Option<String>)]
    pub passphrase: Option<Zeroizing<String>>,
    /// Passphrase mode only; `manual` when absent.
    #[serde(default)]
    pub unlock_policy: Option<UnlockPolicy>,
}

impl std::fmt::Debug for InitRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitRequest")
            .field("mode", &self.mode)
            .field("unlock_policy", &self.unlock_policy)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InitResponse {
    pub status: SysStatus,
    /// A short-lived organisation admin token, shown once.
    pub admin_token: String,
    /// Unix seconds when `admin_token` stops working.
    #[serde(default)]
    pub admin_token_expires_at: i64,
}

impl std::fmt::Debug for InitResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UnsealRequest {
    #[schema(value_type = String)]
    pub passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for UnsealRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsealRequest").finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ChangePassphrase {
    #[schema(value_type = String)]
    pub current: Zeroizing<String>,
    #[schema(value_type = String)]
    pub new: Zeroizing<String>,
    /// Re-encrypt what can be read and leave values, project keys or stored credentials that no
    /// longer decrypt as they are, auditing each. Without it, the change is refused and the error
    /// lists them.
    #[serde(default)]
    pub skip_unreadable: bool,
}

impl std::fmt::Debug for ChangePassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePassphrase").finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SetUnlockPolicy {
    pub policy: UnlockPolicy,
    /// The current passphrase; required for `remember` and `passphrase-file`, which weaken how
    /// the server is unlocked.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub passphrase: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for SetUnlockPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetUnlockPolicy")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PassphraseCheck {
    #[schema(value_type = String)]
    pub passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for PassphraseCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassphraseCheck").finish_non_exhaustive()
    }
}
