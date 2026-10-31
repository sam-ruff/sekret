import type { components } from "./schema";

type Schemas = components["schemas"];

export type Action = Schemas["Action"];
export type AddMembership = Schemas["AddMembership"];
export type AddOrgBinding = Schemas["AddOrgBinding"];
export type AuditEntry = Schemas["AuditEntry"];
export type AuditPage = Schemas["AuditPage"];
export type AuthConfig = Schemas["AuthConfig"];
export type AuthMethodConfig = Schemas["AuthMethodConfig"];
export type AuthMethodKind = Schemas["AuthMethodKind"];
export type BatchResult = Schemas["BatchResult"];
export type BatchWrite = Schemas["BatchWrite"];
export type ChangePassphrase = Schemas["ChangePassphrase"];
export type Charset = Schemas["Charset"];
export type ClaimBindings = Schemas["ClaimBindings"];
export type CliApproveRequest = Schemas["CliApproveRequest"];
export type CliDenyRequest = Schemas["CliDenyRequest"];
export type ClientSecret = Schemas["ClientSecret"];
export type Conditions = Schemas["Conditions"];
export type CreateClientSecret = Schemas["CreateClientSecret"];
export type CreateEnvironment = Schemas["CreateEnvironment"];
export type CreateIdentity = Schemas["CreateIdentity"];
export type CreateProject = Schemas["CreateProject"];
export type CreatedClientSecret = Schemas["CreatedClientSecret"];
export type Effect = Schemas["Effect"];
export type Environment = Schemas["Environment"];
export type ErrorBody = Schemas["ErrorBody"];
export type Folder = Schemas["Folder"];
export type GenerateSecret = Schemas["GenerateSecret"];
export type Generator = Schemas["Generator"];
export type Identity = Schemas["Identity"];
export type InitRequest = Schemas["InitRequest"];
export type InitResponse = Schemas["InitResponse"];
export type IdentityPage = Schemas["IdentityPage"];
export type IdentitySort = Schemas["IdentitySort"];
export type KubernetesAuthConfig = Schemas["KubernetesAuthConfig"];
export type KubernetesMode = Schemas["KubernetesMode"];
export type LogoutResponse = Schemas["LogoutResponse"];
export type Me = Schemas["Me"];
export type Membership = Schemas["Membership"];
export type OidcAuthConfig = Schemas["OidcAuthConfig"];
export type OrgBinding = Schemas["OrgBinding"];
export type Overview = Schemas["Overview"];
export type OverviewRow = Schemas["OverviewRow"];
export type PassphraseCheck = Schemas["PassphraseCheck"];
export type PassphraseStrength = Schemas["PassphraseStrength"];
export type PendingCliLogin = Schemas["PendingCliLogin"];
export type PolicyOverride = Schemas["PolicyOverride"];
export type PrincipalKind = Schemas["PrincipalKind"];
export type Project = Schemas["Project"];
export type ProjectPermissions = Schemas["ProjectPermissions"];
export type PutRole = Schemas["PutRole"];
export type Role = Schemas["Role"];
export type Rule = Schemas["Rule"];
export type SealMode = Schemas["SealMode"];
export type SealState = Schemas["SealState"];
export type Secret = Schemas["Secret"];
export type SecretList = Schemas["SecretList"];
export type SecretPolicy = Schemas["SecretPolicy"];
export type SecretPolicyView = Schemas["SecretPolicyView"];
export type SecretUpsert = Schemas["SecretUpsert"];
export type SecretVersion = Schemas["SecretVersion"];
export type SetSecret = Schemas["SetSecret"];
export type SetUnlockPolicy = Schemas["SetUnlockPolicy"];
export type Snapshot = Schemas["Snapshot"];
export type SnapshotChange = Schemas["SnapshotChange"];
export type SnapshotDetail = Schemas["SnapshotDetail"];
export type SortOrder = Schemas["SortOrder"];
export type Status = Schemas["Status"];
export type Subject = Schemas["Subject"];
export type SysStatus = Schemas["SysStatus"];
export type UnlockPolicy = Schemas["UnlockPolicy"];
export type UnsealRequest = Schemas["UnsealRequest"];
export type UnsealedBy = Schemas["UnsealedBy"];
export type UpdateEnvironment = Schemas["UpdateEnvironment"];
export type UpdateIdentity = Schemas["UpdateIdentity"];
export type UpdateProject = Schemas["UpdateProject"];
export type User = Schemas["User"];
export type UserPage = Schemas["UserPage"];
export type UserSort = Schemas["UserSort"];

/** Returned in place of a stored write-only credential; sending it back keeps the stored value. */
export const REDACTED_CREDENTIAL = "[redacted]";

export const UNLOCK_POLICIES: readonly UnlockPolicy[] = ["manual", "remember", "passphrase-file"];

export const SEAL_MODES: readonly SealMode[] = ["passphrase", "key-file"];

export const UNSEALED_BY: readonly UnsealedBy[] = ["passphrase", "remember", "key-file", "passphrase-file"];

export const ACTIONS: readonly Action[] = ["read", "read-value", "create", "edit", "delete"];

export const PROJECT_SUBJECTS: readonly Subject[] = [
  "secrets",
  "secret-versions",
  "snapshots",
  "folders",
  "environments",
  "members",
  "roles",
  "audit-log",
  "settings",
];

export const ORG_SUBJECTS: readonly Subject[] = [
  "projects",
  "identities",
  "org-members",
  "org-roles",
  "org-audit-log",
  "backups",
];
