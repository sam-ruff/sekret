import type {
  AuditEntry,
  AuthMethodConfig,
  ClientSecret,
  Environment,
  Identity,
  Me,
  Membership,
  OrgBinding,
  PolicyOverride,
  Project,
  Role,
  SecretPolicy,
  User,
} from "../types";

export interface StoredVersion {
  version: number;
  /** Null marks a deletion. */
  value: string | null;
  comment: string;
  tags: string[];
  actor: string;
  created_at: number;
  /** Written by sekret's generator, which makes it eligible for rotation. */
  generated?: boolean;
}

export interface StoredSecret {
  id: string;
  envId: string;
  path: string;
  key: string;
  versions: StoredVersion[];
  /** Absent means inherit the project policy. */
  policy?: PolicyOverride;
}

export interface StoredLogo {
  contentType: string;
  /** Base64, so the state survives a JSON round trip through session storage. */
  data: string;
  updated_at: number;
}

export interface StoredSnapshot {
  id: string;
  envId: string;
  reason: string;
  actor: string;
  created_at: number;
  entries: { secretId: string; version: number }[];
}

export interface StoredFolder {
  envId: string;
  path: string;
  created_at: number;
}

export interface StoredEnvironment extends Environment {
  projectId: string;
}

export interface StoredMembership extends Omit<Membership, "principal_name"> {
  projectId: string;
}

export type StoredIdentity = Omit<Identity, "auth_methods">;

export interface MockState {
  signedOut: boolean;
  seq: number;
  me: Me;
  users: User[];
  projects: Project[];
  environments: StoredEnvironment[];
  folders: StoredFolder[];
  secrets: StoredSecret[];
  snapshots: StoredSnapshot[];
  memberships: StoredMembership[];
  /** Custom roles keyed by project id; the empty key holds organisation roles. */
  roles: Record<string, Role[]>;
  orgBindings: Omit<OrgBinding, "principal_name">[];
  identities: StoredIdentity[];
  authMethods: Record<string, AuthMethodConfig[]>;
  clientSecrets: Record<string, ClientSecret[]>;
  audit: AuditEntry[];
  /** Keyed by project id. */
  logos: Record<string, StoredLogo>;
  /** Keyed by project id; absent means off. */
  projectPolicies: Record<string, SecretPolicy>;
}

export function isDeleted(secret: StoredSecret): boolean {
  return currentVersion(secret).value === null;
}

export function currentVersion(secret: StoredSecret): StoredVersion {
  return secret.versions[secret.versions.length - 1];
}
