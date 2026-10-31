import { client, fetchDownload, unwrap } from "./client";
import type { operations } from "./schema";
import type {
  AddMembership,
  AddOrgBinding,
  AuthMethodConfig,
  AuthMethodKind,
  BatchWrite,
  ChangePassphrase,
  InitRequest,
  UnlockPolicy,
  CreateClientSecret,
  CreateEnvironment,
  CreateIdentity,
  CreateProject,
  GenerateSecret,
  PolicyOverride,
  PrincipalKind,
  PutRole,
  SecretPolicy,
  SetSecret,
  UpdateEnvironment,
  UpdateIdentity,
  UpdateProject,
} from "./types";

type QueryOf<T extends keyof operations> = NonNullable<operations[T]["parameters"]["query"]>;

export type AuditQuery = QueryOf<"org_audit">;
export type UserQuery = QueryOf<"list_users">;
export type IdentityQuery = QueryOf<"list_identities">;

interface SecretLocation {
  project: string;
  env: string;
  path: string;
}

function secretParams(at: SecretLocation, key: string) {
  return { path: { project: at.project, env: at.env, key }, query: { path: at.path } };
}

export const api = {
  /** Public: after setup, only the state, whether web setup is on, and the version. */
  sysStatus: () => unwrap(client.GET("/api/v1/sys/status")),
  /** Every status field; organisation admins only. */
  sysStatusDetail: () => unwrap(client.GET("/api/v1/sys/status/detail")),
  init: (body: InitRequest) => unwrap(client.POST("/api/v1/sys/init", { body })),
  unseal: (passphrase: string) => unwrap(client.POST("/api/v1/sys/unseal", { body: { passphrase } })),
  seal: () => unwrap(client.POST("/api/v1/sys/seal")),
  changePassphrase: (body: ChangePassphrase) => unwrap(client.POST("/api/v1/sys/passphrase", { body })),
  setUnlockPolicy: (policy: UnlockPolicy, passphrase?: string) =>
    unwrap(client.PUT("/api/v1/sys/unlock-policy", { body: { policy, passphrase: passphrase ?? null } })),
  forgetUnlock: () => unwrap(client.POST("/api/v1/sys/forget-unlock")),
  backup: () => fetchDownload("/api/v1/sys/backup", "sekret-backup.skb", "POST"),

  authConfig: () => unwrap(client.GET("/api/v1/auth/config")),
  me: () => unwrap(client.GET("/api/v1/me")),
  logout: () => unwrap(client.POST("/auth/logout")),
  pendingCli: (code: string) => unwrap(client.GET("/api/v1/auth/cli/pending", { params: { query: { code } } })),
  /** `code` must be the one the person typed from their terminal. */
  approveCli: (code: string) => unwrap(client.POST("/api/v1/auth/cli/approve", { body: { code } })),
  /** Ends the request, so the terminal that started it stops waiting. */
  denyCli: (code: string) => unwrap(client.POST("/api/v1/auth/cli/deny", { body: { code } })),

  projects: () => unwrap(client.GET("/api/v1/projects")),
  project: (project: string) => unwrap(client.GET("/api/v1/projects/{project}", { params: { path: { project } } })),
  createProject: (body: CreateProject) => unwrap(client.POST("/api/v1/projects", { body })),
  updateProject: (project: string, body: UpdateProject) =>
    unwrap(client.PATCH("/api/v1/projects/{project}", { params: { path: { project } }, body })),
  deleteProject: (project: string) =>
    unwrap(client.DELETE("/api/v1/projects/{project}", { params: { path: { project } } })),
  permissions: (project: string) =>
    unwrap(client.GET("/api/v1/projects/{project}/permissions", { params: { path: { project } } })),

  environments: (project: string) =>
    unwrap(client.GET("/api/v1/projects/{project}/environments", { params: { path: { project } } })),
  createEnvironment: (project: string, body: CreateEnvironment) =>
    unwrap(client.POST("/api/v1/projects/{project}/environments", { params: { path: { project } }, body })),
  updateEnvironment: (project: string, env: string, body: UpdateEnvironment) =>
    unwrap(
      client.PATCH("/api/v1/projects/{project}/environments/{env}", { params: { path: { project, env } }, body }),
    ),
  deleteEnvironment: (project: string, env: string) =>
    unwrap(client.DELETE("/api/v1/projects/{project}/environments/{env}", { params: { path: { project, env } } })),

  folders: (project: string, env: string) =>
    unwrap(client.GET("/api/v1/projects/{project}/environments/{env}/folders", { params: { path: { project, env } } })),
  createFolder: (project: string, env: string, path: string) =>
    unwrap(
      client.POST("/api/v1/projects/{project}/environments/{env}/folders", {
        params: { path: { project, env } },
        body: { path },
      }),
    ),
  deleteFolder: (project: string, env: string, path: string) =>
    unwrap(
      client.DELETE("/api/v1/projects/{project}/environments/{env}/folders", {
        params: { path: { project, env }, query: { path } },
      }),
    ),

  secrets: (at: SecretLocation, values: boolean) =>
    unwrap(
      client.GET("/api/v1/projects/{project}/environments/{env}/secrets", {
        params: { path: { project: at.project, env: at.env }, query: { path: at.path, values } },
      }),
    ),
  /** One secret with its value, when the caller may read it. */
  secret: (at: SecretLocation, key: string) =>
    unwrap(client.GET("/api/v1/projects/{project}/environments/{env}/secrets/{key}", { params: secretParams(at, key) })),
  setSecret: (at: SecretLocation, key: string, body: SetSecret) =>
    unwrap(client.PUT("/api/v1/projects/{project}/environments/{env}/secrets/{key}", { params: secretParams(at, key), body })),
  deleteSecret: (at: SecretLocation, key: string) =>
    unwrap(client.DELETE("/api/v1/projects/{project}/environments/{env}/secrets/{key}", { params: secretParams(at, key) })),
  batchWrite: (project: string, env: string, body: BatchWrite) =>
    unwrap(
      client.POST("/api/v1/projects/{project}/environments/{env}/secrets/batch", {
        params: { path: { project, env } },
        body,
      }),
    ),
  versions: (at: SecretLocation, key: string, values: boolean) =>
    unwrap(
      client.GET("/api/v1/projects/{project}/environments/{env}/secrets/{key}/versions", {
        params: { path: { project: at.project, env: at.env, key }, query: { path: at.path, values } },
      }),
    ),
  rollback: (at: SecretLocation, key: string, version: number) =>
    unwrap(
      client.POST("/api/v1/projects/{project}/environments/{env}/secrets/{key}/rollback", {
        params: secretParams(at, key),
        body: { version },
      }),
    ),
  generateSecret: (at: SecretLocation, key: string, body: GenerateSecret) =>
    unwrap(
      client.POST("/api/v1/projects/{project}/environments/{env}/secrets/{key}/generate", {
        params: secretParams(at, key),
        body,
      }),
    ),
  secretPolicy: (at: SecretLocation, key: string) =>
    unwrap(
      client.GET("/api/v1/projects/{project}/environments/{env}/secrets/{key}/policy", { params: secretParams(at, key) }),
    ),
  putSecretPolicy: (at: SecretLocation, key: string, body: PolicyOverride) =>
    unwrap(
      client.PUT("/api/v1/projects/{project}/environments/{env}/secrets/{key}/policy", {
        params: secretParams(at, key),
        body,
      }),
    ),
  projectPolicy: (project: string) =>
    unwrap(client.GET("/api/v1/projects/{project}/secret-policy", { params: { path: { project } } })),
  putProjectPolicy: (project: string, body: SecretPolicy) =>
    unwrap(client.PUT("/api/v1/projects/{project}/secret-policy", { params: { path: { project } }, body })),

  /** Sends the file's raw bytes. The schema types a binary body as a string, so the Blob is passed through untouched. */
  putLogo: (project: string, file: Blob) =>
    unwrap(
      client.PUT("/api/v1/projects/{project}/logo", {
        params: { path: { project } },
        body: file as unknown as string,
        bodySerializer: (body) => body as unknown as Blob,
        headers: { "Content-Type": file.type || "application/octet-stream" },
      }),
    ),
  deleteLogo: (project: string) =>
    unwrap(client.DELETE("/api/v1/projects/{project}/logo", { params: { path: { project } } })),

  overview: (project: string, path: string) =>
    unwrap(client.GET("/api/v1/projects/{project}/overview", { params: { path: { project }, query: { path } } })),

  snapshots: (project: string, env: string) =>
    unwrap(
      client.GET("/api/v1/projects/{project}/environments/{env}/snapshots", { params: { path: { project, env } } }),
    ),
  snapshot: (project: string, env: string, id: string, path: string) =>
    unwrap(
      client.GET("/api/v1/projects/{project}/environments/{env}/snapshots/{id}", {
        params: { path: { project, env, id }, query: { path } },
      }),
    ),
  restoreSnapshot: (project: string, env: string, id: string, path: string) =>
    unwrap(
      client.POST("/api/v1/projects/{project}/environments/{env}/snapshots/{id}/restore", {
        params: { path: { project, env, id } },
        body: { path },
      }),
    ),

  members: (project: string) =>
    unwrap(client.GET("/api/v1/projects/{project}/members", { params: { path: { project } } })),
  addMember: (project: string, body: AddMembership) =>
    unwrap(client.POST("/api/v1/projects/{project}/members", { params: { path: { project } }, body })),
  removeMember: (project: string, kind: PrincipalKind, id: string, role: string) =>
    unwrap(
      client.DELETE("/api/v1/projects/{project}/members/{kind}/{id}/{role}", {
        params: { path: { project, kind, id, role } },
      }),
    ),

  roles: (project: string) =>
    unwrap(client.GET("/api/v1/projects/{project}/roles", { params: { path: { project } } })),
  putRole: (project: string, slug: string, body: PutRole) =>
    unwrap(client.PUT("/api/v1/projects/{project}/roles/{slug}", { params: { path: { project, slug } }, body })),
  deleteRole: (project: string, slug: string) =>
    unwrap(client.DELETE("/api/v1/projects/{project}/roles/{slug}", { params: { path: { project, slug } } })),

  projectAudit: (project: string, query: AuditQuery) =>
    unwrap(client.GET("/api/v1/projects/{project}/audit", { params: { path: { project }, query } })),
  orgAudit: (query: AuditQuery) => unwrap(client.GET("/api/v1/audit", { params: { query } })),

  users: (query: UserQuery = {}) => unwrap(client.GET("/api/v1/users", { params: { query } })),
  setUserDisabled: (id: string, disabled: boolean) =>
    unwrap(client.PATCH("/api/v1/users/{id}", { params: { path: { id } }, body: { disabled } })),

  identities: (query: IdentityQuery = {}) => unwrap(client.GET("/api/v1/identities", { params: { query } })),
  identity: (id: string) => unwrap(client.GET("/api/v1/identities/{id}", { params: { path: { id } } })),
  createIdentity: (body: CreateIdentity) => unwrap(client.POST("/api/v1/identities", { body })),
  updateIdentity: (id: string, body: UpdateIdentity) =>
    unwrap(client.PATCH("/api/v1/identities/{id}", { params: { path: { id } }, body })),
  deleteIdentity: (id: string) => unwrap(client.DELETE("/api/v1/identities/{id}", { params: { path: { id } } })),
  revokeIdentityTokens: (id: string) =>
    unwrap(client.POST("/api/v1/identities/{id}/revoke-tokens", { params: { path: { id } } })),
  authMethods: (id: string) => unwrap(client.GET("/api/v1/identities/{id}/auth", { params: { path: { id } } })),
  putAuthMethod: (id: string, body: AuthMethodConfig) =>
    unwrap(client.PUT("/api/v1/identities/{id}/auth/{kind}", { params: { path: { id, kind: body.kind } }, body })),
  deleteAuthMethod: (id: string, kind: AuthMethodKind) =>
    unwrap(client.DELETE("/api/v1/identities/{id}/auth/{kind}", { params: { path: { id, kind } } })),
  clientSecrets: (id: string) =>
    unwrap(client.GET("/api/v1/identities/{id}/client-secrets", { params: { path: { id } } })),
  createClientSecret: (id: string, body: CreateClientSecret) =>
    unwrap(client.POST("/api/v1/identities/{id}/client-secrets", { params: { path: { id } }, body })),
  revokeClientSecret: (id: string, secret: string) =>
    unwrap(
      client.DELETE("/api/v1/identities/{id}/client-secrets/{secret}", { params: { path: { id, secret } } }),
    ),

  orgBindings: () => unwrap(client.GET("/api/v1/org/bindings")),
  addOrgBinding: (body: AddOrgBinding) => unwrap(client.POST("/api/v1/org/bindings", { body })),
  removeOrgBinding: (kind: PrincipalKind, id: string, role: string) =>
    unwrap(client.DELETE("/api/v1/org/bindings/{kind}/{id}/{role}", { params: { path: { kind, id, role } } })),
  orgRoles: () => unwrap(client.GET("/api/v1/org/roles")),
  putOrgRole: (slug: string, body: PutRole) =>
    unwrap(client.PUT("/api/v1/org/roles/{slug}", { params: { path: { slug } }, body })),
  deleteOrgRole: (slug: string) =>
    unwrap(client.DELETE("/api/v1/org/roles/{slug}", { params: { path: { slug } } })),
};
