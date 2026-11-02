import { authorise, type Resource } from "@/lib/permissions";
import { isCompleteCode, normaliseUserCode } from "@/lib/cli-code";
import { isValidSecretKey } from "@/lib/dotenv";
import { keyPatternCanMatch, pathPatternCanMatch } from "@/lib/glob";
import { DEFAULT_GENERATOR, MAX_LENGTH, MAX_ROTATION_DAYS, MIN_LENGTH } from "@/lib/generation";
import { MAX_LOGO_BYTES, validateImage } from "@/lib/images";
import type {
  Action,
  AddMembership,
  AddOrgBinding,
  AuthConfig,
  AuditEntry,
  AuditPage,
  AuthMethodConfig,
  AuthMethodKind,
  BatchResult,
  BatchWrite,
  ChangePassphrase,
  ClientSecret,
  CreateClientSecret,
  CreatedClientSecret,
  CreateEnvironment,
  CreateIdentity,
  CreateProject,
  Environment,
  Folder,
  GenerateSecret,
  Generator,
  Identity,
  IdentityPage,
  InitRequest,
  InitResponse,
  Me,
  Membership,
  OrgBinding,
  Overview,
  PassphraseStrength,
  PendingCliLogin,
  PolicyOverride,
  PrincipalKind,
  Project,
  PutRole,
  Role,
  Rule,
  Secret,
  SecretList,
  SecretPolicy,
  SecretPolicyView,
  SecretUpsert,
  SecretVersion,
  SetSecret,
  Snapshot,
  SnapshotChange,
  SnapshotDetail,
  SortOrder,
  Subject,
  SysStatus,
  UnlockPolicy,
  UpdateEnvironment,
  UpdateIdentity,
  UpdateProject,
  User,
  UserPage,
} from "../types";
import type { StrengthChecker } from "@/lib/passphrase";
import { ORG_SUBJECTS, PROJECT_SUBJECTS, REDACTED_CREDENTIAL } from "../types";
import type { AuditQuery, IdentityQuery, UserQuery } from "../endpoints";
import { generateValue } from "./generate";
import { builtinRoles, covers } from "./roles";
import {
  compactUtc,
  MAX_FAILED_UNSEALS,
  MOCK_BACKOFF_SECONDS,
  MOCK_FOREIGN_KEY_PASSPHRASE,
  MOCK_STALE_MARK_PASSPHRASE,
  MOCK_KDF_BUSY_PASSPHRASE,
  MOCK_CLI_ADDRESS,
  MOCK_CLI_USER_AGENT,
  MOCK_IDP_LOGOUT_URL,
  MOCK_REAUTH_CODE_PREFIX,
  MOCK_SAME_ADDRESS_CODE_PREFIX,
  MOCK_SETUP_CODE,
  MOCK_VERSION,
  publicStatusOf,
  statusOf,
  sysFromControls,
} from "./sys";
import type { MockControls } from "./controls";
import {
  currentVersion,
  isDeleted,
  type MockState,
  type StoredEnvironment,
  type StoredSecret,
  type StoredVersion,
} from "./state";

const DAY = 24 * 3600;
const DEFAULT_PAGE = 50;
const MAX_PAGE = 500;
/** Mirrors the server's history page sizes. */
export const DEFAULT_HISTORY_PAGE = 100;
export const MAX_HISTORY_PAGE = 200;

/** The actor the server records on automatic rotations. */
export const ROTATION_ACTOR = { kind: "identity", id: "sekret-rotation", name: "automatic rotation" } as const;

interface AuditActor {
  kind: string;
  id: string;
  name: string;
  ip?: string;
}

export function encodeCursor(createdAt: number, id: string): string {
  return btoa(`${createdAt}:${id}`).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeCursor(cursor: string): [number, string] {
  const invalid = () => badRequest("cursor is not valid");
  let text: string;
  try {
    text = atob(cursor.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    throw invalid();
  }
  const split = text.indexOf(":");
  if (split < 0) throw invalid();
  const createdAt = Number(text.slice(0, split));
  if (!/^-?\d+$/.test(text.slice(0, split)) || !Number.isSafeInteger(createdAt)) throw invalid();
  return [createdAt, text.slice(split + 1)];
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(data: string): Uint8Array {
  return Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
}

function emptyToUndefined(value: string | null | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function compareIds(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function ordered(ordering: number, order: SortOrder | undefined): number {
  return (order ?? "asc") === "asc" ? ordering : -ordering;
}

function slice<T>(items: T[], offset: number | undefined, limit: number | undefined): { items: T[]; total: number } {
  const start = Math.max(0, offset ?? 0);
  const size = Math.min(MAX_PAGE, Math.max(1, limit ?? DEFAULT_PAGE));
  return { items: items.slice(start, start + size), total: items.length };
}

function validatePolicy(policy: SecretPolicy): void {
  const length = policy.generator?.length;
  if (length !== undefined && (length < MIN_LENGTH || length > MAX_LENGTH)) {
    throw badRequest(`length must be between ${MIN_LENGTH} and ${MAX_LENGTH}`);
  }
  const days = policy.rotation_days;
  if (days != null && (days < 1 || days > MAX_ROTATION_DAYS)) {
    throw badRequest(`rotation must be between 1 and ${MAX_ROTATION_DAYS} days`);
  }
}

function normalisePolicy(policy: SecretPolicy): SecretPolicy {
  const generator = policy.generator ? { length: policy.generator.length, charset: policy.generator.charset ?? "alphanumeric" } : null;
  return { generator, rotation_days: policy.rotation_days ?? null };
}

export class MockError extends Error {
  readonly status: number;
  readonly code: string;
  /** Extra fields of the error body, such as zxcvbn's feedback. */
  readonly extra: Record<string, unknown>;

  constructor(status: number, code: string, message: string, extra: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const badRequest = (message: string, code = "bad_request") => new MockError(400, code, message);

/** The server's `MAX_PRINCIPAL_PATTERNS`: path and key patterns one caller's secret rules may hold. */
const MAX_PRINCIPAL_PATTERNS = 400;

/** The server's `MAX_LIFETIME`: ten years. */
const MAX_TOKEN_LIFETIME = 10 * 365 * 86_400;

function checkLifetimeSetting(seconds: number | null | undefined): void {
  if (seconds == null) return;
  if (seconds < 1 || seconds > MAX_TOKEN_LIFETIME) {
    throw badRequest("max_token_lifetime must be between 1 second and 10 years");
  }
}

/** Mirrors the server: credentials in the URL and cloud metadata addresses are refused, with the URL named. */
function checkOutboundUrl(raw: string): void {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw badRequest(`url not allowed: ${raw}`);
  }
  const host = url.hostname.toLowerCase();
  const metadata =
    /^169\.254\./.test(host) ||
    host === "100.100.100.200" ||
    host === "[fd00:ec2::254]" ||
    /^\[::ffff:a9fe:[0-9a-f]{1,4}\]$/.test(host);
  if (url.username || url.password || metadata) throw badRequest(`url not allowed: ${raw}`);
}
const notFound = (what: string) => new MockError(404, "not_found", `${what} not found`);
const forbidden = () => new MockError(403, "forbidden", "you do not have permission to do that");
const escalation = (message: string) => new MockError(403, "escalation", message);

const SLUG = /^[a-z0-9][a-z0-9-]{0,63}$/;
const DEFAULT_ENVIRONMENTS: CreateEnvironment[] = [
  { slug: "dev", name: "Development" },
  { slug: "staging", name: "Staging" },
  { slug: "prod", name: "Production" },
];

function checkSlug(value: string): void {
  if (!SLUG.test(value)) throw badRequest("slug must be 1-64 lowercase letters, digits or '-'");
}

function checkName(value: string): void {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128) throw badRequest("name must be 1-128 printable characters");
}

export function normaliseFolder(path: string): string {
  if (!path.startsWith("/")) throw badRequest("path must be absolute and made of segments using letters, digits, '_', '-' or '.'");
  const segments = path.split("/").filter(Boolean);
  if (segments.some((s) => !/^[A-Za-z0-9_.-]+$/.test(s) || s === "." || s === "..")) {
    throw badRequest("path must be absolute and made of segments using letters, digits, '_', '-' or '.'");
  }
  return `/${segments.join("/")}`;
}

function within(path: string, folder: string): boolean {
  return folder === "/" || path === folder || path.startsWith(`${folder}/`);
}

function normaliseTags(tags: string[]): string[] {
  const clean = Array.from(new Set(tags.map((t) => t.trim()).filter(Boolean))).sort();
  if (clean.length > 32 || clean.some((t) => !SLUG.test(t))) throw badRequest("tags must be up to 32 lowercase slugs");
  return clean;
}

function redact(config: AuthMethodConfig): AuthMethodConfig {
  if (config.kind !== "kubernetes" || !config.reviewer_jwt) return config;
  return { ...config, reviewer_jwt: REDACTED_CREDENTIAL };
}

function principalLabel(user: User): string {
  return user.email || user.name;
}

export class MockBackend {
  private readonly state: MockState;
  private readonly now: () => number;

  constructor(state: MockState, now: () => number) {
    this.state = state;
    this.now = now;
  }

  private nextId(prefix: string): string {
    this.state.seq += 1;
    return `${prefix}-${this.state.seq.toString(36).padStart(4, "0")}`;
  }

  private get actor(): string {
    return this.state.me.email || this.state.me.name;
  }

  private audit(
    action: string,
    target: Partial<Pick<AuditEntry, "project_id" | "environment" | "path" | "secret_key">>,
    detail: unknown = {},
    actor?: AuditActor,
  ): void {
    this.state.audit.unshift({
      id: this.nextId("audit"),
      created_at: this.now(),
      actor_kind: actor?.kind ?? "user",
      actor_id: actor?.id ?? this.state.me.id,
      actor_name: actor?.name ?? this.actor,
      action,
      project_id: target.project_id ?? null,
      environment: target.environment ?? null,
      path: target.path ?? null,
      secret_key: target.secret_key ?? null,
      detail,
      ip: actor?.ip ?? "127.0.0.1",
    });
  }

  /** Records activity by someone other than the caller, for seeding a realistic history. */
  recordAudit(
    action: string,
    actor: AuditActor,
    target: Partial<Pick<AuditEntry, "project_id" | "environment" | "path" | "secret_key">> = {},
    detail: unknown = {},
  ): void {
    this.audit(action, target, detail, actor);
  }

  // Session and identity of the caller

  requireSession(): void {
    if (this.state.signedOut) throw new MockError(401, "unauthorised", "sign in required");
  }

  signIn(fresh = false): void {
    this.state.signedOut = false;
    this.state.freshSignIn = fresh;
  }

  authConfig(): AuthConfig {
    return { oidc_enabled: !this.state.oidcDisabled, login_url: "/auth/login" };
  }

  logout(): { logout_url: string | null } {
    this.state.signedOut = true;
    this.state.freshSignIn = false;
    return { logout_url: this.state.idpLogoutUrl ?? null };
  }

  orgRules(): Rule[] {
    const custom = this.state.roles[""] ?? [];
    const slugs = this.state.orgBindings
      .filter((b) => this.principalIsMe(b.principal_kind, b.principal_id))
      .map((b) => b.role);
    return slugs.flatMap((slug) => this.roleRules(slug, custom, true) ?? []);
  }

  private principalIsMe(kind: PrincipalKind, id: string): boolean {
    if (kind === "group") return this.state.me.groups.includes(id);
    return kind === "user" && id === this.state.me.id;
  }

  private roleRules(slug: string, custom: Role[], orgScope: boolean): Rule[] | undefined {
    const builtin = builtinRoles(orgScope).find((r) => r.slug === slug);
    return builtin?.rules ?? custom.find((r) => r.slug === slug)?.rules;
  }

  private projectRules(projectId: string): Rule[] {
    const custom = this.state.roles[projectId] ?? [];
    const mine = this.state.memberships.filter(
      (m) => m.projectId === projectId && this.principalIsMe(m.principal_kind, m.principal_id),
    );
    return [...this.orgRules(), ...mine.flatMap((m) => this.roleRules(m.role, custom, false) ?? [])];
  }

  private requireOrg(subject: Subject, action: Action): void {
    if (!authorise(this.orgRules(), subject, action)) throw forbidden();
  }

  /** As the server: an org admin's changes to roles, bindings and members are judged by the org-admin role alone. */
  private managementRules(rules: Rule[]): Rule[] {
    if (!this.isOrgAdmin()) return rules;
    return this.roleRules("org-admin", [], true) ?? rules;
  }

  /** Whether a binding to (`kind`, `id`) reaches an org admin, or a project admin of `projectId`. */
  private reachesAdmin(kind: PrincipalKind, id: string, projectId?: string): boolean {
    const admins = [
      ...this.state.orgBindings.filter((b) => b.role === "org-admin"),
      ...this.state.memberships.filter((m) => m.projectId === projectId && m.role === "admin"),
    ];
    const user = kind === "user" ? this.state.users.find((u) => u.id === id) : undefined;
    const reach = [`${kind}:${id}`, ...(user?.groups ?? []).map((g) => `group:${g}`)];
    return admins.some((a) => reach.includes(`${a.principal_kind}:${a.principal_id}`));
  }

  /** Only an admin may bind deny rules to an admin, so nobody else can lock them out. */
  private checkDenyForAdmin(granted: Rule[], kind: PrincipalKind, id: string, administers: boolean, projectId?: string): void {
    if (!granted.some((r) => r.effect === "deny") || administers) return;
    if (this.reachesAdmin(kind, id, projectId)) throw escalation("only an admin can bind deny rules to an admin");
  }

  me(): Me {
    const roles = this.orgRoleSlugs();
    return { ...this.state.me, org_rules: this.orgRules(), org_roles: roles, is_org_admin: roles.includes("org-admin") };
  }

  private orgRoleSlugs(): string[] {
    const slugs = this.state.orgBindings.filter((b) => this.principalIsMe(b.principal_kind, b.principal_id)).map((b) => b.role);
    return [...new Set(slugs)].sort();
  }

  /** Replaces the caller's organisation roles with one, to try the interface as someone else. */
  setMyOrgRole(role: string): void {
    const others = this.state.orgBindings.filter((b) => !this.principalIsMe(b.principal_kind, b.principal_id));
    this.state.orgBindings = [...others, { principal_kind: "user", principal_id: this.state.me.id, role }];
  }

  applyControls(controls: MockControls): void {
    this.state.sys = sysFromControls(this.state.sys, controls);
    if (controls.orgRole) this.setMyOrgRole(controls.orgRole);
    if (controls.idpLogout) this.state.idpLogoutUrl = MOCK_IDP_LOGOUT_URL;
    if (controls.oidc !== undefined) this.state.oidcDisabled = !controls.oidc;
  }

  // Projects

  private loadProject(idOrSlug: string): { project: Project; rules: Rule[] } {
    const project = this.state.projects.find((p) => p.id === idOrSlug || p.slug === idOrSlug);
    if (!project) throw notFound("project");
    const rules = this.projectRules(project.id);
    const visible = rules.some((r) => r.effect === "allow" && PROJECT_SUBJECTS.includes(r.subject) && r.actions.length > 0);
    if (!visible) throw notFound("project");
    return { project, rules };
  }

  private require(rules: Rule[], subject: Subject, action: Action, resource: Resource = {}): void {
    if (!authorise(rules, subject, action, resource)) throw forbidden();
  }

  private apiProject(project: Project): Project {
    const logo = this.state.logos[project.id];
    return { ...project, logo_url: logo ? `/api/v1/projects/${project.id}/logo?v=${logo.updated_at}` : null };
  }

  listProjects(): Project[] {
    return this.state.projects
      .filter((p) => {
        try {
          this.loadProject(p.id);
          return true;
        } catch {
          return false;
        }
      })
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((p) => this.apiProject(p));
  }

  getProject(id: string): Project {
    return this.apiProject(this.loadProject(id).project);
  }

  createProject(request: CreateProject): Project {
    this.requireOrg("projects", "create");
    checkSlug(request.slug);
    checkName(request.name);
    if (this.state.projects.some((p) => p.slug === request.slug)) {
      throw new MockError(409, "conflict", "the record already exists or was changed by someone else; reload and try again");
    }
    const project: Project = {
      id: this.nextId("proj"),
      slug: request.slug,
      name: request.name.trim(),
      description: request.description ?? "",
      created_at: this.now(),
    };
    const envs = request.environments ?? DEFAULT_ENVIRONMENTS;
    envs.forEach((e) => {
      checkSlug(e.slug);
      checkName(e.name);
    });
    this.state.projects.push(project);
    envs.forEach((e, index) => {
      this.state.environments.push({
        id: this.nextId("env"),
        projectId: project.id,
        slug: e.slug,
        name: e.name,
        position: e.position ?? index,
      });
    });
    this.state.memberships.push({
      projectId: project.id,
      principal_kind: "user",
      principal_id: this.state.me.id,
      role: "admin",
      created_at: this.now(),
    });
    this.audit("project.create", { project_id: project.id }, { slug: project.slug });
    return this.apiProject(project);
  }

  updateProject(id: string, request: UpdateProject): Project {
    const { project, rules } = this.loadProject(id);
    this.require(rules, "settings", "edit");
    checkName(request.name);
    project.name = request.name.trim();
    project.description = request.description ?? "";
    this.audit("project.update", { project_id: project.id });
    return this.apiProject(project);
  }

  // Logos

  /**
   * The server stores every logo as a PNG of at most 512px. `rendered` is that PNG when the caller
   * could produce one; without it the original is kept, which only happens in unit tests.
   */
  putLogo(id: string, bytes: Uint8Array, rendered?: Uint8Array): Project {
    const { project, rules } = this.loadProject(id);
    this.require(rules, "settings", "edit");
    if (bytes.length > MAX_LOGO_BYTES) throw new MockError(413, "too_large", "logos can be at most 512 KiB");
    const check = validateImage(bytes);
    if (!check.ok) throw badRequest(check.message);
    const stored = rendered ?? bytes;
    const contentType = rendered ? "image/png" : check.type;
    this.state.logos[project.id] = { contentType, data: toBase64(stored), updated_at: this.now() };
    this.audit("project.logo-set", { project_id: project.id }, { content_type: "image/png", bytes: bytes.length });
    return this.apiProject(project);
  }

  getLogo(id: string): { contentType: string; bytes: Uint8Array } {
    const { project } = this.loadProject(id);
    const logo = this.state.logos[project.id];
    if (!logo) throw notFound("logo");
    return { contentType: logo.contentType, bytes: fromBase64(logo.data) };
  }

  deleteLogo(id: string): Project {
    const { project, rules } = this.loadProject(id);
    this.require(rules, "settings", "edit");
    delete this.state.logos[project.id];
    this.audit("project.logo-remove", { project_id: project.id });
    return this.apiProject(project);
  }

  // Secret policies

  private projectPolicyOf(projectId: string): SecretPolicy {
    return this.state.projectPolicies[projectId] ?? { generator: null, rotation_days: null };
  }

  private effectivePolicy(projectId: string, secret: StoredSecret | undefined): SecretPolicy {
    if (secret?.policy?.mode === "custom") return normalisePolicy(secret.policy);
    return this.projectPolicyOf(projectId);
  }

  private nextRotation(projectId: string, secret: StoredSecret): number | null {
    const current = currentVersion(secret);
    const days = this.effectivePolicy(projectId, secret).rotation_days;
    if (!days || !current.generated || isDeleted(secret)) return null;
    return current.created_at + days * DAY;
  }

  getProjectPolicy(id: string): SecretPolicy {
    const { project, rules } = this.loadProject(id);
    this.require(rules, "settings", "read");
    return this.projectPolicyOf(project.id);
  }

  putProjectPolicy(id: string, request: SecretPolicy): SecretPolicy {
    const { project, rules } = this.loadProject(id);
    this.require(rules, "settings", "edit");
    validatePolicy(request);
    const policy = normalisePolicy(request);
    if (!policy.generator && !policy.rotation_days) delete this.state.projectPolicies[project.id];
    else this.state.projectPolicies[project.id] = policy;
    this.audit("project.secret-policy", { project_id: project.id }, { policy });
    return policy;
  }

  private policyView(projectId: string, secret: StoredSecret): SecretPolicyView {
    return {
      setting: secret.policy ?? { mode: "inherit" },
      effective: this.effectivePolicy(projectId, secret),
      generated: !!currentVersion(secret).generated,
      next_rotation_at: this.nextRotation(projectId, secret),
    };
  }

  getSecretPolicy(projectId: string, envSlug: string, key: string, rawPath: string): SecretPolicyView {
    const { project, secret } = this.readableSecret(projectId, envSlug, key, rawPath);
    return this.policyView(project.id, secret);
  }

  putSecretPolicy(projectId: string, envSlug: string, key: string, rawPath: string, request: PolicyOverride): SecretPolicyView {
    const { project, env, secret, rules } = this.readableSecret(projectId, envSlug, key, rawPath);
    this.require(rules, "secrets", "edit", this.resource(env, secret, currentVersion(secret).tags));
    if (request.mode === "custom") validatePolicy(request);
    if (request.mode === "inherit") delete secret.policy;
    else secret.policy = { mode: "custom", ...normalisePolicy(request) };
    this.audit("secret.policy", { project_id: project.id, environment: env.slug, path: secret.path, secret_key: key }, { policy: request });
    return this.policyView(project.id, secret);
  }

  private readableSecret(projectId: string, envSlug: string, key: string, rawPath: string) {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(rawPath);
    const secret = this.findSecret(env.id, path, key);
    if (!secret || isDeleted(secret) || !authorise(rules, "secrets", "read", this.resource(env, secret, currentVersion(secret).tags))) {
      throw notFound("secret");
    }
    return { project, env, secret, rules };
  }

  generateSecret(projectId: string, envSlug: string, key: string, rawPath: string, request: GenerateSecret): BatchResult {
    const { project } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(rawPath);
    const existing = this.findSecret(env.id, path, key);
    const generator: Generator =
      request.generator ?? this.effectivePolicy(project.id, existing && !isDeleted(existing) ? existing : undefined).generator ?? DEFAULT_GENERATOR;
    validatePolicy({ generator, rotation_days: null });
    const value = generateValue(generator);
    const result = this.applyBatch(projectId, envSlug, { path, upserts: [{ key, value, comment: request.comment ?? "" }] }, true);
    this.audit("secret.generate", { project_id: project.id, environment: env.slug, path, secret_key: key }, {
      created: result.created.length > 0,
    });
    return result;
  }

  /** Replaces every generated value whose policy says it is due, as the server's background job does. */
  rotateDue(at: number): string[] {
    const rotated: string[] = [];
    for (const secret of this.state.secrets) {
      const env = this.state.environments.find((e) => e.id === secret.envId);
      const project = env && this.state.projects.find((p) => p.id === env.projectId);
      if (!env || !project) continue;
      const due = this.nextRotation(project.id, secret);
      if (due === null || due > at) continue;
      const generator = this.effectivePolicy(project.id, secret).generator ?? DEFAULT_GENERATOR;
      const current = currentVersion(secret);
      secret.versions.push({
        version: current.version + 1,
        value: generateValue(generator),
        // Same wording as the server: the secret's own comment is kept.
        comment: current.comment
          ? `rotated automatically: ${current.comment.replace(/^rotated automatically: /, "")}`
          : "rotated automatically",
        tags: current.tags,
        actor: ROTATION_ACTOR.name,
        created_at: this.now(),
        generated: true,
      });
      this.snapshot(env, `rotated ${secret.path === "/" ? "/" : `${secret.path}/`}${secret.key}`, ROTATION_ACTOR.name);
      this.audit(
        "secret.rotate",
        { project_id: project.id, environment: env.slug, path: secret.path, secret_key: secret.key },
        { automatic: true },
        { ...ROTATION_ACTOR, ip: "::" },
      );
      rotated.push(`${project.slug}/${env.slug}${secret.path.replace(/\/$/, "")}/${secret.key}`);
    }
    return rotated;
  }

  deleteProject(id: string): void {
    const { project, rules } = this.loadProject(id);
    this.require(rules, "settings", "delete");
    const envIds = new Set(this.state.environments.filter((e) => e.projectId === project.id).map((e) => e.id));
    this.state.projects = this.state.projects.filter((p) => p.id !== project.id);
    this.state.environments = this.state.environments.filter((e) => e.projectId !== project.id);
    this.state.secrets = this.state.secrets.filter((s) => !envIds.has(s.envId));
    this.state.folders = this.state.folders.filter((f) => !envIds.has(f.envId));
    this.state.snapshots = this.state.snapshots.filter((s) => !envIds.has(s.envId));
    this.state.memberships = this.state.memberships.filter((m) => m.projectId !== project.id);
    delete this.state.roles[project.id];
    delete this.state.logos[project.id];
    delete this.state.projectPolicies[project.id];
    this.audit("project.delete", { project_id: project.id }, { slug: project.slug });
  }

  permissions(id: string): { rules: Rule[] } {
    return { rules: this.loadProject(id).rules };
  }

  // Environments

  private projectEnvs(projectId: string): StoredEnvironment[] {
    return this.state.environments
      .filter((e) => e.projectId === projectId)
      .sort((a, b) => a.position - b.position || a.slug.localeCompare(b.slug));
  }

  private findEnv(project: Project, slug: string): StoredEnvironment {
    const env = this.projectEnvs(project.id).find((e) => e.slug === slug);
    if (!env) throw notFound("environment");
    return env;
  }

  private apiEnv(e: StoredEnvironment): Environment {
    return { id: e.id, slug: e.slug, name: e.name, position: e.position };
  }

  listEnvironments(projectId: string): Environment[] {
    const { project, rules } = this.loadProject(projectId);
    return this.projectEnvs(project.id)
      .filter((e) => authorise(rules, "environments", "read", { environment: e.slug }))
      .map((e) => this.apiEnv(e));
  }

  createEnvironment(projectId: string, request: CreateEnvironment): Environment {
    const { project, rules } = this.loadProject(projectId);
    this.require(rules, "environments", "create", { environment: request.slug });
    checkSlug(request.slug);
    checkName(request.name);
    const existing = this.projectEnvs(project.id);
    if (existing.some((e) => e.slug === request.slug)) {
      throw new MockError(409, "conflict", "the record already exists or was changed by someone else; reload and try again");
    }
    const env: StoredEnvironment = {
      id: this.nextId("env"),
      projectId: project.id,
      slug: request.slug,
      name: request.name.trim(),
      position: request.position ?? existing.length,
    };
    this.state.environments.push(env);
    this.audit("environment.create", { project_id: project.id, environment: env.slug });
    return this.apiEnv(env);
  }

  updateEnvironment(projectId: string, slug: string, request: UpdateEnvironment): Environment {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, slug);
    this.require(rules, "environments", "edit", { environment: env.slug });
    checkName(request.name);
    env.name = request.name.trim();
    env.position = request.position;
    this.audit("environment.update", { project_id: project.id, environment: env.slug });
    return this.apiEnv(env);
  }

  deleteEnvironment(projectId: string, slug: string): void {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, slug);
    this.require(rules, "environments", "delete", { environment: env.slug });
    if (this.state.secrets.some((s) => s.envId === env.id && !isDeleted(s))) {
      throw new MockError(409, "not_empty", "delete the secrets in this environment first");
    }
    this.state.environments = this.state.environments.filter((e) => e.id !== env.id);
    this.state.secrets = this.state.secrets.filter((s) => s.envId !== env.id);
    this.state.folders = this.state.folders.filter((f) => f.envId !== env.id);
    this.state.snapshots = this.state.snapshots.filter((s) => s.envId !== env.id);
    this.audit("environment.delete", { project_id: project.id, environment: env.slug });
  }

  // Folders

  private ensureFolder(envId: string, path: string): void {
    const segments = path.split("/").filter(Boolean);
    for (let i = 1; i <= segments.length; i += 1) {
      const prefix = `/${segments.slice(0, i).join("/")}`;
      if (!this.state.folders.some((f) => f.envId === envId && f.path === prefix)) {
        this.state.folders.push({ envId, path: prefix, created_at: this.now() });
      }
    }
  }

  listFolders(projectId: string, envSlug: string): Folder[] {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    return this.state.folders
      .filter((f) => f.envId === env.id)
      .filter((f) => authorise(rules, "folders", "read", { environment: env.slug, path: f.path }))
      .sort((a, b) => a.path.localeCompare(b.path))
      .map((f) => ({ path: f.path, created_at: f.created_at }));
  }

  createFolder(projectId: string, envSlug: string, rawPath: string): Folder {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(rawPath);
    if (path === "/") throw badRequest("the root folder always exists");
    this.require(rules, "folders", "create", { environment: env.slug, path });
    this.ensureFolder(env.id, path);
    this.audit("folder.create", { project_id: project.id, environment: env.slug, path });
    return { path, created_at: this.now() };
  }

  deleteFolder(projectId: string, envSlug: string, rawPath: string): void {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(rawPath);
    if (path === "/") throw badRequest("the root folder cannot be deleted");
    this.require(rules, "folders", "delete", { environment: env.slug, path });
    const occupied = this.state.secrets.some((s) => s.envId === env.id && within(s.path, path) && !isDeleted(s));
    if (occupied) throw new MockError(409, "conflict", "the folder still contains secrets");
    this.state.folders = this.state.folders.filter((f) => !(f.envId === env.id && within(f.path, path)));
    this.audit("folder.delete", { project_id: project.id, environment: env.slug, path });
  }

  // Secrets

  private resource(env: StoredEnvironment, s: Pick<StoredSecret, "path" | "key">, tags: string[]): Resource {
    return { environment: env.slug, path: s.path, key: s.key, tags };
  }

  private toApi(env: StoredEnvironment, s: StoredSecret, rules: Rule[], values: boolean): Secret {
    const current = currentVersion(s);
    const mayRead = authorise(rules, "secrets", "read-value", this.resource(env, s, current.tags));
    return {
      id: s.id,
      environment: env.slug,
      path: s.path,
      key: s.key,
      value: values && mayRead ? current.value : null,
      value_hidden: !mayRead,
      version: current.version,
      comment: current.comment,
      tags: current.tags,
      updated_at: current.created_at,
      updated_by: current.actor,
      generated: !!current.generated,
      next_rotation_at: this.nextRotation(env.projectId, s),
    };
  }

  listSecrets(projectId: string, envSlug: string, rawPath: string, values: boolean, recursive = false): SecretList {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(rawPath);
    const patterns = rules
      .filter((r) => r.subject === "secrets")
      .reduce((sum, r) => sum + (r.conditions?.paths?.length ?? 0) + (r.conditions?.keys?.length ?? 0), 0);
    if (patterns > MAX_PRINCIPAL_PATTERNS) {
      throw badRequest(
        `your roles here hold more than ${MAX_PRINCIPAL_PATTERNS} path and key patterns, counting those of your groups; ask a project admin to simplify them`,
        "too_many_patterns",
      );
    }
    const secrets = this.state.secrets
      .filter((s) => s.envId === env.id && (recursive ? within(s.path, path) : s.path === path) && !isDeleted(s))
      .filter((s) => authorise(rules, "secrets", "read", this.resource(env, s, currentVersion(s).tags)))
      .sort((a, b) => a.path.localeCompare(b.path) || a.key.localeCompare(b.key))
      .map((s) => this.toApi(env, s, rules, values));
    const prefix = path === "/" ? "/" : `${path}/`;
    const folders = this.state.folders
      .filter((f) => f.envId === env.id && f.path.startsWith(prefix))
      .map((f) => f.path.slice(prefix.length))
      .filter((rest) => rest !== "" && !rest.includes("/"))
      .sort();
    if (values) {
      this.audit("secret.read", { project_id: project.id, environment: env.slug, path }, {
        count: secrets.filter((s) => s.value != null).length,
        recursive,
      });
    }
    return { secrets, folders };
  }

  private findSecret(envId: string, path: string, key: string): StoredSecret | undefined {
    return this.state.secrets.find((s) => s.envId === envId && s.path === path && s.key === key);
  }

  private newVersion(
    s: StoredSecret | undefined,
    value: string | null,
    comment: string,
    tags: string[],
    generated = false,
  ): StoredVersion {
    return {
      version: (s ? currentVersion(s).version : 0) + 1,
      value,
      comment,
      tags,
      actor: this.actor,
      created_at: this.now(),
      generated,
    };
  }

  private snapshot(env: StoredEnvironment, reason: string, actor = this.actor): string {
    const id = this.nextId("snap");
    this.state.snapshots.unshift({
      id,
      envId: env.id,
      reason,
      actor,
      created_at: this.now(),
      entries: this.state.secrets
        .filter((s) => s.envId === env.id && !isDeleted(s))
        .map((s) => ({ secretId: s.id, version: currentVersion(s).version })),
    });
    return id;
  }

  batchWrite(projectId: string, envSlug: string, request: BatchWrite): BatchResult {
    const result = this.applyBatch(projectId, envSlug, request, false);
    if (!result.snapshot_id) return result;
    const { project } = this.loadProject(projectId);
    this.audit("secret.write", { project_id: project.id, environment: envSlug, path: normaliseFolder(request.path ?? "/") }, {
      created: result.created,
      updated: result.updated,
      deleted: result.deleted,
    });
    return result;
  }

  /** Writes a batch with the caller's permissions; `generated` marks the new values as sekret's own. */
  private applyBatch(projectId: string, envSlug: string, request: BatchWrite, generated: boolean): BatchResult {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(request.path ?? "/");
    const upserts: SecretUpsert[] = request.upserts ?? [];
    const deletes = request.deletes ?? [];
    if (upserts.length + deletes.length > 1000) throw badRequest("at most 1000 changes per batch");
    const seen = new Set<string>();
    for (const key of [...upserts.map((u) => u.key), ...deletes]) {
      if (!isValidSecretKey(key)) {
        throw badRequest("secret key must start with a letter or underscore and contain only letters, digits, '_', '-' or '.' (max 256)");
      }
      if (seen.has(key)) throw badRequest(`${key} appears more than once in the request`);
      seen.add(key);
    }

    const result: BatchResult = { created: [], updated: [], deleted: [], unchanged: [], snapshot_id: null };
    const planned: { existing?: StoredSecret; key: string; version: StoredVersion }[] = [];

    for (const upsert of upserts) {
      const existing = this.findSecret(env.id, path, upsert.key);
      const live = existing && !isDeleted(existing) ? existing : undefined;
      const tags = upsert.tags ? normaliseTags(upsert.tags) : live ? currentVersion(live).tags : [];
      if (live) {
        this.require(rules, "secrets", "edit", this.resource(env, live, currentVersion(live).tags));
        this.require(rules, "secrets", "edit", this.resource(env, live, tags));
        const current = currentVersion(live);
        const same =
          current.value === upsert.value && JSON.stringify(current.tags) === JSON.stringify(tags) && !upsert.comment;
        if (same) {
          result.unchanged.push(upsert.key);
          continue;
        }
        result.updated.push(upsert.key);
      } else {
        this.require(rules, "secrets", "create", { environment: env.slug, path, key: upsert.key, tags });
        result.created.push(upsert.key);
      }
      planned.push({
        existing,
        key: upsert.key,
        version: this.newVersion(existing, upsert.value, upsert.comment ?? "", tags, generated),
      });
    }

    for (const key of deletes) {
      const existing = this.findSecret(env.id, path, key);
      if (!existing || isDeleted(existing)) throw notFound(`secret ${key}`);
      const tags = currentVersion(existing).tags;
      this.require(rules, "secrets", "delete", this.resource(env, existing, tags));
      planned.push({ existing, key, version: this.newVersion(existing, null, "", tags) });
      result.deleted.push(key);
    }

    if (planned.length === 0) return result;
    this.ensureFolder(env.id, path);
    for (const change of planned) {
      if (change.existing) {
        change.existing.versions.push(change.version);
      } else {
        this.state.secrets.push({ id: this.nextId("sec"), envId: env.id, path, key: change.key, versions: [change.version] });
      }
    }
    const reason = `${result.created.length} created, ${result.updated.length} updated, ${result.deleted.length} deleted in ${path}`;
    result.snapshot_id = this.snapshot(env, reason);
    return result;
  }

  getSecret(projectId: string, envSlug: string, key: string, rawPath: string): Secret {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(rawPath);
    const s = this.findSecret(env.id, path, key);
    if (!s || isDeleted(s) || !authorise(rules, "secrets", "read", this.resource(env, s, currentVersion(s).tags))) {
      throw notFound("secret");
    }
    return this.toApi(env, s, rules, true);
  }

  setSecret(projectId: string, envSlug: string, key: string, rawPath: string, request: SetSecret): BatchResult {
    return this.batchWrite(projectId, envSlug, {
      path: rawPath,
      upserts: [{ key, value: request.value, comment: request.comment ?? "", tags: request.tags }],
    });
  }

  deleteSecret(projectId: string, envSlug: string, key: string, rawPath: string): BatchResult {
    this.getSecret(projectId, envSlug, key, rawPath);
    return this.batchWrite(projectId, envSlug, { path: rawPath, deletes: [key] });
  }

  listVersions(
    projectId: string,
    envSlug: string,
    key: string,
    rawPath: string,
    values: boolean,
    page: { limit?: number; before?: number } = {},
  ): SecretVersion[] {
    const limit = page.limit ?? DEFAULT_HISTORY_PAGE;
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_HISTORY_PAGE) {
      throw badRequest(`limit must be between 1 and ${MAX_HISTORY_PAGE}`);
    }
    if (page.before !== undefined && !Number.isSafeInteger(page.before)) {
      throw badRequest("Failed to deserialize query string: before: invalid digit found in string");
    }
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(rawPath);
    const s = this.findSecret(env.id, path, key);
    if (!s) throw notFound("secret");
    const resource = this.resource(env, s, currentVersion(s).tags);
    this.require(rules, "secret-versions", "read", resource);
    const reveal =
      values &&
      authorise(rules, "secret-versions", "read-value", resource) &&
      authorise(rules, "secrets", "read-value", resource);
    if (reveal) {
      this.audit("secret.history-read", { project_id: project.id, environment: env.slug, path, secret_key: key }, {});
    }
    const before = page.before ?? Number.MAX_SAFE_INTEGER;
    const shown = [...s.versions]
      .reverse()
      .filter((v) => v.version < before)
      .slice(0, limit);
    return shown.map((v) => ({
      version: v.version,
      value: reveal ? v.value : null,
      value_hidden: !reveal && v.value !== null,
      deleted: v.value === null,
      comment: v.comment,
      tags: v.tags,
      actor: v.actor,
      created_at: v.created_at,
    }));
  }

  rollback(projectId: string, envSlug: string, key: string, rawPath: string, version: number): BatchResult {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    const path = normaliseFolder(rawPath);
    const s = this.findSecret(env.id, path, key);
    if (!s) throw notFound("secret");
    const action: Action = isDeleted(s) ? "create" : "edit";
    this.require(rules, "secrets", action, this.resource(env, s, currentVersion(s).tags));
    const target = s.versions.find((v) => v.version === version);
    if (!target) throw notFound(`version ${version}`);
    this.require(rules, "secrets", action, this.resource(env, s, target.tags));
    if (target.value === null) throw badRequest("that version is a deletion");
    // Same wording as the server: the restored version keeps its own comment.
    const comment = target.comment
      ? `rolled back to version ${version}: ${target.comment}`
      : `rolled back to version ${version}`;
    s.versions.push(this.newVersion(s, target.value, comment, target.tags, !!target.generated));
    const snapshotId = this.snapshot(env, `rolled back ${s.path === "/" ? "/" : `${s.path}/`}${s.key} to version ${version}`);
    this.audit("secret.rollback", { project_id: project.id, environment: env.slug, path, secret_key: key }, { version });
    return { created: [], updated: [key], deleted: [], unchanged: [], snapshot_id: snapshotId };
  }

  overview(projectId: string, rawPath: string): Overview {
    const { project, rules } = this.loadProject(projectId);
    const path = normaliseFolder(rawPath);
    const envs = this.projectEnvs(project.id).filter((e) => authorise(rules, "environments", "read", { environment: e.slug }));
    const rows = new Map<string, { path: string; key: string; environments: Record<string, number> }>();
    for (const env of envs) {
      for (const s of this.state.secrets) {
        if (s.envId !== env.id || s.path !== path || isDeleted(s)) continue;
        if (!authorise(rules, "secrets", "read", this.resource(env, s, currentVersion(s).tags))) continue;
        const id = `${s.path}\u0000${s.key}`;
        const row = rows.get(id) ?? { path: s.path, key: s.key, environments: {} };
        row.environments[env.slug] = currentVersion(s).version;
        rows.set(id, row);
      }
    }
    return {
      environments: envs.map((e) => this.apiEnv(e)),
      rows: Array.from(rows.values()).sort((a, b) => a.key.localeCompare(b.key)),
    };
  }

  // Snapshots

  private apiSnapshot(s: MockState["snapshots"][number]): Snapshot {
    return { id: s.id, reason: s.reason, actor: s.actor, created_at: s.created_at, secret_count: s.entries.length };
  }

  listSnapshots(projectId: string, envSlug: string): Snapshot[] {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    this.require(rules, "snapshots", "read", { environment: env.slug });
    return this.state.snapshots.filter((s) => s.envId === env.id).slice(0, 200).map((s) => this.apiSnapshot(s));
  }

  private loadSnapshot(envId: string, id: string) {
    const snap = this.state.snapshots.find((s) => s.envId === envId && s.id === id);
    if (!snap) throw notFound("snapshot");
    return snap;
  }

  private snapshotChanges(env: StoredEnvironment, snap: MockState["snapshots"][number], path: string, rules: Rule[]): SnapshotChange[] {
    const wanted = new Map(snap.entries.map((e) => [e.secretId, e.version]));
    const changes: SnapshotChange[] = [];
    const current = this.state.secrets
      .filter((s) => s.envId === env.id && within(s.path, path))
      .filter((s) => authorise(rules, "secrets", "read", this.resource(env, s, currentVersion(s).tags)))
      .sort((a, b) => a.path.localeCompare(b.path) || a.key.localeCompare(b.key));
    for (const s of current) {
      const target = wanted.get(s.id);
      const live = isDeleted(s) ? undefined : currentVersion(s).version;
      let kind: SnapshotChange["kind"] | undefined;
      if (target !== undefined && live === undefined) kind = "added";
      else if (target !== undefined && live !== undefined && target !== live) kind = "changed";
      else if (target === undefined && live !== undefined) kind = "removed";
      if (!kind) continue;
      changes.push({
        path: s.path,
        key: s.key,
        kind,
        snapshot_version: kind === "removed" ? null : (target ?? null),
        current_version: live ?? null,
      });
    }
    return changes;
  }

  getSnapshot(projectId: string, envSlug: string, id: string, rawPath: string): SnapshotDetail {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    this.require(rules, "snapshots", "read", { environment: env.slug });
    const snap = this.loadSnapshot(env.id, id);
    const path = normaliseFolder(rawPath);
    return { snapshot: this.apiSnapshot(snap), changes: this.snapshotChanges(env, snap, path, rules) };
  }

  restoreSnapshot(projectId: string, envSlug: string, id: string, rawPath: string): BatchResult {
    const { project, rules } = this.loadProject(projectId);
    const env = this.findEnv(project, envSlug);
    this.require(rules, "snapshots", "edit", { environment: env.slug });
    const snap = this.loadSnapshot(env.id, id);
    const path = normaliseFolder(rawPath);
    const result: BatchResult = { created: [], updated: [], deleted: [], unchanged: [], snapshot_id: null };
    const changes = this.snapshotChanges(env, snap, path, rules);
    for (const change of changes) {
      const s = this.findSecret(env.id, change.path, change.key);
      if (!s) continue;
      const label = `${s.path.replace(/\/$/, "")}/${s.key}`;
      const tags = currentVersion(s).tags;
      if (change.kind === "removed") {
        this.require(rules, "secrets", "delete", this.resource(env, s, tags));
        s.versions.push(this.newVersion(s, null, `snapshot ${snap.id} restore`, tags));
        result.deleted.push(label);
        continue;
      }
      this.require(rules, "secrets", change.kind === "added" ? "create" : "edit", this.resource(env, s, tags));
      const target = s.versions.find((v) => v.version === change.snapshot_version);
      if (!target || target.value === null) continue;
      s.versions.push(this.newVersion(s, target.value, `restored from snapshot ${snap.id}`, target.tags, !!target.generated));
      (change.kind === "added" ? result.created : result.updated).push(label);
    }
    if (changes.length === 0) return result;
    result.snapshot_id = this.snapshot(env, `restored snapshot ${snap.id} under ${path}`);
    this.audit("snapshot.restore", { project_id: project.id, environment: env.slug, path }, { snapshot: snap.id });
    return result;
  }

  // Members and roles

  private principalNames(): Map<string, string> {
    const names = new Map<string, string>();
    for (const u of this.state.users) names.set(`user:${u.id}`, principalLabel(u));
    for (const i of this.state.identities) names.set(`identity:${i.id}`, i.name);
    return names;
  }

  private ensurePrincipal(kind: PrincipalKind, id: string): void {
    const exists =
      kind === "user"
        ? this.state.users.some((u) => u.id === id)
        : kind === "identity"
          ? this.state.identities.some((i) => i.id === id)
          : id.trim() !== "" && id.length <= 256;
    if (!exists) throw badRequest(`${kind} ${id} does not exist`);
  }

  listMembers(projectId: string): Membership[] {
    const { project, rules } = this.loadProject(projectId);
    this.require(rules, "members", "read");
    const names = this.principalNames();
    return this.state.memberships
      .filter((m) => m.projectId === project.id)
      .map((m) => ({
        principal_kind: m.principal_kind,
        principal_id: m.principal_id,
        principal_name: names.get(`${m.principal_kind}:${m.principal_id}`) ?? m.principal_id,
        role: m.role,
        created_at: m.created_at,
      }));
  }

  private projectRoleRules(projectId: string, slug: string): Rule[] {
    const rules = this.roleRules(slug, this.state.roles[projectId] ?? [], false);
    if (!rules) throw badRequest(`unknown role ${slug}`);
    return rules;
  }

  addMember(projectId: string, request: AddMembership): void {
    const { project, rules: own } = this.loadProject(projectId);
    const rules = this.managementRules(own);
    this.require(rules, "members", "create");
    const granted = this.projectRoleRules(project.id, request.role);
    if (!covers(rules, granted)) throw escalation("you cannot grant a role with more access than you have");
    const administers =
      this.isOrgAdmin() ||
      this.state.memberships.some((m) => m.projectId === project.id && m.role === "admin" && this.principalIsMe(m.principal_kind, m.principal_id));
    this.checkDenyForAdmin(granted, request.principal_kind, request.principal_id, administers, project.id);
    this.ensurePrincipal(request.principal_kind, request.principal_id);
    const duplicate = this.state.memberships.some(
      (m) =>
        m.projectId === project.id &&
        m.principal_kind === request.principal_kind &&
        m.principal_id === request.principal_id &&
        m.role === request.role,
    );
    if (duplicate) {
      throw new MockError(409, "conflict", "the record already exists or was changed by someone else; reload and try again");
    }
    this.state.memberships.push({ projectId: project.id, ...request, created_at: this.now() });
    this.audit("member.add", { project_id: project.id }, request);
  }

  removeMember(projectId: string, kind: PrincipalKind, id: string, role: string): void {
    const { project, rules: own } = this.loadProject(projectId);
    const rules = this.managementRules(own);
    this.require(rules, "members", "delete");
    const removed = this.roleRules(role, this.state.roles[project.id] ?? [], false) ?? [];
    if (!covers(rules, removed)) throw escalation("you cannot remove a role with more access than you have");
    this.state.memberships = this.state.memberships.filter(
      (m) => !(m.projectId === project.id && m.principal_kind === kind && m.principal_id === id && m.role === role),
    );
    this.audit("member.remove", { project_id: project.id }, { principal_kind: kind, principal_id: id, role });
  }

  listRoles(projectId: string): Role[] {
    const { project, rules } = this.loadProject(projectId);
    this.require(rules, "roles", "read");
    return [...builtinRoles(false), ...(this.state.roles[project.id] ?? [])];
  }

  private validateRole(slug: string, request: PutRole, author: Rule[], orgScope: boolean): void {
    checkSlug(slug);
    checkName(request.name);
    if (builtinRoles(orgScope).some((r) => r.slug === slug) || builtinRoles(!orgScope).some((r) => r.slug === slug)) {
      throw badRequest("that slug belongs to a built-in role");
    }
    const scope = orgScope ? ORG_SUBJECTS : PROJECT_SUBJECTS;
    if (request.rules.some((r) => !scope.includes(r.subject) || r.actions.length === 0)) {
      throw badRequest("rules must name subjects for this scope and at least one action");
    }
    if (request.rules.length > 100) throw badRequest("too many rules");
    for (const rule of request.rules) {
      const badPath = rule.conditions?.paths?.find((p) => !pathPatternCanMatch(p));
      if (badPath !== undefined) {
        throw badRequest(
          `path condition ${JSON.stringify(badPath)} can never match: folders look like /payments or /payments/**, starting with / and without a trailing /, // or . and .. segments`,
        );
      }
      const badKey = rule.conditions?.keys?.find((k) => !keyPatternCanMatch(k));
      if (badKey !== undefined) {
        throw badRequest(
          `key condition ${JSON.stringify(badKey)} can never match: keys start with a letter or _ and hold only letters, digits, _, - and .`,
        );
      }
    }
    if (!covers(author, request.rules)) throw escalation("a role cannot grant more access than you have");
  }

  private upsertRole(scopeKey: string, slug: string, request: PutRole): Role {
    const role: Role = {
      slug,
      name: request.name.trim(),
      description: request.description ?? "",
      builtin: false,
      rules: request.rules,
    };
    const list = (this.state.roles[scopeKey] ?? []).filter((r) => r.slug !== slug);
    list.push(role);
    list.sort((a, b) => a.slug.localeCompare(b.slug));
    this.state.roles[scopeKey] = list;
    return role;
  }

  putRole(projectId: string, slug: string, request: PutRole): Role {
    const { project, rules: own } = this.loadProject(projectId);
    const rules = this.managementRules(own);
    const exists = (this.state.roles[project.id] ?? []).some((r) => r.slug === slug);
    this.require(rules, "roles", exists ? "edit" : "create");
    this.validateRole(slug, request, rules, false);
    const role = this.upsertRole(project.id, slug, request);
    this.audit("role.put", { project_id: project.id }, { role: slug });
    return role;
  }

  deleteRole(projectId: string, slug: string): void {
    const { project, rules } = this.loadProject(projectId);
    this.require(this.managementRules(rules), "roles", "delete");
    this.state.roles[project.id] = (this.state.roles[project.id] ?? []).filter((r) => r.slug !== slug);
    this.audit("role.delete", { project_id: project.id }, { role: slug });
  }

  // Audit

  /** Mirrors the server's filters: exact fields, prefixes for action and path, and substring search. */
  private auditMatches(e: AuditEntry, query: AuditQuery): boolean {
    const equals = (value: string | null | undefined, wanted: string | undefined) => wanted === undefined || value === wanted;
    const action = emptyToUndefined(query.action);
    const path = emptyToUndefined(query.path);
    const search = emptyToUndefined(query.q)?.toLowerCase();
    return (
      equals(e.actor_id, emptyToUndefined(query.actor_id)) &&
      equals(e.actor_kind, emptyToUndefined(query.actor_kind)) &&
      equals(e.environment, emptyToUndefined(query.environment)) &&
      equals(e.secret_key, emptyToUndefined(query.key)) &&
      (action === undefined || e.action.startsWith(action)) &&
      (path === undefined || (e.path ?? "").startsWith(path)) &&
      (query.since === undefined || e.created_at >= query.since) &&
      (query.until === undefined || e.created_at <= query.until) &&
      (search === undefined ||
        [e.action, e.actor_name, e.actor_id, e.environment ?? "", e.path ?? "", e.secret_key ?? "", e.ip].some((field) =>
          field.toLowerCase().includes(search),
        ))
    );
  }

  private auditPage(entries: AuditEntry[], query: AuditQuery): AuditPage {
    const limit = Math.min(MAX_PAGE, Math.max(1, query.limit ?? DEFAULT_PAGE));
    const ascending = query.order === "asc";
    const after = query.cursor ? decodeCursor(query.cursor) : undefined;
    const direction = ascending ? 1 : -1;
    const matching = entries.filter((e) => this.auditMatches(e, query));
    const beyond = (e: AuditEntry) => {
      if (!after) return true;
      const [createdAt, id] = after;
      const order = e.created_at - createdAt || compareIds(e.id, id);
      return order * direction > 0;
    };
    const sorted = matching
      .filter(beyond)
      .sort((a, b) => direction * (a.created_at - b.created_at || compareIds(a.id, b.id)));
    const page = sorted.slice(0, limit);
    const last = page.at(-1);
    return {
      entries: page,
      total: matching.length,
      next_cursor: sorted.length > limit && last ? encodeCursor(last.created_at, last.id) : null,
    };
  }

  projectAudit(projectId: string, query: AuditQuery = {}): AuditPage {
    const { project, rules } = this.loadProject(projectId);
    this.require(rules, "audit-log", "read");
    const actorsOnly = this.auditFilterScope(rules, query);
    const entries = this.state.audit.filter((e) => e.project_id === project.id);
    if (!actorsOnly) return this.auditPage(entries, query);
    // `q` may only search what redaction leaves alone.
    const search = emptyToUndefined(query.q)?.toLowerCase();
    const searched = search
      ? entries.filter((e) => [e.action, e.actor_name, e.actor_id, e.ip].some((f) => f.toLowerCase().includes(search)))
      : entries;
    return this.auditPage(searched, { ...query, q: undefined });
  }

  /** As the server: refuses filters that would reveal what redaction hides, and says whether `q` is limited. */
  private auditFilterScope(rules: Rule[], query: AuditQuery): boolean {
    const environment = emptyToUndefined(query.environment?.trim());
    if (environment !== undefined && !authorise(rules, "environments", "read", { environment })) throw forbidden();
    const scope: Resource = { environment };
    if (authorise(rules, "secrets", "read", scope) && authorise(rules, "environments", "read", scope)) return false;
    if (emptyToUndefined(query.key?.trim()) !== undefined || emptyToUndefined(query.path?.trim()) !== undefined) {
      throw new MockError(
        403,
        "filter_hidden",
        "some secrets here are hidden from you, so the log cannot be filtered by key or folder; filter by an environment you can fully read first",
      );
    }
    return true;
  }

  orgAudit(query: AuditQuery = {}): AuditPage {
    this.requireOrg("org-audit-log", "read");
    return this.auditPage(this.state.audit, query);
  }

  // Users

  listUsers(query: UserQuery = {}): UserPage {
    this.requireOrg("org-members", "read");
    const needle = query.q?.trim().toLowerCase() ?? "";
    const sort = query.sort ?? "name";
    const users = this.state.users
      .filter((u) => !query.status || (query.status === "disabled") === u.disabled)
      .filter((u) => !needle || [u.name, u.email, u.groups.join(" "), u.id].some((f) => f.toLowerCase().includes(needle)))
      .sort((a, b) => {
        const primary =
          sort === "email"
            ? compareIds(a.email.toLowerCase(), b.email.toLowerCase())
            : sort === "created"
              ? a.created_at - b.created_at
              : sort === "last_login"
                ? a.last_login_at - b.last_login_at
                : compareIds(a.name.toLowerCase(), b.name.toLowerCase());
        return ordered(primary, query.order) || compareIds(a.id, b.id);
      });
    return slice(users, query.offset, query.limit);
  }

  updateUser(id: string, disabled: boolean): void {
    this.requireOrg("org-members", "edit");
    if (id === this.state.me.id && disabled) throw badRequest("you cannot disable yourself");
    const user = this.state.users.find((u) => u.id === id);
    if (!user) throw notFound("user");
    user.disabled = disabled;
    this.audit("user.update", {}, { user: id, disabled });
  }

  // Identities

  private apiIdentity(i: MockState["identities"][number]): Identity {
    const methods = (this.state.authMethods[i.id] ?? []).map((m) => m.kind).sort();
    return { ...i, auth_methods: methods };
  }

  private loadIdentity(id: string) {
    const identity = this.state.identities.find((i) => i.id === id);
    if (!identity) throw notFound("identity");
    return identity;
  }

  private checkIdentityFields(ttl: number, maxTtl: number, cidrs: string[]): void {
    if (ttl < 60 || maxTtl < ttl || maxTtl > 365 * 24 * 3600) {
      throw badRequest("token TTL must be at least 60 seconds and no more than the max TTL (at most a year)");
    }
    const cidr = /^[0-9a-fA-F:.]+\/\d{1,3}$/;
    if (cidrs.some((c) => !cidr.test(c))) throw badRequest("trusted CIDRs must look like 10.0.0.0/8");
  }

  listIdentities(query: IdentityQuery = {}): IdentityPage {
    this.requireOrg("identities", "read");
    const needle = query.q?.trim().toLowerCase() ?? "";
    const identities = this.state.identities
      .filter((i) => !query.status || (query.status === "disabled") === i.disabled)
      .filter((i) => !needle || [i.name, i.description, i.id].some((f) => f.toLowerCase().includes(needle)))
      .sort((a, b) => {
        const primary =
          query.sort === "created" ? a.created_at - b.created_at : compareIds(a.name.toLowerCase(), b.name.toLowerCase());
        return ordered(primary, query.order) || compareIds(a.id, b.id);
      })
      .map((i) => this.apiIdentity(i));
    return slice(identities, query.offset, query.limit);
  }

  getIdentity(id: string): Identity {
    this.requireOrg("identities", "read");
    return this.apiIdentity(this.loadIdentity(id));
  }

  createIdentity(request: CreateIdentity): Identity {
    this.requireOrg("identities", "create");
    checkName(request.name);
    const ttl = request.token_ttl ?? 3600;
    const maxTtl = request.token_max_ttl ?? Math.max(24 * 3600, ttl);
    const cidrs = request.trusted_cidrs ?? [];
    this.checkIdentityFields(ttl, maxTtl, cidrs);
    const identity = {
      id: this.nextId("ident"),
      name: request.name.trim(),
      description: request.description ?? "",
      token_ttl: ttl,
      token_max_ttl: maxTtl,
      trusted_cidrs: cidrs,
      disabled: false,
      created_at: this.now(),
    };
    this.state.identities.push(identity);
    this.audit("identity.create", {}, { identity: identity.id, name: identity.name });
    return this.apiIdentity(identity);
  }

  updateIdentity(id: string, request: UpdateIdentity): Identity {
    this.requireOrg("identities", "edit");
    const identity = this.loadIdentity(id);
    checkName(request.name);
    const cidrs = request.trusted_cidrs ?? [];
    this.checkIdentityFields(request.token_ttl, request.token_max_ttl, cidrs);
    Object.assign(identity, {
      name: request.name.trim(),
      description: request.description ?? "",
      token_ttl: request.token_ttl,
      token_max_ttl: request.token_max_ttl,
      trusted_cidrs: cidrs,
      disabled: request.disabled ?? false,
    });
    this.audit("identity.update", {}, { identity: id });
    return this.apiIdentity(identity);
  }

  deleteIdentity(id: string): void {
    this.requireOrg("identities", "delete");
    this.loadIdentity(id);
    this.state.identities = this.state.identities.filter((i) => i.id !== id);
    delete this.state.authMethods[id];
    delete this.state.clientSecrets[id];
    this.state.memberships = this.state.memberships.filter((m) => !(m.principal_kind === "identity" && m.principal_id === id));
    this.state.orgBindings = this.state.orgBindings.filter((b) => !(b.principal_kind === "identity" && b.principal_id === id));
    this.audit("identity.delete", {}, { identity: id });
  }

  revokeIdentityTokens(id: string): void {
    this.requireOrg("identities", "edit");
    this.loadIdentity(id);
    this.audit("identity.revoke-tokens", {}, { identity: id });
  }

  listAuthMethods(id: string): AuthMethodConfig[] {
    this.requireOrg("identities", "read");
    this.loadIdentity(id);
    return [...(this.state.authMethods[id] ?? [])].map(redact).sort((a, b) => a.kind.localeCompare(b.kind));
  }

  /** Mirrors the server: the marker keeps the stored reviewer token, and an empty value clears it. */
  private withStoredReviewer(id: string, config: AuthMethodConfig): AuthMethodConfig {
    if (config.kind === "oidc") return { ...config, max_token_lifetime: config.max_token_lifetime ?? 3600 };
    if (config.kind !== "kubernetes") return config;
    // Left out means the server's default, as serde fills it in.
    const withLifetime = { ...config, max_token_lifetime: config.max_token_lifetime ?? 3600 };
    const submitted = config.reviewer_jwt?.trim() || null;
    if (submitted !== REDACTED_CREDENTIAL) return { ...withLifetime, reviewer_jwt: submitted };
    const stored = (this.state.authMethods[id] ?? []).find((m) => m.kind === "kubernetes");
    const previous = stored?.kind === "kubernetes" ? stored.reviewer_jwt : null;
    if (!previous) throw badRequest("there is no stored reviewer token to keep");
    return { ...withLifetime, reviewer_jwt: previous };
  }

  private validateAuthMethod(config: AuthMethodConfig): void {
    if (config.kind === "oidc") {
      if (!/^https?:\/\//.test(config.issuer)) throw badRequest("issuer must be an https URL");
      checkOutboundUrl(config.issuer);
      if (config.jwks_url) checkOutboundUrl(config.jwks_url);
      checkLifetimeSetting(config.max_token_lifetime);
      const b = config.bindings;
      if ((b.audiences ?? []).every((a) => !a.trim())) throw badRequest("at least one bound audience is required");
      const claims = Object.values(b.claims ?? {});
      if ((b.subjects ?? []).length === 0 && claims.every((c) => c.length === 0)) {
        throw badRequest("a bound subject or bound claim is required so arbitrary tokens from the issuer are not accepted");
      }
    }
    if (config.kind === "kubernetes") {
      if ((config.audiences ?? []).length === 0) throw badRequest("at least one audience is required");
      if (config.mode === "token-review" && !config.host) throw badRequest("host is required");
      checkLifetimeSetting(config.max_token_lifetime);
      if (config.mode === "token-review" && config.host) checkOutboundUrl(config.host);
      if (config.mode === "jwks") {
        if (!config.issuer) throw badRequest("issuer is required for JWKS mode");
        if (!config.jwks && !config.jwks_url) throw badRequest("supply jwks or jwks_url");
        if (!config.jwks && config.jwks_url) checkOutboundUrl(config.jwks_url);
      }
    }
  }

  putAuthMethod(id: string, kind: string, config: AuthMethodConfig): void {
    this.requireOrg("identities", "edit");
    this.loadIdentity(id);
    if (config.kind !== kind) throw badRequest("the path and body name different auth methods");
    this.validateAuthMethod(config);
    const stored = this.withStoredReviewer(id, config);
    const list = (this.state.authMethods[id] ?? []).filter((m) => m.kind !== config.kind);
    list.push(stored);
    this.state.authMethods[id] = list;
    this.audit("identity.auth-put", {}, { identity: id, method: kind });
  }

  deleteAuthMethod(id: string, kind: AuthMethodKind): void {
    this.requireOrg("identities", "edit");
    this.loadIdentity(id);
    this.state.authMethods[id] = (this.state.authMethods[id] ?? []).filter((m) => m.kind !== kind);
    this.audit("identity.auth-delete", {}, { identity: id, method: kind });
  }

  listClientSecrets(id: string): ClientSecret[] {
    this.requireOrg("identities", "read");
    this.loadIdentity(id);
    return [...(this.state.clientSecrets[id] ?? [])].sort((a, b) => b.created_at - a.created_at);
  }

  createClientSecret(id: string, request: CreateClientSecret): CreatedClientSecret {
    this.requireOrg("identities", "edit");
    this.loadIdentity(id);
    if ((request.ttl != null && request.ttl <= 0) || (request.max_uses != null && request.max_uses <= 0)) {
      throw badRequest("ttl and max_uses must be positive");
    }
    const raw = Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, "0")).join("");
    const clientSecret = `sks_${raw}`;
    const secret: ClientSecret = {
      id: this.nextId("cs"),
      description: request.description ?? "",
      prefix: clientSecret.slice(0, 10),
      created_at: this.now(),
      expires_at: request.ttl != null ? this.now() + request.ttl : null,
      uses_remaining: request.max_uses ?? null,
      revoked: false,
      last_used_at: null,
    };
    this.state.clientSecrets[id] = [...(this.state.clientSecrets[id] ?? []), secret];
    this.audit("identity.client-secret-create", {}, { identity: id, prefix: secret.prefix });
    return { client_id: id, client_secret: clientSecret, secret };
  }

  revokeClientSecret(id: string, secretId: string): void {
    this.requireOrg("identities", "edit");
    const secret = (this.state.clientSecrets[id] ?? []).find((s) => s.id === secretId);
    if (!secret) throw notFound("client secret");
    secret.revoked = true;
    this.audit("identity.client-secret-revoke", {}, { identity: id, secret: secretId });
  }

  // Organisation access

  listOrgBindings(): OrgBinding[] {
    this.requireOrg("org-members", "read");
    const names = this.principalNames();
    return this.state.orgBindings.map((b) => ({
      ...b,
      principal_name: names.get(`${b.principal_kind}:${b.principal_id}`) ?? b.principal_id,
    }));
  }

  private orgRoleRules(slug: string): Rule[] {
    const rules = this.roleRules(slug, this.state.roles[""] ?? [], true);
    if (!rules) throw badRequest(`unknown organisation role ${slug}`);
    return rules;
  }

  addOrgBinding(request: AddOrgBinding): void {
    const rules = this.managementRules(this.orgRules());
    if (!authorise(rules, "org-members", "create")) throw forbidden();
    const granted = this.orgRoleRules(request.role);
    if (!covers(rules, granted)) {
      throw escalation("you cannot grant a role with more access than you have");
    }
    this.checkDenyForAdmin(granted, request.principal_kind, request.principal_id, this.isOrgAdmin());
    this.ensurePrincipal(request.principal_kind, request.principal_id);
    this.state.orgBindings.push({ principal_kind: request.principal_kind, principal_id: request.principal_id, role: request.role });
    this.audit("org.binding-add", {}, request);
  }

  removeOrgBinding(kind: PrincipalKind, id: string, role: string): void {
    this.require(this.managementRules(this.orgRules()), "org-members", "delete");
    this.state.orgBindings = this.state.orgBindings.filter(
      (b) => !(b.principal_kind === kind && b.principal_id === id && b.role === role),
    );
    this.audit("org.binding-remove", {}, { principal_kind: kind, principal_id: id, role });
  }

  listOrgRoles(): Role[] {
    this.requireOrg("org-roles", "read");
    return [...builtinRoles(true), ...(this.state.roles[""] ?? [])];
  }

  putOrgRole(slug: string, request: PutRole): Role {
    const rules = this.managementRules(this.orgRules());
    const exists = (this.state.roles[""] ?? []).some((r) => r.slug === slug);
    if (!authorise(rules, "org-roles", exists ? "edit" : "create")) throw forbidden();
    this.validateRole(slug, request, rules, true);
    const role = this.upsertRole("", slug, request);
    this.audit("org.role-put", {}, { role: slug });
    return role;
  }

  deleteOrgRole(slug: string): void {
    this.require(this.managementRules(this.orgRules()), "org-roles", "delete");
    this.state.roles[""] = (this.state.roles[""] ?? []).filter((r) => r.slug !== slug);
    this.audit("org.role-delete", {}, { role: slug });
  }

  // Setup, sealing and backups

  /** The unauthenticated status: after setup only the state, whether web setup is on, and the version. */
  publicStatus(): SysStatus {
    return publicStatusOf(this.state.sys);
  }

  /** Every field, for organisation admins. */
  statusDetail(): SysStatus {
    this.requireOrgAdmin();
    return this.sysStatus();
  }

  sysStatus(): SysStatus {
    return statusOf(this.state.sys);
  }

  /** Mirrors the server's gate: everything but the open routes answers 503 until set up and unlocked. */
  requireUnsealed(): void {
    const { state } = this.state.sys;
    if (state === "sealed") throw new MockError(503, "sealed", "the server is sealed; unlock it to continue");
    if (state === "uninitialised") throw new MockError(503, "uninitialised", "the server has not been set up yet");
  }

  private isOrgAdmin(): boolean {
    return this.orgRoleSlugs().includes("org-admin");
  }

  private requireOrgAdmin(): void {
    if (!this.isOrgAdmin()) throw forbidden();
  }

  private requirePassphraseMode(): void {
    if (this.state.sys.mode !== "passphrase") throw new MockError(409, "conflict", "only a server in passphrase mode can do that");
  }

  private systemAudit(action: string, name: string): void {
    this.recordAudit(action, { kind: "identity", id: name, name });
  }

  /** Open while uninitialised; afterwards only organisation admins may ask. */
  checkPassphrase(passphrase: string, check: StrengthChecker): PassphraseStrength {
    if (this.state.sys.state === "sealed") this.requireUnsealed();
    if (this.state.sys.state === "unsealed") {
      this.requireSession();
      this.requireOrgAdmin();
    }
    return check(passphrase);
  }

  private requireStrong(passphrase: string, check: StrengthChecker): void {
    const strength = check(passphrase);
    if (strength.acceptable) return;
    throw new MockError(400, "weak_passphrase", "the passphrase is too easy to guess", { strength });
  }

  init(request: InitRequest, check: StrengthChecker): InitResponse {
    const sys = this.state.sys;
    if (!sys.webSetup) {
      throw new MockError(403, "setup_disabled", "setup through the API is turned off; run `sekret admin init` on the host");
    }
    if (sys.state !== "uninitialised") throw new MockError(409, "conflict", "the server is already initialised");
    if (request.setup_code !== MOCK_SETUP_CODE) {
      throw new MockError(401, "invalid_setup_code", "the setup code is wrong; it is in the server log");
    }
    if (sys.mode && request.mode !== sys.mode) {
      throw badRequest(`the server is configured for ${sys.mode} mode`);
    }
    if (request.mode === "key-file") {
      if (sys.mode !== "key-file") {
        throw badRequest("key-file mode needs a root key file path; start the server with --root-key-file");
      }
      this.state.sys = { ...sys, state: "unsealed", unlockPolicy: null, unsealedBy: "key-file", failedUnseals: 0 };
      return this.initialised();
    }
    if (!request.passphrase) throw badRequest("passphrase mode needs a passphrase");
    this.requireStrong(request.passphrase, check);
    const policy = sys.configured ? (sys.unlockPolicy ?? "manual") : (request.unlock_policy ?? "manual");
    this.state.sys = {
      ...sys,
      state: "unsealed",
      mode: "passphrase",
      unlockPolicy: policy,
      remembered: policy === "remember",
      unsealedBy: "passphrase",
      passphrase: request.passphrase,
      failedUnseals: 0,
    };
    return this.initialised();
  }

  private initialised(): InitResponse {
    this.systemAudit("sys.init", "setup");
    const raw = Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, "0")).join("");
    return {
      status: this.sysStatus(),
      admin_token: `skt_${raw}`,
      admin_token_expires_at: Math.floor(Date.now() / 1000) + 3600,
    };
  }

  /** Refuses while backing off after wrong passphrases, then counts this attempt if it is wrong. */
  private verifyPassphrase(candidate: string): boolean {
    const sys = this.state.sys;
    const wait = Math.ceil((sys.backoffUntil - Date.now()) / 1000);
    if (wait > 0) {
      throw new MockError(429, "passphrase_backoff", `too many wrong passphrases; try again in ${wait} seconds`);
    }
    if (candidate === MOCK_KDF_BUSY_PASSPHRASE) {
      throw new MockError(429, "kdf_busy", "another passphrase check is running; try again in a moment");
    }
    if (candidate === sys.passphrase) {
      sys.failedUnseals = 0;
      return true;
    }
    sys.failedUnseals += 1;
    if (sys.failedUnseals >= MAX_FAILED_UNSEALS) {
      sys.failedUnseals = 0;
      sys.backoffUntil = Date.now() + MOCK_BACKOFF_SECONDS * 1000;
    }
    return false;
  }

  unseal(passphrase: string): SysStatus {
    const sys = this.state.sys;
    if (sys.state === "unsealed") return this.sysStatus();
    this.requireUnsealedOrSealed();
    if (passphrase === MOCK_FOREIGN_KEY_PASSPHRASE) {
      throw new MockError(
        409,
        "root_key_not_recognised",
        "the passphrase opened a root key this server does not recognise; if the database was restored, run sekret admin reset-epoch",
      );
    }
    if (!this.verifyPassphrase(passphrase)) {
      this.systemAudit("sys.unseal.failed", "unseal");
      throw new MockError(401, "invalid_passphrase", "the passphrase is wrong");
    }
    sys.state = "unsealed";
    sys.unsealedBy = "passphrase";
    if (sys.unlockPolicy === "remember") sys.remembered = true;
    this.systemAudit("sys.unseal", "unseal");
    return this.sysStatus();
  }

  private requireUnsealedOrSealed(): void {
    if (this.state.sys.state === "uninitialised") this.requireUnsealed();
  }

  seal(): SysStatus {
    this.requireOrgAdmin();
    this.requirePassphraseMode();
    // A remembered unlock survives sealing, as on the server.
    this.state.sys.state = "sealed";
    this.state.sys.unsealedBy = null;
    this.audit("sys.seal", {});
    return this.sysStatus();
  }

  changePassphrase(request: ChangePassphrase, check: StrengthChecker): void {
    this.requireOrgAdmin();
    this.requirePassphraseMode();
    if (this.state.sys.unsealedBy === "key-file") {
      throw new MockError(
        409,
        "root_key_file_in_use",
        "this server reads its root key from seal.root_key_file, which would still hold the old key after a passphrase change and stop the server starting; remove that file, restart, unseal with the passphrase and change it then",
      );
    }
    this.requireStrong(request.new, check);
    if (!this.verifyPassphrase(request.current)) {
      throw new MockError(401, "invalid_passphrase", "the passphrase is wrong");
    }
    this.state.sys.passphrase = request.new;
    this.state.sys.remembered = false;
    this.audit("sys.passphrase", {});
    this.failIfMarkStale("the passphrase was changed");
  }

  /** The change above is kept; only the mark outside the database is behind, as on the server. */
  private failIfMarkStale(what: string): void {
    if (this.state.sys.passphrase !== MOCK_STALE_MARK_PASSPHRASE) return;
    throw new MockError(
      500,
      "epoch_mark_stale",
      `${what}, but a seal epoch mark could not be updated; see the server log, make the mark writable, then run \`sekret admin reset-epoch\` with the server stopped`,
    );
  }

  setUnlockPolicy(policy: UnlockPolicy, passphrase?: string | null): SysStatus {
    this.requireOrgAdmin();
    this.requirePassphraseMode();
    if (this.state.sys.configured) {
      throw new MockError(409, "conflict", "the unlock policy is set in the server configuration; change it there");
    }
    if (policy !== "manual") {
      if (!passphrase) {
        throw new MockError(
          400,
          "passphrase_required",
          "this change weakens how the server is unlocked; confirm it with the current passphrase",
        );
      }
      if (!this.verifyPassphrase(passphrase)) throw new MockError(401, "invalid_passphrase", "the passphrase is wrong");
    }
    this.state.sys.unlockPolicy = policy;
    this.state.sys.remembered = policy === "remember";
    this.audit("sys.unlock_policy", {}, { policy });
    this.failIfMarkStale("the unlock policy was changed");
    return this.sysStatus();
  }

  forgetUnlock(): SysStatus {
    this.requireOrgAdmin();
    this.requirePassphraseMode();
    this.state.sys.remembered = false;
    this.audit("sys.forget_unlock", {});
    return this.sysStatus();
  }

  /** A stand-in `.skb` file: the real magic and header shape, with random bytes for the ciphertext. */
  backup(): { bytes: Uint8Array; filename: string } {
    this.requireOrg("backups", "read");
    const now = this.now();
    const header = new TextEncoder().encode(
      JSON.stringify({ mode: this.state.sys.mode, created_at: now, version: MOCK_VERSION }),
    );
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, header.length, true);
    const body = crypto.getRandomValues(new Uint8Array(256));
    const bytes = new Uint8Array([...new TextEncoder().encode("SKB1"), ...length, ...header, ...body]);
    this.audit("sys.backup", {}, { bytes: bytes.length });
    return { bytes, filename: `sekret-backup-${compactUtc(now)}.skb` };
  }

  // CLI device login

  /** Any well-formed code but `XXXX-...` stands for a waiting login started a minute ago from the CLI. */
  private knownCliCode(code: string): string {
    const normalised = normaliseUserCode(code);
    if (!isCompleteCode(normalised) || normalised.startsWith("XXXX")) {
      throw new MockError(404, "not_found", "that code is unknown or has expired");
    }
    return normalised;
  }

  /** A code still waiting: known, and neither approved nor denied yet. */
  private waitingCliCode(code: string): string {
    const normalised = this.knownCliCode(code);
    if (this.state.endedCliCodes?.includes(normalised)) {
      throw new MockError(404, "not_found", "that code is unknown or has expired");
    }
    return normalised;
  }

  private endCliLogin(code: string): void {
    this.state.endedCliCodes = [...(this.state.endedCliCodes ?? []), code];
  }

  pendingCli(code: string): PendingCliLogin {
    const normalised = this.waitingCliCode(code);
    const now = Math.floor(Date.now() / 1000);
    return {
      code_hint: null,
      requested_from_ip: MOCK_CLI_ADDRESS,
      same_address: normalised.startsWith(MOCK_SAME_ADDRESS_CODE_PREFIX),
      user_agent: MOCK_CLI_USER_AGENT,
      created_at: now - 60,
      expires_at: now + 540,
    };
  }

  denyCli(code: string): void {
    const normalised = this.waitingCliCode(code);
    this.endCliLogin(normalised);
    this.audit("auth.cli-deny", {}, {});
  }

  approveCli(code: string): void {
    const normalised = this.waitingCliCode(code);
    if (normalised.startsWith(MOCK_REAUTH_CODE_PREFIX) && !this.state.freshSignIn) {
      const back = encodeURIComponent(`/cli-login?code=${encodeURIComponent(normalised)}`);
      throw new MockError(
        403,
        "reauthentication_required",
        `sign in again to approve this; continue at /auth/login?reauth=1&return_to=${back}`,
      );
    }
    this.endCliLogin(normalised);
    this.audit("auth.cli-approve", {}, {});
  }
}
