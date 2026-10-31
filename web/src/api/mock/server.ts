import type {
  AddMembership,
  AddOrgBinding,
  AuthMethodConfig,
  AuthMethodKind,
  BatchWrite,
  ChangePassphrase,
  CliApproveRequest,
  CliDenyRequest,
  CreateClientSecret,
  CreateEnvironment,
  CreateIdentity,
  CreateProject,
  GenerateSecret,
  IdentitySort,
  InitRequest,
  PassphraseCheck,
  PolicyOverride,
  PrincipalKind,
  PutRole,
  SecretPolicy,
  SetSecret,
  SetUnlockPolicy,
  SortOrder,
  Status,
  UpdateEnvironment,
  UpdateIdentity,
  UnsealRequest,
  UpdateProject,
  UserSort,
} from "../types";
import { CSRF_HEADER } from "../client";
import type { AuditQuery, IdentityQuery, UserQuery } from "../endpoints";
import { MockBackend, MockError } from "./backend";
import { renderPng } from "./render-png";
import { HOSTILE_SEED, HOSTILE_SEED_FLAG } from "./hostile-values";
import { seededState } from "./seed";
import { hostileState } from "./seed-hostile";
import type { MockState } from "./state";
import { hasControls, takeControls } from "./controls";
import { loadStrengthChecker } from "@/lib/passphrase";

// Bumped whenever the stored shape changes, so an old session reseeds instead of breaking.
const STORAGE_KEY = "sekret-mock-state-v4";
const LATENCY_MS = 80;

function loadState(): MockState {
  let hostile = false;
  try {
    const saved = window.sessionStorage.getItem(STORAGE_KEY);
    if (saved) return JSON.parse(saved) as MockState;
    hostile = window.sessionStorage.getItem(HOSTILE_SEED_FLAG) === HOSTILE_SEED;
  } catch {
    // Storage may be unavailable; fall back to a fresh seed.
  }
  const now = Math.floor(Date.now() / 1000);
  return hostile ? hostileState(now) : seededState(now);
}

let state: MockState | undefined;
let lastNow = 0;

/** Strictly increasing seconds so ordering by time matches ordering by write. */
function now(): number {
  lastNow = Math.max(lastNow + 1, Math.floor(Date.now() / 1000));
  return lastNow;
}

function backend(): { backend: MockBackend; save: () => void } {
  state ??= loadState();
  const current = state;
  lastNow = Math.max(lastNow, ...current.audit.slice(0, 1).map((a) => a.created_at));
  const b = new MockBackend(current, now);
  const save = () => {
    try {
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(current));
    } catch {
      // Persistence is best effort.
    }
  };
  // `?mock-state=sealed` and friends apply once and then persist for the session.
  const controls = takeControls();
  if (hasControls(controls)) {
    b.applyControls(controls);
    save();
  }
  return { backend: b, save };
}

interface Ctx {
  params: string[];
  query: URLSearchParams;
  body: unknown;
  /** The undecoded request body, for routes that take bytes rather than JSON. */
  raw: Uint8Array;
}

type Handler = (b: MockBackend, ctx: Ctx) => unknown;

interface Route {
  method: string;
  pattern: RegExp;
  handler: Handler;
  status?: number;
  raw?: boolean;
}

const routes: Route[] = [];

function route(method: string, path: string, handler: Handler, status?: number, raw?: boolean) {
  const pattern = new RegExp(`^${path.replace(/\{[^}]+\}/g, "([^/]+)")}$`);
  routes.push({ method, pattern, handler, status, raw });
}

/** A handler result that is sent as-is instead of as JSON. */
class Binary {
  readonly bytes: Uint8Array;
  readonly contentType: string;
  /** Sent as an attachment with this name. */
  readonly filename?: string;

  constructor(bytes: Uint8Array, contentType: string, filename?: string) {
    this.bytes = bytes;
    this.contentType = contentType;
    this.filename = filename;
  }

  headers(): Record<string, string> {
    const headers: Record<string, string> = { "Content-Type": this.contentType };
    if (this.filename) headers["Content-Disposition"] = `attachment; filename="${this.filename}"`;
    return headers;
  }
}

const qs = (ctx: Ctx, name: string, fallback = "/") => ctx.query.get(name) ?? fallback;
const flag = (ctx: Ctx, name: string) => ctx.query.get(name) === "true";
const num = (ctx: Ctx, name: string) => {
  const value = ctx.query.get(name);
  return value === null ? undefined : Number(value);
};
const body = <T>(ctx: Ctx) => ctx.body as T;
const text = (ctx: Ctx, name: string) => ctx.query.get(name) ?? undefined;

/** Parses an enum query parameter the way serde would, refusing unknown values. */
function choice<T extends string>(ctx: Ctx, name: string, allowed: readonly T[]): T | undefined {
  const value = ctx.query.get(name);
  if (value === null) return undefined;
  if (!allowed.includes(value as T)) {
    throw new MockError(400, "bad_request", `Failed to deserialize query string: ${name}: unknown variant \`${value}\``);
  }
  return value as T;
}

const ORDERS: readonly SortOrder[] = ["desc", "asc"];
const STATUSES: readonly Status[] = ["active", "disabled"];
const USER_SORTS: readonly UserSort[] = ["name", "email", "created", "last_login"];
const IDENTITY_SORTS: readonly IdentitySort[] = ["name", "created"];

const auditQuery = (ctx: Ctx): AuditQuery => ({
  q: text(ctx, "q"),
  action: text(ctx, "action"),
  actor_id: text(ctx, "actor_id"),
  actor_kind: text(ctx, "actor_kind"),
  environment: text(ctx, "environment"),
  key: text(ctx, "key"),
  path: text(ctx, "path"),
  since: num(ctx, "since"),
  until: num(ctx, "until"),
  order: choice(ctx, "order", ORDERS),
  cursor: text(ctx, "cursor"),
  limit: num(ctx, "limit"),
});

const userQuery = (ctx: Ctx): UserQuery => ({
  q: text(ctx, "q"),
  status: choice(ctx, "status", STATUSES),
  sort: choice(ctx, "sort", USER_SORTS),
  order: choice(ctx, "order", ORDERS),
  offset: num(ctx, "offset"),
  limit: num(ctx, "limit"),
});

const identityQuery = (ctx: Ctx): IdentityQuery => ({
  q: text(ctx, "q"),
  status: choice(ctx, "status", STATUSES),
  sort: choice(ctx, "sort", IDENTITY_SORTS),
  order: choice(ctx, "order", ORDERS),
  offset: num(ctx, "offset"),
  limit: num(ctx, "limit"),
});

const P = "/api/v1/projects/{project}";
const E = `${P}/environments/{env}`;

route("GET", "/api/v1/sys/status", (b) => b.publicStatus());
route("GET", "/api/v1/sys/status/detail", (b) => b.statusDetail());
route("POST", "/api/v1/sys/init", async (b, c) => b.init(body<InitRequest>(c), await loadStrengthChecker()));
route("POST", "/api/v1/sys/unseal", (b, c) => b.unseal(body<UnsealRequest>(c).passphrase));
route("POST", "/api/v1/sys/passphrase-strength", async (b, c) =>
  b.checkPassphrase(body<PassphraseCheck>(c).passphrase, await loadStrengthChecker()),
);
route("POST", "/api/v1/sys/seal", (b) => b.seal());
route("POST", "/api/v1/sys/passphrase", async (b, c) => b.changePassphrase(body<ChangePassphrase>(c), await loadStrengthChecker()), 204);
route("PUT", "/api/v1/sys/unlock-policy", (b, c) => {
  const request = body<SetUnlockPolicy>(c);
  return b.setUnlockPolicy(request.policy, request.passphrase);
});
route("POST", "/api/v1/sys/forget-unlock", (b) => b.forgetUnlock());
route("POST", "/api/v1/sys/backup", (b) => {
  const file = b.backup();
  return new Binary(file.bytes, "application/octet-stream", file.filename);
});
route("GET", "/api/v1/sys/backup", () => {
  throw new MockError(405, "method_not_allowed", "use POST to make a backup");
});

route("GET", "/api/v1/auth/config", (b) => b.authConfig());
route("GET", "/api/v1/auth/cli/pending", (b, c) => b.pendingCli(qs(c, "code", "")));
route("POST", "/api/v1/auth/cli/approve", (b, c) => b.approveCli(body<CliApproveRequest>(c).code), 204);
route("POST", "/api/v1/auth/cli/deny", (b, c) => b.denyCli(body<CliDenyRequest>(c).code), 204);
route("POST", "/auth/logout", (b) => b.logout());
route("GET", "/api/v1/me", (b) => b.me());

route("GET", "/api/v1/projects", (b) => b.listProjects());
route("POST", "/api/v1/projects", (b, c) => b.createProject(body<CreateProject>(c)), 201);
route("GET", P, (b, c) => b.getProject(c.params[0]));
route("PATCH", P, (b, c) => b.updateProject(c.params[0], body<UpdateProject>(c)));
route("DELETE", P, (b, c) => b.deleteProject(c.params[0]), 204);
route("GET", `${P}/permissions`, (b, c) => b.permissions(c.params[0]));
route("GET", `${P}/overview`, (b, c) => b.overview(c.params[0], qs(c, "path")));
route("GET", `${P}/audit`, (b, c) => b.projectAudit(c.params[0], auditQuery(c)));
route("GET", `${P}/logo`, (b, c) => {
  const logo = b.getLogo(c.params[0]);
  return new Binary(logo.bytes, logo.contentType);
});
route("PUT", `${P}/logo`, async (b, c) => b.putLogo(c.params[0], c.raw, await renderPng(c.raw)), 200, true);
route("DELETE", `${P}/logo`, (b, c) => b.deleteLogo(c.params[0]));
route("GET", `${P}/secret-policy`, (b, c) => b.getProjectPolicy(c.params[0]));
route("PUT", `${P}/secret-policy`, (b, c) => b.putProjectPolicy(c.params[0], body<SecretPolicy>(c)));

route("GET", `${P}/environments`, (b, c) => b.listEnvironments(c.params[0]));
route("POST", `${P}/environments`, (b, c) => b.createEnvironment(c.params[0], body<CreateEnvironment>(c)), 201);
route("PATCH", E, (b, c) => b.updateEnvironment(c.params[0], c.params[1], body<UpdateEnvironment>(c)));
route("DELETE", E, (b, c) => b.deleteEnvironment(c.params[0], c.params[1]), 204);

route("GET", `${E}/folders`, (b, c) => b.listFolders(c.params[0], c.params[1]));
route("POST", `${E}/folders`, (b, c) => b.createFolder(c.params[0], c.params[1], body<{ path: string }>(c).path), 201);
route("DELETE", `${E}/folders`, (b, c) => b.deleteFolder(c.params[0], c.params[1], qs(c, "path")), 204);

route("GET", `${E}/secrets`, (b, c) => b.listSecrets(c.params[0], c.params[1], qs(c, "path"), flag(c, "values"), flag(c, "recursive")));
route("POST", `${E}/secrets/batch`, (b, c) => b.batchWrite(c.params[0], c.params[1], body<BatchWrite>(c)));
route("GET", `${E}/secrets/{key}`, (b, c) => b.getSecret(c.params[0], c.params[1], c.params[2], qs(c, "path")));
route("PUT", `${E}/secrets/{key}`, (b, c) => b.setSecret(c.params[0], c.params[1], c.params[2], qs(c, "path"), body<SetSecret>(c)));
route("DELETE", `${E}/secrets/{key}`, (b, c) => b.deleteSecret(c.params[0], c.params[1], c.params[2], qs(c, "path")));
route("GET", `${E}/secrets/{key}/versions`, (b, c) =>
  b.listVersions(c.params[0], c.params[1], c.params[2], qs(c, "path"), flag(c, "values")),
);
route("POST", `${E}/secrets/{key}/rollback`, (b, c) =>
  b.rollback(c.params[0], c.params[1], c.params[2], qs(c, "path"), body<{ version: number }>(c).version),
);
route("POST", `${E}/secrets/{key}/generate`, (b, c) =>
  b.generateSecret(c.params[0], c.params[1], c.params[2], qs(c, "path"), body<GenerateSecret>(c)),
);
route("GET", `${E}/secrets/{key}/policy`, (b, c) => b.getSecretPolicy(c.params[0], c.params[1], c.params[2], qs(c, "path")));
route("PUT", `${E}/secrets/{key}/policy`, (b, c) =>
  b.putSecretPolicy(c.params[0], c.params[1], c.params[2], qs(c, "path"), body<PolicyOverride>(c)),
);

route("GET", `${E}/snapshots`, (b, c) => b.listSnapshots(c.params[0], c.params[1]));
route("GET", `${E}/snapshots/{id}`, (b, c) => b.getSnapshot(c.params[0], c.params[1], c.params[2], qs(c, "path")));
route("POST", `${E}/snapshots/{id}/restore`, (b, c) =>
  b.restoreSnapshot(c.params[0], c.params[1], c.params[2], body<{ path?: string }>(c).path ?? "/"),
);

route("GET", `${P}/members`, (b, c) => b.listMembers(c.params[0]));
route("POST", `${P}/members`, (b, c) => b.addMember(c.params[0], body<AddMembership>(c)), 201);
route("DELETE", `${P}/members/{kind}/{id}/{role}`, (b, c) =>
  b.removeMember(c.params[0], c.params[1] as PrincipalKind, c.params[2], c.params[3]), 204);
route("GET", `${P}/roles`, (b, c) => b.listRoles(c.params[0]));
route("PUT", `${P}/roles/{slug}`, (b, c) => b.putRole(c.params[0], c.params[1], body<PutRole>(c)));
route("DELETE", `${P}/roles/{slug}`, (b, c) => b.deleteRole(c.params[0], c.params[1]), 204);

route("GET", "/api/v1/audit", (b, c) => b.orgAudit(auditQuery(c)));
route("GET", "/api/v1/users", (b, c) => b.listUsers(userQuery(c)));
route("PATCH", "/api/v1/users/{id}", (b, c) => b.updateUser(c.params[0], body<{ disabled: boolean }>(c).disabled), 204);

route("GET", "/api/v1/identities", (b, c) => b.listIdentities(identityQuery(c)));
route("POST", "/api/v1/identities", (b, c) => b.createIdentity(body<CreateIdentity>(c)), 201);
route("GET", "/api/v1/identities/{id}", (b, c) => b.getIdentity(c.params[0]));
route("PATCH", "/api/v1/identities/{id}", (b, c) => b.updateIdentity(c.params[0], body<UpdateIdentity>(c)));
route("DELETE", "/api/v1/identities/{id}", (b, c) => b.deleteIdentity(c.params[0]), 204);
route("POST", "/api/v1/identities/{id}/revoke-tokens", (b, c) => b.revokeIdentityTokens(c.params[0]), 204);
route("GET", "/api/v1/identities/{id}/auth", (b, c) => b.listAuthMethods(c.params[0]));
route("PUT", "/api/v1/identities/{id}/auth/{kind}", (b, c) => b.putAuthMethod(c.params[0], c.params[1], body<AuthMethodConfig>(c)), 204);
route("DELETE", "/api/v1/identities/{id}/auth/{kind}", (b, c) => b.deleteAuthMethod(c.params[0], c.params[1] as AuthMethodKind), 204);
route("GET", "/api/v1/identities/{id}/client-secrets", (b, c) => b.listClientSecrets(c.params[0]));
route("POST", "/api/v1/identities/{id}/client-secrets", (b, c) => b.createClientSecret(c.params[0], body<CreateClientSecret>(c)), 201);
route("DELETE", "/api/v1/identities/{id}/client-secrets/{secret}", (b, c) => b.revokeClientSecret(c.params[0], c.params[1]), 204);

route("GET", "/api/v1/org/bindings", (b) => b.listOrgBindings());
route("POST", "/api/v1/org/bindings", (b, c) => b.addOrgBinding(body<AddOrgBinding>(c)), 201);
route("DELETE", "/api/v1/org/bindings/{kind}/{id}/{role}", (b, c) =>
  b.removeOrgBinding(c.params[0] as PrincipalKind, c.params[1], c.params[2]), 204);
route("GET", "/api/v1/org/roles", (b) => b.listOrgRoles());
route("PUT", "/api/v1/org/roles/{slug}", (b, c) => b.putOrgRole(c.params[0], body<PutRole>(c)));
route("DELETE", "/api/v1/org/roles/{slug}", (b, c) => b.deleteOrgRole(c.params[0]), 204);

function json(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
}

/** Routes the server answers while sealed or not set up, all without a session. */
const OPEN_WHILE_SEALED = new Set([
  "/api/v1/sys/status",
  "/api/v1/sys/init",
  "/api/v1/sys/unseal",
  "/api/v1/sys/passphrase-strength",
  "/auth/logout",
]);
const PUBLIC = new Set(["/api/v1/auth/config", ...OPEN_WHILE_SEALED]);

const requestLog: string[] = [];

/** Every request answered so far in this page, as `METHOD /path?query`, for tests to check what was asked for. */
export function mockRequestLog(): string[] {
  return [...requestLog];
}

/** Answers a request the way the real server would, against in-memory state. */
export async function mockFetch(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  requestLog.push(`${method} ${url.pathname}${url.search}`);
  await new Promise((resolve) => setTimeout(resolve, LATENCY_MS));
  const match = routes
    .filter((r) => r.method === method)
    .map((r) => ({ r, m: url.pathname.match(r.pattern) }))
    .find((x) => x.m);
  if (!match?.m) return json(404, { error: "not_found", message: "endpoint not found" });

  const { backend: b, save } = backend();
  try {
    if (!OPEN_WHILE_SEALED.has(url.pathname)) b.requireUnsealed();
    if (!PUBLIC.has(url.pathname)) b.requireSession();
    if (method !== "GET" && request.headers.get(CSRF_HEADER) !== "1") {
      throw new MockError(403, "csrf", "missing CSRF header");
    }
    if (b.rotateDue(Math.floor(Date.now() / 1000)).length > 0) save();
    const raw = method === "GET" ? new Uint8Array() : new Uint8Array(await request.arrayBuffer());
    const text = match.r.raw ? "" : new TextDecoder().decode(raw);
    const ctx: Ctx = {
      params: match.m.slice(1).map(decodeURIComponent),
      query: url.searchParams,
      body: text ? JSON.parse(text) : undefined,
      raw,
    };
    const result = await match.r.handler(b, ctx);
    if (method !== "GET") save();
    const status = match.r.status ?? 200;
    if (status === 204) return new Response(null, { status });
    if (result instanceof Binary) {
      return new Response(result.bytes.slice().buffer, { status, headers: result.headers() });
    }
    return json(status, result ?? null);
  } catch (error) {
    // A failed call can still change state, such as counting a wrong passphrase.
    save();
    if (error instanceof MockError) {
      return json(error.status, { ...error.extra, error: error.code, message: error.message });
    }
    return json(500, { error: "internal", message: error instanceof Error ? error.message : "mock failure" });
  }
}

/** `fresh` stands for signing in again with the password and passkey, as reauthentication asks. */
export function mockSignIn(fresh = false): void {
  const { backend: b, save } = backend();
  b.signIn(fresh);
  save();
}

/** Seals the fake server as if someone else had, for trying what an open tab does next. */
export function mockSealServer(): void {
  const { backend: b, save } = backend();
  b.applyControls({ state: "sealed" });
  save();
}
