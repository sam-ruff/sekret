import { formatBytes } from "./format";

/** Plain names for the actions the server records. Unknown actions show their raw code. */
const ACTION_LABELS: Record<string, string> = {
  "auth.cli-approve": "Approved a CLI sign-in",
  "auth.cli-deny": "Denied a CLI sign-in",
  "auth.cli-login": "Signed in from the CLI",
  "auth.login": "Signed in",
  "auth.login.refused": "Sign-in refused",
  "auth.logout": "Signed out",
  "auth.machine-login": "Machine signed in",
  "auth.machine-login.failed": "Machine sign-in failed",
  "auth.token-renew": "Renewed a token",
  "auth.token-revoke": "Revoked a token",
  "environment.create": "Created an environment",
  "environment.delete": "Deleted an environment",
  "environment.update": "Changed an environment",
  "folder.create": "Created a folder",
  "folder.delete": "Deleted a folder",
  "identity.auth-delete": "Removed an auth method",
  "identity.auth-put": "Set up an auth method",
  "identity.client-secret-create": "Created a client secret",
  "identity.client-secret-revoke": "Revoked a client secret",
  "identity.create": "Created a machine identity",
  "identity.delete": "Deleted a machine identity",
  "identity.revoke-tokens": "Revoked an identity's tokens",
  "identity.update": "Changed a machine identity",
  "member.add": "Added a member",
  "member.remove": "Removed a member",
  "org.binding-add": "Gave an organisation role",
  "org.binding-remove": "Took away an organisation role",
  "org.role-delete": "Deleted an organisation role",
  "org.role-put": "Saved an organisation role",
  "project.create": "Created the project",
  "project.delete": "Deleted the project",
  "project.logo-remove": "Removed the logo",
  "project.logo-set": "Changed the logo",
  "project.secret-access": "Changed per-secret access",
  "project.secret-policy": "Changed the default secret policy",
  "project.update": "Changed project details",
  "role.delete": "Deleted a role",
  "role.put": "Saved a role",
  "secret.access": "Changed who can reach a secret",
  "secret.generate": "Generated a value",
  "secret.history-read": "Viewed history values",
  "secret.policy": "Changed a secret's policy",
  "secret.read": "Read values",
  "secret.rollback": "Rolled back a secret",
  "secret.rotate": "Rotated a secret",
  "secret.write": "Changed secrets",
  "secret.write-refused": "Write to a hidden secret refused",
  "snapshot.restore": "Restored a snapshot",
  "sys.backup": "Downloaded a backup",
  "sys.backup.refused": "Backup refused",
  "sys.forbidden": "Refused a server request",
  "sys.forget_unlock": "Forgot the remembered unlock",
  "sys.init": "Set up the server",
  "sys.init.failed": "Server setup failed",
  "sys.passphrase": "Changed the passphrase",
  "sys.passphrase.failed": "Passphrase change failed",
  "sys.passphrase.skipped": "Passphrase change skipped",
  "sys.remember.refused": "Remembered unlock refused",
  "sys.seal": "Locked the server",
  "sys.seal_config.rolled_back": "Unlock settings rolled back",
  "sys.seal_config.tampered": "Unlock settings were tampered with",
  "sys.unlock_policy": "Changed the unlock policy",
  "sys.unseal": "Unlocked the server",
  "sys.unseal.failed": "Unlock failed",
  "sys.unseal.refused": "Unlock refused",
  "user.update": "Changed a user",
};

export function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

type Detail = Record<string, unknown>;

function count(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function listLength(value: unknown): number | null {
  return Array.isArray(value) ? value.length : null;
}

function rawValue(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ");
  if (value !== null && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

const KIND_NAMES: Record<string, string> = { user: "user", group: "group", identity: "machine identity" };

/** "2 created, 1 updated" from the lists a write or restore records. */
function changeCounts(detail: Detail): string | null {
  const parts = (["created", "updated", "deleted"] as const)
    .map((field) => [field, listLength(detail[field])] as const)
    .filter(([, n]) => n !== null && n > 0)
    .map(([field, n]) => `${n} ${field}`);
  const total = (["created", "updated", "deleted"] as const).some((f) => Array.isArray(detail[f]));
  if (!total) return null;
  return parts.length > 0 ? parts.join(", ") : "No changes";
}

function policySummary(policy: unknown): string {
  if (!policy || typeof policy !== "object") return "Policy changed";
  const p = policy as Detail;
  const parts: string[] = [];
  const generator = p.generator as Detail | null | undefined;
  if (generator && typeof generator === "object") {
    const length = typeof generator.length === "number" ? `${generator.length} characters` : null;
    const charset = typeof generator.charset === "string" ? generator.charset : null;
    parts.push(["Generates", length, charset && `of ${charset}`].filter(Boolean).join(" "));
  }
  if (typeof p.rotation_days === "number") parts.push(`rotates every ${count(p.rotation_days, "day", "days")}`);
  else if ("rotation_days" in p && p.rotation_days === null) parts.push("no rotation");
  return parts.length > 0 ? parts.join(", ") : "Policy changed";
}

/** Fields a summary already covers, so they are not listed again. */
const SUMMARISED = new Set([
  "count",
  "recursive",
  "raw",
  "created",
  "updated",
  "deleted",
  "to_version",
  "automatic",
  "policy",
  "principal_kind",
  "principal_id",
  "role",
  "snapshot",
  "content_type",
  "bytes",
  "enabled",
  "restricted",
  "granted",
  "revoked",
  "cleared",
]);

/** The names the access section gives the actions an entry can allow. */
export const ACCESS_ACTION_LABELS: Record<string, string> = {
  read: "Read name",
  "read-value": "Read value",
  edit: "Edit",
  delete: "Delete",
};

interface ListEntry {
  principal_kind?: unknown;
  principal_id?: unknown;
  actions?: unknown;
}

function entryName(entry: ListEntry, names: AuditNames): string {
  const kindCode = String(entry.principal_kind);
  return `${KIND_NAMES[kindCode] ?? "principal"} ${principalName(kindCode, String(entry.principal_id), names)}`;
}

/** Per-secret access changes in plain words. */
function accessSummary(action: string, detail: Detail, names: AuditNames): string[] {
  const parts: string[] = [];
  if (action === "project.secret-access" && typeof detail.enabled === "boolean") {
    parts.push(detail.enabled ? "Turned on" : "Turned off");
  }
  if (action === "secret.access") {
    // The entry records the flag as sent, not whether it changed.
    if (detail.restricted === true) parts.push("Set restricted");
    if (detail.restricted === false) parts.push("Set open");
    const entries = (field: unknown) => (Array.isArray(field) ? (field as ListEntry[]) : []);
    for (const c of entries(detail.cleared)) parts.push(`Removed ${entryName(c, names)}`);
    for (const g of entries(detail.granted)) {
      const actions = Array.isArray(g.actions) ? g.actions.map((a) => ACCESS_ACTION_LABELS[String(a)] ?? String(a)) : [];
      parts.push(`Granted ${entryName(g, names)}${actions.length > 0 ? `: ${actions.join(", ")}` : ""}`);
    }
    for (const r of entries(detail.revoked)) parts.push(`Removed ${entryName(r, names)}`);
  }
  if (action === "secret.write" && Array.isArray(detail.restricted) && detail.restricted.length > 0) {
    parts.push(`Created restricted: ${detail.restricted.join(", ")}`);
  }
  return parts;
}

/** Name lookups the reader's own data can answer; anything they miss shows its ID. */
export interface AuditNames {
  user?: (id: string) => string | undefined;
  identity?: (id: string) => string | undefined;
  role?: (slug: string) => string | undefined;
  project?: (id: string) => string | undefined;
}

const METHOD_NAMES: Record<string, string> = { universal: "Universal", oidc: "OIDC", kubernetes: "Kubernetes" };

function principalName(kind: string, id: string, names: AuditNames): string {
  if (kind === "user") return names.user?.(id) ?? id;
  if (kind === "identity") return names.identity?.(id) ?? id;
  return id;
}

function identityName(detail: Detail, names: AuditNames): string {
  const id = String(detail.identity);
  if (typeof detail.name === "string" && detail.name) return detail.name;
  return names.identity?.(id) ?? id;
}

/** Fields an identity sentence already covers. */
const IDENTITY_SUMMARISED = new Set(["identity", "name", "method", "kind", "prefix", "secret"]);

function identitySummary(action: string, detail: Detail, names: AuditNames): string | null {
  if (!action.startsWith("identity.") || typeof detail.identity !== "string") return null;
  const who = identityName(detail, names);
  const method = detail.method ?? detail.kind;
  const methodName = typeof method === "string" ? (METHOD_NAMES[method] ?? method) : null;
  switch (action) {
    case "identity.auth-put":
    case "identity.auth-delete":
      return methodName ? `${methodName} auth on ${who}` : `Auth method on ${who}`;
    case "identity.client-secret-create":
      return typeof detail.prefix === "string" ? `Client secret starting ${detail.prefix} for ${who}` : `Client secret for ${who}`;
    case "identity.client-secret-revoke":
      return `Client secret of ${who}`;
    default:
      return `Machine identity ${who}`;
  }
}

function summary(action: string, detail: Detail, names: AuditNames): string[] {
  const parts: string[] = [];
  const identity = identitySummary(action, detail, names);
  if (identity) parts.push(identity);
  if (action === "auth.machine-login" && typeof detail.method === "string") {
    parts.push(`Signed in with ${METHOD_NAMES[detail.method] ?? detail.method} auth`);
  }
  if (typeof detail.count === "number") {
    const what = action === "secret.read" ? count(detail.count, "value read", "values read") : String(detail.count);
    parts.push(detail.recursive === true ? `${what}, including sub-folders` : what);
  }
  const changes = changeCounts(detail);
  if (changes) parts.push(changes);
  if (action === "secret.generate" && typeof detail.created === "boolean") {
    parts.push(detail.created ? "New secret" : "New value for an existing secret");
  }
  if (typeof detail.to_version === "number") parts.push(`Back to version ${detail.to_version}`);
  if (detail.automatic === true) parts.push("Automatic");
  if ("policy" in detail) parts.push(policySummary(detail.policy));
  if (typeof detail.snapshot === "string") parts.push(`From snapshot ${detail.snapshot}`);
  parts.push(...accessSummary(action, detail, names));
  if (typeof detail.content_type === "string" && typeof detail.bytes === "number") {
    const format = detail.content_type.replace(/^image\//, "").replace(/\+xml$/, "").toUpperCase();
    parts.push(`${format} image, ${formatBytes(detail.bytes)}`);
  }
  if (typeof detail.role === "string") {
    const role = names.role?.(detail.role) ?? detail.role;
    if (typeof detail.principal_id === "string") {
      const kindCode = String(detail.principal_kind);
      const kind = KIND_NAMES[kindCode] ?? "principal";
      const removed = action.endsWith("remove");
      const who = principalName(kindCode, detail.principal_id, names);
      parts.push(`Role ${role} ${removed ? "taken from" : "given to"} ${kind} ${who}`);
    } else {
      parts.push(`Role ${role}`);
    }
  }
  return parts;
}

/** An audit entry's detail in plain words, falling back to `key: value` for fields it does not know. */
export function describeDetail(action: string, detail: unknown, names: AuditNames = {}): string {
  if (!detail || typeof detail !== "object" || Array.isArray(detail)) return "";
  const fields = detail as Detail;
  const known = summary(action, fields, names);
  const skip = action.startsWith("identity.") && typeof fields.identity === "string" ? IDENTITY_SUMMARISED : null;
  const methodSaid = action === "auth.machine-login" && typeof fields.method === "string";
  const rest = Object.entries(fields)
    .filter(([k]) => !SUMMARISED.has(k) && !skip?.has(k) && !(methodSaid && k === "method"))
    .filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && v.length === 0))
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${rawValue(v)}`);
  return [...known, ...rest].join(" · ");
}
