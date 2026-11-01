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
  "project.secret-policy": "Changed the default secret policy",
  "project.update": "Changed project details",
  "role.delete": "Deleted a role",
  "role.put": "Saved a role",
  "secret.generate": "Generated a value",
  "secret.history-read": "Viewed history values",
  "secret.policy": "Changed a secret's policy",
  "secret.read": "Read values",
  "secret.rollback": "Rolled back a secret",
  "secret.rotate": "Rotated a secret",
  "secret.write": "Changed secrets",
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
]);

function summary(action: string, detail: Detail): string[] {
  const parts: string[] = [];
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
  if (typeof detail.content_type === "string" && typeof detail.bytes === "number") {
    const format = detail.content_type.replace(/^image\//, "").replace(/\+xml$/, "").toUpperCase();
    parts.push(`${format} image, ${formatBytes(detail.bytes)}`);
  }
  if (typeof detail.role === "string" && typeof detail.principal_id === "string") {
    const kind = KIND_NAMES[String(detail.principal_kind)] ?? "principal";
    const removed = action.endsWith("remove");
    parts.push(`Role ${detail.role} ${removed ? "taken from" : "given to"} ${kind} ${detail.principal_id}`);
  } else if (typeof detail.role === "string") {
    parts.push(`Role ${detail.role}`);
  }
  return parts;
}

/** An audit entry's detail in plain words, falling back to `key: value` for fields it does not know. */
export function describeDetail(action: string, detail: unknown): string {
  if (!detail || typeof detail !== "object" || Array.isArray(detail)) return "";
  const fields = detail as Detail;
  const known = summary(action, fields);
  const rest = Object.entries(fields)
    .filter(([k]) => !SUMMARISED.has(k))
    .filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && v.length === 0))
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${rawValue(v)}`);
  return [...known, ...rest].join(" · ");
}
