import type { AuditQuery } from "@/api/endpoints";
import type { SortOrder } from "@/api/types";

export type ActorKind = "" | "user" | "identity";

export interface AuditFilters {
  q: string;
  /** An action prefix such as `secret.`. */
  action: string;
  actorKind: ActorKind;
  actorId: string;
  environment: string;
  key: string;
  path: string;
  /** Inclusive local dates as `YYYY-MM-DD`. */
  from: string;
  to: string;
  order: SortOrder;
}

export const EMPTY_AUDIT_FILTERS: AuditFilters = {
  q: "",
  action: "",
  actorKind: "",
  actorId: "",
  environment: "",
  key: "",
  path: "",
  from: "",
  to: "",
  order: "desc",
};

export const ACTION_CATEGORIES: readonly { prefix: string; label: string; scope: "project" | "org" | "both" }[] = [
  { prefix: "secret.", label: "Secrets", scope: "both" },
  { prefix: "folder.", label: "Folders", scope: "both" },
  { prefix: "snapshot.", label: "Snapshots", scope: "both" },
  { prefix: "environment.", label: "Environments", scope: "both" },
  { prefix: "member.", label: "Members", scope: "both" },
  { prefix: "role.", label: "Roles", scope: "both" },
  { prefix: "project.", label: "Project settings", scope: "both" },
  { prefix: "identity.", label: "Machine identities", scope: "org" },
  { prefix: "auth.", label: "Sign-ins", scope: "org" },
  { prefix: "user.", label: "Users", scope: "org" },
  { prefix: "org.", label: "Organisation access", scope: "org" },
];

const PARAMS: Record<Exclude<keyof AuditFilters, "order">, string> = {
  q: "q",
  action: "action",
  actorKind: "actor_kind",
  actorId: "actor",
  environment: "env",
  key: "key",
  path: "path",
  from: "from",
  to: "to",
};

const DATE = /^\d{4}-\d{2}-\d{2}$/;

function dateParam(value: string | null): string {
  return value && DATE.test(value) ? value : "";
}

export function parseAuditFilters(params: URLSearchParams): AuditFilters {
  const get = (name: string) => params.get(name)?.trim() ?? "";
  const kind = get(PARAMS.actorKind);
  return {
    q: get(PARAMS.q),
    action: get(PARAMS.action),
    actorKind: kind === "user" || kind === "identity" ? kind : "",
    actorId: get(PARAMS.actorId),
    environment: get(PARAMS.environment),
    key: get(PARAMS.key),
    path: get(PARAMS.path),
    from: dateParam(params.get(PARAMS.from)),
    to: dateParam(params.get(PARAMS.to)),
    order: params.get("order") === "asc" ? "asc" : "desc",
  };
}

/** Only non-default values go in the URL, so a clean page has a clean address. */
export function auditSearchParams(filters: AuditFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const [field, name] of Object.entries(PARAMS) as [keyof typeof PARAMS, string][]) {
    const value = filters[field].trim();
    if (value) params.set(name, value);
  }
  if (filters.order === "asc") params.set("order", "asc");
  return params;
}

function localDate(value: string): Date {
  const [y, m, d] = value.split("-").map(Number);
  return new Date(y, m - 1, d);
}

export function dayStart(value: string): number {
  return Math.floor(localDate(value).getTime() / 1000);
}

export function dayEnd(value: string): number {
  const next = localDate(value);
  next.setDate(next.getDate() + 1);
  return Math.floor(next.getTime() / 1000) - 1;
}

export function isoDate(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export function auditQuery(filters: AuditFilters): AuditQuery {
  const query: AuditQuery = { order: filters.order };
  if (filters.q) query.q = filters.q;
  if (filters.action) query.action = filters.action;
  if (filters.actorKind) query.actor_kind = filters.actorKind;
  if (filters.actorId) query.actor_id = filters.actorId;
  if (filters.environment) query.environment = filters.environment;
  if (filters.key) query.key = filters.key;
  if (filters.path) query.path = filters.path;
  if (filters.from) query.since = dayStart(filters.from);
  if (filters.to) query.until = dayEnd(filters.to);
  return query;
}

/** Filters that narrow the results; sort order does not count. */
export function hasActiveFilters(filters: AuditFilters): boolean {
  return (Object.keys(PARAMS) as (keyof typeof PARAMS)[]).some((field) => filters[field] !== "");
}

export interface DatePreset {
  id: string;
  label: string;
  days: number;
}

export const DATE_PRESETS: readonly DatePreset[] = [
  { id: "today", label: "Today", days: 1 },
  { id: "7d", label: "Last 7 days", days: 7 },
  { id: "30d", label: "Last 30 days", days: 30 },
  { id: "90d", label: "Last 90 days", days: 90 },
];

export function presetRange(preset: DatePreset, today = new Date()): { from: string; to: string } {
  const start = new Date(today.getFullYear(), today.getMonth(), today.getDate() - (preset.days - 1));
  return { from: isoDate(start), to: isoDate(today) };
}

const shortDate = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short" });

/** A compact label for the date button, such as "Last 7 days" or "3 Mar - 9 Mar". */
export function dateRangeLabel(from: string, to: string, today = new Date()): string {
  if (!from && !to) return "Any time";
  const preset = DATE_PRESETS.find((p) => {
    const range = presetRange(p, today);
    return range.from === from && range.to === to;
  });
  if (preset) return preset.label;
  if (from && to) return from === to ? shortDate.format(localDate(from)) : `${shortDate.format(localDate(from))} - ${shortDate.format(localDate(to))}`;
  return from ? `From ${shortDate.format(localDate(from))}` : `Until ${shortDate.format(localDate(to))}`;
}
