import type { Action, Conditions as FullConditions, Rule as ApiRule, Subject } from "@/api/types";
import { globMatch } from "./glob";

/** The server defaults every condition list, so any of them may be omitted. */
export type Conditions = Partial<FullConditions>;
export type Rule = Omit<ApiRule, "conditions"> & { conditions?: Conditions };

/** What is being acted upon. Missing fields are unknown, which never satisfies an allow condition. */
export interface Resource {
  environment?: string;
  path?: string;
  key?: string;
  tags?: readonly string[];
  /**
   * For a restricted secret, the actions its access list grants the caller; absent when the
   * secret is open or the caller is exempt. It narrows what rules allow and never widens it.
   */
  granted?: readonly Action[];
}

/** Subjects about one secret, which answer to its access list. */
const LISTED_SUBJECTS: readonly Subject[] = ["secrets", "secret-versions"];

function listPermits(granted: readonly Action[] | undefined, subject: Subject, action: Action): boolean {
  if (granted === undefined || !LISTED_SUBJECTS.includes(subject)) return true;
  return granted.includes(action === "create" ? "edit" : action);
}

function listed(values: readonly string[] | undefined): readonly string[] {
  return values ?? [];
}

function envMatches(conditions: Conditions, env: string): boolean {
  return listed(conditions.environments).includes(env);
}

function pathMatches(conditions: Conditions, path: string): boolean {
  return listed(conditions.paths).some((g) => globMatch(g, path, "/"));
}

function keyMatches(conditions: Conditions, key: string): boolean {
  return listed(conditions.keys).some((g) => globMatch(g, key));
}

function tagsMatch(conditions: Conditions, tags: readonly string[]): boolean {
  const wanted = listed(conditions.tags);
  return wanted.length === 0 || tags.some((t) => wanted.includes(t));
}

/** Every non-empty condition of an allow rule must positively match. */
function allowApplies(conditions: Conditions, resource: Resource): boolean {
  const envOk =
    listed(conditions.environments).length === 0 ||
    (resource.environment !== undefined && envMatches(conditions, resource.environment));
  const pathOk =
    listed(conditions.paths).length === 0 || (resource.path !== undefined && pathMatches(conditions, resource.path));
  const keyOk =
    listed(conditions.keys).length === 0 || (resource.key !== undefined && keyMatches(conditions, resource.key));
  return envOk && pathOk && keyOk && tagsMatch(conditions, resource.tags ?? []);
}

/** A deny rule applies unless the resource is known to fall outside it. */
function denyApplies(conditions: Conditions, resource: Resource): boolean {
  const envHit =
    listed(conditions.environments).length === 0 ||
    resource.environment === undefined ||
    envMatches(conditions, resource.environment);
  const pathHit =
    listed(conditions.paths).length === 0 || resource.path === undefined || pathMatches(conditions, resource.path);
  const keyHit =
    listed(conditions.keys).length === 0 || resource.key === undefined || keyMatches(conditions, resource.key);
  return envHit && pathHit && keyHit && tagsMatch(conditions, resource.tags ?? []);
}

export function authorise(rules: readonly Rule[], subject: Subject, action: Action, resource: Resource = {}): boolean {
  const relevant = rules.filter((r) => r.subject === subject && r.actions.includes(action));
  const conditionsOf = (r: Rule): Conditions => r.conditions ?? {};
  if (relevant.some((r) => r.effect === "deny" && denyApplies(conditionsOf(r), resource))) return false;
  if (!listPermits(resource.granted, subject, action)) return false;
  return relevant.some((r) => r.effect === "allow" && allowApplies(conditionsOf(r), resource));
}

function conditionsEmpty(conditions: Conditions | undefined): boolean {
  if (!conditions) return true;
  return (
    listed(conditions.environments).length === 0 &&
    listed(conditions.paths).length === 0 &&
    listed(conditions.keys).length === 0 &&
    listed(conditions.tags).length === 0
  );
}

/** Whether some rule could allow `action` on `subject` somewhere, for showing entry points to conditional access. */
export function maySomewhere(rules: readonly Rule[], subject: Subject, action: Action): boolean {
  const blanketDeny = rules.some(
    (r) => r.effect === "deny" && r.subject === subject && r.actions.includes(action) && conditionsEmpty(r.conditions),
  );
  if (blanketDeny) return false;
  return rules.some((r) => r.effect === "allow" && r.subject === subject && r.actions.includes(action));
}
