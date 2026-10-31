import type { Action, Effect, Rule, Subject } from "@/api/types";
import { ACTIONS } from "@/api/types";

export interface EditableRule {
  id: string;
  effect: Effect;
  subject: Subject;
  actions: Action[];
  environments: string[];
  paths: string[];
  keys: string[];
  tags: string[];
}

let counter = 0;
const nextId = () => `rule-${(counter += 1)}`;

export function blankRule(subject: Subject, effect: Effect = "allow"): EditableRule {
  return { id: nextId(), effect, subject, actions: [], environments: [], paths: [], keys: [], tags: [] };
}

/** One row per subject, followed by any extra rules the role already carries for that subject. */
export function toEditable(rules: readonly Rule[], subjects: readonly Subject[]): EditableRule[] {
  const rows: EditableRule[] = [];
  for (const subject of subjects) {
    const mine = rules.filter((r) => r.subject === subject);
    if (mine.length === 0) {
      rows.push(blankRule(subject));
      continue;
    }
    for (const r of mine) {
      rows.push({
        id: nextId(),
        effect: r.effect,
        subject,
        actions: ACTIONS.filter((a) => r.actions.includes(a)),
        environments: r.conditions?.environments ?? [],
        paths: r.conditions?.paths ?? [],
        keys: r.conditions?.keys ?? [],
        tags: r.conditions?.tags ?? [],
      });
    }
  }
  return rows;
}

export function hasConditions(rule: EditableRule): boolean {
  return rule.environments.length + rule.paths.length + rule.keys.length + rule.tags.length > 0;
}

/** Rules ready for the API; rows without actions are dropped. */
export function toRules(rows: readonly EditableRule[]): Rule[] {
  return rows
    .filter((r) => r.actions.length > 0)
    .map((r) => {
      const rule: Rule = { effect: r.effect, subject: r.subject, actions: [...r.actions] };
      if (hasConditions(r)) {
        rule.conditions = { environments: r.environments, paths: r.paths, keys: r.keys, tags: r.tags };
      }
      return rule;
    });
}

export function describeConditions(rule: EditableRule): string {
  const parts: string[] = [];
  if (rule.environments.length) parts.push(`in ${rule.environments.join(", ")}`);
  if (rule.paths.length) parts.push(`under ${rule.paths.join(", ")}`);
  if (rule.keys.length) parts.push(`keys ${rule.keys.join(", ")}`);
  if (rule.tags.length) parts.push(`tagged ${rule.tags.join(", ")}`);
  return parts.join("; ");
}

export const ACTION_LABELS: Record<Action, string> = {
  read: "Read",
  "read-value": "Read value",
  create: "Create",
  edit: "Edit",
  delete: "Delete",
};

export const SUBJECT_LABELS: Record<Subject, string> = {
  secrets: "Secrets",
  "secret-versions": "Secret history",
  snapshots: "Snapshots",
  folders: "Folders",
  environments: "Environments",
  members: "Members",
  roles: "Roles",
  "audit-log": "Audit log",
  settings: "Project settings",
  projects: "Projects",
  identities: "Machine identities",
  "org-members": "Organisation members",
  "org-roles": "Organisation roles",
  "org-audit-log": "Organisation audit log",
  backups: "Backups",
};
