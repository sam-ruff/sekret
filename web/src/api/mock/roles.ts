import type { Action, Role, Rule, Subject } from "../types";
import { ACTIONS, ORG_SUBJECTS, PROJECT_SUBJECTS } from "../types";

const allow = (subject: Subject, actions: readonly Action[]): Rule => ({
  effect: "allow",
  subject,
  actions: [...actions],
});

const ALL = ACTIONS;

export const ORG_ADMIN_RULES: Rule[] = [...ORG_SUBJECTS, ...PROJECT_SUBJECTS].map((s) => allow(s, ALL));

export function builtinRoles(orgScope: boolean): Role[] {
  if (orgScope) {
    return [
      {
        slug: "org-admin",
        name: "org admin",
        description: "Full control of the organisation and every project",
        builtin: true,
        rules: ORG_ADMIN_RULES,
      },
      {
        slug: "org-member",
        name: "org member",
        description: "Can create projects",
        builtin: true,
        rules: [
          allow("projects", ["create"]),
          allow("identities", ["read"]),
          allow("org-members", ["read"]),
          allow("org-roles", ["read"]),
        ],
      },
    ];
  }
  return [
    {
      slug: "admin",
      name: "admin",
      description: "Full control of the project",
      builtin: true,
      rules: PROJECT_SUBJECTS.map((s) => allow(s, ALL)),
    },
    {
      slug: "developer",
      name: "developer",
      description: "Read and write secrets, manage folders and restore snapshots",
      builtin: true,
      rules: [
        allow("secrets", ALL),
        allow("secret-versions", ["read", "read-value"]),
        allow("snapshots", ["read", "edit"]),
        allow("folders", ["read", "create", "edit", "delete"]),
        allow("environments", ["read"]),
        allow("members", ["read"]),
        allow("roles", ["read"]),
        allow("audit-log", ["read"]),
      ],
    },
    {
      slug: "viewer",
      name: "viewer",
      description: "Read secrets and their metadata",
      builtin: true,
      rules: [
        allow("secrets", ["read", "read-value"]),
        allow("secret-versions", ["read"]),
        allow("snapshots", ["read"]),
        allow("folders", ["read"]),
        allow("environments", ["read"]),
        allow("members", ["read"]),
        allow("roles", ["read"]),
      ],
    },
    {
      slug: "no-access",
      name: "no access",
      description: "No access; useful for explicit membership with no rights",
      builtin: true,
      rules: [],
    },
  ];
}

function sameConditions(a: Rule, b: Rule): boolean {
  const norm = (r: Rule) =>
    JSON.stringify([
      r.conditions?.environments ?? [],
      r.conditions?.paths ?? [],
      r.conditions?.keys ?? [],
      r.conditions?.tags ?? [],
    ]);
  return norm(a) === norm(b);
}

function unconditional(r: Rule): boolean {
  return sameConditions(r, { ...r, conditions: undefined });
}

/** Port of the server's escalation check: the holder must already have everything granted. */
export function covers(holder: readonly Rule[], granted: readonly Rule[]): boolean {
  return granted
    .filter((g) => g.effect === "allow")
    .every((g) =>
      g.actions.every((action) => {
        const allowed = holder.some(
          (h) =>
            h.effect === "allow" &&
            h.subject === g.subject &&
            h.actions.includes(action) &&
            (unconditional(h) || sameConditions(h, g)),
        );
        const denied = holder.some((h) => h.effect === "deny" && h.subject === g.subject && h.actions.includes(action));
        return allowed && !denied;
      }),
    );
}
