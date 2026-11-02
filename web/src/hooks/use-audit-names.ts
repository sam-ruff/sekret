import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/endpoints";
import type { AuditEntry } from "@/api/types";
import { keys, useOrgRoles, useRoles } from "@/hooks/queries";
import { useOrgPermissions, useProjectPermissions } from "@/hooks/use-permissions";
import type { AuditNames } from "@/lib/audit-labels";

/** Looked up once for names; a larger directory falls back to IDs past this many. */
const DIRECTORY_LIMIT = 100;

type Lookup = Map<string, string>;

function add(map: Lookup, id: string | undefined, name: string | undefined) {
  if (id && name && !map.has(id)) map.set(id, name);
}

/** Names for the IDs audit entries carry, from data the reader may already see. */
export function auditNames(
  entries: readonly AuditEntry[],
  directory: { users?: Lookup; identities?: Lookup; roles?: Lookup; projects?: Lookup },
): AuditNames {
  const users: Lookup = new Map(directory.users);
  const identities: Lookup = new Map(directory.identities);
  const projects: Lookup = new Map(directory.projects);
  for (const e of entries) {
    if (e.actor_kind === "user") add(users, e.actor_id, e.actor_name);
    if (e.actor_kind === "identity") add(identities, e.actor_id, e.actor_name);
    const detail = e.detail as Record<string, unknown> | null;
    if (e.action === "identity.create" && detail && typeof detail.identity === "string" && typeof detail.name === "string") {
      add(identities, detail.identity, detail.name);
    }
    // A project the reader cannot list, or one since deleted, is still named by its slug.
    if (e.action.startsWith("project.") && e.project_id && detail && typeof detail.slug === "string") {
      add(projects, e.project_id, detail.slug);
    }
  }
  return {
    user: (id) => users.get(id),
    identity: (id) => identities.get(id),
    role: (slug) => directory.roles?.get(slug),
    project: (id) => projects.get(id),
  };
}

/** Directory lookups for the org or one project, each only when the reader may list it. */
export function useAuditDirectory(project?: string) {
  const org = useOrgPermissions();
  const perms = useProjectPermissions(project ?? "");
  const inProject = project !== undefined;

  const members = useQuery({
    queryKey: keys.members(project ?? ""),
    queryFn: () => api.members(project ?? ""),
    enabled: inProject && perms.canSomewhere("members", "read"),
    retry: false,
  });
  const projectRoles = useRoles(project ?? "", inProject && perms.canSomewhere("roles", "read"));
  const bindings = useQuery({
    queryKey: keys.orgBindings,
    queryFn: api.orgBindings,
    enabled: !inProject && org.can("org-members", "read"),
    retry: false,
  });
  const orgRoles = useOrgRoles(!inProject && org.can("org-roles", "read"));
  const identities = useQuery({
    queryKey: ["audit-names", "identities"],
    queryFn: () => api.identities({ limit: DIRECTORY_LIMIT }),
    enabled: org.can("identities", "read"),
    retry: false,
  });
  const users = useQuery({
    queryKey: ["audit-names", "users"],
    queryFn: () => api.users({ limit: DIRECTORY_LIMIT }),
    enabled: !inProject && org.can("org-members", "read"),
    retry: false,
  });
  const projects = useQuery({ queryKey: keys.projects, queryFn: api.projects, enabled: !inProject, retry: false });

  const userNames: Lookup = new Map();
  const identityNames: Lookup = new Map();
  for (const u of users.data?.items ?? []) add(userNames, u.id, u.name || u.email);
  for (const i of identities.data?.items ?? []) add(identityNames, i.id, i.name);
  for (const b of [...(members.data ?? []), ...(bindings.data ?? [])]) {
    if (b.principal_kind === "user") add(userNames, b.principal_id, b.principal_name);
    if (b.principal_kind === "identity") add(identityNames, b.principal_id, b.principal_name);
  }
  const roleNames: Lookup = new Map();
  for (const r of [...(projectRoles.data ?? []), ...(orgRoles.data ?? [])]) add(roleNames, r.slug, r.name);
  const projectNames: Lookup = new Map();
  const projectSlugs: Lookup = new Map();
  for (const p of projects.data ?? []) {
    add(projectNames, p.id, p.name);
    add(projectSlugs, p.id, p.slug);
  }
  return { users: userNames, identities: identityNames, roles: roleNames, projects: projectNames, projectSlugs };
}
