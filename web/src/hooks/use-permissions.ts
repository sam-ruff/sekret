import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { api } from "@/api/endpoints";
import type { Action, Subject } from "@/api/types";
import { authorise, maySomewhere, type Resource, type Rule } from "@/lib/permissions";
import { keys, useMe } from "./queries";

export interface Permissions {
  /** True once rules are known; until then every check answers false. */
  ready: boolean;
  can: (subject: Subject, action: Action, resource?: Resource) => boolean;
  /** True if some resource may allow it, for showing entry points to conditional access. */
  canSomewhere: (subject: Subject, action: Action) => boolean;
}

export function permissionsFrom(rules: readonly Rule[] | undefined): Permissions {
  return {
    ready: rules !== undefined,
    can: (subject, action, resource) => (rules ? authorise(rules, subject, action, resource) : false),
    canSomewhere: (subject, action) => (rules ? maySomewhere(rules, subject, action) : false),
  };
}

/** What the server judges by the org-admin role alone for an org admin, whatever denies they hold. */
const ADMIN_MANAGED: readonly Subject[] = ["roles", "members", "org-roles", "org-members"];

/** An org admin may always manage roles, bindings and members, as the server lets them repair access. */
export function withAdminManagement(permissions: Permissions, orgAdmin: boolean): Permissions {
  if (!orgAdmin) return permissions;
  return {
    ready: permissions.ready,
    can: (subject, action, resource) => ADMIN_MANAGED.includes(subject) || permissions.can(subject, action, resource),
    canSomewhere: (subject, action) => ADMIN_MANAGED.includes(subject) || permissions.canSomewhere(subject, action),
  };
}

export function useProjectPermissions(project: string): Permissions {
  const { data } = useQuery({
    queryKey: keys.permissions(project),
    queryFn: () => api.permissions(project),
    staleTime: 30_000,
  });
  const orgAdmin = useIsOrgAdmin();
  const rules = data?.rules;
  return useMemo(() => withAdminManagement(permissionsFrom(rules), orgAdmin), [rules, orgAdmin]);
}

/** Whether the caller is a project or organisation admin, who manages per-secret access. */
export function useManagesSecretAccess(project: string): boolean {
  const { data } = useQuery({
    queryKey: keys.permissions(project),
    queryFn: () => api.permissions(project),
    staleTime: 30_000,
  });
  return data?.manages_secret_access === true;
}

export function useOrgPermissions(): Permissions {
  const { data } = useMe();
  const rules = data?.org_rules;
  const orgAdmin = data?.is_org_admin === true;
  return useMemo(() => withAdminManagement(permissionsFrom(rules), orgAdmin), [rules, orgAdmin]);
}

/** True for organisation admins, who alone may lock the server or change how it unlocks. */
export function useIsOrgAdmin(): boolean {
  const { data } = useMe();
  return data?.is_org_admin === true;
}
