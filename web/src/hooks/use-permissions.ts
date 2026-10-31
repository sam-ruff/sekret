import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { api } from "@/api/endpoints";
import type { Action, Subject } from "@/api/types";
import { ACTIONS, ORG_SUBJECTS } from "@/api/types";
import { authorise, grantsEverything, maySomewhere, type Resource, type Rule } from "@/lib/permissions";
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

export function useProjectPermissions(project: string): Permissions {
  const { data } = useQuery({
    queryKey: keys.permissions(project),
    queryFn: () => api.permissions(project),
    staleTime: 30_000,
  });
  const rules = data?.rules;
  return useMemo(() => permissionsFrom(rules), [rules]);
}

export function useOrgPermissions(): Permissions {
  const { data } = useMe();
  const rules = data?.org_rules;
  return useMemo(() => permissionsFrom(rules), [rules]);
}

/** True for organisation admins, who alone may seal the server or change how it unlocks. */
export function useIsOrgAdmin(): boolean {
  const { data } = useMe();
  const rules = data?.org_rules;
  return useMemo(() => (rules ? grantsEverything(rules, ORG_SUBJECTS, ACTIONS) : false), [rules]);
}
