import type { Me, OrgBinding } from "@/api/types";

export const ORG_ADMIN = "org-admin";

export interface Removal {
  title: string;
  description: string;
  /** Removing it would leave nobody with the role through a binding. */
  blocked: boolean;
}

/** Whether the binding applies to the signed-in person, directly or through a group they are in. */
export function bindingCoversMe(binding: OrgBinding, me: Me | undefined): "user" | "group" | null {
  if (!me) return null;
  if (binding.principal_kind === me.kind && binding.principal_id === me.id) return "user";
  const inGroup = me.groups.includes(binding.principal_id) || me.groups.includes(binding.principal_name);
  if (binding.principal_kind === "group" && inGroup) return "group";
  return null;
}

/** The confirmation for removing an organisation role, worded for whoever it affects. */
export function describeRemoval(binding: OrgBinding, all: readonly OrgBinding[], me: Me | undefined, roleName: string): Removal {
  const lastAdmin = binding.role === ORG_ADMIN && all.filter((b) => b.role === ORG_ADMIN).length <= 1;
  if (lastAdmin) {
    return {
      title: `${binding.principal_name} is the only ${roleName}`,
      description: `Nobody else holds ${roleName}, so removing it could leave nobody able to manage the organisation. Grant ${roleName} to someone else first.`,
      blocked: true,
    };
  }
  const covers = bindingCoversMe(binding, me);
  if (covers === null) {
    return {
      title: `Remove ${roleName} from ${binding.principal_name}?`,
      description: "They lose the access this role granted across the organisation.",
      blocked: false,
    };
  }
  const through = covers === "group" ? ` You are in ${binding.principal_name}, so this applies to you.` : "";
  const page = binding.role === ORG_ADMIN ? " You may lose access to this page, and someone else would have to give it back." : "";
  return {
    title: covers === "user" ? `Remove your own ${roleName} role?` : `Remove ${roleName} from ${binding.principal_name}?`,
    description: `You will lose the access this role granted across the organisation, unless another role still gives it.${through}${page}`,
    blocked: false,
  };
}
