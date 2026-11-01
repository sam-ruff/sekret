import type { AddMembership, Membership, PrincipalKind } from "@/api/types";
import { errorMessage } from "./errors";

/** The two membership calls a role change is made of; the server has no single call for it. */
export interface MemberApi {
  addMember(project: string, body: AddMembership): Promise<unknown>;
  removeMember(project: string, kind: PrincipalKind, id: string, role: string): Promise<unknown>;
}

/** The new role was added but the old one is still there, so the member now holds both. */
export class RoleChangeIncomplete extends Error {
  constructor(who: string, oldRole: string, newRole: string, cause: unknown) {
    super(
      `${who} now has the ${newRole} role, but the ${oldRole} role could not be removed ` +
        `(${errorMessage(cause).replace(/\.$/, "")}). They hold both until you remove ${oldRole} from the list.`,
    );
    this.name = "RoleChangeIncomplete";
  }
}

/**
 * Moves a member to another role by adding the new role before removing the old one,
 * so a failure part way never leaves them with no access at all.
 */
export async function changeMemberRole(
  api: MemberApi,
  project: string,
  member: Membership,
  role: string,
  roleName: (slug: string) => string = (slug) => slug,
): Promise<void> {
  if (role === member.role) return;
  await api.addMember(project, { principal_kind: member.principal_kind, principal_id: member.principal_id, role });
  try {
    await api.removeMember(project, member.principal_kind, member.principal_id, member.role);
  } catch (cause) {
    throw new RoleChangeIncomplete(member.principal_name, roleName(member.role), roleName(role), cause);
  }
}
