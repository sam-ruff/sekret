import type { Membership, Project } from "@/api/types";

/** Members are asked for project by project, so only this many are looked at. */
export const PROJECT_ACCESS_LIMIT = 50;

export interface ProjectAccessRow {
  project: Project;
  /** Roles the identity holds there, or null when the reader cannot see the project's members. */
  roles: string[] | null;
}

/** The roles `identityId` holds in each project, member projects first, then by name. */
export function projectAccessRows(
  identityId: string,
  projects: Project[],
  members: (Membership[] | undefined)[],
): ProjectAccessRow[] {
  const rows = projects.map((project, i) => {
    const list = members[i];
    const roles = list
      ? list.filter((m) => m.principal_kind === "identity" && m.principal_id === identityId).map((m) => m.role)
      : null;
    return { project, roles };
  });
  const rank = (row: ProjectAccessRow) => (row.roles === null ? 2 : row.roles.length > 0 ? 0 : 1);
  return rows.sort((a, b) => rank(a) - rank(b) || a.project.name.localeCompare(b.project.name));
}
