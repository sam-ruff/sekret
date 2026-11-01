import { useQueries } from "@tanstack/react-query";
import { ArrowRight, FolderKey } from "lucide-react";
import { Link } from "react-router";
import { api } from "@/api/endpoints";
import type { Identity } from "@/api/types";
import { ErrorState, ListSkeleton } from "@/components/states";
import { RoleLabel } from "@/components/roles/role-label";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { keys, useProjects } from "@/hooks/queries";
import { PROJECT_ACCESS_LIMIT, projectAccessRows } from "./project-access-model";

function RolesCell({ roles, nameOf }: { roles: string[] | null; nameOf: (slug: string) => string }) {
  if (roles === null) return <span className="text-xs text-muted-foreground">Cannot see members</span>;
  if (roles.length === 0) return <span className="text-xs text-muted-foreground">No access</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {roles.map((role) => (
        <RoleLabel key={role} name={nameOf(role)} id={role} />
      ))}
    </span>
  );
}

/** Which projects an identity can use, with a way to each project's members list to change that. */
export function ProjectAccess({ identity }: { identity: Identity }) {
  const projects = useProjects();
  const shown = (projects.data ?? []).slice(0, PROJECT_ACCESS_LIMIT);
  const members = useQueries({
    queries: shown.map((p) => ({ queryKey: keys.members(p.slug), queryFn: () => api.members(p.slug), retry: false })),
  });
  // Names only; a project whose roles cannot be read falls back to the role IDs.
  const roles = useQueries({
    queries: shown.map((p) => ({ queryKey: keys.roles(p.slug), queryFn: () => api.roles(p.slug), retry: false })),
  });
  const nameIn = (project: string) => {
    const list = roles[shown.findIndex((p) => p.slug === project)]?.data;
    return (slug: string) => list?.find((r) => r.slug === slug)?.name ?? slug;
  };
  const loading = projects.isPending || members.some((m) => m.isPending);
  const rows = projectAccessRows(
    identity.id,
    shown,
    members.map((m) => m.data),
  );

  return (
    <Card data-testid="identity-projects">
      <CardHeader>
        <CardTitle>Project access</CardTitle>
        <CardDescription>
          An identity reads secrets only in projects where it is a member. Add it, or change its role, in the
          project&apos;s Members settings.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {projects.error && <ErrorState error={projects.error} onRetry={() => void projects.refetch()} />}
        {loading && !projects.error && <ListSkeleton rows={2} />}
        {!loading && rows.length === 0 && (
          <p className="text-sm text-muted-foreground" data-testid="identity-projects-none">
            There are no projects yet.
          </p>
        )}
        {!loading && rows.length > 0 && (
          <ul className="divide-y rounded-lg border">
            {rows.map(({ project, roles }) => (
              <li
                key={project.slug}
                className="flex flex-wrap items-center justify-between gap-2 px-3 py-2"
                data-testid={`identity-project-${project.slug}`}
              >
                <div className="flex min-w-0 items-center gap-2">
                  <FolderKey className="size-4 shrink-0 text-muted-foreground" />
                  <span className="truncate text-sm font-medium">{project.name}</span>
                  <RolesCell roles={roles} nameOf={nameIn(project.slug)} />
                </div>
                {roles !== null && (
                  <Button asChild variant="ghost" size="sm" className="ml-auto">
                    <Link to={`/projects/${project.slug}/settings/members`} data-testid={`identity-project-manage-${project.slug}`}>
                      {roles.length > 0 ? "Change" : "Add to project"}
                      <ArrowRight />
                    </Link>
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        {(projects.data?.length ?? 0) > PROJECT_ACCESS_LIMIT && (
          <p className="mt-2 text-xs text-muted-foreground">
            Showing the first {PROJECT_ACCESS_LIMIT} projects. Check others from their Members settings.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
