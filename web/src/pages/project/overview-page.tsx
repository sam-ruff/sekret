import { useQueries, useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Folder, Layers, Minus } from "lucide-react";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { api } from "@/api/endpoints";
import { PageHeader } from "@/components/page-header";
import { FolderBreadcrumbs } from "@/components/project/folder-breadcrumbs";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { folderQuery } from "@/hooks/use-project-env";
import { keys, useEnvironments } from "@/hooks/queries";
import { normalisePath } from "@/lib/paths";
import { cn } from "@/lib/utils";

export function OverviewPage() {
  const { project = "" } = useParams();
  const [search] = useSearchParams();
  const path = normalisePath(search.get("path") ?? "/");
  const [onlyMissing, setOnlyMissing] = useState(false);

  const overview = useQuery({ queryKey: keys.overview(project, path), queryFn: () => api.overview(project, path) });
  const environments = useEnvironments(project);
  const folderLists = useQueries({
    queries: (environments.data ?? []).map((env) => ({
      queryKey: ["project", project, "folders", env.slug],
      queryFn: () => api.folders(project, env.slug),
    })),
  });

  const prefix = path === "/" ? "/" : `${path}/`;
  const subfolders = Array.from(
    new Set(
      folderLists
        .flatMap((q) => q.data ?? [])
        .map((f) => f.path)
        .filter((p) => p.startsWith(prefix) && p.length > prefix.length)
        .map((p) => p.slice(prefix.length).split("/")[0]),
    ),
  ).sort();

  const envs = overview.data?.environments ?? [];
  const rows = overview.data?.rows ?? [];
  const incomplete = rows.filter((r) => envs.some((e) => r.environments[e.slug] === undefined));
  const shown = onlyMissing ? incomplete : rows;
  const href = (p: string) => `/projects/${project}/overview${folderQuery(p)}`;

  return (
    <div className="space-y-6">
      <PageHeader title="Overview" description="Every key across every environment, so gaps stand out before a deploy does." />

      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <FolderBreadcrumbs path={path} hrefFor={href} />
        <div className="flex items-center gap-2">
          <Switch id="only-missing" checked={onlyMissing} onCheckedChange={setOnlyMissing} data-testid="only-missing" />
          <Label htmlFor="only-missing" className="font-normal">
            Only keys with gaps
          </Label>
        </div>
      </div>

      {subfolders.length > 0 && (
        <div className="flex flex-wrap gap-2" data-testid="overview-folders">
          {subfolders.map((name) => (
            <Link
              key={name}
              to={href(`${prefix}${name}`)}
              className="flex items-center gap-1.5 rounded-lg border bg-card px-3 py-1.5 font-mono text-sm hover:border-primary/40"
              data-testid={`overview-folder-${name}`}
            >
              <Folder className="size-3.5 fill-primary/20 text-primary" />
              {name}
            </Link>
          ))}
        </div>
      )}

      {overview.error && <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />}
      {overview.isPending && <ListSkeleton rows={5} />}

      {overview.isSuccess && rows.length > 0 && (
        <div
          className={cn(
            "flex items-center gap-2 rounded-lg border px-3 py-2 text-sm",
            incomplete.length > 0 ? "border-warning/40 bg-warning/10" : "border-success/40 bg-success/10",
          )}
          data-testid="overview-summary"
        >
          {incomplete.length > 0 ? (
            <>
              <AlertTriangle className="size-4 text-warning" />
              {incomplete.length} of {rows.length} keys are missing from at least one environment.
            </>
          ) : (
            <>
              <CheckCircle2 className="size-4 text-success" />
              All {rows.length} keys exist in every environment.
            </>
          )}
        </div>
      )}

      {overview.isSuccess && rows.length === 0 && (
        <EmptyState icon={<Layers />} title="No secrets in this folder" description="Keys appear here once any environment has them." testId="overview-empty" />
      )}

      {shown.length > 0 && (
        <div className="overflow-x-auto rounded-xl border bg-card" data-testid="overview-grid">
          <table className="w-full min-w-max text-sm">
            <thead>
              <tr className="border-b bg-muted">
                <th className="sticky left-0 z-10 bg-muted px-4 py-2 text-left text-xs font-medium text-muted-foreground shadow-[inset_-1px_0_0_var(--color-border)]">
                  Key
                </th>
                {envs.map((env) => (
                  <th key={env.id} className="px-4 py-2 text-center text-xs font-medium text-muted-foreground" data-testid={`overview-env-${env.slug}`}>
                    {env.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((row) => {
                const missing = envs.some((e) => row.environments[e.slug] === undefined);
                return (
                  <tr
                    key={`${row.path}:${row.key}`}
                    className={cn("border-b last:border-b-0", missing && "bg-warning/5")}
                    data-testid={`overview-row-${row.key}`}
                    data-missing={missing}
                  >
                    <td
                      className={cn(
                        "sticky left-0 z-10 max-w-[45vw] bg-card px-4 py-2.5 font-mono font-medium shadow-[inset_-1px_0_0_var(--color-border)] md:max-w-sm",
                        missing && "bg-linear-to-r from-warning/5 to-warning/5",
                      )}
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        {missing ? (
                          <AlertTriangle className="size-3.5 shrink-0 text-warning" aria-label="Missing somewhere" />
                        ) : (
                          <span className="size-3.5 shrink-0" aria-hidden />
                        )}
                        <span className="truncate" title={row.key}>
                          {row.key}
                        </span>
                      </span>
                    </td>
                    {envs.map((env) => {
                      const version = row.environments[env.slug];
                      return (
                        <td key={env.id} className="px-4 py-2.5 text-center" data-testid={`cell-${row.key}-${env.slug}`} data-present={version !== undefined}>
                          <Link
                            to={`/projects/${project}/secrets/${env.slug}${folderQuery(path)}`}
                            className="inline-flex items-center justify-center"
                            aria-label={version !== undefined ? `${row.key} in ${env.name}, version ${version}` : `${row.key} missing in ${env.name}`}
                          >
                            {version !== undefined ? (
                              <Badge variant="outline" className="gap-1 border-success/40 text-success">
                                <CheckCircle2 /> v{version}
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="gap-1 border-destructive/40 text-destructive">
                                <Minus /> Missing
                              </Badge>
                            )}
                          </Link>
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {overview.isSuccess && onlyMissing && rows.length > 0 && incomplete.length === 0 && (
        <p className="py-6 text-center text-sm text-muted-foreground">No gaps here.</p>
      )}
    </div>
  );
}
