import { useQueries, useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, FileUp, Folder, Layers, Minus, Plus } from "lucide-react";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { api } from "@/api/endpoints";
import { PageHeader } from "@/components/page-header";
import { FolderBreadcrumbs } from "@/components/project/folder-breadcrumbs";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { folderQuery } from "@/hooks/use-project-env";
import { keys, useEnvironments } from "@/hooks/queries";
import { useProjectPermissions } from "@/hooks/use-permissions";
import { folderFromLink } from "@/lib/paths";
import { ROW_PAGE } from "@/lib/secret-limits";
import { cn } from "@/lib/utils";

/** A present key opens its environment; a missing one also opens the add form with the key filled in. */
function cellHref(project: string, env: string, path: string, missingKey?: string): string {
  const params = new URLSearchParams();
  if (path !== "/") params.set("path", path);
  if (missingKey) params.set("add", missingKey);
  const query = params.toString();
  return `/projects/${project}/secrets/${env}${query ? `?${query}` : ""}`;
}

/** Opens an environment's secrets page with the add form or the import dialog already open. */
function addHref(project: string, env: string, path: string, open: "add=" | "import=1"): string {
  const folder = path === "/" ? "" : `path=${encodeURIComponent(path)}&`;
  return `/projects/${project}/secrets/${env}?${folder}${open}`;
}

/** Lets a long key wrap after each underscore before it has to break inside a word. */
function BreakableKey({ value }: { value: string }) {
  const parts = value.split(/(?<=_)/);
  return parts.map((part, i) => (
    <span key={i}>
      {part}
      {i < parts.length - 1 && <wbr />}
    </span>
  ));
}

export function OverviewPage() {
  const { project = "" } = useParams();
  const [search] = useSearchParams();
  const path = folderFromLink(search.get("path"));
  const perms = useProjectPermissions(project);
  const [onlyMissing, setOnlyMissing] = useState(false);
  const [shownRows, setShownRows] = useState(ROW_PAGE);
  const [shownFolderCount, setShownFolderCount] = useState(ROW_PAGE);
  const [pageFor, setPageFor] = useState(path);
  if (pageFor !== path) {
    setPageFor(path);
    setShownRows(ROW_PAGE);
    setShownFolderCount(ROW_PAGE);
  }

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

  const firstEnv = environments.data?.[0];
  const envs = overview.data?.environments ?? [];
  const rows = overview.data?.rows ?? [];
  const incomplete = rows.filter((r) => envs.some((e) => r.environments[e.slug] === undefined));
  const matching = onlyMissing ? incomplete : rows;
  // Rows and folder chips are paged, so a folder holding a huge number of keys cannot hang the tab.
  const shown = matching.slice(0, shownRows);
  const hiddenRows = matching.length - shown.length;
  const shownFolders = subfolders.slice(0, shownFolderCount);
  const href = (p: string) => `/projects/${project}/overview${folderQuery(p)}`;

  return (
    <div className="space-y-6">
      <PageHeader title="Overview" description="Every key across every environment, so gaps stand out before a deploy does." />

      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <FolderBreadcrumbs path={path} hrefFor={href} />
        {rows.length > 0 && (
          <div className="flex items-center gap-2">
            <Switch id="only-missing" checked={onlyMissing} onCheckedChange={setOnlyMissing} data-testid="only-missing" />
            <Label htmlFor="only-missing" className="font-normal">
              Only keys with gaps
            </Label>
          </div>
        )}
      </div>

      {subfolders.length > 0 && (
        <div className="flex flex-wrap gap-2" data-testid="overview-folders">
          {shownFolders.map((name) => (
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
          {subfolders.length > shownFolders.length && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShownFolderCount(shownFolderCount + ROW_PAGE)}
              data-testid="overview-folders-more"
            >
              Show {Math.min(ROW_PAGE, subfolders.length - shownFolders.length)} more folders
            </Button>
          )}
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
              {incomplete.length} of {rows.length} keys {incomplete.length === 1 ? "is" : "are"} missing from at least one
              environment.
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
        <EmptyState
          icon={<Layers />}
          title="No secrets in this folder"
          description="Keys appear here once any environment has them."
          action={
            firstEnv &&
            perms.canSomewhere("secrets", "create") && (
              <div className="flex flex-wrap justify-center gap-2">
                <Button asChild>
                  <Link to={addHref(project, firstEnv.slug, path, "add=")} data-testid="overview-add-secret">
                    <Plus />
                    Add secret to {firstEnv.name}
                  </Link>
                </Button>
                <Button variant="outline" asChild>
                  <Link to={addHref(project, firstEnv.slug, path, "import=1")} data-testid="overview-import">
                    <FileUp />
                    Import .env
                  </Link>
                </Button>
              </div>
            )
          }
          testId="overview-empty"
        />
      )}

      {shown.length > 0 && envs.length > 1 && (
        <p className="-mt-3 text-xs text-muted-foreground md:hidden" data-testid="overview-swipe-hint">
          Swipe the table sideways to see every environment.
        </p>
      )}
      {shown.length > 0 && (
        <div className="overflow-x-auto rounded-xl border bg-card" data-testid="overview-grid">
          <table className="w-full min-w-max text-sm">
            <thead>
              <tr className="border-b bg-muted">
                <th className="sticky left-0 z-10 bg-muted px-3 py-2 text-left md:px-4 text-xs font-medium text-muted-foreground shadow-[inset_-1px_0_0_var(--color-border)]">
                  Key
                </th>
                {envs.map((env) => (
                  <th key={env.id} className="px-3 py-2 text-center md:px-4 text-xs font-medium text-muted-foreground" data-testid={`overview-env-${env.slug}`}>
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
                    className={cn("border-b last:border-b-0", missing && "bg-warning/5 dark:bg-warning/12")}
                    data-testid={`overview-row-${row.key}`}
                    data-missing={missing}
                  >
                    <td
                      className={cn(
                        "sticky left-0 z-10 max-w-[36vw] bg-card px-3 py-2.5 font-mono font-medium shadow-[inset_-1px_0_0_var(--color-border)] md:max-w-sm md:px-4",
                        missing && "bg-linear-to-r from-warning/5 to-warning/5 dark:from-warning/12 dark:to-warning/12",
                      )}
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        {missing ? (
                          <AlertTriangle className="size-3.5 shrink-0 text-warning" aria-label="Missing somewhere" />
                        ) : (
                          <span className="size-3.5 shrink-0" aria-hidden />
                        )}
                        {/* Wraps at underscores rather than cutting off, so long keys can be told apart on a phone. */}
                        <span className="max-w-[28vw] min-w-0 break-words md:max-w-sm" data-testid="overview-key">
                          <BreakableKey value={row.key} />
                        </span>
                      </span>
                    </td>
                    {envs.map((env) => {
                      const version = row.environments[env.slug];
                      return (
                        <td key={env.id} className="px-3 py-2.5 text-center md:px-4" data-testid={`cell-${row.key}-${env.slug}`} data-present={version !== undefined}>
                          <Link
                            to={cellHref(project, env.slug, row.path || path, version === undefined ? row.key : undefined)}
                            className="-my-1.5 inline-flex items-center justify-center py-1.5"
                            aria-label={
                              version !== undefined
                                ? `${row.key} in ${env.name}, version ${version}`
                                : `${row.key} missing in ${env.name}. Add it there.`
                            }
                            data-testid={`cell-link-${row.key}-${env.slug}`}
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
      {hiddenRows > 0 && (
        <div className="flex flex-wrap items-center justify-center gap-3 text-sm text-muted-foreground">
          <span data-testid="overview-more-count">
            Showing {shown.length} of {matching.length}
          </span>
          <Button variant="outline" size="sm" onClick={() => setShownRows(shownRows + ROW_PAGE)} data-testid="overview-show-more">
            Show {Math.min(ROW_PAGE, hiddenRows)} more
          </Button>
        </div>
      )}
      {overview.isSuccess && onlyMissing && rows.length > 0 && incomplete.length === 0 && (
        <p className="py-6 text-center text-sm text-muted-foreground">No gaps here.</p>
      )}
    </div>
  );
}
