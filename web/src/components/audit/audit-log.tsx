import { keepPreviousData, useInfiniteQuery } from "@tanstack/react-query";
import { EyeOff, Info, ScrollText, SearchX, X } from "lucide-react";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router";
import { ApiError } from "@/api/client";
import type { AuditQuery } from "@/api/endpoints";
import type { AuditEntry, AuditPage, Environment } from "@/api/types";
import { ResponsiveTable } from "@/components/responsive-table";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import {
  auditQuery,
  auditSearchParams,
  EMPTY_AUDIT_FILTERS,
  hasActiveFilters,
  noMatchHint,
  parseAuditFilters,
  type AuditFilters,
} from "@/lib/audit-filters";
import { auditNames, useAuditDirectory } from "@/hooks/use-audit-names";
import { actionLabel, describeDetail } from "@/lib/audit-labels";
import { formatDateTime, formatRelative } from "@/lib/format";
import { AuditToolbar } from "./audit-toolbar";

const PAGE_SIZE = 50;

interface AuditLogProps {
  queryKey: readonly unknown[];
  fetchPage: (query: AuditQuery) => Promise<AuditPage>;
  scope: "project" | "org";
  /** The project a project-scoped log belongs to, used to name members and roles. */
  project?: string;
  environments?: Environment[];
  /**
   * Whether the reader sees every secret in the entries for this environment filter (or all of
   * them). When not, the server refuses key and folder filters and search skips them.
   */
  seesEverything?: (environment: string | undefined) => boolean;
}

function target(entry: AuditEntry): string {
  const where = entry.path && entry.secret_key ? `${entry.path.replace(/\/$/, "")}/${entry.secret_key}` : entry.path;
  return [entry.environment, where].filter(Boolean).join(" ");
}

function FilterChip({ label, value, onClear, testId }: { label: string; value: string; onClear: () => void; testId: string }) {
  return (
    <Badge variant="secondary" className="h-6 max-w-full gap-1 pr-0.5" data-testid={testId}>
      <span className="text-muted-foreground">{label}</span>
      <span className="truncate font-mono">{value}</span>
      <Button variant="ghost" size="icon-xs" className="size-5" onClick={onClear} aria-label={`Remove ${label.toLowerCase()} filter`}>
        <X />
      </Button>
    </Badge>
  );
}

export function AuditLog({ queryKey, fetchPage, scope, project, environments, seesEverything }: AuditLogProps) {
  const directory = useAuditDirectory(scope === "project" ? project : undefined);
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseAuditFilters(params), [params]);
  const setFilters = useCallback(
    (next: AuditFilters) => setParams(auditSearchParams(next), { replace: true }),
    [setParams],
  );
  const query = useMemo(() => ({ ...auditQuery(filters), limit: PAGE_SIZE }), [filters]);

  const pages = useInfiniteQuery({
    queryKey: [...queryKey, query],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => fetchPage({ ...query, ...(pageParam ? { cursor: pageParam } : {}) }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
  });

  const entries = pages.data?.pages.flatMap((p) => p.entries) ?? [];
  const names = auditNames(entries, directory);
  const total = pages.data?.pages[0]?.total ?? 0;
  const filtered = hasActiveFilters(filters);
  const actorName = entries.find((e) => e.actor_id === filters.actorId)?.actor_name ?? filters.actorId;
  const clear = () => setFilters({ ...EMPTY_AUDIT_FILTERS, order: filters.order });
  const filterHidden = pages.error instanceof ApiError && pages.error.code === "filter_hidden";
  const searchesSecrets = seesEverything?.(filters.environment || undefined) ?? true;
  const keysSkipped = filters.q.trim() !== "" && !searchesSecrets;
  const keysSkippedText =
    "Search here covers actions, people and addresses. Key names and folders are not searched because some secrets in this log are hidden from you. Pick an environment whose secrets you can all read to search them.";

  return (
    <div className="space-y-4">
      <AuditToolbar
        filters={filters}
        onChange={setFilters}
        scope={scope}
        environments={environments}
        searchesSecrets={searchesSecrets}
      />

      <div className="flex min-h-7 flex-wrap items-center gap-2 text-sm">
        <span
          className="text-muted-foreground tabular-nums"
          data-testid="audit-total"
          data-fetching={pages.isFetching}
          data-filters={auditSearchParams(filters).toString()}
        >
          {pages.isSuccess ? `${total} ${total === 1 ? "entry" : "entries"}` : pages.isError ? "" : "Loading"}
        </span>
        {pages.isFetching && !pages.isFetchingNextPage && pages.isSuccess && <Spinner className="size-3.5" />}
        {filters.actorId && (
          <FilterChip label="Actor" value={actorName} onClear={() => setFilters({ ...filters, actorId: "" })} testId="audit-chip-actor" />
        )}
        {filters.key && <FilterChip label="Key" value={filters.key} onClear={() => setFilters({ ...filters, key: "" })} testId="audit-chip-key" />}
        {filters.path && (
          <FilterChip label="Path" value={filters.path} onClear={() => setFilters({ ...filters, path: "" })} testId="audit-chip-path" />
        )}
        {/* An empty result has its own Clear filters button. */}
        {filtered && !(pages.isSuccess && entries.length === 0) && (
          <Button variant="ghost" size="sm" className="ml-auto" onClick={clear} data-testid="audit-clear">
            Clear filters
          </Button>
        )}
      </div>

      {filterHidden && (
        <Alert data-testid="audit-filter-hidden">
          <EyeOff />
          <AlertTitle>Cannot filter by key or folder here</AlertTitle>
          <AlertDescription>
            <p>
              Some secrets in this log are hidden from you, so it cannot be filtered by key or folder. Remove those
              filters, or choose an environment whose secrets you can all read.
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-2"
              onClick={() => setFilters({ ...filters, key: "", path: "" })}
              data-testid="audit-filter-hidden-clear"
            >
              Remove key and folder filters
            </Button>
          </AlertDescription>
        </Alert>
      )}
      {keysSkipped && !(pages.isSuccess && entries.length === 0) && (
        <p className="flex items-start gap-1.5 text-xs text-muted-foreground" data-testid="audit-keys-skipped">
          <Info className="mt-0.5 size-3.5 shrink-0" />
          {keysSkippedText}
        </p>
      )}
      {pages.error && !filterHidden && <ErrorState error={pages.error} onRetry={() => void pages.refetch()} />}
      {pages.isPending && <ListSkeleton rows={6} />}
      {pages.isSuccess && entries.length === 0 && filtered && (
        <EmptyState
          icon={<SearchX />}
          title="No matching activity"
          description={keysSkipped ? `${noMatchHint(filters)} ${keysSkippedText}` : noMatchHint(filters)}
          action={
            <Button variant="outline" size="sm" onClick={clear}>
              Clear filters
            </Button>
          }
          testId="audit-empty"
        />
      )}
      {pages.isSuccess && entries.length === 0 && !filtered && (
        <EmptyState
          icon={<ScrollText />}
          title="No activity yet"
          description="Actions appear here as people and machines use sekret."
          testId="audit-empty"
        />
      )}
      {entries.length > 0 && (
        <ResponsiveTable
          rows={entries}
          rowKey={(e) => e.id}
          rowTestId={() => "audit-row"}
          columns={[
            {
              header: "Action",
              primary: true,
              cell: (e) => (
                <div className="flex min-w-0 flex-col items-start gap-0.5">
                  <Badge
                    variant="secondary"
                    className="max-w-full truncate"
                    title={e.action}
                    data-testid="audit-action"
                    data-action={e.action}
                  >
                    {actionLabel(e.action)}
                  </Badge>
                  <span className="max-w-full truncate font-mono text-[0.7rem] text-muted-foreground" data-testid="audit-action-code">
                    {e.action}
                  </span>
                </div>
              ),
            },
            {
              header: "Actor",
              cell: (e) => (
                <button
                  type="button"
                  className="-my-1 min-h-7 max-w-full truncate py-1 text-left hover:text-primary hover:underline"
                  title={`${e.actor_kind} ${e.actor_id} from ${e.ip}. Show only this actor.`}
                  onClick={() => setFilters({ ...filters, actorId: e.actor_id })}
                  data-testid="audit-actor"
                  data-kind={e.actor_kind}
                >
                  {e.actor_name}
                </button>
              ),
            },
            {
              header: "Target",
              cell: (e) => (
                <span className="truncate font-mono text-xs text-muted-foreground" data-testid="audit-target">
                  {target(e) || "-"}
                </span>
              ),
            },
            {
              header: "Detail",
              className: "md:max-w-72",
              cell: (e) => (
                <span className="line-clamp-2 text-xs break-words text-muted-foreground" data-testid="audit-detail">
                  {describeDetail(e.action, e.detail, names) || "-"}
                </span>
              ),
            },
            {
              header: "When",
              className: "md:w-36",
              cell: (e) => (
                <span className="text-xs whitespace-nowrap text-muted-foreground" title={formatDateTime(e.created_at)} data-testid="audit-when" data-at={e.created_at}>
                  {formatRelative(e.created_at)}
                </span>
              ),
            },
          ]}
        />
      )}
      {entries.length > 0 && (
        <div className="flex flex-col items-center gap-2">
          <p className="text-xs text-muted-foreground tabular-nums" data-testid="audit-shown">
            Showing {entries.length} of {total}
          </p>
          {pages.hasNextPage && (
            <Button
              variant="outline"
              onClick={() => void pages.fetchNextPage()}
              disabled={pages.isFetchingNextPage}
              data-testid="audit-load-more"
            >
              {pages.isFetchingNextPage && <Spinner />}
              Load more
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
