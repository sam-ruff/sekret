import { Bot, MoreHorizontal, Plus, SearchX, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { api } from "@/api/endpoints";
import type { Identity, IdentitySort } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { IdentityFields } from "@/components/identities/identity-fields";
import { ttlProblem, type IdentityDraft } from "@/components/identities/identity-model";
import { ListToolbar } from "@/components/list-toolbar";
import { PageHeader } from "@/components/page-header";
import { Pagination } from "@/components/pagination";
import { ResponsiveTable } from "@/components/responsive-table";
import { SortHeader } from "@/components/sort-header";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Spinner } from "@/components/ui/spinner";
import { keys, useApiMutation, useIdentityPage } from "@/hooks/queries";
import { useListParams } from "@/hooks/use-list-params";
import { useOrgPermissions } from "@/hooks/use-permissions";
import { formatDateTime, formatDuration, formatRelative } from "@/lib/format";
import { listQuery, listSearchParams, toggleSort, type SortSpec } from "@/lib/list-params";

const METHOD_LABELS: Record<string, string> = { oidc: "OIDC", kubernetes: "Kubernetes", universal: "Universal" };

const SPEC: SortSpec<IdentitySort> = { sorts: ["name", "created"], fallback: "name", descending: ["created"] };
const SORT_LABELS: Record<IdentitySort, string> = { name: "Name", created: "Newest" };

const EMPTY: IdentityDraft = { name: "", description: "", tokenTtl: "3600", tokenMaxTtl: "86400", trustedCidrs: [] };

function CreateIdentityDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate();
  const [draft, setDraft] = useState<IdentityDraft>(EMPTY);
  const create = useApiMutation({
    mutationFn: () =>
      api.createIdentity({
        name: draft.name.trim(),
        description: draft.description,
        token_ttl: Number(draft.tokenTtl),
        token_max_ttl: Number(draft.tokenMaxTtl),
        trusted_cidrs: draft.trustedCidrs,
      }),
    invalidate: [keys.identities],
    success: (i) => `Created ${i.name}`,
    onSuccess: (i) => {
      onOpenChange(false);
      setDraft(EMPTY);
      navigate(`/org/identities/${i.id}/auth`);
    },
  });
  const valid = draft.name.trim() !== "" && !ttlProblem(draft);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid) create.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl" data-testid="create-identity-dialog">
        <form onSubmit={submit} className="space-y-6">
          <DialogHeader>
            <DialogTitle>New machine identity</DialogTitle>
            <DialogDescription>
              Machine identities let CI jobs, servers and pods read secrets. Add an auth method after creating it.
            </DialogDescription>
          </DialogHeader>
          <IdentityFields draft={draft} onChange={setDraft} idPrefix="new-identity" />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!valid || create.isPending} data-testid="identity-create-submit">
              {create.isPending && <Spinner />}
              Create identity
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function IdentitiesPage() {
  const org = useOrgPermissions();
  const { list, update } = useListParams(SPEC);
  const page = useIdentityPage(listQuery(list));
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<Identity | null>(null);
  const canCreate = org.can("identities", "create");
  const canDelete = org.can("identities", "delete");

  const remove = useApiMutation({
    mutationFn: (id: string) => api.deleteIdentity(id),
    invalidate: [keys.identities],
    success: "Identity deleted",
  });

  const identities = page.data?.items ?? [];
  const total = page.data?.total ?? 0;
  const filtered = list.q !== "" || list.status !== "";
  const sortHeader = (label: string, sort: IdentitySort) => (
    <SortHeader
      label={label}
      active={list.sort === sort}
      order={list.order}
      onToggle={() => update(toggleSort(list, SPEC, sort))}
      testId={`identities-sort-${sort}`}
    />
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Machine identities"
        description="Non-human accounts for CI pipelines, services and Kubernetes workloads."
        actions={
          canCreate && (
            <Button onClick={() => setCreating(true)} data-testid="new-identity">
              <Plus />
              New identity
            </Button>
          )
        }
      />
      <ListToolbar
        list={list}
        spec={SPEC}
        onChange={update}
        sortLabels={SORT_LABELS}
        searchPlaceholder="Search name or description"
        testId="identities"
      />
      {page.error && <ErrorState error={page.error} onRetry={() => void page.refetch()} />}
      {page.isPending && <ListSkeleton />}
      {page.isSuccess && total === 0 && filtered && (
        <EmptyState
          icon={<SearchX />}
          title="No identities match"
          description="Try a different search or status."
          action={
            <Button variant="outline" size="sm" onClick={() => update({ ...list, q: "", status: "", page: 1 })}>
              Clear filters
            </Button>
          }
          testId="identities-no-matches"
        />
      )}
      {page.isSuccess && total === 0 && !filtered && (
        <EmptyState
          icon={<Bot />}
          title="No machine identities"
          description="Create one for each pipeline or service that needs secrets, so access stays narrow and auditable."
          action={
            canCreate && (
              <Button onClick={() => setCreating(true)}>
                <Plus />
                New identity
              </Button>
            )
          }
          testId="identities-empty"
        />
      )}
      {identities.length > 0 && (
        <ResponsiveTable
          rows={identities}
          rowKey={(i) => i.id}
          rowTestId={(i) => `identity-row-${i.name}`}
          onRowClick={(i) => navigate(`/org/identities/${i.id}`)}
          columns={[
            {
              header: "Identity",
              heading: sortHeader("Identity", "name"),
              primary: true,
              cell: (i) => (
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Link
                      to={`/org/identities/${i.id}`}
                      className="truncate font-medium hover:text-primary"
                      onClick={(e) => e.stopPropagation()}
                      data-testid={`identity-link-${i.name}`}
                    >
                      {i.name}
                    </Link>
                    {i.disabled && <Badge variant="destructive">Disabled</Badge>}
                  </div>
                  {i.description && <div className="truncate text-xs text-muted-foreground">{i.description}</div>}
                </div>
              ),
            },
            {
              header: "Auth methods",
              cell: (i) =>
                i.auth_methods.length === 0 ? (
                  <span className="text-xs text-muted-foreground">None yet</span>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {i.auth_methods.map((m) => (
                      <Badge key={m} variant="secondary">
                        {METHOD_LABELS[m] ?? m}
                      </Badge>
                    ))}
                  </div>
                ),
            },
            {
              header: "Token lifetime",
              cell: (i) => (
                <span className="text-muted-foreground">
                  {formatDuration(i.token_ttl)} up to {formatDuration(i.token_max_ttl)}
                </span>
              ),
            },
            {
              header: "Created",
              heading: sortHeader("Created", "created"),
              className: "md:w-32",
              cell: (i) => (
                <span className="whitespace-nowrap text-muted-foreground" title={formatDateTime(i.created_at)}>
                  {formatRelative(i.created_at)}
                </span>
              ),
            },
            {
              header: "",
              className: "md:w-12",
              actions: true,
              cell: (i) =>
                canDelete && (
                  <div onClick={(e) => e.stopPropagation()}>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${i.name}`} data-testid={`identity-actions-${i.name}`}>
                          <MoreHorizontal />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem variant="destructive" onSelect={() => setDeleting(i)} data-testid="identity-delete">
                          <Trash2 />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                ),
            },
          ]}
        />
      )}
      {page.isSuccess && total > 0 && (
        <Pagination
          page={list.page}
          shown={identities.length}
          total={total}
          busy={page.isFetching}
          onPage={(p) => update({ ...list, page: p })}
          filters={listSearchParams(list, SPEC).toString()}
          testId="identities-pagination"
        />
      )}
      <CreateIdentityDialog open={creating} onOpenChange={setCreating} />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete ${deleting?.name}?`}
        description="Its auth methods, client secrets and memberships are removed, and any tokens stop working."
        confirmLabel="Delete identity"
        destructive
        onConfirm={() => remove.mutateAsync(deleting?.id ?? "")}
      />
    </div>
  );
}
