import { SearchX, UserCheck, Users, UserX } from "lucide-react";
import { useState } from "react";
import { api } from "@/api/endpoints";
import type { User, UserSort } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ListToolbar } from "@/components/list-toolbar";
import { PageHeader } from "@/components/page-header";
import { Pagination } from "@/components/pagination";
import { ResponsiveTable } from "@/components/responsive-table";
import { SortHeader } from "@/components/sort-header";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { keys, useApiMutation, useMe, useUserPage } from "@/hooks/queries";
import { useListParams } from "@/hooks/use-list-params";
import { useOrgPermissions } from "@/hooks/use-permissions";
import { formatDateTime, formatRelative, initials } from "@/lib/format";
import { listQuery, listSearchParams, toggleSort, type SortSpec } from "@/lib/list-params";

const SPEC: SortSpec<UserSort> = {
  sorts: ["name", "email", "created", "last_login"],
  fallback: "name",
  descending: ["created", "last_login"],
};

const SORT_LABELS: Record<UserSort, string> = {
  name: "Name",
  email: "Email",
  created: "Newest",
  last_login: "Recent sign-in",
};

export function UsersPage() {
  const { list, update } = useListParams(SPEC);
  const page = useUserPage(listQuery(list));
  const { data: me } = useMe();
  const org = useOrgPermissions();
  const canEdit = org.can("org-members", "edit");
  const [disabling, setDisabling] = useState<User | null>(null);

  const toggle = useApiMutation({
    mutationFn: ({ user, disabled }: { user: User; disabled: boolean }) => api.setUserDisabled(user.id, disabled),
    invalidate: [keys.users],
    success: (_, { user, disabled }) => `${user.name || user.email} ${disabled ? "disabled" : "enabled"}`,
  });

  const sortHeader = (label: string, sort: UserSort) => (
    <SortHeader
      label={label}
      active={list.sort === sort}
      order={list.order}
      onToggle={() => update(toggleSort(list, SPEC, sort))}
      testId={`users-sort-${sort}`}
    />
  );

  const users = page.data?.items ?? [];
  const total = page.data?.total ?? 0;
  const filtered = list.q !== "" || list.status !== "";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Users"
        description="People who have signed in through your identity provider. Disabled users cannot sign in or use their tokens."
      />
      <ListToolbar
        list={list}
        spec={SPEC}
        onChange={update}
        sortLabels={SORT_LABELS}
        searchPlaceholder="Search name, email or group"
        testId="users"
      />
      {page.error && <ErrorState error={page.error} onRetry={() => void page.refetch()} />}
      {page.isPending && <ListSkeleton />}
      {page.isSuccess && total === 0 && !filtered && (
        <EmptyState icon={<Users />} title="No users yet" description="Users appear here after their first sign-in." />
      )}
      {page.isSuccess && total === 0 && filtered && (
        <EmptyState
          icon={<SearchX />}
          title="No users match"
          description="Try a different search or status."
          action={
            <Button variant="outline" size="sm" onClick={() => update({ ...list, q: "", status: "", page: 1 })}>
              Clear filters
            </Button>
          }
          testId="users-no-matches"
        />
      )}
      {users.length > 0 && (
        <ResponsiveTable
          rows={users}
          rowKey={(u) => u.id}
          rowTestId={(u) => `user-row-${u.email}`}
          columns={[
            {
              header: "User",
              heading: (
                <span className="flex items-center gap-3">
                  {sortHeader("Name", "name")}
                  {sortHeader("Email", "email")}
                </span>
              ),
              primary: true,
              cell: (u) => (
                <div className="flex min-w-0 items-center gap-3">
                  <Avatar className="size-8">
                    <AvatarFallback className="bg-primary/12 text-xs font-semibold text-accent-foreground" data-testid="user-avatar-initials">{initials(u.name || u.email)}</AvatarFallback>
                  </Avatar>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-medium" data-testid="user-name">
                        {u.name || u.email}
                      </span>
                      {u.id === me?.id && <Badge variant="outline">You</Badge>}
                      {u.disabled && (
                        <Badge variant="destructive" data-testid="user-disabled-badge">
                          Disabled
                        </Badge>
                      )}
                    </div>
                    <div className="truncate text-xs text-muted-foreground">{u.email}</div>
                  </div>
                </div>
              ),
            },
            {
              header: "Groups",
              cell: (u) =>
                u.groups.length === 0 ? (
                  <span className="text-xs text-muted-foreground">None</span>
                ) : (
                  <div className="flex flex-wrap justify-end gap-1 md:justify-start">
                    {u.groups.map((g) => (
                      <Badge key={g} variant="secondary">
                        {g}
                      </Badge>
                    ))}
                  </div>
                ),
            },
            {
              header: "Joined",
              heading: sortHeader("Joined", "created"),
              className: "md:w-32",
              cell: (u) => (
                <span className="whitespace-nowrap text-muted-foreground" title={formatDateTime(u.created_at)}>
                  {formatRelative(u.created_at)}
                </span>
              ),
            },
            {
              header: "Last sign-in",
              heading: sortHeader("Last sign-in", "last_login"),
              className: "md:w-36",
              cell: (u) => (
                <span className="whitespace-nowrap text-muted-foreground" title={formatDateTime(u.last_login_at)}>
                  {formatRelative(u.last_login_at)}
                </span>
              ),
            },
            {
              header: "",
              className: "md:w-32 md:text-right",
              actions: true,
              cell: (u) =>
                canEdit &&
                u.id !== me?.id && (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={toggle.isPending}
                    onClick={() => (u.disabled ? toggle.mutate({ user: u, disabled: false }) : setDisabling(u))}
                    data-testid="user-toggle-disabled"
                  >
                    {u.disabled ? <UserCheck /> : <UserX />}
                    {u.disabled ? "Enable" : "Disable"}
                  </Button>
                ),
            },
          ]}
        />
      )}
      {page.isSuccess && total > 0 && (
        <Pagination
          page={list.page}
          shown={users.length}
          total={total}
          busy={page.isFetching}
          onPage={(p) => update({ ...list, page: p })}
          filters={listSearchParams(list, SPEC).toString()}
          testId="users-pagination"
        />
      )}
      <ConfirmDialog
        open={disabling !== null}
        onOpenChange={(open) => !open && setDisabling(null)}
        title={`Disable ${disabling?.name || disabling?.email}?`}
        description="They are signed out and cannot sign in again until you enable them. Their memberships are kept."
        confirmLabel="Disable user"
        destructive
        onConfirm={() => toggle.mutateAsync({ user: disabling as User, disabled: true })}
      />
    </div>
  );
}
