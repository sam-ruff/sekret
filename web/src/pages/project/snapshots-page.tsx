import { useQuery } from "@tanstack/react-query";
import { Camera, ChevronRight, History, Minus, Plus, RefreshCw, Undo2 } from "lucide-react";
import { useRef, useState } from "react";
import { Navigate } from "react-router";
import { api } from "@/api/endpoints";
import type { Snapshot, SnapshotChange } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { EnvTabs } from "@/components/project/env-tabs";
import { MissingEnvironment } from "@/components/project/missing-environment";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useProjectEnv } from "@/hooks/use-project-env";
import { keys, useApiMutation } from "@/hooks/queries";
import { useProjectPermissions } from "@/hooks/use-permissions";
import { formatDateTime, formatRelative } from "@/lib/format";
import { useDebouncedValue } from "@/hooks/use-debounced-value";
import { normalisePath } from "@/lib/paths";
import { ROW_PAGE } from "@/lib/secret-limits";
import { restoreSummary, snapshotTitle } from "@/lib/snapshots";
import { cn } from "@/lib/utils";

const KIND_STYLE: Record<SnapshotChange["kind"], { label: string; className: string; icon: typeof Plus }> = {
  added: { label: "Restored", className: "border-success/40 text-success", icon: Plus },
  removed: { label: "Removed", className: "border-destructive/40 text-destructive", icon: Minus },
  changed: { label: "Changed", className: "border-warning/50 text-warning", icon: RefreshCw },
};

function ChangeRow({ change }: { change: SnapshotChange }) {
  const style = KIND_STYLE[change.kind];
  const where = change.path === "/" ? "/" : `${change.path}/`;
  return (
    <li className="flex items-center gap-3 rounded-lg border bg-card px-3 py-2" data-testid={`change-${change.key}`}>
      <Badge variant="outline" className={cn("w-24 justify-start", style.className)}>
        <style.icon /> {style.label}
      </Badge>
      <div className="min-w-0 flex-1">
        <div className="truncate font-mono text-sm">
          <span className="text-muted-foreground">{where}</span>
          {change.key}
        </div>
        <div className="text-xs text-muted-foreground" data-testid="change-detail">
          {change.kind === "removed" && `Would be removed (currently version ${change.current_version})`}
          {change.kind === "added" && `Comes back with the value from version ${change.snapshot_version}`}
          {change.kind === "changed" &&
            `Goes back to the value from version ${change.snapshot_version} (currently version ${change.current_version})`}
        </div>
      </div>
    </li>
  );
}

function SnapshotSheet({
  project,
  env,
  envName,
  snapshot,
  canRestore,
  onClose,
}: {
  project: string;
  env: string;
  envName: string;
  snapshot: Snapshot | null;
  canRestore: boolean;
  onClose: () => void;
}) {
  const [folder, setFolder] = useState("/");
  const [confirming, setConfirming] = useState(false);
  const [shownRows, setShownRows] = useState(ROW_PAGE);
  const content = useRef<HTMLDivElement>(null);
  // Each keystroke would otherwise ask the server for a full recursive comparison.
  const path = normalisePath(useDebouncedValue(folder, 400));
  const id = snapshot?.id ?? "";

  const detail = useQuery({
    queryKey: keys.snapshot(project, env, id, path),
    queryFn: () => api.snapshot(project, env, id, path),
    enabled: snapshot !== null,
  });

  const restore = useApiMutation({
    mutationFn: () => api.restoreSnapshot(project, env, id, path),
    invalidate: [["project", project]],
    success: (r) => {
      const total = r.created.length + r.updated.length + r.deleted.length;
      return total === 0 ? "Nothing needed restoring" : `Restored ${total} ${total === 1 ? "secret" : "secrets"}`;
    },
    onSuccess: onClose,
  });

  const changes = detail.data?.changes ?? [];
  const settling = normalisePath(folder) !== path;
  const removes = changes.some((c) => c.kind === "removed");
  const hiddenRows = Math.max(0, changes.length - shownRows);

  return (
    <Sheet
      open={snapshot !== null}
      onOpenChange={(open) => {
        if (open) return;
        setFolder("/");
        onClose();
      }}
    >
      <SheetContent
        ref={content}
        className="w-full gap-0 data-[side=right]:w-full sm:max-w-xl"
        // Focusing the folder field first would open the on-screen keyboard over the changes.
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          content.current?.focus();
        }}
        data-testid="snapshot-sheet"
      >
        <SheetHeader className="border-b pr-12">
          <SheetTitle>Snapshot from {snapshot && formatRelative(snapshot.created_at)}</SheetTitle>
          <SheetDescription data-testid="snapshot-drawer-description">
            {snapshot && formatDateTime(snapshot.created_at)} · {snapshot && snapshotTitle(snapshot.reason)} · {snapshot?.actor} ·{" "}
            {envName}
          </SheetDescription>
        </SheetHeader>
        <ScrollArea className="min-h-0 flex-1" viewportClassName="[&>div]:!block [&>div]:min-w-0">
          <div className="space-y-5 p-4">
            <Field>
              <FieldLabel htmlFor="restore-path">Limit to folder</FieldLabel>
              <Input
                id="restore-path"
                value={folder}
                className="font-mono"
                onChange={(e) => {
                  setFolder(e.target.value || "/");
                  setShownRows(ROW_PAGE);
                }}
                data-testid="restore-path"
              />
              <FieldDescription>
                Only secrets in this folder and below are compared and restored. <span className="font-mono">/</span> is
                the top folder, so it covers everything.
              </FieldDescription>
            </Field>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold">What restoring would change</h3>
              {detail.isPending && <ListSkeleton rows={3} />}
              {detail.error && <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />}
              {detail.isSuccess && changes.length === 0 && (
                <p className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground" data-testid="no-changes">
                  This folder already matches the snapshot.
                </p>
              )}
              {changes.length > 0 && (
                <ul className="space-y-2" data-testid="snapshot-changes">
                  {changes.slice(0, shownRows).map((c) => (
                    <ChangeRow key={`${c.path}:${c.key}`} change={c} />
                  ))}
                </ul>
              )}
              {hiddenRows > 0 && (
                <div className="flex flex-wrap items-center justify-center gap-3 pt-1 text-sm text-muted-foreground">
                  <span data-testid="changes-more-count">
                    Showing {shownRows} of {changes.length}
                  </span>
                  <Button variant="outline" size="sm" onClick={() => setShownRows(shownRows + ROW_PAGE)} data-testid="changes-show-more">
                    Show {Math.min(ROW_PAGE, hiddenRows)} more
                  </Button>
                </div>
              )}
            </section>
          </div>
        </ScrollArea>
        {canRestore && (
          <SheetFooter className="border-t">
            <Button
              variant={removes ? "destructive" : "default"}
              onClick={() => setConfirming(true)}
              disabled={changes.length === 0 || settling || !detail.isSuccess}
              data-testid="restore-snapshot"
            >
              <Undo2 />
              Restore {changes.length > 0 ? `${changes.length} ${changes.length === 1 ? "change" : "changes"}` : ""}
            </Button>
          </SheetFooter>
        )}
        <ConfirmDialog
          open={confirming}
          onOpenChange={setConfirming}
          title="Restore this snapshot?"
          description={restoreSummary(changes, path, envName)}
          confirmLabel="Restore"
          destructive={removes}
          onConfirm={() => restore.mutateAsync()}
          testId="restore-confirm"
        />
      </SheetContent>
    </Sheet>
  );
}

export function SnapshotsPage() {
  const { project, envParam, env, envs, environments } = useProjectEnv();
  const perms = useProjectPermissions(project);
  const [open, setOpen] = useState<Snapshot | null>(null);
  const envSlug = env?.slug ?? "";

  const list = useQuery({
    queryKey: keys.snapshots(project, envSlug),
    queryFn: () => api.snapshots(project, envSlug),
    enabled: !!env,
  });

  if (environments.isSuccess && !envParam && env) {
    return <Navigate to={`/projects/${project}/snapshots/${env.slug}`} replace />;
  }

  const canRestore = perms.can("snapshots", "edit", { environment: envSlug });

  return (
    <div className="space-y-6">
      <PageHeader title="Snapshots" description="Every change saves the state of an environment. Restore one to undo a bad change." />
      {environments.error && <ErrorState error={environments.error} onRetry={() => void environments.refetch()} />}
      {environments.isPending && <ListSkeleton rows={5} />}
      {environments.isSuccess && envs.length === 0 && (
        <EmptyState icon={<Camera />} title="No environments" description="Snapshots appear once an environment has secrets." />
      )}
      {envParam && environments.isSuccess && !env && envs.length > 0 && (
        <MissingEnvironment name={envParam} first={envs[0]} hrefFor={(slug) => `/projects/${project}/snapshots/${slug}`} />
      )}
      {env && (
        <>
          <EnvTabs envs={envs} current={env.slug} hrefFor={(e) => `/projects/${project}/snapshots/${e.slug}`} />
          {list.error && <ErrorState error={list.error} onRetry={() => void list.refetch()} />}
          {list.isPending && <ListSkeleton rows={5} />}
          {list.isSuccess && list.data.length === 0 && (
            <EmptyState icon={<Camera />} title={`No snapshots for ${env.name}`} description="A snapshot is taken each time secrets change." testId="snapshots-empty" />
          )}
          {list.data && list.data.length > 0 && (
            <ol className="relative space-y-2 border-l pl-6 md:ml-2" data-testid="snapshot-list">
              {list.data.map((s, index) => (
                <li key={s.id} className="relative">
                  <span
                    className={cn(
                      "absolute top-4 -left-[1.95rem] flex size-3 items-center justify-center rounded-full border-2 border-background",
                      index === 0 ? "bg-primary" : "bg-muted-foreground/40",
                    )}
                  />
                  <button
                    type="button"
                    onClick={() => setOpen(s)}
                    className="flex w-full items-center gap-3 rounded-xl border bg-card p-3 text-left transition-colors hover:border-primary/40 hover:bg-muted/30"
                    data-testid={`snapshot-${index}`}
                  >
                    <History className="size-4 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-start gap-2">
                        <div className="line-clamp-2 min-w-0 flex-1 text-sm font-medium break-words" title={s.reason} data-testid="snapshot-title">
                          {snapshotTitle(s.reason)}
                        </div>
                        {index === 0 && <Badge variant="secondary">Latest</Badge>}
                      </div>
                      <div className="text-xs break-words text-muted-foreground" title={formatDateTime(s.created_at)} data-testid="snapshot-meta">
                        {s.actor} · {formatRelative(s.created_at)} · {s.secret_count} {s.secret_count === 1 ? "secret" : "secrets"}
                      </div>
                    </div>
                    <ChevronRight className="size-4 shrink-0 text-muted-foreground" />
                  </button>
                </li>
              ))}
            </ol>
          )}
          <SnapshotSheet
            key={open?.id ?? "none"}
            project={project}
            env={envSlug}
            envName={env.name}
            snapshot={open}
            canRestore={canRestore}
            onClose={() => setOpen(null)}
          />
        </>
      )}
    </div>
  );
}
