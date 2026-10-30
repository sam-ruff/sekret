import { useQuery } from "@tanstack/react-query";
import { Camera, ChevronRight, History, Minus, Plus, RefreshCw, Undo2 } from "lucide-react";
import { useState } from "react";
import { Navigate } from "react-router";
import { api } from "@/api/endpoints";
import type { Snapshot, SnapshotChange } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { EnvTabs } from "@/components/project/env-tabs";
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
import { normalisePath } from "@/lib/paths";
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
        <div className="text-xs text-muted-foreground">
          {change.kind === "removed" && `Version ${change.current_version} would be deleted`}
          {change.kind === "added" && `Comes back as version ${change.snapshot_version}`}
          {change.kind === "changed" && `Version ${change.current_version} goes back to version ${change.snapshot_version}`}
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
  const path = normalisePath(folder);
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

  return (
    <Sheet
      open={snapshot !== null}
      onOpenChange={(open) => {
        if (open) return;
        setFolder("/");
        onClose();
      }}
    >
      <SheetContent className="w-full gap-0 sm:max-w-xl" data-testid="snapshot-sheet">
        <SheetHeader className="border-b">
          <SheetTitle>Snapshot from {snapshot && formatRelative(snapshot.created_at)}</SheetTitle>
          <SheetDescription>
            {snapshot?.reason} · {snapshot?.actor} · {envName}
          </SheetDescription>
        </SheetHeader>
        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-5 p-4">
            <Field>
              <FieldLabel htmlFor="restore-path">Limit to folder</FieldLabel>
              <Input
                id="restore-path"
                value={folder}
                className="font-mono"
                onChange={(e) => setFolder(e.target.value || "/")}
                data-testid="restore-path"
              />
              <FieldDescription>Only secrets in this folder and below are compared and restored.</FieldDescription>
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
                  {changes.map((c) => (
                    <ChangeRow key={`${c.path}:${c.key}`} change={c} />
                  ))}
                </ul>
              )}
            </section>
          </div>
        </ScrollArea>
        {canRestore && (
          <SheetFooter className="border-t">
            <Button onClick={() => setConfirming(true)} disabled={changes.length === 0} data-testid="restore-snapshot">
              <Undo2 />
              Restore {changes.length > 0 ? `${changes.length} ${changes.length === 1 ? "change" : "changes"}` : ""}
            </Button>
          </SheetFooter>
        )}
        <ConfirmDialog
          open={confirming}
          onOpenChange={setConfirming}
          title="Restore this snapshot?"
          description={`${changes.length} ${changes.length === 1 ? "secret" : "secrets"} under ${path} in ${envName} will be written as new versions. History is kept, so this can be undone with another restore.`}
          confirmLabel="Restore"
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
                      <div className="truncate text-sm font-medium">{s.reason}</div>
                      <div className="truncate text-xs text-muted-foreground" title={formatDateTime(s.created_at)}>
                        {s.actor} · {formatRelative(s.created_at)} · {s.secret_count} {s.secret_count === 1 ? "secret" : "secrets"}
                      </div>
                    </div>
                    {index === 0 && <Badge variant="secondary">Latest</Badge>}
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
