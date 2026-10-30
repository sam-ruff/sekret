import { useQuery } from "@tanstack/react-query";
import { Eye, EyeOff, History, Lock, RotateCcw, Trash2 } from "lucide-react";
import { useState } from "react";
import { api } from "@/api/endpoints";
import type { SecretVersion } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { keys, useApiMutation } from "@/hooks/queries";
import { diffLines } from "@/lib/diff";
import { formatDateTime, formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { PolicySection } from "./policy-section";

interface SecretDrawerProps {
  project: string;
  env: string;
  envName: string;
  path: string;
  secretKey: string | null;
  canRollback: boolean;
  /** May change this secret's generation policy and rotate it. */
  canEditPolicy: boolean;
  onRotate: (key: string) => void;
  onClose: () => void;
}

function versionText(v: SecretVersion | undefined): string {
  if (!v || v.deleted) return "";
  return v.value ?? "";
}

function VersionDiff({ versions }: { versions: SecretVersion[] }) {
  const choices = versions.filter((v) => !v.deleted);
  const [to, setTo] = useState(String(choices[0]?.version ?? ""));
  const [from, setFrom] = useState(String(choices[1]?.version ?? choices[0]?.version ?? ""));
  const find = (n: string) => versions.find((v) => String(v.version) === n);
  const lines = diffLines(versionText(find(from)), versionText(find(to)));

  if (choices.length < 2) {
    return <p className="text-sm text-muted-foreground">There is only one version to compare.</p>;
  }
  const hidden = versions.some((v) => v.value_hidden);

  return (
    <div className="space-y-3" data-testid="version-diff">
      <div className="grid grid-cols-2 gap-3">
        {[
          { label: "From", value: from, set: setFrom, id: "diff-from" },
          { label: "To", value: to, set: setTo, id: "diff-to" },
        ].map((side) => (
          <div key={side.id} className="space-y-1.5">
            <Label htmlFor={side.id}>{side.label}</Label>
            <Select value={side.value} onValueChange={side.set}>
              <SelectTrigger id={side.id} className="w-full" data-testid={side.id}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {choices.map((v) => (
                  <SelectItem key={v.version} value={String(v.version)}>
                    Version {v.version}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        ))}
      </div>
      {hidden ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <Lock className="size-4" /> You cannot read these values, so they cannot be compared.
        </p>
      ) : (
        <pre className="max-h-64 overflow-auto rounded-lg border bg-muted/40 py-2 font-mono text-xs" data-testid="diff-output">
          {lines.length === 0 && <div className="px-3 text-muted-foreground">Both versions are empty.</div>}
          {lines.map((line, i) => (
            <div
              key={i}
              className={cn(
                "px-3 whitespace-pre-wrap break-all",
                line.kind === "added" && "bg-success/15 text-success",
                line.kind === "removed" && "bg-destructive/12 text-destructive",
              )}
              data-kind={line.kind}
            >
              <span className="mr-2 inline-block w-3 select-none opacity-60">
                {line.kind === "added" ? "+" : line.kind === "removed" ? "-" : " "}
              </span>
              {line.text || " "}
            </div>
          ))}
        </pre>
      )}
    </div>
  );
}

function VersionItem({
  version,
  current,
  canRollback,
  onRollback,
}: {
  version: SecretVersion;
  current: boolean;
  canRollback: boolean;
  onRollback: () => void;
}) {
  const [shown, setShown] = useState(false);
  return (
    <li className="space-y-2 rounded-lg border bg-card p-3" data-testid={`version-${version.version}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium">Version {version.version}</span>
            {current && <Badge>Current</Badge>}
            {version.deleted && (
              <Badge variant="destructive">
                <Trash2 /> Deleted
              </Badge>
            )}
          </div>
          <div className="truncate text-xs text-muted-foreground" title={formatDateTime(version.created_at)}>
            {version.actor} · {formatRelative(version.created_at)}
          </div>
        </div>
        {!current && !version.deleted && canRollback && (
          <Button variant="outline" size="sm" onClick={onRollback} data-testid={`rollback-${version.version}`}>
            <RotateCcw />
            Roll back
          </Button>
        )}
      </div>
      {version.comment && <p className="text-sm text-muted-foreground">{version.comment}</p>}
      {!version.deleted && (
        <div className="flex items-center gap-1">
          <div className="min-w-0 flex-1 truncate rounded-md bg-muted/60 px-2 py-1 font-mono text-xs">
            {version.value_hidden ? (
              <span className="flex items-center gap-1 text-muted-foreground">
                <Lock className="size-3" /> Hidden
              </span>
            ) : shown ? (
              version.value || <span className="italic text-muted-foreground">empty</span>
            ) : (
              <span className="text-muted-foreground">{"•".repeat(10)}</span>
            )}
          </div>
          {!version.value_hidden && (
            <Button
              variant="ghost"
              size="icon-xs"
              onClick={() => setShown(!shown)}
              aria-label={shown ? "Hide value" : "Show value"}
              data-testid={`version-reveal-${version.version}`}
            >
              {shown ? <EyeOff /> : <Eye />}
            </Button>
          )}
        </div>
      )}
      {version.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {version.tags.map((t) => (
            <Badge key={t} variant="secondary" className="text-[0.7rem]">
              {t}
            </Badge>
          ))}
        </div>
      )}
    </li>
  );
}

export function SecretDrawer({ project, env, envName, path, secretKey, canRollback, canEditPolicy, onRotate, onClose }: SecretDrawerProps) {
  const at = { project, env, path };
  const [target, setTarget] = useState<number | null>(null);
  const versions = useQuery({
    queryKey: keys.versions(project, env, path, secretKey ?? ""),
    queryFn: async () => {
      const list = await api.versions(at, secretKey ?? "");
      return [...list].sort((a, b) => b.version - a.version);
    },
    enabled: secretKey !== null,
  });

  const rollback = useApiMutation({
    mutationFn: (version: number) => api.rollback(at, secretKey ?? "", version),
    invalidate: [keys.versions(project, env, path, secretKey ?? ""), ["project", project, "secrets"], ["project", project, "secret-values"], ["project", project, "overview"], keys.snapshots(project, env)],
    success: (_, version) => `Rolled ${secretKey} back to version ${version}`,
  });

  const list = versions.data ?? [];
  const currentVersion = list[0]?.version;

  return (
    <Sheet open={secretKey !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full gap-0 sm:max-w-xl" data-testid="secret-drawer">
        <SheetHeader className="border-b">
          <SheetTitle className="flex items-center gap-2 font-mono">
            <History className="size-4 shrink-0 text-muted-foreground" />
            <span className="truncate">{secretKey}</span>
          </SheetTitle>
          <SheetDescription>
            {envName} · <span className="font-mono">{path}</span>
          </SheetDescription>
        </SheetHeader>
        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-6 p-4">
            {secretKey && (
              <PolicySection at={at} secretKey={secretKey} canEdit={canEditPolicy} onRotate={() => onRotate(secretKey)} />
            )}
            {versions.isPending && <ListSkeleton rows={3} />}
            {versions.error && <ErrorState error={versions.error} onRetry={() => void versions.refetch()} />}
            {list.length > 0 && (
              <>
                <section className="space-y-3">
                  <h3 className="text-sm font-semibold">Compare versions</h3>
                  <VersionDiff key={currentVersion} versions={list} />
                </section>
                <section className="space-y-3">
                  <h3 className="text-sm font-semibold">History</h3>
                  <ol className="space-y-2" data-testid="version-list">
                    {list.map((v) => (
                      <VersionItem
                        key={v.version}
                        version={v}
                        current={v.version === currentVersion}
                        canRollback={canRollback}
                        onRollback={() => setTarget(v.version)}
                      />
                    ))}
                  </ol>
                </section>
              </>
            )}
          </div>
        </ScrollArea>
        <ConfirmDialog
          open={target !== null}
          onOpenChange={(open) => !open && setTarget(null)}
          title={`Roll back to version ${target}?`}
          description={`This writes a new version of ${secretKey} with the value and tags from version ${target}. Nothing is lost; the current value stays in history.`}
          confirmLabel="Roll back"
          onConfirm={() => rollback.mutateAsync(target ?? 0)}
          testId="rollback-confirm"
        />
      </SheetContent>
    </Sheet>
  );
}
