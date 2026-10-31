import { useQuery } from "@tanstack/react-query";
import { Eye, EyeOff, History, Lock, RotateCcw, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
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
import { keys, SECRET_VALUE_GC_TIME, useApiMutation, useSealWatch } from "@/hooks/queries";
import { useIdle } from "@/hooks/use-idle";
import { diffLines } from "@/lib/diff";
import { formatDateTime, formatRelative } from "@/lib/format";
import { folderLabel } from "@/lib/paths";
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
  onCloseAutoFocus?: (event: Event) => void;
}

function versionText(v: SecretVersion | undefined): string {
  if (!v || v.deleted) return "";
  return v.value ?? "";
}

/** Lines drawn at most, so a long value does not stall the page. */
const MAX_SHOWN_LINES = 2_000;

function VersionDiff({ versions }: { versions: SecretVersion[] }) {
  const choices = versions.filter((v) => !v.deleted);
  const [to, setTo] = useState(String(choices[0]?.version ?? ""));
  const [from, setFrom] = useState(String(choices[1]?.version ?? choices[0]?.version ?? ""));
  const fromText = versionText(versions.find((v) => String(v.version) === from));
  const toText = versionText(versions.find((v) => String(v.version) === to));
  const lines = useMemo(() => diffLines(fromText, toText), [fromText, toText]);

  if (choices.length < 2) {
    return <p className="text-sm text-muted-foreground">There is only one version to compare.</p>;
  }
  const hidden = versions.some((v) => v.value_hidden);
  const shown = lines?.slice(0, MAX_SHOWN_LINES) ?? [];

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
      ) : lines === null ? (
        <p className="text-sm text-muted-foreground" data-testid="diff-too-large">
          These versions differ in too many lines to compare here.
        </p>
      ) : (
        <pre className="max-h-64 overflow-auto rounded-lg border bg-muted/40 py-2 font-mono text-xs" data-testid="diff-output">
          {lines.length === 0 && <div className="px-3 text-muted-foreground">Both versions are empty.</div>}
          {shown.map((line, i) => (
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
          {lines.length > shown.length && (
            <div className="px-3 pt-1 text-muted-foreground" data-testid="diff-truncated">
              {lines.length - shown.length} more lines not shown.
            </div>
          )}
        </pre>
      )}
    </div>
  );
}

function VersionValue({ version, shown }: { version: SecretVersion; shown: boolean }) {
  if (!shown) return <span className="text-muted-foreground">{"•".repeat(10)}</span>;
  if (version.value_hidden) {
    return (
      <span className="flex items-center gap-1 text-muted-foreground">
        <Lock className="size-3" /> Hidden
      </span>
    );
  }
  return version.value || <span className="italic text-muted-foreground">empty</span>;
}

function VersionItem({
  version,
  current,
  shown,
  canRollback,
  onRollback,
}: {
  version: SecretVersion;
  current: boolean;
  /** Values were fetched after the reader asked for them. */
  shown: boolean;
  canRollback: boolean;
  onRollback: () => void;
}) {
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
        <div
          className="min-w-0 truncate rounded-md bg-muted/60 px-2 py-1 font-mono text-xs"
          data-testid={`version-value-${version.version}`}
        >
          <VersionValue version={version} shown={shown} />
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

export function SecretDrawer({
  project,
  env,
  envName,
  path,
  secretKey,
  canRollback,
  canEditPolicy,
  onRotate,
  onClose,
  onCloseAutoFocus,
}: SecretDrawerProps) {
  const at = { project, env, path };
  const [target, setTarget] = useState<number | null>(null);
  // Values are shown only for the secret they were asked for, and hidden again on close or a switch
  // to another key, folder or environment, even one holding a key of the same name.
  const location = secretKey === null ? null : JSON.stringify([project, env, path, secretKey]);
  const [valuesFor, setValuesFor] = useState<string | null>(null);
  const [openAt, setOpenAt] = useState(location);
  if (openAt !== location) {
    setOpenAt(location);
    setValuesFor(null);
    setTarget(null);
  }
  const showValues = location !== null && valuesFor === location;

  const historyKey = keys.versions(project, env, path, secretKey ?? "");
  const loadVersions = async (values: boolean) => {
    const list = await api.versions(at, secretKey ?? "", values);
    return [...list].sort((a, b) => b.version - a.version);
  };
  const versions = useQuery({
    queryKey: historyKey,
    queryFn: () => loadVersions(false),
    enabled: secretKey !== null,
    gcTime: SECRET_VALUE_GC_TIME,
  });
  const withValues = useQuery({
    queryKey: [...historyKey, "values"],
    queryFn: () => loadVersions(true),
    enabled: showValues,
    gcTime: SECRET_VALUE_GC_TIME,
  });
  useSealWatch(showValues);
  useIdle(showValues, () => setValuesFor(null));

  const close = () => {
    setValuesFor(null);
    onClose();
  };

  const rollback = useApiMutation({
    mutationFn: (version: number) => api.rollback(at, secretKey ?? "", version),
    invalidate: [keys.versions(project, env, path, secretKey ?? ""), ["project", project, "secrets"], ["project", project, "secret-values"], ["project", project, "overview"], keys.snapshots(project, env)],
    success: (_, version) => `Rolled ${secretKey} back to version ${version}`,
  });

  const revealed = showValues ? withValues.data : undefined;
  const list = revealed ?? versions.data ?? [];
  const currentVersion = list[0]?.version;

  return (
    <Sheet open={secretKey !== null} onOpenChange={(open) => !open && close()}>
      <SheetContent
        className="w-full gap-0 data-[side=right]:w-full sm:max-w-xl"
        onCloseAutoFocus={onCloseAutoFocus}
        data-testid="secret-drawer"
      >
        <SheetHeader className="border-b pr-12">
          <SheetTitle className="flex min-w-0 items-center gap-2 font-mono">
            <History className="size-4 shrink-0 text-muted-foreground" />
            <span className="truncate">{secretKey}</span>
          </SheetTitle>
          <SheetDescription data-testid="secret-drawer-where">
            {envName} · <span className="font-mono break-all">{folderLabel(path)}</span>
          </SheetDescription>
        </SheetHeader>
        <ScrollArea className="min-h-0 flex-1" viewportClassName="[&>div]:!block [&>div]:min-w-0">
          <div className="space-y-6 p-4">
            {versions.isPending && <ListSkeleton rows={3} />}
            {versions.error && <ErrorState error={versions.error} onRetry={() => void versions.refetch()} />}
            {list.length > 0 && (
              <>
                <section className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-semibold">Compare versions</h3>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setValuesFor(showValues ? null : location)}
                      aria-pressed={showValues}
                      data-testid="history-values-toggle"
                    >
                      {showValues ? <EyeOff /> : <Eye />}
                      {showValues ? "Hide values" : "Show values"}
                    </Button>
                  </div>
                  {!showValues && (
                    <p className="text-sm text-muted-foreground" data-testid="history-values-hidden">
                      Values are hidden. Showing them is recorded in the audit log.
                    </p>
                  )}
                  {showValues && withValues.isPending && <ListSkeleton rows={1} />}
                  {showValues && withValues.error && (
                    <ErrorState error={withValues.error} onRetry={() => void withValues.refetch()} />
                  )}
                  {revealed && <VersionDiff key={currentVersion} versions={revealed} />}
                </section>
                <section className="space-y-3">
                  <h3 className="text-sm font-semibold">History</h3>
                  <ol className="space-y-2" data-testid="version-list">
                    {list.map((v) => (
                      <VersionItem
                        key={v.version}
                        version={v}
                        current={v.version === currentVersion}
                        shown={revealed !== undefined}
                        canRollback={canRollback}
                        onRollback={() => setTarget(v.version)}
                      />
                    ))}
                  </ol>
                </section>
              </>
            )}
            {secretKey && (
              <PolicySection at={at} secretKey={secretKey} canEdit={canEditPolicy} onRotate={() => onRotate(secretKey)} />
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
