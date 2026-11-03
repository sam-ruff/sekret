import { useInfiniteQuery, useQueries } from "@tanstack/react-query";
import { Eye, EyeOff, KeyRound, Lock, RotateCcw, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/api/endpoints";
import type { SecretVersion } from "@/api/types";
import { InlineConfirm } from "@/components/inline-confirm";
import { ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";
import { keys, SECRET_VALUE_GC_TIME, useApiMutation, useSealWatch } from "@/hooks/queries";
import { useIdle, useOnPageHidden } from "@/hooks/use-idle";
import { diffLines } from "@/lib/diff";
import { formatDateTime, formatRelative } from "@/lib/format";
import { folderLabel } from "@/lib/paths";
import { cn } from "@/lib/utils";
import { HISTORY_PAGE, mergeHistory, nextHistoryCursor, sameContent } from "@/lib/versions";
import { AccessSection } from "./access-section";
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
  /** Only those on its access list, and admins, can reach it. */
  restricted?: boolean;
  /** Show the access section first, when the reader needs to check it. */
  accessFirst?: boolean;
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
              <span className="mr-2 inline-block w-3 select-none">
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
  sameAsCurrent,
  confirming,
  secretKey,
  onRollback,
  onCancelRollback,
  onConfirmRollback,
}: {
  version: SecretVersion;
  current: boolean;
  /** Values were fetched after the reader asked for them. */
  shown: boolean;
  canRollback: boolean;
  /** Rolling back would change nothing; only known once values are shown. */
  sameAsCurrent: boolean;
  /** Asking whether to roll back to this version. */
  confirming: boolean;
  secretKey: string;
  onRollback: () => void;
  onCancelRollback: () => void;
  onConfirmRollback: () => Promise<unknown>;
}) {
  const button = useRef<HTMLButtonElement>(null);
  const wasConfirming = useRef(confirming);
  // Back to the button once the question is answered or dismissed, rather than to the page body.
  useEffect(() => {
    if (wasConfirming.current && !confirming) button.current?.focus();
    wasConfirming.current = confirming;
  }, [confirming]);

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
        {!current && !version.deleted && canRollback && sameAsCurrent && (
          <span className="shrink-0 pt-1 text-xs text-muted-foreground" data-testid={`same-as-current-${version.version}`}>
            Same as current
          </span>
        )}
        {!current && !version.deleted && canRollback && !sameAsCurrent && (
          <Button
            ref={button}
            variant="outline"
            size="sm"
            onClick={onRollback}
            aria-expanded={confirming}
            data-testid={`rollback-${version.version}`}
          >
            <RotateCcw />
            Roll back
          </Button>
        )}
      </div>
      {confirming && (
        <InlineConfirm
          title={`Roll back to version ${version.version}?`}
          description={`${secretKey} gets a new version with the value and tags from version ${version.version}. The current value stays in history.`}
          confirmLabel="Roll back"
          onConfirm={onConfirmRollback}
          onCancel={onCancelRollback}
          testId="rollback-confirm"
        />
      )}
      {version.comment && <p className="text-sm text-muted-foreground first-letter:uppercase">{version.comment}</p>}
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
  restricted = false,
  accessFirst = false,
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
  const loadPage = async (values: boolean, before: number | undefined) => {
    const list = await api.versions(at, secretKey ?? "", { values, before, limit: HISTORY_PAGE });
    return [...list].sort((a, b) => b.version - a.version);
  };
  // History is fetched a page at a time, so a secret written thousands of times stays quick to open.
  const versions = useInfiniteQuery({
    queryKey: historyKey,
    queryFn: ({ pageParam }) => loadPage(false, pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: nextHistoryCursor,
    enabled: secretKey !== null,
    gcTime: SECRET_VALUE_GC_TIME,
  });
  // Values are fetched for exactly the pages loaded. Every reveal asks the server, so each one is
  // audited and a revoked reader sees nothing stale; hiding them drops every observer.
  const cursors = versions.data?.pageParams ?? [];
  const valuePages = useQueries({
    queries: showValues
      ? cursors.map((before) => ({
          queryKey: [...historyKey, "values", before ?? "newest"],
          queryFn: () => loadPage(true, before as number | undefined),
          staleTime: 0,
          gcTime: SECRET_VALUE_GC_TIME,
        }))
      : [],
  });
  const withValues = showValues
    ? {
        isPending: valuePages.some((q) => q.isPending),
        error: valuePages.find((q) => q.error)?.error ?? null,
        refetch: () => Promise.all(valuePages.filter((q) => q.error).map((q) => q.refetch())),
      }
    : undefined;
  useSealWatch(showValues);
  useIdle(showValues, () => setValuesFor(null));
  useOnPageHidden(showValues, () => setValuesFor(null));

  const close = () => {
    setValuesFor(null);
    onClose();
  };

  const rollback = useApiMutation({
    mutationFn: (version: number) => api.rollback(at, secretKey ?? "", version),
    invalidate: [keys.versions(project, env, path, secretKey ?? ""), ["project", project, "secrets"], ["project", project, "secret-values"], ["project", project, "overview"], keys.snapshots(project, env)],
    success: (_, version) => `Rolled ${secretKey} back to version ${version}`,
  });

  const { revealed, list } = mergeHistory(versions.data?.pages ?? [], showValues ? valuePages.map((q) => q.data) : []);
  const currentVersion = list[0]?.version;
  const loadingOlder = versions.isFetchingNextPage || (revealed !== undefined && !!withValues?.isPending);

  return (
    <Sheet open={secretKey !== null} onOpenChange={(open) => !open && close()}>
      <SheetContent
        className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-xl"
        onCloseAutoFocus={onCloseAutoFocus}
        // Escape answers an open rollback question first, and only then closes the drawer.
        onEscapeKeyDown={(event) => {
          if (target === null) return;
          event.preventDefault();
          setTarget(null);
        }}
        data-testid="secret-drawer"
      >
        <SheetHeader className="border-b pr-12">
          <SheetTitle className="flex min-w-0 items-center gap-2 font-mono">
            <KeyRound className="size-4 shrink-0 text-muted-foreground" />
            <span className="truncate">{secretKey}</span>
          </SheetTitle>
          <SheetDescription data-testid="secret-drawer-where">
            {envName} · <span className="font-mono break-all">{folderLabel(path)}</span>          </SheetDescription>
        </SheetHeader>
        <ScrollArea className="min-h-0 flex-1" viewportClassName="[&>div]:!block [&>div]:min-w-0">
          <div className="space-y-6 p-4">
            {secretKey && accessFirst && <AccessSection at={at} secretKey={secretKey} restricted={restricted} />}
            {versions.isPending && <ListSkeleton rows={3} />}
            {versions.error && !versions.isFetchNextPageError && (
              <ErrorState error={versions.error} onRetry={() => void versions.refetch()} />
            )}
            {list.length > 0 && (
              <>
                <section className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-semibold">History</h3>
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
                      Values are hidden. Show them to see each version and compare versions. Showing them is recorded in
                      the audit log.
                    </p>
                  )}
                  {withValues?.isPending && !revealed && <ListSkeleton rows={1} />}
                  {withValues?.error && <ErrorState error={withValues.error} onRetry={() => void withValues.refetch()} />}
                  <ol className="space-y-2" data-testid="version-list">
                    {list.map((v, index) => (
                      <VersionItem
                        key={v.version}
                        version={v}
                        current={v.version === currentVersion}
                        shown={revealed !== undefined && index < revealed.length}
                        canRollback={canRollback}
                        sameAsCurrent={revealed !== undefined && index < revealed.length && sameContent(v, revealed[0])}
                        confirming={target === v.version}
                        secretKey={secretKey ?? ""}
                        onRollback={() => setTarget(v.version)}
                        onCancelRollback={() => setTarget(null)}
                        onConfirmRollback={async () => {
                          await rollback.mutateAsync(v.version);
                          setTarget(null);
                        }}
                      />
                    ))}
                  </ol>
                  {versions.hasNextPage && (
                    <div className="flex flex-wrap items-center justify-center gap-3 text-sm text-muted-foreground">
                      <span data-testid="history-shown-count">Showing the newest {list.length} versions</span>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={loadingOlder || versions.isFetchingNextPage}
                        onClick={() => void versions.fetchNextPage()}
                        data-testid="history-load-older"
                      >
                        {loadingOlder && <Spinner />}
                        Load older versions
                      </Button>
                    </div>
                  )}
                  {versions.isFetchNextPageError && (
                    <ErrorState error={versions.error} onRetry={() => void versions.fetchNextPage()} />
                  )}
                </section>
                {revealed && revealed.filter((v) => !v.deleted).length > 1 && (
                  <section className="space-y-3" data-testid="compare-section">
                    <h3 className="text-sm font-semibold">Compare versions</h3>
                    <VersionDiff key={currentVersion} versions={revealed} />
                  </section>
                )}
              </>
            )}
            {secretKey && !accessFirst && <AccessSection at={at} secretKey={secretKey} restricted={restricted} />}
            {secretKey && (
              <PolicySection at={at} secretKey={secretKey} canEdit={canEditPolicy} onRotate={() => onRotate(secretKey)} />
            )}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
