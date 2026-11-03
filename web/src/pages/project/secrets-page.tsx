import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, FileUp, Folder, FolderPlus, KeyRound, Lock, MoreHorizontal, Plus, Search, Trash2 } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, Navigate, useSearchParams } from "react-router";
import { toast } from "sonner";
import { api } from "@/api/endpoints";
import type { Secret } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { EnvTabs } from "@/components/project/env-tabs";
import { FolderBreadcrumbs } from "@/components/project/folder-breadcrumbs";
import { DeleteFolderDialog } from "@/components/secrets/delete-folder-dialog";
import { ImportEnvDialog } from "@/components/secrets/import-env-dialog";
import { SecretDrawer } from "@/components/secrets/secret-drawer";
import { SecretEditor, type SecretDraft } from "@/components/secrets/secret-editor";
import { SECRET_ROW_COLUMNS, SecretRow } from "@/components/secrets/secret-row";
import { MissingEnvironment } from "@/components/project/missing-environment";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
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
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Spinner } from "@/components/ui/spinner";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { folderQuery, useProjectEnv } from "@/hooks/use-project-env";
import { keys, SECRET_VALUE_GC_TIME, useApiMutation, useOptionalQuery, useProject, useSealWatch } from "@/hooks/queries";
import { useIdle, useOnPageHidden } from "@/hooks/use-idle";
import { useIsMobile } from "@/hooks/use-mobile";
import { useManagesSecretAccess, useProjectPermissions } from "@/hooks/use-permissions";
import { isValidSecretKey } from "@/lib/dotenv";
import { generatorFromDraft } from "@/lib/generation";
import { folderLabel, isValidFolderName, joinPath } from "@/lib/paths";
import { countByChildFolder, matchesBelow, matchesSecret, relativeFolder } from "@/lib/secret-search";
import { focusInstead } from "@/lib/return-focus";
import { REVEAL_ALL_LIMIT, ROW_PAGE } from "@/lib/secret-limits";
import { cn } from "@/lib/utils";

function NewFolderDialog({
  open,
  onOpenChange,
  parent,
  onCreate,
  busy,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  parent: string;
  onCreate: (name: string) => void;
  busy: boolean;
}) {
  const [name, setName] = useState("");
  const valid = isValidFolderName(name);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid) onCreate(name);
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setName("");
        onOpenChange(next);
      }}
    >
      <DialogContent className="sm:max-w-md" data-testid="new-folder-dialog">
        <form onSubmit={submit} className="space-y-6">
          <DialogHeader>
            <DialogTitle>New folder</DialogTitle>
            <DialogDescription>
              Created inside <span className="font-mono">{folderLabel(parent)}</span>.
            </DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel htmlFor="folder-name">Name</FieldLabel>
            <Input
              id="folder-name"
              value={name}
              autoFocus
              className="font-mono"
              aria-invalid={name !== "" && !valid}
              onChange={(e) => setName(e.target.value.trim())}
              data-testid="folder-name"
            />
            <FieldDescription>Letters, digits, dots, dashes and underscores.</FieldDescription>
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!valid || busy} data-testid="folder-create">
              {busy && <Spinner />}
              Create folder
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Column headings; on phones the rows are cards, so the headings are only read out. */
function SecretTableHeader() {
  return (
    <div
      role="row"
      className={cn(
        "grid gap-x-2 border-b bg-muted/40 px-4 py-2 text-xs font-medium text-muted-foreground max-md:sr-only",
        SECRET_ROW_COLUMNS,
      )}
    >
      <span role="columnheader">Key</span>
      <span role="columnheader">Value</span>
      <span role="columnheader" className="text-right">
        <span className="sr-only lg:not-sr-only">Updated</span>
        <span className="sr-only"> and actions</span>
      </span>
    </div>
  );
}

/** Matches from subfolders listed at once; more ask for a narrower search. */
const BELOW_LIMIT = 50;

const secretCount = (count: number) => (count === 1 ? "1 secret" : `${count} secrets`);

/** A subfolder, with how many secrets it holds; only an empty one offers to be deleted. */
function FolderRow({
  name,
  href,
  count,
  canDelete,
  onDelete,
}: {
  name: string;
  href: string;
  count: number;
  canDelete: boolean;
  onDelete: () => void;
}) {
  const deleteButton = (blocked: boolean) => (
    <Button
      variant="ghost"
      size="icon-sm"
      className="text-muted-foreground"
      disabled={blocked}
      onClick={onDelete}
      aria-label={`Delete folder ${name}`}
      data-testid={`delete-folder-${name}`}
    >
      <Trash2 />
    </Button>
  );

  return (
    <div
      role="row"
      className="group/folder flex items-center gap-2 border-b px-4 py-2.5 last:border-b-0 hover:bg-muted/40"
      data-testid={`folder-row-${name}`}
    >
      <div role="cell" aria-colspan={2} className="flex min-w-0 flex-1 items-center gap-2">
        <Link to={href} className="-my-2.5 flex min-w-0 flex-1 items-center gap-2 py-2.5 font-mono text-sm" data-testid={`open-folder-${name}`}>
          <Folder className="size-4 shrink-0 fill-primary/20 text-primary" />
          <span className="truncate">{name}</span>
        </Link>
        {count > 0 && (
          <span className="shrink-0 text-xs text-muted-foreground" data-testid={`folder-count-${name}`}>
            {secretCount(count)}
          </span>
        )}
      </div>
      <div role="cell" className="flex shrink-0 justify-end">
        {canDelete && count === 0 && deleteButton(false)}
        {canDelete && count > 0 && (
          <Tooltip>
            <TooltipTrigger asChild>
              {/* A disabled button gets no pointer events, so the wrapper carries the tooltip. Shown on hover or
                  focus only, so an unusable bin does not sit on every folder. */}
              <span
                tabIndex={0}
                className="rounded-lg opacity-0 transition-opacity group-hover/folder:opacity-100 focus-visible:opacity-100"
                data-testid={`delete-folder-blocked-${name}`}
              >
                {deleteButton(true)}
              </span>
            </TooltipTrigger>
            <TooltipContent>Holds {secretCount(count)}. Delete them first to delete the folder.</TooltipContent>
          </Tooltip>
        )}
      </div>
    </div>
  );
}

/** Stands in for the editor until the current value has loaded, or says why it could not. */
function ValueLoadState({
  secretKey,
  error,
  onRetry,
  onCancel,
}: {
  secretKey: string;
  error: Error | null;
  onRetry: () => void;
  onCancel: () => void;
}) {
  if (!error) return <ListSkeleton rows={1} />;
  return (
    <div className="space-y-3" data-testid={`edit-load-failed-${secretKey}`}>
      <ErrorState error={error} onRetry={onRetry} />
      <p className="text-sm text-muted-foreground">
        The editor opens once the current value of <span className="font-mono">{secretKey}</span> has loaded, so a save
        cannot replace it with an empty one.
      </p>
      <div className="flex justify-end">
        <Button variant="outline" size="sm" onClick={onCancel} data-testid="edit-load-cancel">
          Cancel
        </Button>
      </div>
    </div>
  );
}

/**
 * Each project, environment and folder gets fresh state, so values revealed, an editor open or the
 * history drawer in one place never carry over to the same key somewhere else.
 */
export function SecretsPage() {
  const { project, envParam, path } = useProjectEnv();
  return <SecretsView key={`${project}/${envParam ?? ""}/${path}`} />;
}

function SecretsView() {
  const { project, envParam, env, envs, path, environments } = useProjectEnv();
  const projectQuery = useProject(project);
  const perms = useProjectPermissions(project);
  const managesAccess = useManagesSecretAccess(project);
  const queryClient = useQueryClient();
  const isMobile = useIsMobile();

  const [search, setSearch] = useSearchParams();
  // A search result from a parent folder links here with `?q=` set to its key.
  const [filter, setFilter] = useState(() => search.get("q") ?? "");
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [revealAll, setRevealAll] = useState(false);
  /** Keys hidden again by hand while everything else is revealed. */
  const [hiddenFromAll, setHiddenFromAll] = useState<Set<string>>(new Set());
  /** The key the new secret form starts with, or null while the form is closed. An empty `?add=` opens it blank. */
  const [adding, setAdding] = useState<string | null>(() => {
    const key = search.get("add");
    return key !== null && (key === "" || isValidSecretKey(key)) ? key : null;
  });
  const [shownRows, setShownRows] = useState(ROW_PAGE);
  const [editing, setEditing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Secret | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
  const [drawerKey, setDrawerKey] = useState<string | null>(null);
  const [importing, setImporting] = useState(() => search.get("import") === "1");
  const [newFolder, setNewFolder] = useState(false);
  const [deletingFolder, setDeletingFolder] = useState<string | null>(null);
  /** What had focus before a drawer or dialog opened from a row menu, whose item is gone by the time it closes. */
  const returnFocus = useRef<HTMLElement | null>(null);
  const rotateReturnFocus = useRef<HTMLElement | null>(null);

  // The prefilled key, search or import request has been read; a reload should not apply it again.
  useEffect(() => {
    if (!search.has("add") && !search.has("import") && !search.has("q")) return;
    setSearch(
      (current) => {
        const next = new URLSearchParams(current);
        next.delete("add");
        next.delete("import");
        next.delete("q");
        return next;
      },
      { replace: true },
    );
  }, [search, setSearch]);

  const envSlug = env?.slug ?? "";
  const at = { project, env: envSlug, path };
  const base = `/projects/${project}/secrets/${envSlug}`;

  const list = useQuery({
    queryKey: keys.secrets(project, envSlug, path),
    queryFn: () => api.secrets(at, false),
    enabled: !!env,
  });
  // Everything below this folder, without values: it counts what each subfolder holds and lets search reach into them.
  const under = useQuery({
    queryKey: [...keys.secrets(project, envSlug, path), "recursive"],
    queryFn: () => api.secretsUnder(at),
    enabled: !!env && (list.data?.folders.length ?? 0) > 0,
  });
  const tooManyToRevealAll = (list.data?.secrets.length ?? 0) > REVEAL_ALL_LIMIT;
  // Reveal all fetches the folder's values in one go; anything else fetches only the secret it is for.
  // The query exists only while revealed, so hiding drops the values and the next reveal is audited.
  const allValues = useOptionalQuery(
    env && revealAll && !tooManyToRevealAll
      ? {
          queryKey: keys.secretValues(project, envSlug, path),
          queryFn: async () => {
            const result = await api.secrets(at, true);
            return new Map(result.secrets.map((s) => [s.key, s.value ?? null]));
          },
          staleTime: 15_000,
          gcTime: SECRET_VALUE_GC_TIME,
        }
      : null,
  );
  const singleValue = (key: string) => ({
    queryKey: keys.secretValue(project, envSlug, path, key),
    queryFn: async () => (await api.secret(at, key)).value ?? null,
    staleTime: 15_000,
    gcTime: SECRET_VALUE_GC_TIME,
  });
  const singleKeys = [...new Set([...(revealAll ? [] : revealed), ...(editing === null ? [] : [editing])])];
  const singles = useQueries({
    queries: singleKeys.map((key) => ({ ...singleValue(key), enabled: !!env })),
  });
  const singleQuery = (key: string) => singles[singleKeys.indexOf(key)];
  /** Undefined while loading or not asked for. */
  const valueOf = (key: string): string | null | undefined =>
    revealAll && editing !== key ? allValues?.data?.get(key) : singleQuery(key)?.data;
  // Open editors and the import dialog can hold typed or pasted values, so they count as revealed.
  const holdsTypedText = adding !== null || editing !== null || importing;
  const anyRevealed = revealAll || revealed.size > 0 || holdsTypedText;
  useSealWatch(anyRevealed);

  const invalidate = [
    ["project", project, "secrets"],
    ["project", project, "secret-values"],
    ["project", project, "versions"],
    ["project", project, "overview"],
    keys.snapshots(project, envSlug),
  ] as const;

  const save = useApiMutation({
    mutationFn: ({ draft }: { draft: SecretDraft; isNew: boolean }) =>
      draft.generator
        ? api.generateSecret(at, draft.key, {
            generator: generatorFromDraft(draft.generator),
            comment: draft.comment,
            ...(draft.restricted && { restricted: true }),
          })
        : api.setSecret(at, draft.key, {
            value: draft.value,
            comment: draft.comment,
            tags: draft.tags,
            ...(draft.restricted && { restricted: true }),
          }),
    invalidate: [...invalidate, ["project", project, "policy"]],
    success: (r, { draft, isNew }) => {
      if (draft.generator) return isNew ? `Generated ${draft.key}` : `Generated a new value for ${draft.key}`;
      return r.unchanged.length > 0 ? `${draft.key} is unchanged` : isNew ? `Added ${draft.key}` : `Saved ${draft.key}`;
    },
    onSuccess: (result, { draft }) => {
      // A server from before per-secret access ignores the flag and writes the secret open.
      if (draft.restricted && !(result.restricted ?? []).includes(draft.key)) {
        toast.error(
          `The server did not confirm that ${draft.key} is restricted. Check its access settings before you rely on it.`,
        );
      }
      setAdding(null);
      setEditing(null);
      // The finished mutation still holds the saved value as its variables.
      save.reset();
    },
  });

  // A failed save keeps the typed value as its variables until reset.
  const forgetFailedSave = () => {
    if (!save.isPending) save.reset();
  };

  const maskAll = () => {
    setRevealAll(false);
    setRevealed(new Set());
    setHiddenFromAll(new Set());
  };
  useOnPageHidden(revealAll || revealed.size > 0, maskAll);

  useIdle(anyRevealed, () => {
    maskAll();
    const closed = [
      editing !== null && `the editor for ${editing}`,
      adding !== null && "the new secret form",
      importing && "the import",
    ].filter(Boolean);
    setEditing(null);
    setAdding(null);
    setImporting(false);
    forgetFailedSave();
    if (closed.length === 0) return;
    toast.info(`Closed ${closed.join(" and ")} after three idle minutes. Unsaved changes were dropped.`);
  });

  const rotate = useApiMutation({
    // The comment describes the secret, so a rotation carries it forward; the audit log records the rotation.
    mutationFn: (key: string) =>
      api.generateSecret(at, key, { comment: list.data?.secrets.find((s) => s.key === key)?.comment ?? "" }),
    invalidate: [...invalidate, ["project", project, "policy"]],
    success: (_, key) => `Rotated ${key}`,
  });

  const remove = useApiMutation({
    mutationFn: (key: string) => api.deleteSecret(at, key),
    invalidate: [...invalidate],
    success: (_, key) => `Deleted ${key}`,
  });

  const createFolder = useApiMutation({
    mutationFn: (name: string) => api.createFolder(project, envSlug, joinPath(path, name)),
    invalidate: [["project", project, "secrets"]],
    success: (f) => `Created ${f.path}`,
    onSuccess: () => setNewFolder(false),
  });

  const removeFolder = useApiMutation({
    mutationFn: (folder: string) => api.deleteFolder(project, envSlug, folder),
    invalidate: [["project", project, "secrets"]],
    success: (_, folder) => `Deleted ${folder}`,
  });

  if (environments.isSuccess && envs.length > 0 && !envParam && env) {
    return <Navigate to={`${base}${folderQuery(path)}`} replace />;
  }

  const secrets = list.data?.secrets ?? [];
  const folders = list.data?.folders ?? [];
  const needle = filter.trim().toLowerCase();
  const visibleSecrets = secrets.filter((s) => matchesSecret(s, needle));
  const visibleFolders = folders.filter((f) => !needle || f.toLowerCase().includes(needle));
  const folderCounts = under.data ? countByChildFolder(path, under.data.secrets) : undefined;
  const below = under.data ? matchesBelow(path, under.data.secrets, needle) : [];
  const searchingBelow = folders.length > 0 && under.isPending;
  const nothingFound =
    needle !== "" &&
    visibleSecrets.length + visibleFolders.length + below.length === 0 &&
    !searchingBelow &&
    secrets.length + folders.length > 0;
  /** Opens a match from a subfolder with the search narrowed to its key. */
  const matchHref = (secret: Secret) => {
    const params = new URLSearchParams();
    if (secret.path !== "/") params.set("path", secret.path);
    params.set("q", secret.key);
    return `${base}?${params.toString()}`;
  };
  // Rows are drawn a page at a time, so a folder with thousands of keys stays usable.
  const shownFolders = visibleFolders.slice(0, shownRows);
  const shownSecrets = visibleSecrets.slice(0, Math.max(0, shownRows - shownFolders.length));
  const hiddenRows = visibleFolders.length + visibleSecrets.length - shownFolders.length - shownSecrets.length;

  // `granted` narrows a restricted secret to what the caller's own list entry allows.
  const resourceFor = (s: Secret) => ({
    environment: envSlug,
    path,
    key: s.key,
    tags: s.tags,
    ...(s.granted && { granted: s.granted }),
  });
  const drawerSecret = secrets.find((s) => s.key === drawerKey);
  const rotatingSecret = secrets.find((s) => s.key === rotating);
  const rotatingTyped = rotatingSecret !== undefined && !rotatingSecret.generated;
  const canCreateSecret = perms.canSomewhere("secrets", "create");
  const canCreateFolder = perms.canSomewhere("folders", "create");
  const canRollback = perms.canSomewhere("secrets", "edit");
  const hiddenCount = secrets.filter((s) => s.value_hidden).length;
  const nothingToReveal = secrets.length > 0 && hiddenCount === secrets.length;
  const isRevealed = (key: string) => (revealAll ? !hiddenFromAll.has(key) : revealed.has(key));

  const toggle = (set: Set<string>, key: string) => {
    const next = new Set(set);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    return next;
  };
  const toggleReveal = (key: string) => {
    if (revealAll) setHiddenFromAll((current) => toggle(current, key));
    else setRevealed((current) => toggle(current, key));
  };

  const fetchValue = (key: string) => queryClient.fetchQuery(singleValue(key));

  return (
    <div className="space-y-6">
      <PageHeader
        title="Secrets"
        description={projectQuery.data?.description || "Keys and values for each environment of this project."}
      />

      {environments.error && <ErrorState error={environments.error} onRetry={() => void environments.refetch()} />}
      {environments.isPending && <ListSkeleton rows={5} />}
      {environments.isSuccess && envs.length === 0 && (
        <EmptyState
          icon={<KeyRound />}
          title="No environments"
          description="Add an environment in project settings before storing secrets."
          action={
            <Button asChild variant="outline">
              <Link to={`/projects/${project}/settings`}>Open settings</Link>
            </Button>
          }
        />
      )}
      {envParam && environments.isSuccess && !env && envs.length > 0 && (
        <MissingEnvironment name={envParam} first={envs[0]} hrefFor={(slug) => `/projects/${project}/secrets/${slug}`} />
      )}

      {env && (
        <>
          <EnvTabs envs={envs} current={env.slug} hrefFor={(e) => `/projects/${project}/secrets/${e.slug}${folderQuery(path)}`} />

          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <FolderBreadcrumbs path={path} hrefFor={(p) => `${base}${folderQuery(p)}`} />
            <div className="flex items-center gap-2">
              <InputGroup className="md:w-64">
                <InputGroupAddon>
                  <Search />
                </InputGroupAddon>
                <InputGroupInput
                  placeholder={isMobile ? "Search" : "Search keys, comments, tags"}
                  aria-label="Search keys, comments and tags"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  data-testid="secret-search"
                />
              </InputGroup>
              {tooManyToRevealAll ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    {/* A disabled button gets no pointer events, so the wrapper carries the tooltip. */}
                    <span tabIndex={0} className="rounded-lg" data-testid="reveal-all-limit">
                      <Button variant="outline" size="icon" aria-label="Reveal all values" data-testid="reveal-all" disabled>
                        <Eye />
                      </Button>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>
                    This folder has more than {REVEAL_ALL_LIMIT} secrets, too many to reveal at once. Reveal them one at a time.
                  </TooltipContent>
                </Tooltip>
              ) : (
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => {
                    setRevealAll(!revealAll);
                    setRevealed(new Set());
                    setHiddenFromAll(new Set());
                  }}
                  aria-label={revealAll ? "Hide all values" : "Reveal all values"}
                  data-testid="reveal-all"
                  disabled={!perms.canSomewhere("secrets", "read-value") || nothingToReveal}
                >
                  {revealAll ? <EyeOff /> : <Eye />}
                </Button>
              )}
              {(canCreateSecret || canCreateFolder) && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="icon" aria-label="More actions" data-testid="secrets-more">
                      <MoreHorizontal />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    {canCreateFolder && (
                      <DropdownMenuItem onSelect={() => setNewFolder(true)} data-testid="new-folder">
                        <FolderPlus />
                        New folder
                      </DropdownMenuItem>
                    )}
                    {canCreateSecret && (
                      <DropdownMenuItem onSelect={() => setImporting(true)} data-testid="import-env">
                        <FileUp />
                        Import .env
                      </DropdownMenuItem>
                    )}
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
              {canCreateSecret && (
                <Button
                  onClick={() => setAdding("")}
                  disabled={adding !== null}
                  aria-label="Add secret"
                  data-testid="add-secret"
                >
                  <Plus />
                  <span className="hidden sm:inline">Add secret</span>
                </Button>
              )}
            </div>
          </div>

          {adding !== null && canCreateSecret && (
            <SecretEditor
              isNew
              canRestrict={managesAccess && projectQuery.data?.secret_access === true}
              initial={{ key: adding, value: "", comment: "", tags: [] }}
              busy={save.isPending}
              onCancel={() => {
                setAdding(null);
                forgetFailedSave();
              }}
              onSave={(draft) => save.mutate({ draft, isNew: true })}
            />
          )}

          {list.error && <ErrorState error={list.error} onRetry={() => void list.refetch()} />}
          {list.isPending && <ListSkeleton />}

          {list.isSuccess && secrets.length === 0 && folders.length === 0 && (adding === null || !canCreateSecret) && (
            <EmptyState
              icon={<KeyRound />}
              title={path === "/" ? `No secrets in ${env.name} yet` : "This folder is empty"}
              description="Add secrets one at a time or paste a .env file."
              action={
                canCreateSecret && (
                  <div className="flex flex-wrap justify-center gap-2">
                    <Button onClick={() => setAdding("")}>
                      <Plus />
                      Add secret
                    </Button>
                    <Button variant="outline" onClick={() => setImporting(true)}>
                      <FileUp />
                      Import .env
                    </Button>
                  </div>
                )
              }
              testId="secrets-empty"
            />
          )}

          {list.isSuccess && (visibleFolders.length > 0 || visibleSecrets.length > 0) && (
            <div className="overflow-hidden rounded-xl border bg-card">
              <div role="table" aria-label={`Secrets in ${folderLabel(path)}`} data-testid="secrets-table">
                <SecretTableHeader />
                {shownFolders.map((name) => {
                  const folderPath = joinPath(path, name);
                  return (
                    <FolderRow
                      key={name}
                      name={name}
                      href={`${base}${folderQuery(folderPath)}`}
                      count={folderCounts?.get(name) ?? 0}
                      canDelete={perms.can("folders", "delete", { environment: envSlug, path: folderPath })}
                      onDelete={() => setDeletingFolder(folderPath)}
                    />
                  );
                })}
                {shownSecrets.map((secret) =>
                  editing === secret.key ? (
                    <div key={secret.key} role="row" className="border-b p-3 last:border-b-0">
                      <div role="cell" aria-colspan={3}>
                        {/* The update replaces the value, so the editor waits for it rather than starting empty. */}
                        {!secret.value_hidden && valueOf(secret.key) === undefined ? (
                          <ValueLoadState
                            secretKey={secret.key}
                            error={singleQuery(secret.key)?.error ?? null}
                            onRetry={() => void singleQuery(secret.key)?.refetch()}
                            onCancel={() => setEditing(null)}
                          />
                        ) : (
                          <SecretEditor
                            isNew={false}
                            valueHidden={secret.value_hidden}
                            generated={secret.generated}
                            initial={{
                              key: secret.key,
                              value: valueOf(secret.key) ?? "",
                              comment: secret.comment,
                              tags: secret.tags,
                            }}
                            busy={save.isPending}
                            onCancel={() => {
                              setEditing(null);
                              forgetFailedSave();
                            }}
                            onSave={(draft) => {
                              const unchanged =
                                !draft.generator &&
                                draft.value === (valueOf(secret.key) ?? "") &&
                                draft.comment === secret.comment &&
                                draft.tags.join() === secret.tags.join() &&
                                !secret.value_hidden;
                              if (unchanged) {
                                setEditing(null);
                                return;
                              }
                              save.mutate({ draft, isNew: false });
                            }}
                          />
                        )}
                      </div>
                    </div>
                  ) : (
                    <SecretRow
                      key={secret.key}
                      secret={secret}
                      revealed={isRevealed(secret.key)}
                      value={isRevealed(secret.key) ? valueOf(secret.key) : undefined}
                      abilities={{
                        edit: perms.can("secrets", "edit", resourceFor(secret)),
                        remove: perms.can("secrets", "delete", resourceFor(secret)),
                        history: perms.can("secret-versions", "read", resourceFor(secret)),
                      }}
                      onToggleReveal={() => toggleReveal(secret.key)}
                      onCopyValue={() => fetchValue(secret.key)}
                      onEdit={() => setEditing(secret.key)}
                      onDelete={() => setDeleting(secret)}
                      onHistory={(returnTo) => {
                        returnFocus.current = returnTo;
                        setDrawerKey(secret.key);
                      }}
                      onRotate={(returnTo) => {
                        rotateReturnFocus.current = returnTo;
                        setRotating(secret.key);
                      }}
                    />
                  ),
                )}
              </div>
              {hiddenCount > 0 && (
                <p className="flex items-start gap-1.5 px-4 py-2.5 text-xs text-muted-foreground" data-testid="hidden-values-note">
                  <Lock className="mt-0.5 size-3.5 shrink-0" />
                  {nothingToReveal ? "Your roles do not let you read the values here." : `Your roles do not let you read ${hiddenCount === 1 ? "one of these values" : `${hiddenCount} of these values`}.`}{" "}
                  Roles add up, but a deny rule in any of them wins over every role that allows the same thing.
                </p>
              )}
              {hiddenRows > 0 && (
                <div className="flex flex-wrap items-center justify-center gap-3 border-t px-4 py-3 text-sm text-muted-foreground">
                  <span data-testid="secrets-more-count">
                    Showing {shownFolders.length + shownSecrets.length} of {visibleFolders.length + visibleSecrets.length}
                  </span>
                  <Button variant="outline" size="sm" onClick={() => setShownRows(shownRows + ROW_PAGE)} data-testid="secrets-show-more">
                    Show {Math.min(ROW_PAGE, hiddenRows)} more
                  </Button>
                </div>
              )}
            </div>
          )}

          {list.isSuccess && needle && below.length > 0 && (
            <section className="space-y-2" aria-labelledby="search-below-heading" data-testid="search-below">
              <h2 id="search-below-heading" className="text-sm font-medium text-muted-foreground">
                {below.length === 1 ? "1 match" : `${below.length} matches`} in folders inside {folderLabel(path)}
              </h2>
              <ul className="overflow-hidden rounded-xl border bg-card">
                {below.slice(0, BELOW_LIMIT).map((secret) => (
                  <li key={secret.id} className="border-b last:border-b-0">
                    <Link
                      to={matchHref(secret)}
                      className="flex min-w-0 items-center gap-2 px-4 py-2.5 font-mono text-sm hover:bg-muted/40"
                      data-testid={`search-below-${secret.key}`}
                    >
                      <Folder className="size-4 shrink-0 fill-primary/20 text-primary" />
                      <span className="min-w-0 truncate">
                        <span className="text-muted-foreground">{relativeFolder(path, secret.path)}/</span>
                        {secret.key}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
              {below.length > BELOW_LIMIT && (
                <p className="text-xs text-muted-foreground" data-testid="search-below-more">
                  Showing the first {BELOW_LIMIT}. Type more of the name to narrow the search.
                </p>
              )}
            </section>
          )}
          {list.isSuccess && needle && under.isError && (
            <p className="text-xs text-muted-foreground" data-testid="search-below-failed">
              The folders inside this one could not be searched.
            </p>
          )}

          {list.isSuccess && nothingFound && (
            <EmptyState
              icon={<Search />}
              title={`Nothing matches "${filter.trim()}"`}
              description="Search looks at keys, comments and tags in this folder and the folders inside it."
              action={
                <Button variant="outline" size="sm" onClick={() => setFilter("")}>
                  Clear search
                </Button>
              }
              testId="no-search-results"
            />
          )}

          <ImportEnvDialog
            open={importing && canCreateSecret && list.isSuccess}
            onOpenChange={setImporting}
            project={project}
            env={envSlug}
            envName={env.name}
            path={path}
            existingKeys={secrets.map((s) => s.key)}
            invalidate={invalidate}
          />
          <NewFolderDialog
            open={newFolder}
            onOpenChange={setNewFolder}
            parent={path}
            busy={createFolder.isPending}
            onCreate={(name) => createFolder.mutate(name)}
          />
          <SecretDrawer
            project={project}
            env={envSlug}
            envName={env.name}
            path={path}
            secretKey={drawerKey}
            canRollback={canRollback && (drawerSecret ? perms.can("secrets", "edit", resourceFor(drawerSecret)) : true)}
            canEditPolicy={drawerSecret ? perms.can("secrets", "edit", resourceFor(drawerSecret)) : false}
            restricted={drawerSecret?.restricted === true}
            onRotate={(key) => {
              rotateReturnFocus.current = null;
              setRotating(key);
            }}
            onClose={() => setDrawerKey(null)}
            onCloseAutoFocus={(event) => focusInstead(event, returnFocus.current)}
          />
        </>
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete ${deleting?.key}?`}
        description="The secret disappears from this environment. Its history is kept and it can be restored from a snapshot."
        confirmLabel="Delete secret"
        destructive
        onConfirm={() => remove.mutateAsync(deleting?.key ?? "")}
      />
      <ConfirmDialog
        open={rotating !== null}
        onOpenChange={(open) => !open && setRotating(null)}
        title={`Rotate ${rotating} now?`}
        description={
          <>
            {rotatingTyped && (
              <span className="mb-2 block font-medium text-foreground" data-testid="rotate-typed-warning">
                The current value was typed or imported, not generated. Rotating replaces it with random characters, which
                breaks anything that expects a particular value, such as a URL or a setting.
              </span>
            )}
            sekret replaces the value with a newly generated one using this secret&apos;s policy. The old value stays in
            history, but anything still using it needs the new one.
          </>
        }
        confirmLabel={rotatingTyped ? "Replace with a generated value" : "Rotate now"}
        destructive={rotatingTyped}
        onConfirm={() => rotate.mutateAsync(rotating ?? "")}
        onCloseAutoFocus={(event) => focusInstead(event, rotateReturnFocus.current)}
        testId="rotate-confirm"
      />
      {env && (
        <DeleteFolderDialog
          project={project}
          env={envSlug}
          folder={deletingFolder}
          onClose={() => setDeletingFolder(null)}
          onDelete={(folder) => removeFolder.mutateAsync(folder)}
        />
      )}
    </div>
  );
}
