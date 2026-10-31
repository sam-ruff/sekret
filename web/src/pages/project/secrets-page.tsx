import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, FileUp, Folder, FolderPlus, KeyRound, MoreHorizontal, Plus, Search, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, Navigate } from "react-router";
import { api } from "@/api/endpoints";
import type { Secret } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PageHeader } from "@/components/page-header";
import { EnvTabs } from "@/components/project/env-tabs";
import { FolderBreadcrumbs } from "@/components/project/folder-breadcrumbs";
import { ImportEnvDialog } from "@/components/secrets/import-env-dialog";
import { SecretDrawer } from "@/components/secrets/secret-drawer";
import { SecretEditor, type SecretDraft } from "@/components/secrets/secret-editor";
import { SecretRow } from "@/components/secrets/secret-row";
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
import { folderQuery, useProjectEnv } from "@/hooks/use-project-env";
import { keys, SECRET_VALUE_GC_TIME, useApiMutation, useProject, useSealWatch } from "@/hooks/queries";
import { useProjectPermissions } from "@/hooks/use-permissions";
import { generatorFromDraft } from "@/lib/generation";
import { isValidFolderName, joinPath } from "@/lib/paths";

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
              Created inside <span className="font-mono">{parent}</span>.
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

export function SecretsPage() {
  const { project, envParam, env, envs, path, environments } = useProjectEnv();
  const projectQuery = useProject(project);
  const perms = useProjectPermissions(project);
  const queryClient = useQueryClient();

  const [filter, setFilter] = useState("");
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [revealAll, setRevealAll] = useState(false);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Secret | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
  const [drawerKey, setDrawerKey] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [newFolder, setNewFolder] = useState(false);
  const [deletingFolder, setDeletingFolder] = useState<string | null>(null);

  const envSlug = env?.slug ?? "";
  const at = { project, env: envSlug, path };
  const base = `/projects/${project}/secrets/${envSlug}`;

  const list = useQuery({
    queryKey: keys.secrets(project, envSlug, path),
    queryFn: () => api.secrets(at, false),
    enabled: !!env,
  });
  const wantValues = revealAll || revealed.size > 0 || editing !== null;
  const values = useQuery({
    queryKey: keys.secretValues(project, envSlug, path),
    queryFn: async () => {
      const result = await api.secrets(at, true);
      return new Map(result.secrets.map((s) => [s.key, s.value ?? null]));
    },
    enabled: !!env && wantValues,
    staleTime: 15_000,
    gcTime: SECRET_VALUE_GC_TIME,
  });
  useSealWatch(revealAll || revealed.size > 0);

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
        ? api.generateSecret(at, draft.key, { generator: generatorFromDraft(draft.generator), comment: draft.comment })
        : api.setSecret(at, draft.key, { value: draft.value, comment: draft.comment, tags: draft.tags }),
    invalidate: [...invalidate, ["project", project, "policy"]],
    success: (r, { draft, isNew }) => {
      if (draft.generator) return isNew ? `Generated ${draft.key}` : `Generated a new value for ${draft.key}`;
      return r.unchanged.length > 0 ? `${draft.key} is unchanged` : isNew ? `Added ${draft.key}` : `Saved ${draft.key}`;
    },
    onSuccess: () => {
      setAdding(false);
      setEditing(null);
    },
  });

  const rotate = useApiMutation({
    mutationFn: (key: string) => api.generateSecret(at, key, { comment: "rotated by hand" }),
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
  const visibleSecrets = secrets.filter(
    (s) =>
      !needle ||
      s.key.toLowerCase().includes(needle) ||
      s.comment.toLowerCase().includes(needle) ||
      s.tags.some((t) => t.includes(needle)),
  );
  const visibleFolders = folders.filter((f) => !needle || f.toLowerCase().includes(needle));

  const resourceFor = (s: Secret) => ({ environment: envSlug, path, key: s.key, tags: s.tags });
  const drawerSecret = secrets.find((s) => s.key === drawerKey);
  const canCreateSecret = perms.canSomewhere("secrets", "create");
  const canCreateFolder = perms.canSomewhere("folders", "create");
  const canRollback = perms.canSomewhere("secrets", "edit");
  const isRevealed = (key: string) => revealAll || revealed.has(key);

  const toggleReveal = (key: string) => {
    setRevealAll(false);
    setRevealed((current) => {
      const next = new Set(revealAll ? secrets.map((s) => s.key) : current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const fetchValue = async (key: string) => {
    const map = await queryClient.fetchQuery({
      queryKey: keys.secretValues(project, envSlug, path),
      queryFn: async () => {
        const result = await api.secrets(at, true);
        return new Map(result.secrets.map((s) => [s.key, s.value ?? null]));
      },
      staleTime: 15_000,
      gcTime: SECRET_VALUE_GC_TIME,
    });
    return map.get(key);
  };

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
        <ErrorState error={new Error(`There is no environment called ${envParam}.`)} />
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
                  placeholder="Search keys, comments, tags"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  data-testid="secret-search"
                />
              </InputGroup>
              <Button
                variant="outline"
                size="icon"
                onClick={() => {
                  setRevealAll(!revealAll);
                  setRevealed(new Set());
                }}
                aria-label={revealAll ? "Hide all values" : "Reveal all values"}
                data-testid="reveal-all"
                disabled={!perms.canSomewhere("secrets", "read-value")}
              >
                {revealAll ? <EyeOff /> : <Eye />}
              </Button>
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
                <Button onClick={() => setAdding(true)} disabled={adding} data-testid="add-secret">
                  <Plus />
                  <span className="hidden sm:inline">Add secret</span>
                </Button>
              )}
            </div>
          </div>

          {adding && (
            <SecretEditor
              isNew
              initial={{ key: "", value: "", comment: "", tags: [] }}
              busy={save.isPending}
              onCancel={() => setAdding(false)}
              onSave={(draft) => save.mutate({ draft, isNew: true })}
            />
          )}

          {list.error && <ErrorState error={list.error} onRetry={() => void list.refetch()} />}
          {list.isPending && <ListSkeleton />}

          {list.isSuccess && secrets.length === 0 && folders.length === 0 && !adding && (
            <EmptyState
              icon={<KeyRound />}
              title={path === "/" ? `No secrets in ${env.name} yet` : "This folder is empty"}
              description="Add secrets one at a time or paste a .env file."
              action={
                canCreateSecret && (
                  <div className="flex flex-wrap justify-center gap-2">
                    <Button onClick={() => setAdding(true)}>
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
            <div className="overflow-hidden rounded-xl border bg-card" data-testid="secrets-table">
              <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,3fr)_auto] gap-2 border-b bg-muted/40 px-4 py-2 text-xs font-medium text-muted-foreground md:grid">
                <span>Key</span>
                <span>Value</span>
                <span className="w-8" />
              </div>
              {visibleFolders.map((name) => {
                const folderPath = joinPath(path, name);
                const canDelete = perms.can("folders", "delete", { environment: envSlug, path: folderPath });
                return (
                  <div key={name} className="flex items-center gap-2 border-b px-4 py-2.5 last:border-b-0 hover:bg-muted/40" data-testid={`folder-row-${name}`}>
                    <Link
                      to={`${base}${folderQuery(folderPath)}`}
                      className="flex min-w-0 flex-1 items-center gap-2 font-mono text-sm"
                      data-testid={`open-folder-${name}`}
                    >
                      <Folder className="size-4 shrink-0 fill-primary/20 text-primary" />
                      <span className="truncate">{name}</span>
                    </Link>
                    {canDelete && (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        className="text-muted-foreground"
                        onClick={() => setDeletingFolder(folderPath)}
                        aria-label={`Delete folder ${name}`}
                        data-testid={`delete-folder-${name}`}
                      >
                        <Trash2 />
                      </Button>
                    )}
                  </div>
                );
              })}
              {visibleSecrets.map((secret) =>
                editing === secret.key ? (
                  <div key={secret.key} className="border-b p-3 last:border-b-0">
                    {values.isPending && !secret.value_hidden ? (
                      <ListSkeleton rows={1} />
                    ) : (
                      <SecretEditor
                        isNew={false}
                        valueHidden={secret.value_hidden}
                        generated={secret.generated}
                        initial={{
                          key: secret.key,
                          value: values.data?.get(secret.key) ?? "",
                          comment: secret.comment,
                          tags: secret.tags,
                        }}
                        busy={save.isPending}
                        onCancel={() => setEditing(null)}
                        onSave={(draft) => {
                          const unchanged =
                            !draft.generator &&
                            draft.value === (values.data?.get(secret.key) ?? "") &&
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
                ) : (
                  <SecretRow
                    key={secret.key}
                    secret={secret}
                    revealed={isRevealed(secret.key)}
                    value={values.data?.get(secret.key)}
                    abilities={{
                      edit: perms.can("secrets", "edit", resourceFor(secret)),
                      remove: perms.can("secrets", "delete", resourceFor(secret)),
                      history: perms.can("secret-versions", "read", resourceFor(secret)),
                    }}
                    onToggleReveal={() => toggleReveal(secret.key)}
                    onCopyValue={() => fetchValue(secret.key)}
                    onEdit={() => setEditing(secret.key)}
                    onDelete={() => setDeleting(secret)}
                    onHistory={() => setDrawerKey(secret.key)}
                    onRotate={() => setRotating(secret.key)}
                  />
                ),
              )}
            </div>
          )}

          {list.isSuccess && needle && visibleSecrets.length === 0 && visibleFolders.length === 0 && secrets.length + folders.length > 0 && (
            <EmptyState
              icon={<Search />}
              title={`Nothing matches "${filter.trim()}"`}
              description="Search looks at keys, comments and tags in this folder."
              action={
                <Button variant="outline" size="sm" onClick={() => setFilter("")}>
                  Clear search
                </Button>
              }
              testId="no-search-results"
            />
          )}

          <ImportEnvDialog
            open={importing}
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
            canRollback={canRollback}
            canEditPolicy={drawerSecret ? perms.can("secrets", "edit", resourceFor(drawerSecret)) : false}
            onRotate={setRotating}
            onClose={() => setDrawerKey(null)}
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
        description="sekret replaces the value with a newly generated one using this secret's policy. The old value stays in history, but anything still using it needs the new one."
        confirmLabel="Rotate now"
        onConfirm={() => rotate.mutateAsync(rotating ?? "")}
        testId="rotate-confirm"
      />
      <ConfirmDialog
        open={deletingFolder !== null}
        onOpenChange={(open) => !open && setDeletingFolder(null)}
        title={`Delete folder ${deletingFolder}?`}
        description="Only empty folders can be deleted. Move or delete the secrets inside first."
        confirmLabel="Delete folder"
        destructive
        onConfirm={() => removeFolder.mutateAsync(deletingFolder ?? "/")}
      />
    </div>
  );
}
