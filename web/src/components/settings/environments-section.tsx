import { ArrowDown, ArrowUp, Layers, Pencil, Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api } from "@/api/endpoints";
import type { Environment } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
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
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { keys, useApiMutation, useEnvironments } from "@/hooks/queries";
import type { Permissions } from "@/hooks/use-permissions";
import { slugify } from "@/lib/format";

type Editing = { mode: "new" } | { mode: "rename"; env: Environment } | null;

function EnvironmentDialog({
  editing,
  onClose,
  busy,
  onSubmit,
}: {
  editing: Exclude<Editing, null>;
  onClose: () => void;
  busy: boolean;
  onSubmit: (name: string, slug: string) => void;
}) {
  const current = editing.mode === "rename" ? editing.env : undefined;
  const [name, setName] = useState(current?.name ?? "");
  const [slug, setSlug] = useState(current?.slug ?? "");
  const valid = name.trim() !== "" && /^[a-z0-9][a-z0-9-]*$/.test(slug);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid) onSubmit(name.trim(), slug);
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md" data-testid="environment-dialog">
        <form onSubmit={submit} className="space-y-6">
          <DialogHeader>
            <DialogTitle>{current ? `Rename ${current.name}` : "New environment"}</DialogTitle>
            <DialogDescription>
              {current ? "The slug stays the same so the CLI and integrations keep working." : "Environments hold their own copy of every secret."}
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="env-name">Name</FieldLabel>
              <Input
                id="env-name"
                value={name}
                autoFocus
                data-testid="env-name"
                onChange={(e) => {
                  setName(e.target.value);
                  if (!current) setSlug(slugify(e.target.value));
                }}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="env-slug">ID</FieldLabel>
              <Input
                id="env-slug"
                value={slug}
                disabled={!!current}
                className="font-mono"
                data-testid="env-slug"
                onChange={(e) => setSlug(e.target.value.toLowerCase())}
              />
              <FieldDescription>Used with --env on the command line. It cannot change later.</FieldDescription>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!valid || busy} data-testid="env-save">
              {busy && <Spinner />}
              {current ? "Save" : "Add environment"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function EnvironmentsSection({ project, perms }: { project: string; perms: Permissions }) {
  const environments = useEnvironments(project);
  const [editing, setEditing] = useState<Editing>(null);
  const [deleting, setDeleting] = useState<Environment | null>(null);
  const envs = environments.data ?? [];
  const invalidate = [keys.environments(project), ["project", project, "overview"]];

  const create = useApiMutation({
    mutationFn: ({ name, slug }: { name: string; slug: string }) =>
      api.createEnvironment(project, { name, slug, position: envs.length }),
    invalidate,
    success: (e) => `Added ${e.name}`,
    onSuccess: () => setEditing(null),
  });

  const rename = useApiMutation({
    mutationFn: ({ env, name }: { env: Environment; name: string }) =>
      api.updateEnvironment(project, env.slug, { name, position: env.position }),
    invalidate,
    success: (e) => `Renamed to ${e.name}`,
    onSuccess: () => setEditing(null),
  });

  const reorder = useApiMutation({
    mutationFn: async (ordered: Environment[]) => {
      for (const [position, env] of ordered.entries()) {
        if (env.position !== position) await api.updateEnvironment(project, env.slug, { name: env.name, position });
      }
    },
    invalidate,
  });

  const remove = useApiMutation({
    mutationFn: (env: Environment) => api.deleteEnvironment(project, env.slug),
    invalidate: [["project", project]],
    success: (_, env) => `Deleted ${env.name}`,
  });

  const move = (index: number, by: -1 | 1) => {
    const next = [...envs];
    const [item] = next.splice(index, 1);
    next.splice(index + by, 0, item);
    reorder.mutate(next);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-muted-foreground">The order here is the order of tabs and overview columns.</p>
        {perms.canSomewhere("environments", "create") && (
          <Button onClick={() => setEditing({ mode: "new" })} data-testid="add-environment">
            <Plus />
            Add environment
          </Button>
        )}
      </div>
      {environments.error && <ErrorState error={environments.error} onRetry={() => void environments.refetch()} />}
      {environments.isPending && <ListSkeleton rows={3} />}
      {environments.isSuccess && envs.length === 0 && <EmptyState icon={<Layers />} title="No environments" />}
      {envs.length > 0 && (
        <ul className="divide-y overflow-hidden rounded-xl border bg-card" data-testid="environment-list">
          {envs.map((env, index) => {
            const canEdit = perms.can("environments", "edit", { environment: env.slug });
            const canDelete = perms.can("environments", "delete", { environment: env.slug });
            return (
              <li key={env.id} className="flex items-center gap-3 px-4 py-3" data-testid={`environment-row-${env.slug}`}>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium">{env.name}</div>
                  <div className="font-mono text-xs text-muted-foreground">{env.slug}</div>
                </div>
                {canEdit && (
                  <div className="flex items-center">
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      disabled={index === 0 || reorder.isPending}
                      onClick={() => move(index, -1)}
                      aria-label={`Move ${env.name} up`}
                      data-testid={`env-up-${env.slug}`}
                    >
                      <ArrowUp />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      disabled={index === envs.length - 1 || reorder.isPending}
                      onClick={() => move(index, 1)}
                      aria-label={`Move ${env.name} down`}
                      data-testid={`env-down-${env.slug}`}
                    >
                      <ArrowDown />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      onClick={() => setEditing({ mode: "rename", env })}
                      aria-label={`Rename ${env.name}`}
                      data-testid={`env-rename-${env.slug}`}
                    >
                      <Pencil />
                    </Button>
                  </div>
                )}
                {canDelete && (
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="text-destructive"
                    onClick={() => setDeleting(env)}
                    aria-label={`Delete ${env.name}`}
                    data-testid={`env-delete-${env.slug}`}
                  >
                    <Trash2 />
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {editing && (
        <EnvironmentDialog
          key={editing.mode === "new" ? "new" : editing.env.id}
          editing={editing}
          onClose={() => setEditing(null)}
          busy={create.isPending || rename.isPending}
          onSubmit={(name, slug) =>
            editing.mode === "new" ? create.mutate({ name, slug }) : rename.mutate({ env: editing.env, name })
          }
        />
      )}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={`Delete ${deleting?.name}?`}
        description="Every secret, version and snapshot in this environment is deleted for good. This cannot be undone."
        confirmLabel="Delete environment"
        destructive
        onConfirm={() => remove.mutateAsync(deleting as Environment)}
      />
    </div>
  );
}
