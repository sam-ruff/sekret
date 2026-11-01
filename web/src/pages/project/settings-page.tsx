import { useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router";
import { toast } from "sonner";
import { api } from "@/api/endpoints";
import type { Project, PutRole } from "@/api/types";
import { PROJECT_SUBJECTS } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ErrorBoundary } from "@/components/error-boundary";
import { LinkTabs } from "@/components/link-tabs";
import { PageHeader } from "@/components/page-header";
import { RolesPanel } from "@/components/roles/roles-panel";
import { EnvironmentsSection } from "@/components/settings/environments-section";
import { LogoCard } from "@/components/settings/logo-card";
import { MembersSection } from "@/components/settings/members-section";
import { SecretDefaultsCard } from "@/components/settings/secret-defaults-card";
import { ErrorState } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { keys, useApiMutation, useEnvironments, useProject, useRoles } from "@/hooks/queries";
import { useProjectPermissions, type Permissions } from "@/hooks/use-permissions";

const TABS = [
  { id: "general", label: "General" },
  { id: "environments", label: "Environments" },
  { id: "members", label: "Members" },
  { id: "roles", label: "Roles" },
  { id: "danger", label: "Danger zone" },
] as const;

type TabId = (typeof TABS)[number]["id"];

function GeneralSection({ project, perms }: { project: string; perms: Permissions }) {
  const query = useProject(project);
  if (query.isPending) return <Skeleton className="h-56 rounded-xl" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  const canEdit = perms.can("settings", "edit");
  return (
    <div className="space-y-6">
      <GeneralForm key={query.data.id} project={query.data} perms={perms} />
      <LogoCard project={query.data} canEdit={canEdit} />
      {perms.can("settings", "read") && <SecretDefaultsCard project={query.data.slug} canEdit={canEdit} />}
    </div>
  );
}

function GeneralForm({ project: details, perms }: { project: Project; perms: Permissions }) {
  const project = details.slug;
  const [name, setName] = useState(details.name);
  const [description, setDescription] = useState(details.description);

  const save = useApiMutation({
    mutationFn: () => api.updateProject(project, { name: name.trim(), description }),
    invalidate: [keys.projects, keys.project(project)],
    success: "Project saved",
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    save.mutate();
  };
  const canEdit = perms.can("settings", "edit");

  return (
    <Card className="max-w-3xl">
      <form onSubmit={submit} className="flex flex-col gap-6">
        <CardHeader>
          <CardTitle>Project details</CardTitle>
          <CardDescription>
            The ID <span className="font-mono">{details.slug}</span> cannot change.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="settings-name">Name</FieldLabel>
              <Input id="settings-name" value={name} disabled={!canEdit} onChange={(e) => setName(e.target.value)} data-testid="settings-name" />
            </Field>
            <Field>
              <FieldLabel htmlFor="settings-description">Description</FieldLabel>
              <Textarea
                id="settings-description"
                rows={3}
                value={description}
                disabled={!canEdit}
                onChange={(e) => setDescription(e.target.value)}
              />
            </Field>
          </FieldGroup>
        </CardContent>
        {canEdit && (
          <CardFooter className="justify-end">
            <Button type="submit" disabled={!name.trim() || save.isPending} data-testid="settings-save">
              {save.isPending && <Spinner />}
              Save changes
            </Button>
          </CardFooter>
        )}
      </form>
    </Card>
  );
}

function DangerSection({ project, perms }: { project: string; perms: Permissions }) {
  const navigate = useNavigate();
  const query = useProject(project);
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const slug = query.data?.slug ?? project;

  const remove = useApiMutation({
    mutationFn: () => api.deleteProject(project),
    invalidate: [keys.projects],
    success: `Deleted ${slug}`,
    onSuccess: () => navigate("/projects"),
  });

  return (
    <Card className="max-w-3xl ring-destructive/30">
      <CardContent className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0 space-y-1">
          <div className="flex items-center gap-2 font-medium text-destructive">
            <AlertTriangle className="size-4 shrink-0" />
            Delete this project
          </div>
          <p className="text-sm text-muted-foreground">
            Every environment, secret, version, snapshot, member and custom role goes with it. There is no undo.
          </p>
        </div>
        <Button
          variant="destructive"
          className="shrink-0 self-start sm:self-auto"
          disabled={!perms.can("settings", "delete")}
          onClick={() => setOpen(true)}
          data-testid="delete-project"
        >
          <Trash2 />
          Delete project
        </Button>
      </CardContent>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) setTyped("");
        }}
        title={`Delete ${query.data?.name ?? slug}?`}
        description={
          <>
            Type <span className="font-mono font-semibold">{slug}</span> to confirm.
          </>
        }
        confirmLabel="Delete project"
        destructive
        confirmDisabled={typed !== slug}
        onConfirm={() => remove.mutateAsync()}
        testId="delete-project-confirm"
      >
        <Input value={typed} onChange={(e) => setTyped(e.target.value)} className="font-mono" data-testid="delete-project-slug" />
      </ConfirmDialog>
    </Card>
  );
}

function RolesSection({ project, perms }: { project: string; perms: Permissions }) {
  const queryClient = useQueryClient();
  const roles = useRoles(project);
  const envs = useEnvironments(project);

  const save = async (slug: string, body: PutRole) => {
    await api.putRole(project, slug, body);
    await queryClient.invalidateQueries({ queryKey: keys.roles(project) });
    await queryClient.invalidateQueries({ queryKey: keys.permissions(project) });
    toast.success(`Saved ${body.name}`);
  };

  const remove = useApiMutation({
    mutationFn: (slug: string) => api.deleteRole(project, slug),
    invalidate: [keys.roles(project), keys.permissions(project)],
    success: "Role deleted",
  });

  return (
    <RolesPanel
      roles={roles.data}
      loading={roles.isPending}
      error={roles.error}
      onRetry={() => void roles.refetch()}
      subjects={PROJECT_SUBJECTS}
      intro="Built-in roles cover common needs. Custom roles can narrow access by environment, folder, key or tag."
      environments={(envs.data ?? []).map((e) => e.slug)}
      canCreate={perms.can("roles", "create")}
      canEdit={perms.can("roles", "edit")}
      canDelete={perms.can("roles", "delete")}
      onSave={save}
      onDelete={(slug) => remove.mutateAsync(slug)}
    />
  );
}

export function SettingsPage() {
  const { project = "", tab = "general" } = useParams();
  const perms = useProjectPermissions(project);
  const active: TabId = TABS.some((t) => t.id === tab) ? (tab as TabId) : "general";

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" description="Environments, people and permissions for this project." />
      <LinkTabs
        label="Settings sections"
        current={active}
        tabs={TABS.map((t) => ({
          value: t.id,
          label: t.label,
          to: `/projects/${project}/settings/${t.id}`,
          testId: `settings-tab-${t.id}`,
          destructive: t.id === "danger",
        }))}
      />
      <ErrorBoundary variant="section" resetKey={active}>
        {active === "general" && <GeneralSection project={project} perms={perms} />}
        {active === "environments" && <EnvironmentsSection project={project} perms={perms} />}
        {active === "members" && <MembersSection project={project} perms={perms} />}
        {active === "roles" && <RolesSection project={project} perms={perms} />}
        {active === "danger" && <DangerSection project={project} perms={perms} />}
      </ErrorBoundary>
    </div>
  );
}
