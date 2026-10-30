import { FolderKey, Plus, Search, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { api } from "@/api/endpoints";
import type { CreateEnvironment } from "@/api/types";
import { PageHeader } from "@/components/page-header";
import { ProjectLogo } from "@/components/project-logo";
import { EmptyState, ErrorState } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { keys, useApiMutation, useProjects } from "@/hooks/queries";
import { useOrgPermissions } from "@/hooks/use-permissions";
import { formatRelative, slugify } from "@/lib/format";

const DEFAULT_ENVS: CreateEnvironment[] = [
  { slug: "dev", name: "Development" },
  { slug: "staging", name: "Staging" },
  { slug: "prod", name: "Production" },
];

function CreateProjectDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [description, setDescription] = useState("");
  const [custom, setCustom] = useState(false);
  const [envs, setEnvs] = useState<CreateEnvironment[]>(DEFAULT_ENVS);

  const reset = () => {
    setName("");
    setSlug("");
    setSlugEdited(false);
    setDescription("");
    setCustom(false);
    setEnvs(DEFAULT_ENVS);
  };

  const create = useApiMutation({
    mutationFn: () =>
      api.createProject({
        name: name.trim(),
        slug,
        description,
        environments: custom ? envs.map((e, position) => ({ ...e, position })) : null,
      }),
    invalidate: [keys.projects],
    success: (p) => `Created ${p.name}`,
    onSuccess: (p) => {
      onOpenChange(false);
      reset();
      navigate(`/projects/${p.slug}/secrets`);
    },
  });

  const updateEnv = (index: number, patch: Partial<CreateEnvironment>) =>
    setEnvs((current) => current.map((e, i) => (i === index ? { ...e, ...patch } : e)));

  const submit = (event: FormEvent) => {
    event.preventDefault();
    create.mutate();
  };

  const envsValid = !custom || (envs.length > 0 && envs.every((e) => e.name.trim() && /^[a-z0-9][a-z0-9-]*$/.test(e.slug)));
  const valid = name.trim() !== "" && /^[a-z0-9][a-z0-9-]*$/.test(slug) && envsValid;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg" data-testid="create-project-dialog">
        <form onSubmit={submit} className="space-y-6">
          <DialogHeader>
            <DialogTitle>New project</DialogTitle>
            <DialogDescription>Projects hold secrets for one application across its environments.</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="project-name">Name</FieldLabel>
              <Input
                id="project-name"
                value={name}
                autoFocus
                data-testid="project-name"
                onChange={(e) => {
                  setName(e.target.value);
                  if (!slugEdited) setSlug(slugify(e.target.value));
                }}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="project-slug">Slug</FieldLabel>
              <Input
                id="project-slug"
                value={slug}
                className="font-mono"
                data-testid="project-slug"
                onChange={(e) => {
                  setSlugEdited(true);
                  setSlug(e.target.value.toLowerCase());
                }}
              />
              <FieldDescription>Lowercase letters, digits and dashes. Used by the CLI and in URLs.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="project-description">Description</FieldLabel>
              <Textarea
                id="project-description"
                rows={2}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </Field>
            <Field orientation="horizontal">
              <Switch id="custom-envs" checked={custom} onCheckedChange={setCustom} data-testid="custom-envs" />
              <FieldLabel htmlFor="custom-envs" className="font-normal">
                Choose environments (defaults are development, staging and production)
              </FieldLabel>
            </Field>
            {custom && (
              <div className="space-y-2" data-testid="custom-env-list">
                {envs.map((env, index) => (
                  <div key={index} className="flex items-center gap-2">
                    <Input
                      aria-label="Environment name"
                      placeholder="Name"
                      value={env.name}
                      data-testid={`env-name-${index}`}
                      onChange={(e) => updateEnv(index, { name: e.target.value, slug: slugify(e.target.value) })}
                    />
                    <Input
                      aria-label="Environment slug"
                      placeholder="slug"
                      className="w-32 font-mono"
                      value={env.slug}
                      data-testid={`env-slug-${index}`}
                      onChange={(e) => updateEnv(index, { slug: e.target.value.toLowerCase() })}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      aria-label={`Remove ${env.name || "environment"}`}
                      onClick={() => setEnvs((current) => current.filter((_, i) => i !== index))}
                    >
                      <Trash2 />
                    </Button>
                  </div>
                ))}
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setEnvs((current) => [...current, { slug: "", name: "" }])}
                  data-testid="add-env-row"
                >
                  <Plus />
                  Add environment
                </Button>
              </div>
            )}
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!valid || create.isPending} data-testid="create-project-submit">
              {create.isPending && <Spinner />}
              Create project
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function ProjectsPage() {
  const { data: projects, isPending, error, refetch } = useProjects();
  const org = useOrgPermissions();
  const [creating, setCreating] = useState(false);
  const [filter, setFilter] = useState("");
  const canCreate = org.can("projects", "create");

  const visible = (projects ?? []).filter((p) =>
    `${p.name} ${p.slug} ${p.description}`.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Projects"
        description="Each project keeps its secrets separate, with its own members and roles."
        actions={
          canCreate && (
            <Button onClick={() => setCreating(true)} data-testid="new-project">
              <Plus />
              New project
            </Button>
          )
        }
      />
      {(projects?.length ?? 0) > 3 && (
        <InputGroup className="max-w-sm">
          <InputGroupAddon>
            <Search />
          </InputGroupAddon>
          <InputGroupInput placeholder="Filter projects" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </InputGroup>
      )}
      {error && <ErrorState error={error} onRetry={() => void refetch()} />}
      {isPending && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3" data-testid="loading">
          {Array.from({ length: 3 }, (_, i) => (
            <Skeleton key={i} className="h-28 rounded-xl" />
          ))}
        </div>
      )}
      {projects && projects.length === 0 && (
        <EmptyState
          icon={<FolderKey />}
          title="No projects yet"
          description={canCreate ? "Create a project to start storing secrets." : "Ask an administrator to add you to a project."}
          action={
            canCreate && (
              <Button onClick={() => setCreating(true)}>
                <Plus />
                New project
              </Button>
            )
          }
          testId="projects-empty"
        />
      )}
      {visible.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3" data-testid="project-list">
          {visible.map((p) => (
            <Link key={p.id} to={`/projects/${p.slug}/secrets`} data-testid={`project-card-${p.slug}`} className="group">
              <Card className="h-full transition-all group-hover:-translate-y-0.5 group-hover:border-primary/40 group-hover:shadow-md">
                <CardHeader>
                  <ProjectLogo
                    url={p.logo_url}
                    className="mb-2 size-9 rounded-lg"
                    fallback={
                      <div className="mb-2 flex size-9 items-center justify-center rounded-lg bg-primary/12 text-primary" data-testid="project-logo-fallback">
                        <FolderKey className="size-4" />
                      </div>
                    }
                  />
                  <CardTitle className="truncate">{p.name}</CardTitle>
                  <CardDescription className="line-clamp-2 min-h-10">
                    {p.description || <span className="font-mono text-xs">{p.slug}</span>}
                  </CardDescription>
                  <p className="pt-1 text-xs text-muted-foreground">Created {formatRelative(p.created_at)}</p>
                </CardHeader>
              </Card>
            </Link>
          ))}
        </div>
      )}
      <CreateProjectDialog open={creating} onOpenChange={setCreating} />
    </div>
  );
}
