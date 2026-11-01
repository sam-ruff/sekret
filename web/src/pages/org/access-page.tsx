import { useQueryClient, useQuery } from "@tanstack/react-query";
import { Bot, Plus, ShieldAlert, ShieldCheck, Trash2, User as UserIcon, Users } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Navigate, useParams } from "react-router";
import { api } from "@/api/endpoints";
import type { OrgBinding, PrincipalKind } from "@/api/types";
import { ORG_SUBJECTS } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ErrorBoundary } from "@/components/error-boundary";
import { LinkTabs } from "@/components/link-tabs";
import { PageHeader } from "@/components/page-header";
import { PrincipalPicker, type PrincipalOption } from "@/components/principal-picker";
import { ResponsiveTable } from "@/components/responsive-table";
import { RoleLabel } from "@/components/roles/role-label";
import { RolesPanel } from "@/components/roles/roles-panel";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { keys, useApiMutation, useOrgRoles } from "@/hooks/queries";
import { useOrgPermissions } from "@/hooks/use-permissions";
import { errorMessage, isEscalation } from "@/lib/errors";

const KIND_ICONS: Record<PrincipalKind, typeof UserIcon> = { user: UserIcon, group: Users, identity: Bot };
const KIND_LABELS: Record<PrincipalKind, string> = { user: "User", group: "Group", identity: "Machine identity" };

function AddBindingDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const org = useOrgPermissions();
  const [kind, setKind] = useState<PrincipalKind>("user");
  const [group, setGroup] = useState("");
  const [chosen, setChosen] = useState<PrincipalOption>();
  const [role, setRole] = useState("");
  const [escalation, setEscalation] = useState<string>();
  const roles = useOrgRoles(open);
  const principal = kind === "group" ? group : (chosen?.id ?? "");

  const reset = () => {
    setGroup("");
    setChosen(undefined);
    setRole("");
    setEscalation(undefined);
  };

  const add = useApiMutation({
    mutationFn: () => api.addOrgBinding({ principal_kind: kind, principal_id: principal.trim(), role }),
    invalidate: [keys.orgBindings],
    success: "Role granted",
    onSuccess: () => {
      reset();
      onOpenChange(false);
    },
    onError: (error) => {
      if (!isEscalation(error)) return false;
      setEscalation(errorMessage(error));
      return true;
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (principal.trim() && role) add.mutate();
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
    >
      <DialogContent className="sm:max-w-md" data-testid="add-binding-dialog">
        <form onSubmit={submit} className="space-y-6">
          <DialogHeader>
            <DialogTitle>Grant an organisation role</DialogTitle>
            <DialogDescription>Organisation roles apply everywhere, including every project.</DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel>Who</FieldLabel>
            <ToggleGroup
              type="single"
              variant="outline"
              value={kind}
              onValueChange={(v) => {
                if (!v) return;
                setKind(v as PrincipalKind);
                setGroup("");
                setChosen(undefined);
              }}
              className="w-full"
            >
              {(["user", "identity", "group"] as const).map((k) => (
                <ToggleGroupItem key={k} value={k} className="flex-1" data-testid={`binding-kind-${k}`}>
                  {k === "identity" ? "Identity" : KIND_LABELS[k]}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
          </Field>
          {kind === "group" ? (
            <Field>
              <FieldLabel htmlFor="binding-group">Group name</FieldLabel>
              <Input
                id="binding-group"
                value={group}
                onChange={(e) => setGroup(e.target.value)}
                placeholder="platform"
                data-testid="binding-group"
              />
              <FieldDescription>As it appears in the groups claim from your identity provider.</FieldDescription>
            </Field>
          ) : (
            <Field>
              <FieldLabel htmlFor="binding-principal">{KIND_LABELS[kind]}</FieldLabel>
              <PrincipalPicker
                key={kind}
                kind={kind}
                selected={chosen}
                onSelect={setChosen}
                canList={org.can(kind === "user" ? "org-members" : "identities", "read")}
                id="binding-principal"
                testId="binding-principal"
              />
            </Field>
          )}
          <Field>
            <FieldLabel htmlFor="binding-role">Role</FieldLabel>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger id="binding-role" className="w-full" data-testid="binding-role">
                <SelectValue placeholder="Choose a role" />
              </SelectTrigger>
              <SelectContent>
                {(roles.data ?? []).map((r) => (
                  <SelectItem key={r.slug} value={r.slug}>
                    {r.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {escalation && (
            <Alert variant="destructive" data-testid="binding-escalation">
              <ShieldAlert />
              <AlertTitle>You cannot grant that role</AlertTitle>
              <AlertDescription>{escalation}. Choose a role with no more access than your own.</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!principal.trim() || !role || add.isPending} data-testid="binding-submit">
              {add.isPending && <Spinner />}
              Grant role
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function BindingsTab() {
  const org = useOrgPermissions();
  const bindings = useQuery({ queryKey: keys.orgBindings, queryFn: api.orgBindings });
  const roles = useOrgRoles();
  const roleName = (slug: string) => roles.data?.find((r) => r.slug === slug)?.name ?? slug;
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<OrgBinding | null>(null);
  const canCreate = org.can("org-members", "create");
  const canDelete = org.can("org-members", "delete");

  const remove = useApiMutation({
    mutationFn: (b: OrgBinding) => api.removeOrgBinding(b.principal_kind, b.principal_id, b.role),
    invalidate: [keys.orgBindings, keys.me],
    success: "Role removed",
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-muted-foreground">Who holds which organisation role.</p>
        {canCreate && (
          <Button onClick={() => setAdding(true)} data-testid="binding-add">
            <Plus />
            Grant role
          </Button>
        )}
      </div>
      {bindings.error && <ErrorState error={bindings.error} onRetry={() => void bindings.refetch()} />}
      {bindings.isPending && <ListSkeleton rows={3} />}
      {bindings.data && bindings.data.length === 0 && (
        <EmptyState icon={<ShieldCheck />} title="No organisation roles granted" />
      )}
      {bindings.data && bindings.data.length > 0 && (
        <ResponsiveTable
          rows={bindings.data}
          rowKey={(b) => `${b.principal_kind}:${b.principal_id}:${b.role}`}
          rowTestId={(b) => `binding-row-${b.principal_kind}-${b.principal_name}-${b.role}`}
          columns={[
            {
              header: "Person, group or machine",
              primary: true,
              cell: (b) => {
                const Icon = KIND_ICONS[b.principal_kind];
                return (
                  <div className="flex min-w-0 items-center gap-2">
                    <Icon className="size-4 shrink-0 text-muted-foreground" aria-label={KIND_LABELS[b.principal_kind]} />
                    <span className="truncate">{b.principal_name}</span>
                  </div>
                );
              },
            },
            {
              header: "Kind",
              cell: (b) => <span className="text-muted-foreground">{KIND_LABELS[b.principal_kind]}</span>,
            },
            {
              header: "Role",
              cell: (b) => <RoleLabel name={roleName(b.role)} id={b.role} />,
            },
            {
              header: "",
              className: "md:w-12",
              actions: true,
              cell: (b) =>
                canDelete && (
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    onClick={() => setRemoving(b)}
                    aria-label={`Remove ${roleName(b.role)} from ${b.principal_name}`}
                    data-testid="binding-remove"
                  >
                    <Trash2 />
                  </Button>
                ),
            },
          ]}
        />
      )}
      <AddBindingDialog open={adding} onOpenChange={setAdding} />
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={`Remove ${removing ? roleName(removing.role) : ""} from ${removing?.principal_name}?`}
        description="They lose the access this role granted across the organisation."
        confirmLabel="Remove role"
        destructive
        onConfirm={() => remove.mutateAsync(removing as OrgBinding)}
      />
    </div>
  );
}

function RolesTab() {
  const org = useOrgPermissions();
  const roles = useOrgRoles();
  const queryClient = useQueryClient();

  const refresh = () => queryClient.invalidateQueries({ queryKey: keys.orgRoles });

  return (
    <RolesPanel
      roles={roles.data}
      loading={roles.isPending}
      error={roles.error}
      onRetry={() => void roles.refetch()}
      subjects={ORG_SUBJECTS}
      intro="Built-in roles cover common needs. Custom roles pick which organisation areas, such as projects, machine identities or the audit log, someone can see or manage."
      canCreate={org.can("org-roles", "create")}
      canEdit={org.can("org-roles", "edit")}
      canDelete={org.can("org-roles", "delete")}
      onSave={async (slug, body) => {
        const role = await api.putOrgRole(slug, body);
        await refresh();
        toast.success(`Saved ${role.name}`);
      }}
      onDelete={async (slug) => {
        try {
          await api.deleteOrgRole(slug);
        } catch (error) {
          toast.error(errorMessage(error));
          throw error;
        }
        await refresh();
        toast.success("Role deleted");
      }}
    />
  );
}

export function AccessPage() {
  const { tab } = useParams();
  if (tab && tab !== "bindings" && tab !== "roles") return <Navigate to="/org/access" replace />;
  const current = tab ?? "bindings";

  return (
    <div className="space-y-6">
      <PageHeader title="Access control" description="Organisation-wide roles for people, groups and machines." />
      <LinkTabs
        label="Access sections"
        current={current}
        tabs={[
          { value: "bindings", label: "Who has which role", to: "/org/access", testId: "access-tab-bindings" },
          { value: "roles", label: "Roles", to: "/org/access/roles", testId: "access-tab-roles" },
        ]}
      />
      <ErrorBoundary variant="section" resetKey={current}>
        {current === "bindings" ? <BindingsTab /> : <RolesTab />}
      </ErrorBoundary>
    </div>
  );
}
