import { Bot, ShieldAlert, Trash2, User, UserPlus, Users } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/endpoints";
import type { Membership, PrincipalKind } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PrincipalPicker, type PrincipalOption } from "@/components/principal-picker";
import { ResponsiveTable } from "@/components/responsive-table";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { keys, useApiMutation, useRoles } from "@/hooks/queries";
import { useOrgPermissions, type Permissions } from "@/hooks/use-permissions";
import { errorMessage, isEscalation } from "@/lib/errors";
import { formatRelative } from "@/lib/format";

const KIND_ICON: Record<PrincipalKind, typeof User> = { user: User, group: Users, identity: Bot };
const KIND_LABEL: Record<PrincipalKind, string> = { user: "User", group: "Group", identity: "Machine identity" };

function AddMemberDialog({ project, onClose }: { project: string; onClose: () => void }) {
  const org = useOrgPermissions();
  const [kind, setKind] = useState<PrincipalKind>("user");
  const [group, setGroup] = useState("");
  const [chosen, setChosen] = useState<PrincipalOption>();
  const [role, setRole] = useState("developer");
  const [problem, setProblem] = useState<{ escalation: boolean; message: string }>();
  const roles = useRoles(project);
  const principal = kind === "group" ? group : (chosen?.id ?? "");

  const add = useApiMutation({
    mutationFn: () => api.addMember(project, { principal_kind: kind, principal_id: principal.trim(), role }),
    invalidate: [keys.members(project)],
    success: "Member added",
    onSuccess: onClose,
    onError: (error) => {
      setProblem({ escalation: isEscalation(error), message: errorMessage(error) });
      return true;
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setProblem(undefined);
    add.mutate();
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md" data-testid="add-member-dialog">
        <form onSubmit={submit} className="space-y-6">
          <DialogHeader>
            <DialogTitle>Add member</DialogTitle>
            <DialogDescription>Give a person, a group from your identity provider or a machine a role here.</DialogDescription>
          </DialogHeader>
          <FieldGroup>
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
                data-testid="member-kind"
              >
                {(["user", "group", "identity"] as const).map((k) => {
                  const Icon = KIND_ICON[k];
                  return (
                    <ToggleGroupItem key={k} value={k} className="flex-1" data-testid={`member-kind-${k}`}>
                      <Icon /> {k === "identity" ? "Machine" : KIND_LABEL[k]}
                    </ToggleGroupItem>
                  );
                })}
              </ToggleGroup>
            </Field>
            {kind === "group" ? (
              <Field>
                <FieldLabel htmlFor="member-group">Group name</FieldLabel>
                <Input
                  id="member-group"
                  value={group}
                  onChange={(e) => setGroup(e.target.value)}
                  placeholder="engineering"
                  data-testid="member-group"
                />
                <FieldDescription>Must match a group claim from your identity provider exactly.</FieldDescription>
              </Field>
            ) : (
              <Field>
                <FieldLabel htmlFor="member-principal">{kind === "user" ? "User" : "Machine identity"}</FieldLabel>
                <PrincipalPicker
                  key={kind}
                  kind={kind}
                  selected={chosen}
                  onSelect={setChosen}
                  canList={org.can(kind === "user" ? "org-members" : "identities", "read")}
                  id="member-principal"
                  testId="member-principal"
                />
                {kind === "user" && <FieldDescription>People appear here after their first sign-in.</FieldDescription>}
              </Field>
            )}
            <Field>
              <FieldLabel htmlFor="member-role">Role</FieldLabel>
              <Select value={role} onValueChange={setRole}>
                <SelectTrigger id="member-role" className="w-full" data-testid="member-role">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(roles.data ?? []).map((r) => (
                    <SelectItem key={r.slug} value={r.slug}>
                      <span className="first-letter:uppercase">{r.name}</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          </FieldGroup>
          {problem && (
            <Alert variant="destructive" data-testid={problem.escalation ? "member-escalation" : "member-error"}>
              <ShieldAlert />
              <AlertTitle>{problem.escalation ? "That role has more access than you" : "The member was not added"}</AlertTitle>
              <AlertDescription>
                {problem.message}.{problem.escalation && " Choose a narrower role or ask a project admin."}
              </AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!principal.trim() || !role || add.isPending} data-testid="member-add-submit">
              {add.isPending && <Spinner />}
              Add member
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function MembersSection({ project, perms }: { project: string; perms: Permissions }) {
  const members = useQuery({ queryKey: keys.members(project), queryFn: () => api.members(project) });
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Membership | null>(null);

  const remove = useApiMutation({
    mutationFn: (m: Membership) => api.removeMember(project, m.principal_kind, m.principal_id, m.role),
    invalidate: [keys.members(project), keys.permissions(project)],
    success: (_, m) => `Removed ${m.principal_name}`,
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-muted-foreground">Organisation admins can always manage this project.</p>
        {perms.can("members", "create") && (
          <Button onClick={() => setAdding(true)} data-testid="add-member">
            <UserPlus />
            Add member
          </Button>
        )}
      </div>
      {members.error && <ErrorState error={members.error} onRetry={() => void members.refetch()} />}
      {members.isPending && <ListSkeleton rows={3} />}
      {members.isSuccess && members.data.length === 0 && <EmptyState icon={<Users />} title="No members yet" />}
      {members.data && members.data.length > 0 && (
        <ResponsiveTable
          rows={members.data}
          rowKey={(m) => `${m.principal_kind}:${m.principal_id}:${m.role}`}
          rowTestId={(m) => `member-row-${m.principal_name}`}
          columns={[
            {
              header: "Member",
              primary: true,
              cell: (m) => {
                const Icon = KIND_ICON[m.principal_kind];
                return (
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-muted">
                      <Icon className="size-4 text-muted-foreground" />
                    </div>
                    <div className="min-w-0">
                      <div className="truncate font-medium">{m.principal_name}</div>
                      <div className="text-xs text-muted-foreground">{KIND_LABEL[m.principal_kind]}</div>
                    </div>
                  </div>
                );
              },
            },
            {
              header: "Role",
              cell: (m) => (
                <Badge variant="secondary" className="font-mono">
                  {m.role}
                </Badge>
              ),
            },
            {
              header: "Added",
              cell: (m) => <span className="text-xs text-muted-foreground">{formatRelative(m.created_at)}</span>,
            },
            {
              header: "",
              actions: true,
              className: "md:w-12",
              cell: (m) =>
                perms.can("members", "delete") && (
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    onClick={() => setRemoving(m)}
                    aria-label={`Remove ${m.principal_name}`}
                    data-testid="member-remove"
                  >
                    <Trash2 />
                  </Button>
                ),
            },
          ]}
        />
      )}
      {adding && <AddMemberDialog project={project} onClose={() => setAdding(false)} />}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={`Remove ${removing?.principal_name}?`}
        description={`They lose the ${removing?.role} role in this project. Other roles they hold are unaffected.`}
        confirmLabel="Remove"
        destructive
        onConfirm={() => remove.mutateAsync(removing as Membership)}
      />
    </div>
  );
}
