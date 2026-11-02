import { useQuery } from "@tanstack/react-query";
import { Bot, Lock, Plus, Trash2, User, Users } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api } from "@/api/endpoints";
import type { Action, PrincipalKind, SecretAccess, SecretAccessChange, SecretGrant } from "@/api/types";
import { PrincipalPicker, type PrincipalOption } from "@/components/principal-picker";
import { ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { keys, useApiMutation, useProject } from "@/hooks/queries";
import { useManagesSecretAccess, useOrgPermissions } from "@/hooks/use-permissions";

interface Location {
  project: string;
  env: string;
  path: string;
}

const KIND_ICON: Record<PrincipalKind, typeof User> = { user: User, group: Users, identity: Bot };
const KIND_LABEL: Record<PrincipalKind, string> = { user: "User", group: "Group", identity: "Machine identity" };

/** What an entry can grant beyond reading the secret's name, which every entry allows. */
const EXTRA_ACTIONS: { action: Action; label: string }[] = [
  { action: "read-value", label: "Read value" },
  { action: "edit", label: "Edit" },
  { action: "delete", label: "Delete" },
];

interface AccessSectionProps {
  at: Location;
  secretKey: string;
  /** From the listing, so non-admins see the state without asking for the list. */
  restricted: boolean;
}

/** Who may reach this secret: the restricted switch and its access list for admins, a note for everyone else. */
export function AccessSection({ at, secretKey, restricted }: AccessSectionProps) {
  const manages = useManagesSecretAccess(at.project);
  if (!manages) {
    if (!restricted) return null;
    return (
      <section className="space-y-2" data-testid="access-section">
        <h3 className="text-sm font-semibold">Access</h3>
        <p className="flex items-start gap-2 text-sm text-muted-foreground" data-testid="access-restricted-note">
          <Lock className="mt-0.5 size-4 shrink-0" aria-hidden />
          Restricted: only those on its access list, and admins, can reach this secret.
        </p>
      </section>
    );
  }
  return <ManagedAccess at={at} secretKey={secretKey} />;
}

function ManagedAccess({ at, secretKey }: { at: Location; secretKey: string }) {
  const project = useProject(at.project);
  const enabled = project.data?.secret_access === true;
  const access = useQuery({
    queryKey: keys.secretAccess(at.project, at.env, at.path, secretKey),
    queryFn: () => api.secretAccess(at, secretKey),
  });
  const change = useApiMutation({
    mutationFn: (body: SecretAccessChange) => api.changeSecretAccess(at, secretKey, body),
    invalidate: [
      keys.secretAccess(at.project, at.env, at.path, secretKey),
      ["project", at.project, "secrets"],
      keys.secretAccessSetting(at.project),
    ],
  });

  return (
    <section className="space-y-3" data-testid="access-section">
      <h3 className="text-sm font-semibold">Access</h3>
      {access.isPending && <ListSkeleton rows={2} />}
      {access.error && <ErrorState error={access.error} onRetry={() => void access.refetch()} />}
      {access.data && (
        <div className="space-y-4 rounded-lg border bg-card p-3">
          <Field orientation="horizontal">
            <Switch
              id="access-restricted"
              checked={access.data.restricted}
              // Unrestricting always works, so a project can be cleaned up before the setting goes off.
              disabled={change.isPending || (!access.data.restricted && !enabled)}
              onCheckedChange={(restricted) => change.mutate({ restricted })}
              data-testid="access-restricted"
            />
            <FieldLabel htmlFor="access-restricted" className="font-normal">
              Restricted to its access list
            </FieldLabel>
          </Field>
          <p className="text-sm text-muted-foreground" data-testid="access-summary">
            {access.data.restricted
              ? "Only the principals below, project admins and organisation admins can reach it, and only as far as their roles allow."
              : enabled
                ? "Open: roles alone decide who can reach it. The list below has no effect until it is restricted."
                : "Open: roles alone decide who can reach it."}
          </p>
          {!enabled && !access.data.restricted && (
            <p className="text-sm text-muted-foreground" data-testid="access-off">
              Per-secret access is off for this project. Turn it on in the{" "}
              <Link className="underline underline-offset-2" to={`/projects/${at.project}/settings/general`}>
                project settings
              </Link>{" "}
              to restrict secrets.
            </p>
          )}
          <GrantList access={access.data} enabled={enabled} busy={change.isPending} onChange={(body) => change.mutateAsync(body)} />
          {enabled && <AddGrant busy={change.isPending} onAdd={(body) => change.mutateAsync(body)} />}
        </div>
      )}
    </section>
  );
}

function GrantList({
  access,
  enabled,
  busy,
  onChange,
}: {
  access: SecretAccess;
  enabled: boolean;
  busy: boolean;
  onChange: (body: SecretAccessChange) => Promise<unknown>;
}) {
  if (access.grants.length === 0) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="access-empty">
        {access.restricted ? "No one is on the list yet, so only admins can reach it." : "No one is on the list."}
      </p>
    );
  }
  return (
    <ul className="divide-y rounded-md border" data-testid="access-grants">
      {access.grants.map((g) => (
        <GrantRow key={`${g.principal_kind}:${g.principal_id}`} grant={g} enabled={enabled} busy={busy} onChange={onChange} />
      ))}
    </ul>
  );
}

function GrantRow({
  grant,
  enabled,
  busy,
  onChange,
}: {
  grant: SecretGrant;
  enabled: boolean;
  busy: boolean;
  onChange: (body: SecretAccessChange) => Promise<unknown>;
}) {
  const Icon = KIND_ICON[grant.principal_kind];
  const principal = { principal_kind: grant.principal_kind, principal_id: grant.principal_id };
  const id = `${grant.principal_kind}-${grant.principal_id}`.replace(/[^A-Za-z0-9_-]/g, "_");
  const toggle = (action: Action, on: boolean) => {
    const actions = on ? [...grant.actions, action] : grant.actions.filter((a) => a !== action);
    void onChange({ grant: [{ ...principal, actions }] }).catch(() => undefined);
  };
  return (
    <li className="space-y-2 p-3" data-testid={`access-grant-${grant.principal_name}`}>
      <div className="flex items-center gap-2">
        <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <span className="min-w-0 flex-1 truncate text-sm font-medium" title={grant.principal_id}>
          {grant.principal_name}
        </span>
        <Badge variant="secondary" className="shrink-0 text-[0.7rem]">
          {KIND_LABEL[grant.principal_kind]}
        </Badge>
        <Button
          variant="ghost"
          size="icon-sm"
          disabled={busy}
          aria-label={`Remove ${grant.principal_name} from the access list`}
          onClick={() => void onChange({ revoke: [principal] }).catch(() => undefined)}
          data-testid={`access-revoke-${grant.principal_name}`}
        >
          <Trash2 />
        </Button>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-2 pl-6 text-sm">
        <span className="text-muted-foreground">Read name</span>
        {EXTRA_ACTIONS.map(({ action, label }) => (
          <div key={action} className="flex items-center gap-1.5">
            <Checkbox
              id={`${id}-${action}`}
              checked={grant.actions.includes(action)}
              disabled={busy || !enabled}
              onCheckedChange={(on) => toggle(action, on === true)}
              data-testid={`access-action-${grant.principal_name}-${action}`}
            />
            <Label htmlFor={`${id}-${action}`} className="font-normal">
              {label}
            </Label>
          </div>
        ))}
      </div>
    </li>
  );
}

function AddGrant({ busy, onAdd }: { busy: boolean; onAdd: (body: SecretAccessChange) => Promise<unknown> }) {
  const org = useOrgPermissions();
  const [kind, setKind] = useState<PrincipalKind>("identity");
  const [group, setGroup] = useState("");
  const [chosen, setChosen] = useState<PrincipalOption>();
  const [actions, setActions] = useState<Action[]>(["read", "read-value"]);
  const principal = kind === "group" ? group.trim() : (chosen?.id ?? "");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!principal) return;
    try {
      await onAdd({ grant: [{ principal_kind: kind, principal_id: principal, actions }] });
      setGroup("");
      setChosen(undefined);
    } catch {
      // The mutation has already shown why.
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-3 border-t pt-3" data-testid="access-add">
      <p className="text-sm font-medium">Add to the list</p>
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
        aria-label="Kind of principal"
        data-testid="access-kind"
      >
        {(["identity", "user", "group"] as const).map((k) => {
          const Icon = KIND_ICON[k];
          return (
            <ToggleGroupItem key={k} value={k} className="flex-auto max-sm:[&_svg]:hidden" data-testid={`access-kind-${k}`}>
              <Icon /> {KIND_LABEL[k]}
            </ToggleGroupItem>
          );
        })}
      </ToggleGroup>
      {kind === "group" ? (
        <Field>
          <FieldLabel htmlFor="access-group">Group name</FieldLabel>
          <Input
            id="access-group"
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            placeholder="engineering"
            data-testid="access-group"
          />
        </Field>
      ) : (
        <Field>
          <FieldLabel htmlFor="access-principal">{KIND_LABEL[kind]}</FieldLabel>
          <PrincipalPicker
            key={kind}
            kind={kind}
            selected={chosen}
            onSelect={setChosen}
            canList={org.can(kind === "user" ? "org-members" : "identities", "read")}
            id="access-principal"
            testId="access-principal"
          />
        </Field>
      )}
      <fieldset className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
        <legend className="sr-only">Allowed actions</legend>
        <span className="text-muted-foreground">Read name</span>
        {EXTRA_ACTIONS.map(({ action, label }) => (
          <div key={action} className="flex items-center gap-1.5">
            <Checkbox
              id={`access-new-${action}`}
              checked={actions.includes(action)}
              onCheckedChange={(on) =>
                setActions(on === true ? [...actions, action] : actions.filter((a) => a !== action))
              }
              data-testid={`access-new-${action}`}
            />
            <Label htmlFor={`access-new-${action}`} className="font-normal">
              {label}
            </Label>
          </div>
        ))}
      </fieldset>
      <p className="text-xs text-muted-foreground">
        A list only narrows what roles allow. Someone whose role cannot edit still cannot edit, whatever the list says.
      </p>
      <div className="flex justify-end">
        <Button type="submit" size="sm" disabled={!principal || busy} data-testid="access-add-submit">
          {busy ? <Spinner /> : <Plus />}
          Add
        </Button>
      </div>
    </form>
  );
}
