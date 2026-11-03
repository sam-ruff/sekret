import { useQuery } from "@tanstack/react-query";
import { Bot, Lock, Plus, Trash2, User, Users } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type RefObject } from "react";
import { Link } from "react-router";
import { api } from "@/api/endpoints";
import type { Action, PrincipalKind, SecretAccess, SecretAccessChange, SecretGrant } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
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

/** What an entry can allow beyond seeing the secret exists, which every entry allows. */
const EXTRA_ACTIONS: { action: Action; label: string }[] = [
  { action: "read-value", label: "Read value" },
  { action: "edit", label: "Edit" },
  { action: "delete", label: "Delete" },
];

/** Names shown in a confirmation before the rest are counted. */
const NAMED_IN_CONFIRM = 3;

/** The first few names, then how many more. */
function namesWithMore(names: string[]): string {
  if (names.length <= NAMED_IN_CONFIRM) return names.join(", ");
  const rest = names.length - NAMED_IN_CONFIRM;
  return `${names.slice(0, NAMED_IN_CONFIRM).join(", ")} and ${rest} more`;
}

const entryId = (g: Pick<SecretGrant, "principal_kind" | "principal_id">) => `${g.principal_kind}:${g.principal_id}`;

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

/** A change to the list, with what to say once it is saved. */
interface Change {
  body: SecretAccessChange;
  message: string;
}

function ManagedAccess({ at, secretKey }: { at: Location; secretKey: string }) {
  const project = useProject(at.project);
  const enabled = project.data?.secret_access === true;
  const access = useQuery({
    queryKey: keys.secretAccess(at.project, at.env, at.path, secretKey),
    queryFn: () => api.secretAccess(at, secretKey),
  });
  const [announced, setAnnounced] = useState("");
  const change = useApiMutation({
    mutationFn: ({ body }: Change) => api.changeSecretAccess(at, secretKey, body),
    invalidate: [
      keys.secretAccess(at.project, at.env, at.path, secretKey),
      ["project", at.project, "secrets"],
      keys.secretAccessSetting(at.project),
    ],
    success: (_, { message }) => message,
    onSuccess: (_, { message }) => setAnnounced(message),
  });
  const save = (next: Change) => change.mutateAsync(next).then(() => undefined);
  const section = useRef<HTMLElement>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const listed = access.data?.grants ?? [];
  const busy = change.isPending;

  const setRestricted = (restricted: boolean) => {
    if (busy) return;
    // Opening a secret exposes it, and clears its list, so it is always confirmed.
    if (!restricted) {
      setConfirmOpen(true);
      return;
    }
    change.mutate({ body: { restricted: true }, message: `Restricted ${secretKey}` });
  };

  const off = !enabled && access.data?.restricted === false;

  return (
    <section ref={section} className="space-y-3" data-testid="access-section">
      <h3 className="text-sm font-semibold" tabIndex={-1} data-focus="access-heading">
        Access
      </h3>
      {/* Says each saved change again for screen readers, as the toast may be missed. */}
      <p className="sr-only" role="status" data-testid="access-announce">
        {announced}
      </p>
      {access.isPending && <ListSkeleton rows={2} />}
      {access.error && <ErrorState error={access.error} onRetry={() => void access.refetch()} />}
      {access.data && off && listed.length === 0 && (
        <p className="text-sm text-muted-foreground" data-testid="access-off">
          Per-secret access is off for this project, so roles alone decide who can reach this secret. Turn it on in the{" "}
          <Link className="underline underline-offset-2" to={`/projects/${at.project}/settings/general`}>
            project settings
          </Link>{" "}
          to restrict secrets.
        </p>
      )}
      {access.data && !(off && listed.length === 0) && (
        <div className="space-y-4 rounded-lg border bg-card p-3">
          <Field orientation="horizontal">
            <Switch
              id="access-restricted"
              checked={access.data.restricted}
              // Unrestricting always works, so a project can be cleaned up before the setting goes off.
              disabled={!access.data.restricted && !enabled}
              aria-disabled={busy || undefined}
              onCheckedChange={setRestricted}
              data-testid="access-restricted"
            />
            <FieldLabel htmlFor="access-restricted" className="font-normal">
              Restricted to its access list
            </FieldLabel>
          </Field>
          <p className="text-sm text-muted-foreground" data-testid="access-summary">
            {access.data.restricted
              ? "Only the people, groups and machine identities below, project admins and organisation admins can reach it, and only as far as their roles allow."
              : "Open: roles alone decide who can reach it. Anyone added below only counts once it is restricted."}
          </p>
          <ConfirmDialog
            open={confirmOpen}
            onOpenChange={setConfirmOpen}
            title={`Open ${secretKey} to everyone its roles allow?`}
            description={
              listed.length === 0 ? (
                <>Everyone whose role allows it can read {secretKey} again.</>
              ) : (
                <>
                  Everyone whose role allows it can read {secretKey} again, and its access list is cleared:{" "}
                  {namesWithMore(listed.map((g) => g.principal_name))} {listed.length === 1 ? "is" : "are"} removed.
                  Restricting it again starts with an empty list.
                </>
              )
            }
            confirmLabel="Unrestrict"
            destructive
            onConfirm={() => save({ body: { restricted: false }, message: `Opened ${secretKey} to everyone its roles allow` })}
            testId="access-unrestrict-confirm"
          />
          {off && (
            <p className="text-sm text-muted-foreground" data-testid="access-off">
              Per-secret access is off for this project. Turn it on in the{" "}
              <Link className="underline underline-offset-2" to={`/projects/${at.project}/settings/general`}>
                project settings
              </Link>{" "}
              to restrict secrets.
            </p>
          )}
          <GrantList access={access.data} enabled={enabled} busy={busy} section={section} onChange={save} />
          {enabled && <AddGrant busy={busy} existing={listed} onAdd={save} />}
        </div>
      )}
    </section>
  );
}

function GrantList({
  access,
  enabled,
  busy,
  section,
  onChange,
}: {
  access: SecretAccess;
  enabled: boolean;
  busy: boolean;
  section: RefObject<HTMLElement | null>;
  onChange: (change: Change) => Promise<void>;
}) {
  // After a removal, focus moves to the next entry's remove button, or on to adding.
  const focusNext = useRef<string | null>(null);
  // Runs once the list without the removed entry is on screen.
  useEffect(() => {
    const wanted = focusNext.current;
    if (wanted === null) return;
    const root = section.current;
    const target =
      root?.querySelector<HTMLElement>(`[data-focus="${CSS.escape(wanted)}"]`) ??
      root?.querySelector<HTMLElement>('[data-focus="access-add-heading"]') ??
      root?.querySelector<HTMLElement>('[data-focus="access-heading"]');
    if (!target) return;
    target.focus();
    focusNext.current = null;
  }, [access.grants, section]);

  if (access.grants.length === 0) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="access-empty">
        {access.restricted ? "No one is on the list yet, so only admins can reach it." : "No one is on the list."}
      </p>
    );
  }
  const revoke = async (index: number) => {
    const grant = access.grants[index];
    const next = access.grants[index + 1] ?? access.grants[index - 1];
    focusNext.current = next ? `revoke:${entryId(next)}` : "access-add-heading";
    try {
      await onChange({
        body: { revoke: [{ principal_kind: grant.principal_kind, principal_id: grant.principal_id }] },
        message: `Removed ${grant.principal_name}`,
      });
    } catch (error) {
      focusNext.current = null;
      throw error;
    }
  };
  return (
    <ul className="divide-y rounded-md border" data-testid="access-grants">
      {access.grants.map((g, index) => (
        <GrantRow
          key={entryId(g)}
          grant={g}
          enabled={enabled}
          busy={busy}
          onChange={onChange}
          onRevoke={() => void revoke(index).catch(() => undefined)}
        />
      ))}
    </ul>
  );
}

function GrantRow({
  grant,
  enabled,
  busy,
  onChange,
  onRevoke,
}: {
  grant: SecretGrant;
  enabled: boolean;
  busy: boolean;
  onChange: (change: Change) => Promise<void>;
  onRevoke: () => void;
}) {
  const Icon = KIND_ICON[grant.principal_kind];
  const principal = { principal_kind: grant.principal_kind, principal_id: grant.principal_id };
  const id = entryId(grant).replace(/[^A-Za-z0-9_-]/g, "_");
  const name = grant.principal_name;
  const toggle = (action: Action, on: boolean) => {
    if (busy) return;
    const actions = on ? [...grant.actions, action] : grant.actions.filter((a) => a !== action);
    void onChange({ body: { grant: [{ ...principal, actions }] }, message: `Updated what ${name} may do` }).catch(
      () => undefined,
    );
  };
  return (
    <li className="space-y-2 p-3" data-testid={`access-grant-${name}`}>
      <div className="flex items-start gap-2">
        <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
        <span className="min-w-0 flex-1 text-sm font-medium break-all" title={grant.principal_id}>
          {name}
        </span>
        <Badge variant="secondary" className="shrink-0 text-[0.7rem]">
          {KIND_LABEL[grant.principal_kind]}
        </Badge>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-disabled={busy || undefined}
          aria-label={`Remove ${name} from the access list`}
          onClick={() => {
            if (!busy) onRevoke();
          }}
          data-focus={`revoke:${entryId(grant)}`}
          data-testid={`access-revoke-${name}`}
        >
          <Trash2 />
        </Button>
      </div>
      <fieldset className="flex flex-wrap gap-x-4 gap-y-2 pl-6 text-sm">
        <legend className="sr-only">What {name} may do</legend>
        <div className="flex items-center gap-1.5">
          <Checkbox id={`${id}-read`} checked disabled aria-label={`Read name for ${name}`} />
          <Label htmlFor={`${id}-read`} className="font-normal text-muted-foreground">
            Read name
          </Label>
        </div>
        {EXTRA_ACTIONS.map(({ action, label }) => (
          <div key={action} className="flex items-center gap-1.5">
            <Checkbox
              id={`${id}-${action}`}
              checked={grant.actions.includes(action)}
              disabled={!enabled}
              aria-disabled={busy || undefined}
              aria-label={`${label} for ${name}`}
              onCheckedChange={(on) => toggle(action, on === true)}
              data-testid={`access-action-${name}-${action}`}
            />
            <Label htmlFor={`${id}-${action}`} className="font-normal">
              {label}
            </Label>
          </div>
        ))}
      </fieldset>
    </li>
  );
}

function AddGrant({
  busy,
  existing,
  onAdd,
}: {
  busy: boolean;
  existing: SecretGrant[];
  onAdd: (change: Change) => Promise<void>;
}) {
  const org = useOrgPermissions();
  const [kind, setKind] = useState<PrincipalKind>("identity");
  const [group, setGroup] = useState("");
  const [chosen, setChosen] = useState<PrincipalOption>();
  const [actions, setActions] = useState<Action[]>(["read", "read-value"]);
  const principal = kind === "group" ? group.trim() : (chosen?.id ?? "");
  const name = kind === "group" ? group.trim() : (chosen?.label ?? "");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!principal || busy) return;
    const already = existing.some((g) => g.principal_kind === kind && g.principal_id === principal);
    try {
      await onAdd({
        body: { grant: [{ principal_kind: kind, principal_id: principal, actions }] },
        message: already ? `Updated what ${name} may do` : `Added ${name}`,
      });
      setGroup("");
      setChosen(undefined);
    } catch {
      // The mutation has already shown why.
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-3 border-t pt-3" data-testid="access-add">
      <p className="text-sm font-medium" tabIndex={-1} data-focus="access-add-heading">
        Add to the list
      </p>
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
        aria-label="Kind of entry"
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
        <legend className="sr-only">What they may do</legend>
        <div className="flex items-center gap-1.5">
          <Checkbox id="access-new-read" checked disabled />
          <Label htmlFor="access-new-read" className="font-normal text-muted-foreground">
            Read name
          </Label>
        </div>
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
        Everyone on the list can see that the secret exists. The list only narrows what roles allow: someone whose role
        cannot edit still cannot edit, whatever the list says.
      </p>
      <div className="flex justify-end">
        <Button
          type="submit"
          size="sm"
          disabled={!principal}
          aria-disabled={busy || undefined}
          data-testid="access-add-submit"
        >
          {busy ? <Spinner /> : <Plus />}
          Add
        </Button>
      </div>
    </form>
  );
}
