import { useQuery } from "@tanstack/react-query";
import { KeyRound, Plus, ShieldAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api } from "@/api/endpoints";
import type { ClientSecret, CreatedClientSecret } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { CopyButton } from "@/components/copy-button";
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
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { keys, useApiMutation } from "@/hooks/queries";
import { formatDateTime, formatDuration, formatRelative } from "@/lib/format";

function positiveOrNull(text: string): number | null | "invalid" {
  if (!text.trim()) return null;
  const n = Number(text);
  return Number.isInteger(n) && n > 0 ? n : "invalid";
}

function CreateSecretDialog({
  identityId,
  open,
  onOpenChange,
  onCreated,
}: {
  identityId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (created: CreatedClientSecret) => void;
}) {
  const [description, setDescription] = useState("");
  const [ttl, setTtl] = useState("");
  const [maxUses, setMaxUses] = useState("");
  const ttlValue = positiveOrNull(ttl);
  const usesValue = positiveOrNull(maxUses);
  const valid = ttlValue !== "invalid" && usesValue !== "invalid";

  const create = useApiMutation({
    mutationFn: () =>
      api.createClientSecret(identityId, {
        description,
        ttl: ttlValue === "invalid" ? null : ttlValue,
        max_uses: usesValue === "invalid" ? null : usesValue,
      }),
    invalidate: [keys.clientSecrets(identityId)],
    onSuccess: (created) => {
      setDescription("");
      setTtl("");
      setMaxUses("");
      onOpenChange(false);
      onCreated(created);
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid) create.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" data-testid="create-client-secret-dialog">
        <form onSubmit={submit} className="space-y-6">
          <DialogHeader>
            <DialogTitle>New client secret</DialogTitle>
            <DialogDescription>Machines exchange the client id and this secret for a short-lived token.</DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel htmlFor="cs-description">Description</FieldLabel>
            <Input
              id="cs-description"
              value={description}
              placeholder="Where this secret is used"
              onChange={(e) => setDescription(e.target.value)}
              data-testid="client-secret-description"
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor="cs-ttl">Expires after (seconds)</FieldLabel>
              <Input
                id="cs-ttl"
                inputMode="numeric"
                value={ttl}
                placeholder="Never"
                aria-invalid={ttlValue === "invalid"}
                onChange={(e) => setTtl(e.target.value.trim())}
                data-testid="client-secret-ttl"
              />
              <FieldDescription>
                {typeof ttlValue === "number" ? formatDuration(ttlValue) : "Leave empty for no expiry"}
              </FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="cs-uses">Max uses</FieldLabel>
              <Input
                id="cs-uses"
                inputMode="numeric"
                value={maxUses}
                placeholder="Unlimited"
                aria-invalid={usesValue === "invalid"}
                onChange={(e) => setMaxUses(e.target.value.trim())}
                data-testid="client-secret-max-uses"
              />
            </Field>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!valid || create.isPending} data-testid="client-secret-create">
              {create.isPending && <Spinner />}
              Create secret
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function CreatedSecretDialog({ created, onClose }: { created: CreatedClientSecret | null; onClose: () => void }) {
  return (
    <Dialog open={created !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg" data-testid="client-secret-once-dialog">
        <DialogHeader>
          <DialogTitle>Client secret created</DialogTitle>
          <DialogDescription>Store it somewhere safe, such as your CI provider's secret store.</DialogDescription>
        </DialogHeader>
        <Alert className="border-warning/50 bg-warning/10">
          <ShieldAlert className="text-warning" />
          <AlertTitle>You will not see this secret again</AlertTitle>
          <AlertDescription>Only a hash is kept. If you lose it, create a new one and revoke this one.</AlertDescription>
        </Alert>
        {created && (
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label>Client id</Label>
              <div className="flex items-center gap-1 rounded-md border bg-muted/50 py-1 pr-1 pl-3">
                <code className="min-w-0 flex-1 truncate font-mono text-sm" data-testid="client-id-value">
                  {created.client_id}
                </code>
                <CopyButton value={created.client_id} label="Copy client id" testId="client-id-copy" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>Client secret</Label>
              <div className="flex items-center gap-1 rounded-md border bg-muted/50 py-1 pr-1 pl-3">
                <code className="min-w-0 flex-1 font-mono text-sm break-all" data-testid="client-secret-value">
                  {created.client_secret}
                </code>
                <CopyButton
                  value={created.client_secret}
                  label="Copy client secret"
                  testId="client-secret-copy"
                  sensitive
                />
              </div>
            </div>
          </div>
        )}
        <DialogFooter>
          <Button onClick={onClose} data-testid="client-secret-done">
            I have stored it
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ClientSecrets({ identityId, canEdit }: { identityId: string; canEdit: boolean }) {
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedClientSecret | null>(null);
  const [revoking, setRevoking] = useState<ClientSecret | null>(null);
  const list = useQuery({ queryKey: keys.clientSecrets(identityId), queryFn: () => api.clientSecrets(identityId) });

  const revoke = useApiMutation({
    mutationFn: (secretId: string) => api.revokeClientSecret(identityId, secretId),
    invalidate: [keys.clientSecrets(identityId)],
    success: "Client secret revoked",
  });

  return (
    <div className="space-y-3" data-testid="client-secrets">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-semibold">Client secrets</h4>
        {canEdit && (
          <Button size="sm" onClick={() => setCreating(true)} data-testid="new-client-secret">
            <Plus />
            New client secret
          </Button>
        )}
      </div>
      {list.error && <ErrorState error={list.error} onRetry={() => void list.refetch()} />}
      {list.isPending && <ListSkeleton rows={2} />}
      {list.data && list.data.length === 0 && (
        <EmptyState icon={<KeyRound />} title="No client secrets" description="Create one to log in with universal auth." />
      )}
      {list.data && list.data.length > 0 && (
        <ResponsiveTable
          rows={list.data}
          rowKey={(s) => s.id}
          rowTestId={(s) => `client-secret-row-${s.id}`}
          columns={[
            {
              header: "Secret",
              primary: true,
              cell: (s) => (
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <code className="font-mono text-sm">{s.prefix}...</code>
                    {s.revoked && <Badge variant="destructive">Revoked</Badge>}
                  </div>
                  <div className="truncate text-xs text-muted-foreground">{s.description || "No description"}</div>
                </div>
              ),
            },
            {
              header: "Created",
              cell: (s) => (
                <span className="text-muted-foreground" title={formatDateTime(s.created_at)}>
                  {formatRelative(s.created_at)}
                </span>
              ),
            },
            {
              header: "Expires",
              cell: (s) => (
                <span className="text-muted-foreground">{s.expires_at ? formatDateTime(s.expires_at) : "Never"}</span>
              ),
            },
            {
              header: "Uses left",
              cell: (s) => <span className="text-muted-foreground">{s.uses_remaining ?? "Unlimited"}</span>,
            },
            {
              header: "Last used",
              cell: (s) => (
                <span className="text-muted-foreground">{s.last_used_at ? formatRelative(s.last_used_at) : "Never"}</span>
              ),
            },
            {
              header: "",
              actions: true,
              className: "md:w-24",
              cell: (s) =>
                canEdit &&
                !s.revoked && (
                  <Button variant="outline" size="sm" onClick={() => setRevoking(s)} data-testid="client-secret-revoke">
                    Revoke
                  </Button>
                ),
            },
          ]}
        />
      )}
      <CreateSecretDialog identityId={identityId} open={creating} onOpenChange={setCreating} onCreated={setCreated} />
      <CreatedSecretDialog created={created} onClose={() => setCreated(null)} />
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={`Revoke ${revoking?.prefix}...?`}
        description="Machines using this secret can no longer log in. Tokens they already hold keep working until they expire."
        confirmLabel="Revoke secret"
        destructive
        onConfirm={() => revoke.mutateAsync(revoking?.id ?? "")}
      />
    </div>
  );
}
