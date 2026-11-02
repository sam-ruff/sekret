import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Bot, Save, ShieldOff, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router";
import { api } from "@/api/endpoints";
import type { Identity } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { AuthMethods } from "@/components/identities/auth-methods";
import { IdentityFields } from "@/components/identities/identity-fields";
import { ttlProblem, type IdentityDraft } from "@/components/identities/identity-model";
import { LinkTabs } from "@/components/link-tabs";
import { ProjectAccess } from "@/components/identities/project-access";
import { UsageSnippets } from "@/components/identities/usage-snippets";
import { PageHeader } from "@/components/page-header";
import { ErrorBoundary } from "@/components/error-boundary";
import { ErrorState, ListSkeleton, MissingState } from "@/components/states";
import { isNotFound } from "@/lib/errors";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldLabel } from "@/components/ui/field";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { keys, useApiMutation } from "@/hooks/queries";
import { usePageTitle } from "@/hooks/use-page-title";
import { useOrgPermissions } from "@/hooks/use-permissions";
import { durationText, formatDateTime, parseDuration } from "@/lib/format";

const TABS = ["details", "auth", "usage"] as const;
type Tab = (typeof TABS)[number];

function draftFrom(identity: Identity): IdentityDraft {
  return {
    name: identity.name,
    description: identity.description,
    tokenTtl: durationText(identity.token_ttl),
    tokenMaxTtl: durationText(identity.token_max_ttl),
    trustedCidrs: identity.trusted_cidrs,
  };
}

function DetailsTab({ identity, canEdit, canDelete }: { identity: Identity; canEdit: boolean; canDelete: boolean }) {
  const navigate = useNavigate();
  const [draft, setDraft] = useState<IdentityDraft>(() => draftFrom(identity));
  const [disabled, setDisabled] = useState(identity.disabled);
  const [revoking, setRevoking] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const invalidate = [keys.identity(identity.id), keys.identities];

  const save = useApiMutation({
    mutationFn: () =>
      api.updateIdentity(identity.id, {
        name: draft.name.trim(),
        description: draft.description,
        token_ttl: parseDuration(draft.tokenTtl) ?? 0,
        token_max_ttl: parseDuration(draft.tokenMaxTtl) ?? 0,
        trusted_cidrs: draft.trustedCidrs,
        disabled,
      }),
    invalidate,
    success: "Identity saved",
  });
  const revoke = useApiMutation({
    mutationFn: () => api.revokeIdentityTokens(identity.id),
    success: "All tokens for this identity were revoked",
  });
  const remove = useApiMutation({
    mutationFn: () => api.deleteIdentity(identity.id),
    invalidate: [keys.identities],
    success: `Deleted ${identity.name}`,
    onSuccess: () => navigate("/org/identities"),
  });

  const valid = draft.name.trim() !== "" && !ttlProblem(draft);
  // Lifetimes compare as seconds, so "1800" and "30m" count as the same.
  const comparable = (d: IdentityDraft) =>
    JSON.stringify({ ...d, tokenTtl: parseDuration(d.tokenTtl), tokenMaxTtl: parseDuration(d.tokenMaxTtl) });
  const changed = disabled !== identity.disabled || comparable(draft) !== comparable(draftFrom(identity));
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid && changed) save.mutate();
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
          <CardDescription>Created {formatDateTime(identity.created_at)}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-6" data-testid="identity-details-form">
            <fieldset disabled={!canEdit} className="space-y-6">
              <IdentityFields draft={draft} onChange={setDraft} idPrefix="identity" />
              <Field orientation="horizontal">
                <Switch id="identity-disabled" checked={disabled} onCheckedChange={setDisabled} data-testid="identity-disabled" />
                <FieldLabel htmlFor="identity-disabled" className="font-normal">
                  Disable sign-ins for this identity
                </FieldLabel>
              </Field>
            </fieldset>
            {canEdit && (
              <div className="flex justify-end">
                <Button type="submit" disabled={!valid || !changed || save.isPending} data-testid="identity-save">
                  {save.isPending ? <Spinner /> : <Save />}
                  Save changes
                </Button>
              </div>
            )}
          </form>
        </CardContent>
      </Card>
      {(canEdit || canDelete) && (
        <Card className="ring-destructive/30">
          <CardHeader>
            <CardTitle>Danger zone</CardTitle>
            <CardDescription>These actions take effect immediately.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {canEdit && (
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="text-sm font-medium">Revoke all tokens</div>
                  <p className="text-sm text-muted-foreground">Every token issued to this identity stops working.</p>
                </div>
                <Button variant="outline" onClick={() => setRevoking(true)} data-testid="revoke-tokens">
                  <ShieldOff />
                  Revoke tokens
                </Button>
              </div>
            )}
            {canDelete && (
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="text-sm font-medium">Delete identity</div>
                  <p className="text-sm text-muted-foreground">Removes its auth methods, client secrets and memberships.</p>
                </div>
                <Button variant="destructive" onClick={() => setDeleting(true)} data-testid="identity-delete">
                  <Trash2 />
                  Delete identity
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}
      <ConfirmDialog
        open={revoking}
        onOpenChange={setRevoking}
        title="Revoke every token?"
        description="Machines using this identity must log in again. Their auth methods are not changed."
        confirmLabel="Revoke tokens"
        destructive
        onConfirm={() => revoke.mutateAsync()}
      />
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${identity.name}?`}
        description="This cannot be undone. Machines using it lose access straight away."
        confirmLabel="Delete identity"
        destructive
        onConfirm={() => remove.mutateAsync()}
      />
    </div>
  );
}

function MissingIdentity() {
  usePageTitle("Identity not found");
  return (
    <MissingState
      title="Identity not found"
      description="There is no machine identity at this address. It may have been deleted."
      backTo="/org/identities"
      backLabel="Back to machine identities"
      testId="identity-missing"
    />
  );
}

export function IdentityPage() {
  const { id = "", tab } = useParams();
  const org = useOrgPermissions();
  const identity = useQuery({ queryKey: keys.identity(id), queryFn: () => api.identity(id) });

  if (tab && !TABS.includes(tab as Tab)) return <Navigate to={`/org/identities/${id}`} replace />;
  const current: Tab = (tab as Tab | undefined) ?? "details";
  const canEdit = org.can("identities", "edit");
  const canDelete = org.can("identities", "delete");

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm" className="-ml-2">
        <Link to="/org/identities">
          <ArrowLeft />
          Machine identities
        </Link>
      </Button>
      {isNotFound(identity.error) && <MissingIdentity />}
      {identity.error && !isNotFound(identity.error) && (
        <ErrorState error={identity.error} onRetry={() => void identity.refetch()} />
      )}
      {identity.isPending && <ListSkeleton rows={3} />}
      {identity.data && (
        <>
          <PageHeader
            documentTitle={identity.data.name}
            title={
              <span className="flex items-center gap-2">
                <Bot className="size-6 shrink-0 text-primary" />
                <span className="truncate">{identity.data.name}</span>
                {identity.data.disabled && <Badge variant="destructive">Disabled</Badge>}
              </span>
            }
            description={identity.data.description || undefined}
          />
          <LinkTabs
            label="Identity sections"
            current={current}
            tabs={[
              { value: "details", label: "Details", to: `/org/identities/${id}`, testId: "identity-tab-details" },
              { value: "auth", label: "Auth methods", to: `/org/identities/${id}/auth`, testId: "identity-tab-auth" },
              { value: "usage", label: "Access and usage", to: `/org/identities/${id}/usage`, testId: "identity-tab-usage" },
            ]}
          />
          <ErrorBoundary variant="section" resetKey={current}>
            {current === "details" && (
              <DetailsTab key={JSON.stringify(identity.data)} identity={identity.data} canEdit={canEdit} canDelete={canDelete} />
            )}
            {current === "auth" && <AuthMethods identityId={id} canEdit={canEdit} />}
            {current === "usage" && (
              <div className="space-y-6">
                <ProjectAccess identity={identity.data} />
                <UsageSnippets identity={identity.data} />
              </div>
            )}
          </ErrorBoundary>
        </>
      )}
    </div>
  );
}
