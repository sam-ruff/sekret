import { useQuery } from "@tanstack/react-query";
import { Boxes, CheckCircle2, Circle, KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { api } from "@/api/endpoints";
import type { AuthMethodConfig, AuthMethodKind } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ErrorState, ListSkeleton } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { keys, useApiMutation } from "@/hooks/queries";
import { ClientSecrets } from "./client-secrets";
import { KubernetesForm } from "./kubernetes-form";
import { OidcForm } from "./oidc-form";

const LABELS: Record<AuthMethodKind, string> = {
  oidc: "OIDC",
  kubernetes: "Kubernetes",
  universal: "Universal auth",
};

function MethodCard({
  kind,
  icon,
  description,
  configured,
  canEdit,
  onRemove,
  children,
}: {
  kind: AuthMethodKind;
  icon: ReactNode;
  description: string;
  configured: boolean;
  canEdit: boolean;
  onRemove: () => void;
  children: ReactNode;
}) {
  return (
    <Card data-testid={`auth-method-${kind}`}>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/12 text-primary">{icon}</div>
          <div className="min-w-0 space-y-1">
            <CardTitle className="flex flex-wrap items-center gap-2">
              {LABELS[kind]}
              {configured ? (
                <Badge className="bg-success/15 text-success" data-testid={`auth-method-${kind}-status`}>
                  <CheckCircle2 /> Configured
                </Badge>
              ) : (
                <Badge variant="outline" data-testid={`auth-method-${kind}-status`}>
                  <Circle /> Not configured
                </Badge>
              )}
            </CardTitle>
            <CardDescription>{description}</CardDescription>
          </div>
        </div>
        {configured && canEdit && (
          <Button variant="ghost" size="sm" onClick={onRemove} data-testid={`auth-method-${kind}-remove`}>
            <Trash2 />
            Remove
          </Button>
        )}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

export function AuthMethods({ identityId, canEdit }: { identityId: string; canEdit: boolean }) {
  const [removing, setRemoving] = useState<AuthMethodKind | null>(null);
  // The reviewer token reads back redacted, so a replaced token leaves the config unchanged; remount on each save.
  const [kubernetesSaves, setKubernetesSaves] = useState(0);
  const methods = useQuery({ queryKey: keys.authMethods(identityId), queryFn: () => api.authMethods(identityId) });
  const invalidate = [keys.authMethods(identityId), keys.identity(identityId), keys.identities];

  const put = useApiMutation({
    mutationFn: (config: AuthMethodConfig) => api.putAuthMethod(identityId, config),
    invalidate,
    success: (_, config) => `${LABELS[config.kind]} saved`,
    onSuccess: (_, config) => {
      if (config.kind === "kubernetes") setKubernetesSaves((n) => n + 1);
      // The finished mutation still holds the reviewer token as its variables.
      put.reset();
    },
  });
  const remove = useApiMutation({
    mutationFn: (kind: AuthMethodKind) => api.deleteAuthMethod(identityId, kind),
    invalidate,
    success: (_, kind) => `${LABELS[kind]} removed`,
  });

  if (methods.error) return <ErrorState error={methods.error} onRetry={() => void methods.refetch()} />;
  if (methods.isPending) return <ListSkeleton rows={3} />;

  const find = <K extends AuthMethodKind>(kind: K) =>
    methods.data.find((m): m is Extract<AuthMethodConfig, { kind: K }> => m.kind === kind);
  const oidc = find("oidc");
  const kubernetes = find("kubernetes");
  const universal = find("universal");
  const pendingKind = put.isPending ? put.variables?.kind : undefined;

  return (
    <div className="space-y-4">
      <MethodCard
        kind="oidc"
        icon={<ShieldCheck className="size-4" />}
        description="Log in with a JWT from an OpenID Connect issuer, such as GitHub Actions or GitLab CI."
        configured={!!oidc}
        canEdit={canEdit}
        onRemove={() => setRemoving("oidc")}
      >
        <OidcForm
          key={JSON.stringify(oidc ?? null)}
          initial={oidc}
          disabled={!canEdit}
          busy={pendingKind === "oidc"}
          onSave={(config) => put.mutate({ kind: "oidc", ...config })}
        />
      </MethodCard>
      <MethodCard
        kind="kubernetes"
        icon={<Boxes className="size-4" />}
        description="Log in with a pod's service account token."
        configured={!!kubernetes}
        canEdit={canEdit}
        onRemove={() => setRemoving("kubernetes")}
      >
        <KubernetesForm
          key={`${kubernetesSaves}:${JSON.stringify(kubernetes ?? null)}`}
          initial={kubernetes}
          disabled={!canEdit}
          busy={pendingKind === "kubernetes"}
          onSave={(config) => put.mutate({ kind: "kubernetes", ...config })}
        />
      </MethodCard>
      <MethodCard
        kind="universal"
        icon={<KeyRound className="size-4" />}
        description="Log in anywhere with a client id and client secret. Prefer OIDC or Kubernetes where possible."
        configured={!!universal}
        canEdit={canEdit}
        onRemove={() => setRemoving("universal")}
      >
        {universal ? (
          <ClientSecrets identityId={identityId} canEdit={canEdit} />
        ) : (
          canEdit && (
            <Button onClick={() => put.mutate({ kind: "universal" })} disabled={put.isPending} data-testid="universal-enable">
              {pendingKind === "universal" && <Spinner />}
              Enable universal auth
            </Button>
          )
        )}
      </MethodCard>
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={`Remove ${removing ? LABELS[removing] : ""}?`}
        description="The identity can no longer log in this way. Tokens already issued keep working until they expire."
        confirmLabel="Remove"
        destructive
        onConfirm={() => remove.mutateAsync(removing ?? "oidc")}
        testId="remove-auth-method-confirm"
      />
    </div>
  );
}
