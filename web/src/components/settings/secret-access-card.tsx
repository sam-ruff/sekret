import { useQuery } from "@tanstack/react-query";
import { Lock } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { RestrictedSecret, SecretAccessSetting } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ErrorState } from "@/components/states";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldLabel } from "@/components/ui/field";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { keys, useApiMutation } from "@/hooks/queries";
import { errorMessage } from "@/lib/errors";

function place(path: string, key: string): string {
  return path === "/" ? key : `${path}/${key}`;
}

/** The secret's drawer, opened at its access section. */
function drawerLink(project: string, s: RestrictedSecret): string {
  const params = new URLSearchParams({ open: s.key, access: "1" });
  if (s.path !== "/") params.set("path", s.path);
  return `/projects/${project}/secrets/${s.environment}?${params.toString()}`;
}

/** The project's per-secret access setting and its restricted secrets. Admins only. */
export function SecretAccessCard({ project, canEdit }: { project: string; canEdit: boolean }) {
  const setting = useQuery({ queryKey: keys.secretAccessSetting(project), queryFn: () => api.secretAccessSetting(project) });
  return (
    <Card className="max-w-3xl" data-testid="secret-access-setting">
      <CardHeader>
        <CardTitle>Per-secret access</CardTitle>
        <CardDescription>
          Off by default. When on, admins can restrict a secret so only the people, groups and machine identities on its
          access list can reach it. A list only narrows what roles allow, never widens it, and project and organisation
          admins always keep access.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {setting.isPending && <Skeleton className="h-16 rounded-lg" />}
        {setting.error && <ErrorState error={setting.error} onRetry={() => void setting.refetch()} />}
        {setting.data && <SettingForm project={project} setting={setting.data} canEdit={canEdit} />}
      </CardContent>
    </Card>
  );
}

function SettingForm({ project, setting, canEdit }: { project: string; setting: SecretAccessSetting; canEdit: boolean }) {
  const [refused, setRefused] = useState<string | null>(null);
  const [confirmOff, setConfirmOff] = useState(false);
  const save = useApiMutation({
    mutationFn: (enabled: boolean) => api.putSecretAccessSetting(project, enabled),
    invalidate: [keys.secretAccessSetting(project), keys.project(project), keys.projects, ["project", project, "access"]],
    success: (_, enabled) => (enabled ? "Per-secret access turned on" : "Per-secret access turned off"),
    onSuccess: () => setRefused(null),
    onError: (error) => {
      if (error instanceof ApiError && error.code === "secrets_restricted") {
        setRefused(errorMessage(error));
        return true;
      }
      return false;
    },
  });
  const hidden = setting.restricted_count - setting.restricted.length;
  const change = (enabled: boolean) => {
    // Stays focusable while saving, so keyboard users keep their place.
    if (save.isPending) return;
    if (enabled) {
      save.mutate(true);
      return;
    }
    setConfirmOff(true);
  };

  return (
    <div className="space-y-4">
      <Field orientation="horizontal">
        <Switch
          id="secret-access-on"
          checked={setting.enabled}
          disabled={!canEdit}
          aria-disabled={save.isPending || undefined}
          onCheckedChange={change}
          data-testid="secret-access-enabled"
        />
        <FieldLabel htmlFor="secret-access-on" className="font-normal">
          Let admins restrict secrets to an access list
        </FieldLabel>
      </Field>
      <ConfirmDialog
        open={confirmOff}
        onOpenChange={setConfirmOff}
        title="Turn per-secret access off?"
        description="Secrets can no longer be restricted, and every access list in the project is cleared, including lists prepared on secrets that are still open."
        confirmLabel="Turn off"
        destructive
        onConfirm={() => save.mutateAsync(false).catch(() => undefined)}
        testId="secret-access-off-confirm"
      />
      {refused && (
        <Alert variant="destructive" data-testid="secret-access-refused">
          <AlertDescription>{refused}.</AlertDescription>
        </Alert>
      )}
      {setting.restricted_count === 0 ? (
        <p className="text-sm text-muted-foreground" data-testid="secret-access-none">
          No secrets are restricted.{setting.enabled && " Turning this off clears every access list in the project."}
        </p>
      ) : (
        <div className="space-y-2">
          <p className="text-sm font-medium">
            {setting.restricted_count} restricted secret{setting.restricted_count === 1 ? "" : "s"}
          </p>
          <ul className="divide-y rounded-lg border text-sm" data-testid="secret-access-restricted">
            {setting.restricted.map((s) => (
              <li key={`${s.environment}:${s.path}:${s.key}`}>
                <Link
                  to={drawerLink(project, s)}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 hover:bg-muted/50 focus-visible:bg-muted/50"
                  data-testid={`secret-access-open-${s.environment}-${s.key}`}
                >
                  <Lock className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="min-w-0 break-all font-mono">{place(s.path, s.key)}</span>
                  <Badge variant="outline">{s.environment}</Badge>
                  {s.deleted && <Badge variant="secondary">Deleted</Badge>}
                  <span className="ml-auto text-xs text-muted-foreground">
                    {s.grants === 0 ? "Admins only" : `${s.grants} on the list`}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
          {hidden > 0 && (
            <p className="text-xs text-muted-foreground">
              {hidden} more {hidden === 1 ? "is" : "are"} in places your roles hide from you.
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            Per-secret access can only be turned off once nothing is restricted, so no restriction lapses unnoticed.
            Turning it off then clears every access list in the project.
          </p>
        </div>
      )}
    </div>
  );
}
