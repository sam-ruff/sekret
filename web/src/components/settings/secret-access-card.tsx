import { useQuery } from "@tanstack/react-query";
import { Lock } from "lucide-react";
import { useState } from "react";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { SecretAccessSetting } from "@/api/types";
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
  const save = useApiMutation({
    mutationFn: (enabled: boolean) => api.putSecretAccessSetting(project, enabled),
    invalidate: [keys.secretAccessSetting(project), keys.project(project), keys.projects],
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

  return (
    <div className="space-y-4">
      <Field orientation="horizontal">
        <Switch
          id="secret-access-on"
          checked={setting.enabled}
          disabled={!canEdit || save.isPending}
          onCheckedChange={(enabled) => save.mutate(enabled)}
          data-testid="secret-access-enabled"
        />
        <FieldLabel htmlFor="secret-access-on" className="font-normal">
          Let admins restrict secrets to an access list
        </FieldLabel>
      </Field>
      {refused && (
        <Alert variant="destructive" data-testid="secret-access-refused">
          <AlertDescription>{refused}.</AlertDescription>
        </Alert>
      )}
      {setting.restricted_count === 0 ? (
        <p className="text-sm text-muted-foreground" data-testid="secret-access-none">
          No secrets are restricted.
        </p>
      ) : (
        <div className="space-y-2">
          <p className="text-sm font-medium">
            {setting.restricted_count} restricted secret{setting.restricted_count === 1 ? "" : "s"}
          </p>
          <ul className="divide-y rounded-lg border text-sm" data-testid="secret-access-restricted">
            {setting.restricted.map((s) => (
              <li key={`${s.environment}:${s.path}:${s.key}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
                <Lock className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                <span className="min-w-0 break-all font-mono">{place(s.path, s.key)}</span>
                <Badge variant="outline">{s.environment}</Badge>
                {s.deleted && <Badge variant="secondary">Deleted</Badge>}
                <span className="ml-auto text-xs text-muted-foreground">
                  {s.grants === 0 ? "Admins only" : `${s.grants} on the list`}
                </span>
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
          </p>
        </div>
      )}
    </div>
  );
}
