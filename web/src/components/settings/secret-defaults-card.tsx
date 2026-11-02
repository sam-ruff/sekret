import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/api/endpoints";
import type { SecretPolicy } from "@/api/types";
import { GeneratorFields, RotationField } from "@/components/secrets/generator-fields";
import { ErrorState } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldLabel } from "@/components/ui/field";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { keys, useApiMutation } from "@/hooks/queries";
import {
  describeGenerator,
  describeRotation,
  draftFromPolicy,
  draftProblem,
  isPolicyOff,
  policyFromDraft,
  type PolicyDraft,
} from "@/lib/generation";

const OFF: SecretPolicy = { generator: null, rotation_days: null };

export function SecretDefaultsCard({ project, canEdit }: { project: string; canEdit: boolean }) {
  const policy = useQuery({ queryKey: keys.projectPolicy(project), queryFn: () => api.projectPolicy(project) });
  return (
    <Card className="max-w-3xl" data-testid="secret-defaults">
      <CardHeader>
        <CardTitle>Secret defaults</CardTitle>
        <CardDescription>
          How sekret generates and rotates values for secrets that do not set their own policy. Without project defaults,
          Generate makes 32 letters and digits and nothing rotates unless a secret sets its own policy. Automatic rotation
          only ever replaces values sekret generated, never ones that were typed or imported.
        </CardDescription>
      </CardHeader>
      {policy.isPending && (
        <CardContent>
          <Skeleton className="h-24 rounded-lg" />
        </CardContent>
      )}
      {policy.error && (
        <CardContent>
          <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />
        </CardContent>
      )}
      {policy.data && <DefaultsForm key={JSON.stringify(policy.data)} project={project} policy={policy.data} canEdit={canEdit} />}
    </Card>
  );
}

function DefaultsForm({ project, policy, canEdit }: { project: string; policy: SecretPolicy; canEdit: boolean }) {
  const initiallyOn = !isPolicyOff(policy);
  const initialDraft = draftFromPolicy(policy);
  const [on, setOn] = useState(initiallyOn);
  const [draft, setDraft] = useState<PolicyDraft>(initialDraft);

  const save = useApiMutation({
    mutationFn: () => api.putProjectPolicy(project, on ? policyFromDraft(draft) : OFF),
    invalidate: [keys.projectPolicy(project), ["project", project, "secrets"], ["project", project, "policy"]],
    success: "Secret defaults saved",
  });

  const problem = on ? draftProblem(draft) : undefined;
  const changed = on !== initiallyOn || (on && JSON.stringify(draft) !== JSON.stringify(initialDraft));

  return (
    <>
      <CardContent className="space-y-4">
        <Field orientation="horizontal">
          <Switch id="defaults-on" checked={on} disabled={!canEdit} onCheckedChange={setOn} data-testid="defaults-enabled" />
          <FieldLabel htmlFor="defaults-on" className="font-normal">
            Set project-wide generation and rotation
          </FieldLabel>
        </Field>
        {on ? (
          <div className="grid gap-5 md:grid-cols-2">
            <div className="space-y-2">
              <p className="text-sm font-medium">Generated values</p>
              <GeneratorFields
                idPrefix="defaults"
                length={draft.length}
                charset={draft.charset}
                disabled={!canEdit}
                onChange={(g) => setDraft({ ...draft, ...g })}
              />
            </div>
            <div className="space-y-2">
              <p className="text-sm font-medium">Rotation</p>
              <RotationField
                idPrefix="defaults"
                rotate={draft.rotate}
                days={draft.days}
                disabled={!canEdit}
                onChange={(r) => setDraft({ ...draft, ...r })}
                hint="Rotation applies once a value is generated."
              />
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground" data-testid="defaults-summary">
            {initiallyOn && !on
              ? "Saving turns the defaults off. Secrets with their own policy keep it."
              : "Off."}
          </p>
        )}
        {on && !problem && (
          <p className="text-xs text-muted-foreground" data-testid="defaults-preview">
            New generated values: {describeGenerator(policyFromDraft(draft).generator)}. {describeRotation(policyFromDraft(draft).rotation_days)}.
          </p>
        )}
      </CardContent>
      {canEdit && (
        <CardFooter className="justify-end">
          <Button disabled={!changed || !!problem || save.isPending} onClick={() => save.mutate()} data-testid="defaults-save">
            {save.isPending && <Spinner />}
            Save defaults
          </Button>
        </CardFooter>
      )}
    </>
  );
}
