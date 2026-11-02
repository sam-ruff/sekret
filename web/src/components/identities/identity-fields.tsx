import { ListInput } from "@/components/list-input";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { formatDurationWords, parseDuration } from "@/lib/format";
import { ttlProblem, type IdentityDraft } from "./identity-model";

const CIDR = /^[0-9a-fA-F:.]+\/\d{1,3}$/;

/** "How long each token lasts: 1 hour.", leaving the words out while the text is not a duration. */
function hint(lead: string, text: string): string {
  const seconds = parseDuration(text);
  return seconds !== null && seconds > 0 ? `${lead}: ${formatDurationWords(seconds)}.` : `${lead}.`;
}

export function IdentityFields({
  draft,
  onChange,
  idPrefix,
}: {
  draft: IdentityDraft;
  onChange: (draft: IdentityDraft) => void;
  idPrefix: string;
}) {
  const problem = ttlProblem(draft);
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Field>
        <FieldLabel htmlFor={`${idPrefix}-name`}>Name</FieldLabel>
        <Input
          id={`${idPrefix}-name`}
          value={draft.name}
          onChange={(e) => onChange({ ...draft, name: e.target.value })}
          data-testid="identity-name"
        />
      </Field>
      <Field>
        <FieldLabel htmlFor={`${idPrefix}-description`}>Description</FieldLabel>
        <Textarea
          id={`${idPrefix}-description`}
          rows={1}
          value={draft.description}
          onChange={(e) => onChange({ ...draft, description: e.target.value })}
          data-testid="identity-description"
        />
      </Field>
      <Field>
        <FieldLabel htmlFor={`${idPrefix}-ttl`}>Token lifetime</FieldLabel>
        <Input
          id={`${idPrefix}-ttl`}
          value={draft.tokenTtl}
          placeholder="1h"
          aria-invalid={!!problem}
          aria-describedby={problem ? `${idPrefix}-ttl-hint ${idPrefix}-ttl-problem` : `${idPrefix}-ttl-hint`}
          onChange={(e) => onChange({ ...draft, tokenTtl: e.target.value.trim() })}
          data-testid="identity-ttl"
        />
        <FieldDescription id={`${idPrefix}-ttl-hint`} data-testid="identity-ttl-hint">
          {hint("How long each token lasts", draft.tokenTtl)}
        </FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor={`${idPrefix}-max-ttl`}>Longest renewed lifetime</FieldLabel>
        <Input
          id={`${idPrefix}-max-ttl`}
          value={draft.tokenMaxTtl}
          placeholder="1d"
          aria-invalid={!!problem}
          aria-describedby={problem ? `${idPrefix}-max-ttl-hint ${idPrefix}-ttl-problem` : `${idPrefix}-max-ttl-hint`}
          onChange={(e) => onChange({ ...draft, tokenMaxTtl: e.target.value.trim() })}
          data-testid="identity-max-ttl"
        />
        <FieldDescription id={`${idPrefix}-max-ttl-hint`} data-testid="identity-max-ttl-hint">
          {hint("How long renewals can keep a token going", draft.tokenMaxTtl)}
        </FieldDescription>
      </Field>
      <p className="text-xs text-muted-foreground md:col-span-2">
        Lifetimes take a number of seconds or a unit, such as 30m, 1h, 7d or 1h 30m.
      </p>
      {problem && (
        <p id={`${idPrefix}-ttl-problem`} role="alert" className="text-sm text-destructive md:col-span-2" data-testid="identity-ttl-problem">
          {problem}
        </p>
      )}
      <Field className="md:col-span-2">
        <FieldLabel htmlFor={`${idPrefix}-cidrs`}>Allowed networks (CIDR ranges)</FieldLabel>
        <ListInput
          id={`${idPrefix}-cidrs`}
          value={draft.trustedCidrs}
          onChange={(trustedCidrs) => onChange({ ...draft, trustedCidrs })}
          placeholder="e.g. 10.0.0.0/8"
          mono
          validate={(c) => (CIDR.test(c) ? undefined : "Use a range such as 10.0.0.0/8 or 192.168.1.5/32")}
          testId="identity-cidrs"
        />
        <FieldDescription>
          Sign-ins are only accepted from these networks, for example 10.0.0.0/8 for a private network or 203.0.113.7/32
          for one address. Leave empty to allow any.
        </FieldDescription>
      </Field>
    </div>
  );
}
