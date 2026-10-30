import { ListInput } from "@/components/list-input";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { formatDuration } from "@/lib/format";
import { ttlProblem, type IdentityDraft } from "./identity-model";

const CIDR = /^[0-9a-fA-F:.]+\/\d{1,3}$/;

function hint(seconds: string): string {
  const n = Number(seconds);
  return Number.isInteger(n) && n > 0 ? formatDuration(n) : "seconds";
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
        <FieldLabel htmlFor={`${idPrefix}-ttl`}>Token TTL (seconds)</FieldLabel>
        <Input
          id={`${idPrefix}-ttl`}
          inputMode="numeric"
          value={draft.tokenTtl}
          aria-invalid={!!problem}
          onChange={(e) => onChange({ ...draft, tokenTtl: e.target.value.trim() })}
          data-testid="identity-ttl"
        />
        <FieldDescription>How long each token lasts: {hint(draft.tokenTtl)}</FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor={`${idPrefix}-max-ttl`}>Max TTL (seconds)</FieldLabel>
        <Input
          id={`${idPrefix}-max-ttl`}
          inputMode="numeric"
          value={draft.tokenMaxTtl}
          aria-invalid={!!problem}
          onChange={(e) => onChange({ ...draft, tokenMaxTtl: e.target.value.trim() })}
          data-testid="identity-max-ttl"
        />
        <FieldDescription>Longest a token can be renewed to: {hint(draft.tokenMaxTtl)}</FieldDescription>
      </Field>
      {problem && <p className="text-sm text-destructive md:col-span-2">{problem}</p>}
      <Field className="md:col-span-2">
        <FieldLabel htmlFor={`${idPrefix}-cidrs`}>Trusted CIDRs</FieldLabel>
        <ListInput
          id={`${idPrefix}-cidrs`}
          value={draft.trustedCidrs}
          onChange={(trustedCidrs) => onChange({ ...draft, trustedCidrs })}
          placeholder="10.0.0.0/8 then Enter"
          mono
          validate={(c) => (CIDR.test(c) ? undefined : "Use CIDR notation such as 10.0.0.0/8")}
          testId="identity-cidrs"
        />
        <FieldDescription>Logins are only accepted from these networks. Leave empty to allow any.</FieldDescription>
      </Field>
    </div>
  );
}
