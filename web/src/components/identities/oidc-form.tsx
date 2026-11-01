import { AlertTriangle, Plus, Trash2, Workflow } from "lucide-react";
import { useState, type FormEvent } from "react";
import type { OidcAuthConfig } from "@/api/types";
import { ListInput } from "@/components/list-input";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { durationText, formatDurationWords } from "@/lib/format";
import { DEFAULT_MAX_TOKEN_LIFETIME, outboundUrlProblem, parseLifetime } from "./identity-model";
import { MaxLifetimeField } from "./max-lifetime-field";
import { UrlField } from "./url-field";

export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
export const GITHUB_SUBJECT_TEMPLATE = "repo:OWNER/REPO:ref:refs/heads/main";

interface ClaimRow {
  id: number;
  name: string;
  globs: string[];
}

let rowId = 0;

function claimRows(claims: Record<string, string[]> | undefined): ClaimRow[] {
  return Object.entries(claims ?? {}).map(([name, globs]) => ({ id: (rowId += 1), name, globs }));
}

interface OidcFormProps {
  initial?: OidcAuthConfig;
  busy: boolean;
  disabled?: boolean;
  onSave: (config: OidcAuthConfig) => void;
}

export function OidcForm({ initial, busy, disabled, onSave }: OidcFormProps) {
  const [issuer, setIssuer] = useState(initial?.issuer ?? "");
  const [jwksUrl, setJwksUrl] = useState(initial?.jwks_url ?? "");
  const [audiences, setAudiences] = useState<string[]>(initial?.bindings.audiences ?? ["sekret"]);
  const [subjects, setSubjects] = useState<string[]>(initial?.bindings.subjects ?? []);
  const [claims, setClaims] = useState<ClaimRow[]>(() => claimRows(initial?.bindings.claims));
  const [lifetime, setLifetime] = useState(durationText(initial?.max_token_lifetime ?? DEFAULT_MAX_TOKEN_LIFETIME));
  const maxLifetime = parseLifetime(lifetime);

  const applyGithubPreset = () => {
    setIssuer(GITHUB_ISSUER);
    setJwksUrl("");
    setAudiences(["sekret"]);
    setSubjects((current) => (current.length > 0 ? current : [GITHUB_SUBJECT_TEMPLATE]));
  };

  const boundClaims = claims.filter((c) => c.name.trim() && c.globs.length > 0);
  const unbounded = subjects.length === 0 && boundClaims.length === 0;
  const valid =
    issuer.trim() !== "" &&
    !outboundUrlProblem(issuer) &&
    !outboundUrlProblem(jwksUrl) &&
    audiences.length > 0 &&
    !unbounded &&
    maxLifetime !== null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!valid || maxLifetime === null) return;
    onSave({
      issuer: issuer.trim(),
      jwks_url: jwksUrl.trim() || null,
      max_token_lifetime: maxLifetime,
      bindings: {
        audiences,
        subjects,
        claims: Object.fromEntries(boundClaims.map((c) => [c.name.trim(), c.globs])),
      },
    });
  };

  const updateClaim = (id: number, patch: Partial<ClaimRow>) =>
    setClaims((current) => current.map((c) => (c.id === id ? { ...c, ...patch } : c)));

  return (
    <form onSubmit={submit} className="space-y-4" data-testid="oidc-form">
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" size="sm" onClick={applyGithubPreset} disabled={disabled} data-testid="oidc-preset-github">
          <Workflow />
          GitHub Actions preset
        </Button>
        <span className="text-xs text-muted-foreground">Fills the issuer and a subject template to edit.</span>
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 [&>*]:min-w-0" data-testid="oidc-fields">
        <UrlField
          id="oidc-issuer"
          label="Issuer"
          value={issuer}
          disabled={disabled}
          placeholder="https://issuer.example.com"
          onChange={setIssuer}
        />
        <UrlField
          id="oidc-jwks-url"
          label="JWKS URL (optional)"
          value={jwksUrl}
          disabled={disabled}
          placeholder="Discovered from the issuer when empty"
          onChange={setJwksUrl}
        />
        <Field>
          <FieldLabel htmlFor="oidc-audiences">Audiences</FieldLabel>
          <ListInput
            id="oidc-audiences"
            value={audiences}
            onChange={setAudiences}
            mono
            disabled={disabled}
            placeholder="sekret"
            testId="oidc-audiences"
          />
          <FieldDescription>The token's aud claim must match one of these.</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="oidc-subjects">Subjects</FieldLabel>
          <ListInput
            id="oidc-subjects"
            value={subjects}
            onChange={setSubjects}
            mono
            disabled={disabled}
            placeholder="repo:org/repo:* then Enter"
            testId="oidc-subjects"
          />
          <FieldDescription>Globs over the sub claim; * matches anything.</FieldDescription>
        </Field>
      </div>
      <div className="space-y-2">
        <Label>Claims</Label>
        <p className="text-xs text-muted-foreground">
          Each claim must match one of its globs. Names starting with / are JSON pointers into the token.
        </p>
        {claims.map((claim) => (
          <div key={claim.id} className="flex flex-col gap-2 rounded-lg border p-2 sm:flex-row sm:items-start" data-testid="oidc-claim-row">
            <Input
              aria-label="Claim name"
              value={claim.name}
              disabled={disabled}
              placeholder="repository_owner"
              className="font-mono sm:w-48"
              onChange={(e) => updateClaim(claim.id, { name: e.target.value })}
              data-testid="oidc-claim-name"
            />
            <div className="min-w-0 flex-1">
              <ListInput
                value={claim.globs}
                ariaLabel={claim.name.trim() ? `Globs for claim ${claim.name.trim()}` : "Globs for this claim"}
                onChange={(globs) => updateClaim(claim.id, { globs })}
                mono
                disabled={disabled}
                placeholder="Glob then Enter"
                testId="oidc-claim-globs"
              />
            </div>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-label="Remove claim"
              disabled={disabled}
              onClick={() => setClaims((current) => current.filter((c) => c.id !== claim.id))}
            >
              <Trash2 />
            </Button>
          </div>
        ))}
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={disabled}
          onClick={() => setClaims((current) => [...current, { id: (rowId += 1), name: "", globs: [] }])}
          data-testid="oidc-add-claim"
        >
          <Plus />
          Add claim
        </Button>
      </div>
      <MaxLifetimeField
        idPrefix="oidc"
        label="Longest OIDC token accepted"
        value={lifetime}
        disabled={disabled}
        onChange={setLifetime}
        help={(seconds) => (
          <>
            Tokens valid for longer than this, or without an <code className="font-mono text-xs">iat</code> claim, are
            refused: {formatDurationWords(seconds)}.
          </>
        )}
      />
      {unbounded && (
        <p className="flex items-start gap-2 text-sm text-muted-foreground" data-testid="oidc-unbounded">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
          Bind at least one subject or claim so not every token from this issuer is accepted.
        </p>
      )}
      {!disabled && (
        <div className="flex justify-end">
          <Button type="submit" disabled={!valid || busy} data-testid="oidc-save">
            {busy && <Spinner />}
            Save OIDC
          </Button>
        </div>
      )}
    </form>
  );
}
