import { LockKeyhole } from "lucide-react";
import { useState, type FormEvent } from "react";
import { REDACTED_CREDENTIAL, type KubernetesAuthConfig, type KubernetesMode } from "@/api/types";
import { ListInput } from "@/components/list-input";
import { SecretInput } from "@/components/secret-field";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import {
  credentialPayload,
  DEFAULT_MAX_TOKEN_LIFETIME,
  initialCredential,
  parseJwks,
  parseLifetime,
  type WriteOnlyCredential,
} from "./identity-model";

interface KubernetesFormProps {
  initial?: KubernetesAuthConfig;
  busy: boolean;
  disabled?: boolean;
  onSave: (config: KubernetesAuthConfig) => void;
}

const optional = (value: string) => value.trim() || null;

interface ReviewerTokenFieldProps {
  value: WriteOnlyCredential;
  hadStored: boolean;
  disabled?: boolean;
  onChange: (value: WriteOnlyCredential) => void;
}

function ReviewerTokenField({ value, hadStored, disabled, onChange }: ReviewerTokenFieldProps) {
  return (
    <Field className="md:col-span-2">
      <FieldLabel htmlFor="k8s-reviewer-jwt">Reviewer token</FieldLabel>
      {value.kind === "stored" ? (
        <div
          className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/40 px-3 py-2"
          data-testid="k8s-reviewer-jwt-stored"
        >
          <span className="flex items-center gap-2 text-sm">
            <LockKeyhole className="size-4 text-success" aria-hidden />
            Token stored
          </span>
          {!disabled && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onChange({ kind: "new", value: "" })}
              data-testid="k8s-reviewer-jwt-replace"
            >
              Replace
            </Button>
          )}
        </div>
      ) : (
        <div className="flex gap-2">
          <SecretInput
            id="k8s-reviewer-jwt"
            type="password"
            value={value.value}
            disabled={disabled}
            placeholder={hadStored ? "Paste a new token, or leave empty to remove it" : "eyJhbGciOi..."}
            className="min-w-0 flex-1 font-mono"
            onChange={(e) => onChange({ kind: "new", value: e.target.value })}
            data-testid="k8s-reviewer-jwt"
          />
          {hadStored && (
            <Button
              type="button"
              variant="ghost"
              onClick={() => onChange({ kind: "stored" })}
              data-testid="k8s-reviewer-jwt-keep"
            >
              Keep stored
            </Button>
          )}
        </div>
      )}
      <FieldDescription>
        A token for a service account bound to <code className="font-mono text-xs">system:auth-delegator</code>. Without
        it, sekret falls back to reviewing with the workload&apos;s own token, which most clusters refuse. It is never
        shown again once saved.
      </FieldDescription>
    </Field>
  );
}

export function KubernetesForm({ initial, busy, disabled, onSave }: KubernetesFormProps) {
  const hadStoredReviewer = initial?.reviewer_jwt === REDACTED_CREDENTIAL;
  const [reviewer, setReviewer] = useState<WriteOnlyCredential>(() => initialCredential(initial?.reviewer_jwt));
  const [mode, setMode] = useState<KubernetesMode>(initial?.mode ?? "token-review");
  const [host, setHost] = useState(initial?.host ?? "");
  const [caCert, setCaCert] = useState(initial?.ca_cert ?? "");
  const [issuer, setIssuer] = useState(initial?.issuer ?? "");
  const [jwksUrl, setJwksUrl] = useState(initial?.jwks_url ?? "");
  const [jwksText, setJwksText] = useState(initial?.jwks ? JSON.stringify(initial.jwks, null, 2) : "");
  const [namespaces, setNamespaces] = useState<string[]>(initial?.namespaces ?? []);
  const [serviceAccounts, setServiceAccounts] = useState<string[]>(initial?.service_accounts ?? []);
  const [audiences, setAudiences] = useState<string[]>(initial?.audiences ?? ["sekret"]);
  const [lifetime, setLifetime] = useState(String(initial?.max_token_lifetime ?? DEFAULT_MAX_TOKEN_LIFETIME));

  const jwks = parseJwks(jwksText);
  const maxLifetime = parseLifetime(lifetime);
  const modeValid =
    mode === "token-review" ? host.trim() !== "" : issuer.trim() !== "" && !jwks.error && (!!jwks.value || jwksUrl.trim() !== "");
  const valid =
    modeValid && namespaces.length > 0 && serviceAccounts.length > 0 && audiences.length > 0 && maxLifetime !== null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!valid || maxLifetime === null) return;
    const tokenReview = mode === "token-review";
    onSave({
      mode,
      host: tokenReview ? optional(host) : null,
      ca_cert: tokenReview ? optional(caCert) : null,
      reviewer_jwt: tokenReview ? credentialPayload(reviewer) : null,
      issuer: tokenReview ? null : optional(issuer),
      jwks_url: tokenReview ? null : optional(jwksUrl),
      jwks: tokenReview ? null : jwks.value,
      namespaces,
      service_accounts: serviceAccounts,
      audiences,
      max_token_lifetime: maxLifetime,
    });
  };

  return (
    <form onSubmit={submit} className="space-y-4" data-testid="k8s-form">
      <Field>
        <FieldLabel htmlFor="k8s-mode">Verification</FieldLabel>
        <Select value={mode} onValueChange={(v) => setMode(v as KubernetesMode)} disabled={disabled}>
          <SelectTrigger id="k8s-mode" className="w-full sm:w-80" data-testid="k8s-mode">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="token-review" data-testid="k8s-mode-token-review">
              TokenReview API
            </SelectItem>
            <SelectItem value="jwks" data-testid="k8s-mode-jwks">
              Service account signing keys (JWKS)
            </SelectItem>
          </SelectContent>
        </Select>
        <FieldDescription>
          {mode === "token-review"
            ? "sekret asks the cluster's API server whether the presented token is valid."
            : "sekret checks the token signature itself, so it does not need to reach the cluster."}
        </FieldDescription>
      </Field>
      {mode === "token-review" ? (
        <div className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel htmlFor="k8s-host">API server URL</FieldLabel>
            <Input
              id="k8s-host"
              value={host}
              disabled={disabled}
              placeholder="https://kubernetes.example.com:6443"
              className="font-mono"
              onChange={(e) => setHost(e.target.value)}
              data-testid="k8s-host"
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="k8s-ca">CA certificate (optional)</FieldLabel>
            <Textarea
              id="k8s-ca"
              value={caCert}
              disabled={disabled}
              rows={3}
              placeholder="-----BEGIN CERTIFICATE-----"
              className="font-mono text-xs"
              onChange={(e) => setCaCert(e.target.value)}
              data-testid="k8s-ca-cert"
            />
          </Field>
          <ReviewerTokenField value={reviewer} hadStored={hadStoredReviewer} disabled={disabled} onChange={setReviewer} />
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel htmlFor="k8s-issuer">Service account issuer</FieldLabel>
            <Input
              id="k8s-issuer"
              value={issuer}
              disabled={disabled}
              placeholder="https://kubernetes.default.svc"
              className="font-mono"
              onChange={(e) => setIssuer(e.target.value)}
              data-testid="k8s-issuer"
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="k8s-jwks-url">JWKS URL</FieldLabel>
            <Input
              id="k8s-jwks-url"
              value={jwksUrl}
              disabled={disabled}
              placeholder="Or paste the keys below"
              className="font-mono"
              onChange={(e) => setJwksUrl(e.target.value)}
              data-testid="k8s-jwks-url"
            />
          </Field>
          <Field className="md:col-span-2">
            <FieldLabel htmlFor="k8s-jwks">Inline JWKS</FieldLabel>
            <Textarea
              id="k8s-jwks"
              value={jwksText}
              disabled={disabled}
              rows={4}
              aria-invalid={!!jwks.error}
              placeholder='Output of: kubectl get --raw /openid/v1/jwks'
              className="font-mono text-xs"
              onChange={(e) => setJwksText(e.target.value)}
              data-testid="k8s-jwks"
            />
            {jwks.error && (
              <p className="text-xs text-destructive" data-testid="k8s-jwks-error">
                {jwks.error}
              </p>
            )}
          </Field>
        </div>
      )}
      <div className="grid gap-4 md:grid-cols-3">
        <Field>
          <FieldLabel htmlFor="k8s-namespaces">Namespaces</FieldLabel>
          <ListInput
            id="k8s-namespaces"
            value={namespaces}
            onChange={setNamespaces}
            mono
            disabled={disabled}
            placeholder="billing then Enter"
            testId="k8s-namespaces"
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="k8s-service-accounts">Service accounts</FieldLabel>
          <ListInput
            id="k8s-service-accounts"
            value={serviceAccounts}
            onChange={setServiceAccounts}
            mono
            disabled={disabled}
            placeholder="worker then Enter"
            testId="k8s-service-accounts"
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="k8s-audiences">Audiences</FieldLabel>
          <ListInput
            id="k8s-audiences"
            value={audiences}
            onChange={setAudiences}
            mono
            disabled={disabled}
            placeholder="sekret"
            testId="k8s-audiences"
          />
        </Field>
      </div>
      <p className="text-xs text-muted-foreground">Namespaces and service accounts accept globs, such as team-*.</p>
      <Field data-invalid={maxLifetime === null}>
        <FieldLabel htmlFor="k8s-max-lifetime">Maximum token lifetime (seconds)</FieldLabel>
        <Input
          id="k8s-max-lifetime"
          inputMode="numeric"
          value={lifetime}
          disabled={disabled}
          className="w-full font-mono sm:w-40"
          aria-invalid={maxLifetime === null}
          aria-describedby="k8s-max-lifetime-help"
          onChange={(e) => setLifetime(e.target.value)}
          data-testid="k8s-max-lifetime"
        />
        <FieldDescription id="k8s-max-lifetime-help">
          {maxLifetime === null
            ? "Enter a whole number of seconds, 1 or more."
            : "Tokens issued for longer than this are refused. Keep pods' projected token expirationSeconds at or below it."}
        </FieldDescription>
      </Field>
      {!disabled && (
        <div className="flex justify-end">
          <Button type="submit" disabled={!valid || busy} data-testid="k8s-save">
            {busy && <Spinner />}
            Save Kubernetes
          </Button>
        </div>
      )}
    </form>
  );
}
