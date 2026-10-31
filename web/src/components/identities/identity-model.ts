import { REDACTED_CREDENTIAL } from "@/api/types";

export interface IdentityDraft {
  name: string;
  description: string;
  tokenTtl: string;
  tokenMaxTtl: string;
  trustedCidrs: string[];
}

export function ttlProblem(draft: IdentityDraft): string | undefined {
  const ttl = Number(draft.tokenTtl);
  const max = Number(draft.tokenMaxTtl);
  if (!Number.isInteger(ttl) || !Number.isInteger(max)) return "TTLs are whole numbers of seconds";
  if (ttl < 60) return "Token TTL must be at least 60 seconds";
  if (max < ttl) return "Max TTL cannot be shorter than the token TTL";
  if (max > 365 * 24 * 3600) return "Max TTL can be at most a year";
  return undefined;
}

/** The server's cap on a service account token's `exp - iat` when none is set. */
export const DEFAULT_MAX_TOKEN_LIFETIME = 3600;

/** Whole seconds of at least one, or null when the text is not that. */
export function parseLifetime(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const seconds = Number(trimmed);
  return Number.isSafeInteger(seconds) && seconds >= 1 ? seconds : null;
}

export function parseJwks(text: string): { value: unknown; error?: string } {
  if (!text.trim()) return { value: null };
  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== "object" || !Array.isArray((value as { keys?: unknown }).keys)) {
      return { value: null, error: "A JWKS document is an object with a keys array" };
    }
    return { value };
  } catch {
    return { value: null, error: "This is not valid JSON" };
  }
}

/** A write-only credential is either kept as stored on the server or replaced by what the user typed. */
export type WriteOnlyCredential = { kind: "stored" } | { kind: "new"; value: string };

export function initialCredential(fromServer: string | null | undefined): WriteOnlyCredential {
  if (fromServer === REDACTED_CREDENTIAL) return { kind: "stored" };
  return { kind: "new", value: fromServer ?? "" };
}

/** The value to send: the marker keeps the stored credential, and null clears it. */
export function credentialPayload(credential: WriteOnlyCredential): string | null {
  if (credential.kind === "stored") return REDACTED_CREDENTIAL;
  return credential.value.trim() || null;
}

export function cliUniversalSnippet(server: string, id: string): string {
  return [
    `export SEKRET_URL=${server}`,
    `export SEKRET_CLIENT_SECRET=<client secret>`,
    `sekret login --client-id ${id}`,
    ``,
    `sekret run --project <project> --env <environment> -- ./app`,
  ].join("\n");
}

export function cliKubernetesSnippet(server: string, id: string): string {
  return [
    `export SEKRET_URL=${server}`,
    `sekret login --kubernetes --identity-id ${id}`,
    `sekret export --project <project> --env <environment> --format dotenv > .env`,
  ].join("\n");
}

export function githubActionsSnippet(server: string, id: string): string {
  return `name: deploy
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: [self-hosted]
    env:
      SEKRET_URL: ${server}
    steps:
      - uses: actions/checkout@v4
      - name: Log in to sekret
        run: |
          OIDC_TOKEN=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sekret" | jq -r .value)
          SEKRET_TOKEN=$(curl -sSf -X POST "$SEKRET_URL/api/v1/auth/oidc/login" \\
            -H "Content-Type: application/json" \\
            -d "{\\"identity_id\\":\\"${id}\\",\\"token\\":\\"$OIDC_TOKEN\\"}" | jq -r .access_token)
          echo "::add-mask::$SEKRET_TOKEN"
          echo "SEKRET_TOKEN=$SEKRET_TOKEN" >> "$GITHUB_ENV"
      - name: Deploy with secrets
        run: sekret run --project <project> --env <environment> -- ./deploy.sh`;
}

export function githubActionsCliSnippet(id: string): string {
  return `      - name: Log in to sekret
        run: sekret login --github-actions --identity-id ${id}`;
}
