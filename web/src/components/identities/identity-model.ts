import { REDACTED_CREDENTIAL } from "@/api/types";
import { parseDuration } from "@/lib/format";

export interface IdentityDraft {
  name: string;
  description: string;
  tokenTtl: string;
  tokenMaxTtl: string;
  trustedCidrs: string[];
}

/** How a duration field explains what it accepts. */
export const DURATION_FORMAT = "a duration such as 3600, 30m, 1h or 7d";

export function ttlProblem(draft: IdentityDraft): string | undefined {
  const ttl = parseDuration(draft.tokenTtl);
  const max = parseDuration(draft.tokenMaxTtl);
  if (ttl === null || max === null) return `Enter each lifetime as ${DURATION_FORMAT}`;
  if (ttl < 60) return "The token lifetime must be at least 60 seconds";
  if (max < ttl) return "The longest renewed lifetime cannot be shorter than the token lifetime";
  if (max > 365 * 24 * 3600) return "The longest renewed lifetime can be at most a year";
  return undefined;
}

/** The server's cap on a machine token's `exp - iat` when none is set. */
export const DEFAULT_MAX_TOKEN_LIFETIME = 3600;

/** The longest `max_token_lifetime` the server accepts: ten years. */
export const MAX_TOKEN_LIFETIME_LIMIT = 10 * 365 * 86_400;

/** A duration from one second up to ten years, or null when the text is not that. */
export function parseLifetime(text: string): number | null {
  const seconds = parseDuration(text);
  return seconds !== null && seconds >= 1 && seconds <= MAX_TOKEN_LIFETIME_LIMIT ? seconds : null;
}

/** IPv4 dotted quad from the last 32 bits of an IPv4-mapped IPv6 address, as URL parsing writes it. */
function mappedIpv4(host: string): string | null {
  const match = /^\[::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})\]$/i.exec(host);
  if (!match) return null;
  const [high, low] = [parseInt(match[1], 16), parseInt(match[2], 16)];
  return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

function isMetadataHost(rawHost: string): boolean {
  const host = mappedIpv4(rawHost) ?? rawHost.toLowerCase();
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  if (host === "100.100.100.200") return true;
  return host === "[fd00:ec2::254]";
}

/**
 * Why the server would refuse an auth method URL, checked before saving so the reason shows by
 * the field. Mirrors the server: no credentials in the URL and no cloud metadata addresses.
 * The scheme is left to the server, which may allow http for testing.
 */
export function outboundUrlProblem(raw: string): string | undefined {
  const text = raw.trim();
  if (!text) return undefined;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return "Enter a full URL, such as https://issuer.example.com.";
  }
  if (url.username || url.password) return "Leave the username and password out of the URL.";
  if (isMetadataHost(url.hostname)) {
    return "That is a cloud metadata address, which sekret never contacts. Use the service's own address.";
  }
  return undefined;
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
