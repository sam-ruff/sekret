import { ApiError } from "@/api/client";

/** Plain wording for codes whose server message is written for logs and the CLI. */
const FRIENDLY: Record<string, string> = {
  kdf_busy: "Another unlock is in progress. Try again in a moment.",
  backup_in_progress: "Another backup is being made. Try again when it finishes.",
  passphrase_required: "Confirm this change with the current passphrase.",
  reauthentication_required: "Sign in again to approve this.",
  logo_busy: "Your previous logo is still being processed. Upload one at a time, and try again in a moment.",
};

const DENY_FOR_ADMIN = "only an admin can bind deny rules to an admin";

/** Binding a deny to an admin, which only an admin may do; not a case of granting too much. */
export function isDenyForAdmin(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403 && error.message === DENY_FOR_ADMIN;
}

/** Browsers' wording when a request or a lazily loaded part of the page could not be fetched. */
const UNREACHABLE = [/failed to fetch/i, /networkerror/i, /load failed/i, /dynamically imported module/i, /importing a module script failed/i];

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return apiErrorMessage(error);
  if (error instanceof Error && UNREACHABLE.some((pattern) => pattern.test(error.message))) {
    return "Could not reach the server. Reload the page and try again.";
  }
  if (error instanceof Error && error.message) return error.message;
  return "Something went wrong.";
}

function apiErrorMessage(error: ApiError): string {
  const friendly = FRIENDLY[error.code];
  if (friendly) return friendly;
  if (isDenyForAdmin(error)) {
    return "Only an admin can give deny rules to an admin, so that nobody else can lock the admins out";
  }
  if (error.status === 413) {
    return "That is too large for the server to accept. Make it smaller, or split it into several changes.";
  }
  const refusedUrl = error.status === 400 ? /^url not allowed: (.+)$/.exec(error.message) : null;
  if (refusedUrl) {
    return (
      `The server will not contact ${refusedUrl[1]}. Use an https address with no username or password in it, ` +
      "and not a cloud metadata address such as 169.254.169.254."
    );
  }
  const seconds = backoffSeconds(error);
  if (seconds !== null) return `Too many wrong passphrases. Try again in ${seconds} seconds.`;
  return capitalise(error.message);
}

/** Seconds to wait after too many wrong passphrases, or null for any other error. */
export function backoffSeconds(error: unknown): number | null {
  if (!(error instanceof ApiError) || error.code !== "passphrase_backoff") return null;
  const match = /(\d+)\s*second/.exec(error.message);
  return match ? Math.max(1, Number(match[1])) : 60;
}

export function isEscalation(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 403 && error.code === "escalation" && !isDenyForAdmin(error);
}

/** The change was saved, but the seal mark file outside the database is behind and needs repair on the host. */
export function isEpochMarkStale(error: unknown): error is ApiError {
  return error instanceof ApiError && error.code === "epoch_mark_stale";
}

export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

function capitalise(text: string): string {
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}
