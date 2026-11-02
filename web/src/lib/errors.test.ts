import { describe, expect, it } from "vitest";
import { ApiError } from "@/api/client";
import { backoffSeconds, errorMessage, isDenyForAdmin, isEscalation } from "./errors";

describe("errorMessage", () => {
  it.each([
    ["kdf_busy", 429, "Another unlock is in progress. Try again in a moment."],
    ["backup_in_progress", 429, "Another backup is being made. Try again when it finishes."],
    ["passphrase_required", 400, "Confirm this change with the current passphrase."],
    ["reauthentication_required", 403, "Sign in again to approve this."],
  ])("words %s plainly", (code, status, text) => {
    expect(errorMessage(new ApiError("server wording", status, code))).toBe(text);
  });

  it("explains an oversized body", () => {
    const message = "That is too large for the server to accept. Make it smaller, or split it into several changes.";
    expect(errorMessage(ApiError.from(413, undefined))).toBe(message);
    expect(errorMessage(new ApiError("the request body is too large or arrived too slowly", 413, "too_large"))).toBe(message);
  });

  it("explains a URL the server refuses to contact", () => {
    const error = new ApiError("url not allowed: http://169.254.169.254/latest", 400, "bad_request");
    expect(errorMessage(error)).toBe(
      "The server will not contact http://169.254.169.254/latest. Use an https address with no username or password in it, " +
        "and not a cloud metadata address such as 169.254.169.254.",
    );
  });

  it("gives the wait after too many wrong passphrases", () => {
    const error = new ApiError("too many wrong passphrases; try again in 42 seconds", 429, "passphrase_backoff");
    expect(errorMessage(error)).toBe("Too many wrong passphrases. Try again in 42 seconds.");
  });

  it.each([
    "Failed to fetch dynamically imported module: http://localhost:5173/node_modules/.vite/deps/chunk.js",
    "Failed to fetch",
    "NetworkError when attempting to fetch resource.",
    "Importing a module script failed.",
  ])("hides the browser's network wording: %s", (message) => {
    expect(errorMessage(new TypeError(message))).toBe("Could not reach the server. Reload the page and try again.");
  });

  it("capitalises anything else", () => {
    expect(errorMessage(new ApiError("not found", 404, "not_found"))).toBe("Not found");
  });
});

describe("errors from the latest server checks", () => {
  it("says a logo upload is still being processed in plain words", () => {
    expect(errorMessage(new ApiError("your previous logo is still being processed", 429, "logo_busy"))).toContain(
      "Upload one at a time",
    );
  });

  it("shows the too many patterns refusal as the server words it", () => {
    const error = new ApiError("your roles here hold more than 400 path and key patterns", 400, "too_many_patterns");
    expect(errorMessage(error)).toBe("Your roles here hold more than 400 path and key patterns");
  });

  it("tells a deny bound to an admin apart from granting too much", () => {
    const deny = new ApiError("only an admin can bind deny rules to an admin", 403, "escalation");
    expect(isDenyForAdmin(deny)).toBe(true);
    expect(isEscalation(deny)).toBe(false);
    expect(errorMessage(deny)).toContain("Only an admin can give deny rules to an admin");
    const grant = new ApiError("you cannot grant a role with more access than you have", 403, "escalation");
    expect(isEscalation(grant)).toBe(true);
    expect(isDenyForAdmin(grant)).toBe(false);
  });
});

describe("backoffSeconds", () => {
  it("reads the seconds from the message", () => {
    expect(backoffSeconds(new ApiError("try again in 7 seconds", 429, "passphrase_backoff"))).toBe(7);
    expect(backoffSeconds(new ApiError("try again in 1 second", 429, "passphrase_backoff"))).toBe(1);
  });

  it("waits a minute when the message has no number, and ignores other errors", () => {
    expect(backoffSeconds(new ApiError("slow down", 429, "passphrase_backoff"))).toBe(60);
    expect(backoffSeconds(new ApiError("try again in 7 seconds", 429, "rate_limited"))).toBeNull();
    expect(backoffSeconds(new Error("x"))).toBeNull();
  });
});
