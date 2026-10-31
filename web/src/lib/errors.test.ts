import { describe, expect, it } from "vitest";
import { ApiError } from "@/api/client";
import { backoffSeconds, errorMessage } from "./errors";

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
    expect(errorMessage(ApiError.from(413, undefined))).toBe("That is too large for the server to accept.");
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
