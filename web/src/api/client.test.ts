import { describe, expect, it } from "vitest";
import { ApiError, isSealError } from "./client";

describe("ApiError.from", () => {
  it("keeps zxcvbn's feedback from a weak passphrase refusal", () => {
    const error = ApiError.from(400, {
      error: "weak_passphrase",
      message: "the passphrase is too easy to guess",
      strength: { score: 1, acceptable: false, warning: "Too common.", suggestions: ["Add a word.", 7] },
    });
    expect(error.code).toBe("weak_passphrase");
    expect(error.strength).toEqual({ score: 1, acceptable: false, warning: "Too common.", suggestions: ["Add a word."] });
  });

  it("ignores a malformed strength", () => {
    expect(ApiError.from(400, { error: "weak_passphrase", strength: "weak" }).strength).toBeUndefined();
  });

  it("explains rate limiting without a server message", () => {
    expect(ApiError.from(429, undefined).message).toMatch(/Too many attempts/);
  });
});

describe("isSealError", () => {
  it("matches only the gate's 503 codes", () => {
    expect(isSealError(ApiError.from(503, { error: "sealed" }))).toBe(true);
    expect(isSealError(ApiError.from(503, { error: "uninitialised" }))).toBe(true);
    expect(isSealError(ApiError.from(503, { error: "unavailable" }))).toBe(false);
    expect(isSealError(ApiError.from(401, { error: "sealed" }))).toBe(false);
    expect(isSealError(new Error("sealed"))).toBe(false);
  });
});
