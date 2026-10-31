import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, CSRF_HEADER, fetchDownload, isSealError, reauthUrl } from "./client";
import { api } from "./endpoints";

const origin = "https://sekret.example";

describe("fetchDownload", () => {
  afterEach(() => vi.unstubAllGlobals());

  function capture(): Request[] {
    const seen: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((request: Request) => {
        seen.push(request);
        return Promise.resolve(
          new Response("SKB1", { headers: { "Content-Disposition": 'attachment; filename="sekret-backup-1.skb"' } }),
        );
      }),
    );
    return seen;
  }

  it("asks for the backup with POST and the CSRF header", async () => {
    const seen = capture();
    const file = await api.backup();
    expect(file.filename).toBe("sekret-backup-1.skb");
    expect(seen[0].method).toBe("POST");
    expect(seen[0].headers.get(CSRF_HEADER)).toBe("1");
    expect(new URL(seen[0].url).pathname).toBe("/api/v1/sys/backup");
  });

  it("leaves a GET without the header", async () => {
    const seen = capture();
    await fetchDownload("/api/v1/thing", "thing");
    expect(seen[0].method).toBe("GET");
    expect(seen[0].headers.has(CSRF_HEADER)).toBe(false);
  });
});

describe("reauthUrl", () => {
  const error = (message: string) => new ApiError(message, 403, "reauthentication_required");

  it("follows the server's link back to the CLI approval", () => {
    const link = "/auth/login?reauth=1&return_to=%2Fcli-login%3Fcode%3DBCDF-2345";
    expect(reauthUrl(error(`sign in again to approve this; continue at ${link}`), "/elsewhere", origin)).toBe(link);
  });

  it.each([
    "sign in again; continue at /auth/login?reauth=1&return_to=https%3A%2F%2Fevil.example",
    "sign in again; continue at /auth/login?reauth=1&return_to=%2F..%2F%2Fevil.example",
    "sign in again; continue at https://evil.example/auth/login?x=1",
    "sign in again",
  ])("builds its own link when the message offers no safe one: %s", (message) => {
    expect(reauthUrl(error(message), "/cli-login?code=BCDF-2345", origin)).toBe(
      "/auth/login?reauth=1&return_to=%2Fcli-login%3Fcode%3DBCDF-2345",
    );
  });
});

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
