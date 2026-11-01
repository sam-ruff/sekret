import { describe, expect, it } from "vitest";
import {
  credentialPayload,
  githubActionsSnippet,
  initialCredential,
  MAX_TOKEN_LIFETIME_LIMIT,
  outboundUrlProblem,
  parseJwks,
  parseLifetime,
  ttlProblem,
  type IdentityDraft,
} from "./identity-model";
import { REDACTED_CREDENTIAL } from "@/api/types";

describe("parseLifetime", () => {
  it("takes a duration from one second up to ten years", () => {
    expect(parseLifetime(" 900 ")).toBe(900);
    expect(parseLifetime("15m")).toBe(900);
    expect(parseLifetime("10y")).toBe(MAX_TOKEN_LIFETIME_LIMIT);
    expect(parseLifetime(String(MAX_TOKEN_LIFETIME_LIMIT))).toBe(MAX_TOKEN_LIFETIME_LIMIT);
    expect(MAX_TOKEN_LIFETIME_LIMIT).toBe(315_360_000);
  });

  it.each(["0", "0h", "-5", "1.5", "soon", "", "11y", String(MAX_TOKEN_LIFETIME_LIMIT + 1)])("refuses %j", (text) => {
    expect(parseLifetime(text)).toBeNull();
  });
});

describe("outboundUrlProblem", () => {
  it.each([
    "https://169.254.169.254/latest/meta-data",
    "https://169.254.170.2",
    "http://[::ffff:169.254.169.254]/",
    "https://[fd00:ec2::254]/",
    "https://100.100.100.200",
  ])("flags the cloud metadata address %s", (url) => {
    expect(outboundUrlProblem(url)).toMatch(/cloud metadata address/);
  });

  it("flags credentials in the URL and text that is not a URL", () => {
    expect(outboundUrlProblem("https://user:pw@issuer.example.com")).toMatch(/username and password/);
    expect(outboundUrlProblem("issuer.example.com")).toMatch(/full URL/);
  });

  it("accepts ordinary addresses and leaves an empty field alone", () => {
    expect(outboundUrlProblem("https://token.actions.githubusercontent.com")).toBeUndefined();
    expect(outboundUrlProblem("https://10.0.0.5:6443")).toBeUndefined();
    expect(outboundUrlProblem("  ")).toBeUndefined();
  });
});

const draft = (tokenTtl: string, tokenMaxTtl: string): IdentityDraft => ({
  name: "ci",
  description: "",
  tokenTtl,
  tokenMaxTtl,
  trustedCidrs: [],
});

describe("ttlProblem", () => {
  it("accepts sensible TTLs, in seconds or with units", () => {
    expect(ttlProblem(draft("3600", "86400"))).toBeUndefined();
    expect(ttlProblem(draft("1h", "1d"))).toBeUndefined();
    expect(ttlProblem(draft("15m", "1h 30m"))).toBeUndefined();
  });

  it("mirrors the server's TTL rules", () => {
    expect(ttlProblem(draft("30", "3600"))).toMatch(/at least 60/);
    expect(ttlProblem(draft("1h", "1m"))).toMatch(/shorter/);
    expect(ttlProblem(draft("3600", "400d"))).toMatch(/a year/);
    expect(ttlProblem(draft("1.5", "3600"))).toBe("Enter each lifetime as a duration such as 3600, 30m, 1h or 7d");
  });
});

describe("parseJwks", () => {
  it("treats empty text as no inline keys", () => {
    expect(parseJwks("  ")).toEqual({ value: null });
  });

  it("accepts a keys document", () => {
    expect(parseJwks('{"keys":[]}')).toEqual({ value: { keys: [] } });
  });

  it("explains invalid input", () => {
    expect(parseJwks("{").error).toMatch(/not valid JSON/);
    expect(parseJwks('{"kty":"RSA"}').error).toMatch(/keys array/);
  });
});

describe("write-only credentials", () => {
  it("treats the redaction marker as a stored credential and sends it back unchanged", () => {
    const credential = initialCredential(REDACTED_CREDENTIAL);
    expect(credential).toEqual({ kind: "stored" });
    expect(credentialPayload(credential)).toBe(REDACTED_CREDENTIAL);
  });

  it("starts empty when nothing is stored", () => {
    expect(initialCredential(undefined)).toEqual({ kind: "new", value: "" });
    expect(initialCredential(null)).toEqual({ kind: "new", value: "" });
  });

  it("sends a trimmed new value", () => {
    expect(credentialPayload({ kind: "new", value: "  eyJhbGciOi  " })).toBe("eyJhbGciOi");
  });

  it("clears the credential when the replacement is left empty", () => {
    expect(credentialPayload({ kind: "new", value: "   " })).toBeNull();
  });
});

describe("githubActionsSnippet", () => {
  it("requests an id token and posts it with the identity id", () => {
    const snippet = githubActionsSnippet("https://sekret.example", "ident-1");
    expect(snippet).toContain("id-token: write");
    expect(snippet).toContain("https://sekret.example");
    expect(snippet).toContain("/api/v1/auth/oidc/login");
    expect(snippet).toContain('\\"identity_id\\":\\"ident-1\\"');
  });
});
