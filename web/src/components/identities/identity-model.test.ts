import { describe, expect, it } from "vitest";
import {
  credentialPayload,
  githubActionsSnippet,
  initialCredential,
  parseJwks,
  ttlProblem,
  type IdentityDraft,
} from "./identity-model";
import { REDACTED_CREDENTIAL } from "@/api/types";

const draft = (tokenTtl: string, tokenMaxTtl: string): IdentityDraft => ({
  name: "ci",
  description: "",
  tokenTtl,
  tokenMaxTtl,
  trustedCidrs: [],
});

describe("ttlProblem", () => {
  it("accepts sensible TTLs", () => {
    expect(ttlProblem(draft("3600", "86400"))).toBeUndefined();
  });

  it("mirrors the server's TTL rules", () => {
    expect(ttlProblem(draft("30", "3600"))).toMatch(/at least 60/);
    expect(ttlProblem(draft("3600", "60"))).toMatch(/shorter/);
    expect(ttlProblem(draft("3600", String(400 * 86400)))).toMatch(/a year/);
    expect(ttlProblem(draft("1.5", "3600"))).toMatch(/whole numbers/);
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
