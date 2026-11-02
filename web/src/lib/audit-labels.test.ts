import { describe, expect, it } from "vitest";
import { actionLabel, describeDetail } from "./audit-labels";

describe("actionLabel", () => {
  it("names known actions in plain words and keeps unknown codes", () => {
    expect(actionLabel("secret.history-read")).toBe("Viewed history values");
    expect(actionLabel("project.secret-policy")).toBe("Changed the default secret policy");
    expect(actionLabel("future.thing")).toBe("future.thing");
  });
});

describe("describeDetail", () => {
  it("counts values read", () => {
    expect(describeDetail("secret.read", { count: 2, recursive: false })).toBe("2 values read");
    expect(describeDetail("secret.read", { count: 1, recursive: true })).toBe("1 value read, including sub-folders");
  });

  it("summarises writes and restores", () => {
    expect(describeDetail("secret.write", { created: ["A", "B"], updated: ["C"], deleted: [] })).toBe("2 created, 1 updated");
    expect(describeDetail("secret.write", { created: [], updated: [], deleted: [] })).toBe("No changes");
    expect(describeDetail("snapshot.restore", { snapshot: "snap-1", created: [], updated: ["A"], deleted: [] })).toBe(
      "1 updated · From snapshot snap-1",
    );
  });

  it("describes an uploaded logo by format and size", () => {
    expect(describeDetail("project.logo", { content_type: "image/png", bytes: 186 })).toBe("PNG image, 186 bytes");
    expect(describeDetail("project.logo", { content_type: "image/svg+xml", bytes: 20_480 })).toBe("SVG image, 20.0 KB");
  });

  it("describes policies instead of dumping JSON", () => {
    const policy = { generator: { length: 40, charset: "symbols" }, rotation_days: 30 };
    expect(describeDetail("project.secret-policy", { policy })).toBe("Generates 40 characters of symbols, rotates every 30 days");
    expect(describeDetail("secret.policy", { policy: null })).toBe("Policy changed");
  });

  it("says who was given or lost a role", () => {
    const binding = { principal_kind: "user", principal_id: "user-sam", role: "no-prod-values" };
    expect(describeDetail("member.add", binding)).toBe("Role no-prod-values given to user user-sam");
    expect(describeDetail("org.binding-remove", { ...binding, principal_kind: "identity" })).toBe(
      "Role no-prod-values taken from machine identity user-sam",
    );
    expect(describeDetail("role.put", { role: "deployer" })).toBe("Role deployer");
  });

  it("covers rollbacks, generation and automatic rotation", () => {
    expect(describeDetail("secret.rollback", { to_version: 3 })).toBe("Back to version 3");
    expect(describeDetail("secret.generate", { created: true })).toBe("New secret");
    expect(describeDetail("secret.rotate", { automatic: true })).toBe("Automatic");
  });

  it("names principals and roles when the reader's data knows them", () => {
    const names = {
      user: (id: string) => (id === "user-sam" ? "Sam Ruff" : undefined),
      identity: (id: string) => (id === "ident-1" ? "github-deploy" : undefined),
      role: (slug: string) => (slug === "org-admin" ? "org admin" : undefined),
    };
    expect(describeDetail("org.binding-add", { principal_kind: "user", principal_id: "user-sam", role: "org-admin" }, names)).toBe(
      "Role org admin given to user Sam Ruff",
    );
    expect(describeDetail("member.add", { principal_kind: "identity", principal_id: "ident-1", role: "viewer" }, names)).toBe(
      "Role viewer given to machine identity github-deploy",
    );
    expect(describeDetail("member.add", { principal_kind: "identity", principal_id: "ident-9", role: "viewer" }, names)).toBe(
      "Role viewer given to machine identity ident-9",
    );
  });

  it("gives machine identity actions sentences instead of ID fields", () => {
    const names = { identity: (id: string) => (id === "ident-1" ? "github-deploy" : undefined) };
    expect(describeDetail("identity.create", { identity: "ident-1", name: "ci-runner" })).toBe("Machine identity ci-runner");
    expect(describeDetail("identity.update", { identity: "ident-1" }, names)).toBe("Machine identity github-deploy");
    expect(describeDetail("identity.auth-put", { identity: "ident-1", method: "oidc" }, names)).toBe("OIDC auth on github-deploy");
    expect(describeDetail("identity.auth-delete", { identity: "ident-1", method: "kubernetes" }, names)).toBe(
      "Kubernetes auth on github-deploy",
    );
    expect(describeDetail("identity.client-secret-create", { identity: "ident-1", prefix: "sks_ab12" }, names)).toBe(
      "Client secret starting sks_ab12 for github-deploy",
    );
    expect(describeDetail("identity.client-secret-revoke", { identity: "ident-1", secret: "cs-9" }, names)).toBe(
      "Client secret of github-deploy",
    );
    expect(describeDetail("identity.revoke-tokens", { identity: "ident-2" })).toBe("Machine identity ident-2");
  });

  it("says how a machine signed in instead of showing the raw method", () => {
    expect(describeDetail("auth.machine-login", { method: "universal" })).toBe("Signed in with Universal auth");
    expect(describeDetail("auth.machine-login", { method: "oidc", claims: { sub: "repo:x" } })).toBe(
      'Signed in with OIDC auth · claims: {"sub":"repo:x"}',
    );
    expect(describeDetail("auth.machine-login", { method: "carrier-pigeon" })).toBe("Signed in with carrier-pigeon auth");
  });

  it("falls back to plain fields for anything unknown", () => {
    expect(describeDetail("identity.auth-put", { identity: "id-1", method: "oidc", empty: "", none: null })).toBe(
      "OIDC auth on id-1",
    );
    expect(describeDetail("x", { nested: { a: 1 }, list: ["a", "b"] })).toBe('nested: {"a":1} · list: a, b');
    expect(describeDetail("x", null)).toBe("");
  });
});
