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

  it("falls back to plain fields for anything unknown", () => {
    expect(describeDetail("identity.auth-put", { identity: "id-1", method: "oidc", empty: "", none: null })).toBe(
      "identity: id-1 · method: oidc",
    );
    expect(describeDetail("x", { nested: { a: 1 }, list: ["a", "b"] })).toBe('nested: {"a":1} · list: a, b');
    expect(describeDetail("x", null)).toBe("");
  });
});
