import { describe, expect, it } from "vitest";
import type { Action, Subject } from "@/api/types";
import { ACTIONS } from "@/api/types";
import { authorise, maySomewhere, type Conditions, type Resource, type Rule } from "./permissions";

const allow = (subject: Subject, actions: Action[], conditions?: Conditions): Rule => ({
  effect: "allow",
  subject,
  actions,
  conditions,
});
const deny = (subject: Subject, actions: Action[], conditions?: Conditions): Rule => ({
  effect: "deny",
  subject,
  actions,
  conditions,
});
const secret = (environment: string, path: string, key: string, tags: string[] = []): Resource => ({
  environment,
  path,
  key,
  tags,
});

const viewer: Rule[] = [
  allow("secrets", ["read", "read-value"]),
  allow("secret-versions", ["read"]),
  allow("folders", ["read"]),
];
const admin: Rule[] = (
  ["secrets", "secret-versions", "snapshots", "folders", "environments", "members", "roles", "audit-log", "settings"] as Subject[]
).map((s) => allow(s, [...ACTIONS]));

describe("authorise", () => {
  it("denies everything by default", () => {
    expect(authorise([], "secrets", "read")).toBe(false);
  });

  it("lets a viewer read values but not write", () => {
    const r = secret("prod", "/", "DB");
    expect(authorise(viewer, "secrets", "read-value", r)).toBe(true);
    expect(authorise(viewer, "secrets", "edit", r)).toBe(false);
    expect(authorise(viewer, "members", "create")).toBe(false);
  });

  it("requires allow conditions to match positively", () => {
    const rules = [allow("secrets", ["read", "read-value"], { environments: ["dev"], paths: ["/app/**"] })];
    expect(authorise(rules, "secrets", "read-value", secret("dev", "/app/db", "X"))).toBe(true);
    expect(authorise(rules, "secrets", "read-value", secret("prod", "/app/db", "X"))).toBe(false);
    expect(authorise(rules, "secrets", "read-value", secret("dev", "/other", "X"))).toBe(false);
    expect(authorise(rules, "secrets", "read-value", {})).toBe(false);
  });

  it("supports key globs and tag conditions", () => {
    const rules = [allow("secrets", ["read-value"], { keys: ["DB_*"] }), allow("secrets", ["edit"], { tags: ["shared"] })];
    expect(authorise(rules, "secrets", "read-value", secret("x", "/", "DB_PASS"))).toBe(true);
    expect(authorise(rules, "secrets", "read-value", secret("x", "/", "API"))).toBe(false);
    expect(authorise(rules, "secrets", "edit", secret("x", "/", "A", ["shared"]))).toBe(true);
    expect(authorise(rules, "secrets", "edit", secret("x", "/", "A"))).toBe(false);
  });

  it("lets deny win and apply when the resource is unknown", () => {
    const rules = [...admin, deny("secrets", ["read-value"], { environments: ["prod"] })];
    expect(authorise(rules, "secrets", "read-value", secret("prod", "/", "A"))).toBe(false);
    expect(authorise(rules, "secrets", "read-value", secret("dev", "/", "A"))).toBe(true);
    expect(authorise(rules, "secrets", "read-value", {})).toBe(false);
    expect(authorise(rules, "secrets", "read", secret("prod", "/", "A"))).toBe(true);
  });

  it("only applies a tag-scoped deny when the tag is present", () => {
    const rules = [...admin, deny("secrets", ["edit"], { tags: ["locked"] })];
    expect(authorise(rules, "secrets", "edit", secret("dev", "/", "A"))).toBe(true);
    expect(authorise(rules, "secrets", "edit", secret("dev", "/", "A", ["locked"]))).toBe(false);
  });

  it("never grants through rules for other subjects", () => {
    expect(authorise(admin, "projects", "create")).toBe(false);
  });

  it("narrows secrets to what an access list grants and never widens", () => {
    const listed = { ...secret("prod", "/", "A"), granted: ["read", "edit"] as const };
    expect(authorise(admin, "secrets", "read", listed)).toBe(true);
    expect(authorise(admin, "secrets", "edit", listed)).toBe(true);
    expect(authorise(admin, "secrets", "create", listed)).toBe(true);
    expect(authorise(admin, "secrets", "read-value", listed)).toBe(false);
    expect(authorise(admin, "secret-versions", "read-value", listed)).toBe(false);
    expect(authorise(viewer, "secrets", "edit", listed)).toBe(false);
    expect(authorise(admin, "secrets", "read", { ...secret("prod", "/", "A"), granted: [] })).toBe(false);
    expect(authorise(admin, "snapshots", "read", { environment: "prod", granted: [] })).toBe(true);
  });

  it("treats missing conditions as unconditional", () => {
    expect(authorise([{ effect: "allow", subject: "roles", actions: ["read"] }], "roles", "read")).toBe(true);
  });
});

describe("maySomewhere", () => {
  it("is true when any allow exists and no blanket deny", () => {
    const rules = [allow("secrets", ["edit"], { environments: ["dev"] })];
    expect(maySomewhere(rules, "secrets", "edit")).toBe(true);
    expect(authorise(rules, "secrets", "edit")).toBe(false);
  });

  it("is false under an unconditional deny", () => {
    expect(maySomewhere([...admin, deny("secrets", ["edit"])], "secrets", "edit")).toBe(false);
  });

  it("is false with no matching allow", () => {
    expect(maySomewhere(viewer, "secrets", "edit")).toBe(false);
  });
});
