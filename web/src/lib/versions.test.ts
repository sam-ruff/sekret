import { describe, expect, it } from "vitest";
import type { SecretVersion } from "@/api/types";
import { sameContent } from "./versions";

const version = (overrides: Partial<SecretVersion>): SecretVersion => ({
  version: 1,
  value: "debug",
  value_hidden: false,
  deleted: false,
  comment: "",
  tags: [],
  actor: "alice",
  created_at: 1_700_000_000,
  ...overrides,
});

describe("sameContent", () => {
  it("matches the same value and tags in any order", () => {
    expect(sameContent(version({ tags: ["a", "b"] }), version({ version: 4, tags: ["b", "a"] }))).toBe(true);
  });

  it("differs on value or tags", () => {
    expect(sameContent(version({}), version({ value: "info" }))).toBe(false);
    expect(sameContent(version({}), version({ tags: ["x"] }))).toBe(false);
  });

  it("never claims a match it cannot see", () => {
    expect(sameContent(version({ value: null, value_hidden: true }), version({ value: null, value_hidden: true }))).toBe(false);
    expect(sameContent(version({}), undefined)).toBe(false);
    expect(sameContent(version({ deleted: true }), version({}))).toBe(false);
  });
});
