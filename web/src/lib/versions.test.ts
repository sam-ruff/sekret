import { describe, expect, it } from "vitest";
import type { SecretVersion } from "@/api/types";
import { HISTORY_PAGE, mergeHistory, nextHistoryCursor, sameContent } from "./versions";

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

describe("nextHistoryCursor", () => {
  const page = (from: number, count: number) => Array.from({ length: count }, (_, i) => version({ version: from - i }));

  it("points at the oldest version of a full page", () => {
    expect(nextHistoryCursor(page(120, HISTORY_PAGE))).toBe(120 - HISTORY_PAGE + 1);
  });

  it("stops after a short or empty page", () => {
    expect(nextHistoryCursor(page(10, 3))).toBeUndefined();
    expect(nextHistoryCursor([])).toBeUndefined();
  });
});

describe("mergeHistory", () => {
  const plain = (n: number) => version({ version: n, value: null, value_hidden: true });
  const shown = (n: number) => version({ version: n, value: `v${n}` });

  it("shows plain history until the newest page's values arrive", () => {
    expect(mergeHistory([[plain(3), plain(2)]], [])).toEqual({ revealed: undefined, list: [plain(3), plain(2)] });
    expect(mergeHistory([[plain(3)], [plain(2)]], [undefined, [shown(2)]]).revealed).toBeUndefined();
  });

  it("keeps revealed pages while an older page's values load, without repeating versions", () => {
    const merged = mergeHistory([[plain(4), plain(3)], [plain(2), plain(1)]], [[shown(4), shown(3)], undefined]);
    expect(merged.revealed).toEqual([shown(4), shown(3)]);
    expect(merged.list.map((v) => [v.version, v.value])).toEqual([
      [4, "v4"],
      [3, "v3"],
      [2, null],
      [1, null],
    ]);
  });

  it("puts a version written since the plain list loaded first, once", () => {
    const merged = mergeHistory([[plain(3), plain(2)]], [[shown(4), shown(3)]]);
    expect(merged.list.map((v) => v.version)).toEqual([4, 3, 2]);
  });
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
