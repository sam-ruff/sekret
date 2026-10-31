import { describe, expect, it } from "vitest";
import { diffLines } from "./diff";

describe("diffLines", () => {
  it("reports identical text as unchanged", () => {
    expect(diffLines("a\nb", "a\nb")).toEqual([
      { kind: "same", text: "a" },
      { kind: "same", text: "b" },
    ]);
  });

  it("shows a single-line change as remove then add", () => {
    expect(diffLines("old", "new")).toEqual([
      { kind: "removed", text: "old" },
      { kind: "added", text: "new" },
    ]);
  });

  it("keeps common lines around insertions and deletions", () => {
    expect(diffLines("a\nb\nc", "a\nc\nd")).toEqual([
      { kind: "same", text: "a" },
      { kind: "removed", text: "b" },
      { kind: "same", text: "c" },
      { kind: "added", text: "d" },
    ]);
  });

  it("matches shared lines at both ends without a large table", () => {
    const before = `${"x\n".repeat(60_000)}old\n${"y\n".repeat(5_000)}`;
    const after = `${"x\n".repeat(60_000)}new\n${"y\n".repeat(5_000)}`;
    const lines = diffLines(before, after);
    expect(lines?.filter((l) => l.kind !== "same")).toEqual([
      { kind: "removed", text: "old" },
      { kind: "added", text: "new" },
    ]);
    expect(lines).toHaveLength(65_003);
  });

  it("refuses to compare values whose differing parts are too large, instead of throwing", () => {
    // Two 64 KiB values with nothing in common, the largest a secret can be.
    const before = "\n".repeat(65_536);
    const after = "a\n".repeat(32_768);
    expect(() => diffLines(before, after)).not.toThrow();
    expect(diffLines(before, after)).toBeNull();
  });

  it("still compares a change just under the limit", () => {
    const before = Array.from({ length: 1_000 }, (_, i) => `a${i}`).join("\n");
    const after = Array.from({ length: 1_000 }, (_, i) => `b${i}`).join("\n");
    expect(diffLines(before, after)).toHaveLength(2_000);
  });

  it("handles empty sides", () => {
    expect(diffLines("", "x")).toEqual([{ kind: "added", text: "x" }]);
    expect(diffLines("x", "")).toEqual([{ kind: "removed", text: "x" }]);
    expect(diffLines("", "")).toEqual([]);
  });
});
