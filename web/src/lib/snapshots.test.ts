import { describe, expect, it } from "vitest";
import { snapshotTitle } from "./snapshots";

describe("snapshotTitle", () => {
  it.each([
    ["1 created, 0 updated, 0 deleted in /payments/stripe", "1 added in /payments/stripe"],
    ["0 created, 2 updated, 1 deleted in /", "2 changed, 1 deleted in the top folder"],
    ["3 created, 1 updated, 2 deleted", "3 added, 1 changed, 2 deleted"],
    ["0 created, 0 updated, 0 deleted in /a", "No changes in /a"],
    ["restored snapshot 0192", "restored snapshot 0192"],
  ])("turns %s into %s", (reason, title) => {
    expect(snapshotTitle(reason)).toBe(title);
  });
});
