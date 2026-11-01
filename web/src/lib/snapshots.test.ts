import { describe, expect, it } from "vitest";
import type { SnapshotChange } from "@/api/types";
import { restoreSummary, snapshotTitle } from "./snapshots";

describe("snapshotTitle", () => {
  it.each([
    ["1 created, 0 updated, 0 deleted in /payments/stripe", "1 secret added in /payments/stripe"],
    ["0 created, 2 updated, 1 deleted in /", "2 secrets changed, 1 deleted in /"],
    ["3 created, 1 updated, 2 deleted", "3 secrets added, 1 changed, 2 deleted"],
    ["0 created, 0 updated, 0 deleted in /a", "No changes in /a"],
    ["restored snapshot 0192", "restored snapshot 0192"],
  ])("turns %s into %s", (reason, title) => {
    expect(snapshotTitle(reason)).toBe(title);
  });
});

const change = (kind: SnapshotChange["kind"], key: string, path = "/"): SnapshotChange => ({
  kind,
  key,
  path,
  current_version: kind === "added" ? null : 3,
  snapshot_version: kind === "removed" ? null : 1,
});

describe("restoreSummary", () => {
  it("names removed secrets and says their history is kept", () => {
    const summary = restoreSummary(
      [change("removed", "FEATURE_FLAGS"), change("removed", "SESSION_SECRET"), change("changed", "LOG_LEVEL")],
      "/",
      "Development",
    );
    expect(summary).toBe(
      "Restoring / in Development removes FEATURE_FLAGS and SESSION_SECRET and changes LOG_LEVEL. " +
        "Each change is saved as a new version, so removed secrets keep their history and this can be undone with another restore.",
    );
  });

  it("describes restores with nothing removed without mentioning removal", () => {
    const summary = restoreSummary([change("added", "SMTP_PASS", "/email"), change("changed", "PORT")], "/", "Staging");
    expect(summary).toBe(
      "Restoring / in Staging brings back /email/SMTP_PASS and changes PORT. " +
        "Each change is saved as a new version, so history is kept and this can be undone with another restore.",
    );
  });

  it("shortens long lists", () => {
    const removed = ["A", "B", "C", "D", "E"].map((key) => change("removed", key, "/app"));
    expect(restoreSummary(removed, "/app", "Production")).toMatch(
      /^Restoring \/app in Production removes \/app\/A, \/app\/B, \/app\/C and 2 more\./,
    );
  });

  it("says when there is nothing to restore", () => {
    expect(restoreSummary([], "/", "Development")).toBe("/ in Development already matches this snapshot.");
  });
});
