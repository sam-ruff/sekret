import { describe, expect, it } from "vitest";
import type { Rule } from "@/api/types";
import { describeConditions, toEditable, toRules } from "./rule-model";

describe("rule model", () => {
  it("creates one empty row per subject without rules", () => {
    const rows = toEditable([], ["secrets", "folders"]);
    expect(rows.map((r) => [r.subject, r.actions.length])).toEqual([
      ["secrets", 0],
      ["folders", 0],
    ]);
    expect(toRules(rows)).toEqual([]);
  });

  it("round trips rules with and without conditions", () => {
    const rules: Rule[] = [
      { effect: "allow", subject: "secrets", actions: ["read", "edit"] },
      {
        effect: "deny",
        subject: "secrets",
        actions: ["read-value"],
        conditions: { environments: ["prod"], paths: [], keys: ["DB_*"], tags: [] },
      },
    ];
    const rows = toEditable(rules, ["secrets", "folders"]);
    expect(rows).toHaveLength(3);
    expect(toRules(rows)).toEqual(rules);
  });

  it("orders actions canonically", () => {
    const rows = toEditable([{ effect: "allow", subject: "roles", actions: ["delete", "read"] }], ["roles"]);
    expect(rows[0].actions).toEqual(["read", "delete"]);
  });

  it("summarises conditions in plain words", () => {
    const [row] = toEditable(
      [{ effect: "allow", subject: "secrets", actions: ["read"], conditions: { environments: ["dev"], paths: ["/app/**"], keys: [], tags: ["db"] } }],
      ["secrets"],
    );
    expect(describeConditions(row)).toBe("in dev; under /app/**; tagged db");
  });
});
