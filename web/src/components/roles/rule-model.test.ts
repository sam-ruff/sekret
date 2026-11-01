import { describe, expect, it } from "vitest";
import type { Rule } from "@/api/types";
import { actionsFor, describeConditions, onlyDenies, SUBJECT_ACTIONS, toEditable, toRules } from "./rule-model";

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

  it("offers only the actions the server checks for each subject", () => {
    expect(actionsFor({ subject: "secrets", actions: [] })).toEqual(["read", "read-value", "create", "edit", "delete"]);
    expect(actionsFor({ subject: "secret-versions", actions: [] })).toEqual(["read", "read-value"]);
    expect(actionsFor({ subject: "audit-log", actions: [] })).toEqual(["read"]);
    expect(actionsFor({ subject: "snapshots", actions: [] })).toEqual(["read", "edit"]);
    expect(actionsFor({ subject: "folders", actions: [] })).toEqual(["read", "create", "delete"]);
    expect(actionsFor({ subject: "projects", actions: [] })).toEqual(["create"]);
    expect(actionsFor({ subject: "backups", actions: [] })).toEqual(["read"]);
    // Only secrets and their history have values to read.
    for (const subject of Object.keys(SUBJECT_ACTIONS) as (keyof typeof SUBJECT_ACTIONS)[]) {
      if (subject === "secrets" || subject === "secret-versions") continue;
      expect(SUBJECT_ACTIONS[subject]).not.toContain("read-value");
    }
  });

  it("keeps an action an older role already holds so it can be seen and removed", () => {
    expect(actionsFor({ subject: "folders", actions: ["edit"] })).toEqual(["read", "create", "edit", "delete"]);
    const rows = toEditable([{ effect: "allow", subject: "folders", actions: ["read", "edit"] }], ["folders"]);
    expect(toRules(rows)).toEqual([{ effect: "allow", subject: "folders", actions: ["read", "edit"] }]);
  });

  it("summarises conditions in plain words", () => {
    const [row] = toEditable(
      [{ effect: "allow", subject: "secrets", actions: ["read"], conditions: { environments: ["dev"], paths: ["/app/**"], keys: [], tags: ["db"] } }],
      ["secrets"],
    );
    expect(describeConditions(row)).toBe("in dev; under /app/**; tagged db");
  });

  it("spots a role that only takes access away", () => {
    const deny: Rule = { effect: "deny", subject: "secrets", actions: ["read-value"] };
    const allow: Rule = { effect: "allow", subject: "secrets", actions: ["read"] };
    expect(onlyDenies([deny])).toBe(true);
    expect(onlyDenies([deny, allow])).toBe(false);
    expect(onlyDenies([])).toBe(false);
  });
});
