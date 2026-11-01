import { describe, expect, it } from "vitest";
import type { AuditEntry } from "@/api/types";
import { auditNames } from "./use-audit-names";

const entry = (overrides: Partial<AuditEntry>): AuditEntry => ({
  id: "a-1",
  action: "secret.read",
  actor_id: "user-sam",
  actor_kind: "user",
  actor_name: "Sam",
  created_at: 1_700_000_000,
  detail: {},
  ip: "127.0.0.1",
  ...overrides,
});

describe("auditNames", () => {
  it("learns names from actors and created identities in the loaded entries", () => {
    const names = auditNames(
      [
        entry({}),
        entry({ actor_kind: "identity", actor_id: "ident-1", actor_name: "github-deploy" }),
        entry({ action: "identity.create", detail: { identity: "ident-2", name: "ci-runner" } }),
      ],
      {},
    );
    expect(names.user?.("user-sam")).toBe("Sam");
    expect(names.identity?.("ident-1")).toBe("github-deploy");
    expect(names.identity?.("ident-2")).toBe("ci-runner");
    expect(names.identity?.("ident-9")).toBeUndefined();
  });

  it("prefers the directory, then falls back to entries", () => {
    const names = auditNames([entry({ actor_name: "Old name" })], {
      users: new Map([["user-sam", "Sam Ruff"]]),
      roles: new Map([["org-admin", "org admin"]]),
    });
    expect(names.user?.("user-sam")).toBe("Sam Ruff");
    expect(names.role?.("org-admin")).toBe("org admin");
    expect(names.role?.("custom")).toBeUndefined();
  });
});
