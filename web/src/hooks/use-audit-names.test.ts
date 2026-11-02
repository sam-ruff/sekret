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

  it("names projects from the directory, then from the slug a project entry records", () => {
    const names = auditNames(
      [
        entry({ action: "project.delete", project_id: "proj-gone", detail: { slug: "old-shop" } }),
        entry({ action: "project.create", project_id: "proj-1", detail: { slug: "storefront" } }),
        entry({ action: "secret.read", project_id: "proj-2", detail: { slug: "not-a-project-entry" } }),
      ],
      { projects: new Map([["proj-1", "Storefront"]]) },
    );
    expect(names.project?.("proj-1")).toBe("Storefront");
    expect(names.project?.("proj-gone")).toBe("old-shop");
    expect(names.project?.("proj-2")).toBeUndefined();
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
