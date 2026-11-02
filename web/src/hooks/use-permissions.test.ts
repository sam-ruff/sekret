import { describe, expect, it } from "vitest";
import type { Rule } from "@/lib/permissions";
import { permissionsFrom, withAdminManagement } from "./use-permissions";

// Everything allowed, then a deny on roles and members, as another admin might bind.
const rules: Rule[] = [
  { effect: "allow", subject: "roles", actions: ["read", "create", "edit", "delete"] },
  { effect: "allow", subject: "members", actions: ["read", "create", "delete"] },
  { effect: "allow", subject: "org-members", actions: ["read", "create", "delete"] },
  { effect: "allow", subject: "secrets", actions: ["read", "edit"] },
  { effect: "deny", subject: "roles", actions: ["edit"] },
  { effect: "deny", subject: "members", actions: ["create"] },
  { effect: "deny", subject: "org-members", actions: ["create"] },
  { effect: "deny", subject: "secrets", actions: ["edit"] },
];

describe("withAdminManagement", () => {
  it("lets an org admin manage roles, bindings and members whatever denies they hold", () => {
    const admin = withAdminManagement(permissionsFrom(rules), true);
    expect(admin.can("roles", "edit")).toBe(true);
    expect(admin.can("members", "create")).toBe(true);
    expect(admin.can("org-members", "create")).toBe(true);
    expect(admin.canSomewhere("org-roles", "create")).toBe(true);
    // Only management is lifted; other denies still apply.
    expect(admin.can("secrets", "edit")).toBe(false);
  });

  it("changes nothing for anyone else", () => {
    const other = withAdminManagement(permissionsFrom(rules), false);
    expect(other.can("roles", "edit")).toBe(false);
    expect(other.can("members", "create")).toBe(false);
    expect(other.can("roles", "read")).toBe(true);
  });
});
