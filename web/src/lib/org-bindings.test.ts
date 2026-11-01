import { describe, expect, it } from "vitest";
import type { Me, OrgBinding } from "@/api/types";
import { bindingCoversMe, describeRemoval } from "./org-bindings";

const me: Me = {
  id: "user-sam",
  kind: "user",
  name: "Sam",
  email: "sam@example.com",
  groups: ["engineering"],
  org_rules: [],
};

const binding = (overrides: Partial<OrgBinding>): OrgBinding => ({
  principal_kind: "user",
  principal_id: "user-sam",
  principal_name: "sam@example.com",
  role: "org-admin",
  ...overrides,
});

describe("bindingCoversMe", () => {
  it("matches the signed-in person directly or through a group", () => {
    expect(bindingCoversMe(binding({}), me)).toBe("user");
    expect(bindingCoversMe(binding({ principal_kind: "group", principal_id: "engineering" }), me)).toBe("group");
    expect(bindingCoversMe(binding({ principal_id: "user-priya" }), me)).toBeNull();
    expect(bindingCoversMe(binding({ principal_kind: "identity" }), me)).toBeNull();
    expect(bindingCoversMe(binding({}), undefined)).toBeNull();
  });
});

describe("describeRemoval", () => {
  const otherAdmin = binding({ principal_id: "user-priya", principal_name: "priya@example.com" });

  it("blocks removing the only org-admin binding", () => {
    const removal = describeRemoval(binding({}), [binding({})], me, "org admin");
    expect(removal.blocked).toBe(true);
    expect(removal.title).toBe("sam@example.com is the only org admin");
    expect(removal.description).toContain("Grant org admin to someone else first.");
  });

  it("warns that removing your own admin role can lock you out", () => {
    const removal = describeRemoval(binding({}), [binding({}), otherAdmin], me, "org admin");
    expect(removal.blocked).toBe(false);
    expect(removal.title).toBe("Remove your own org admin role?");
    expect(removal.description).toContain("You will lose the access");
    expect(removal.description).toContain("You may lose access to this page");
  });

  it("says when a group binding includes you", () => {
    const group = binding({ principal_kind: "group", principal_id: "engineering", principal_name: "engineering", role: "org-member" });
    const removal = describeRemoval(group, [group, binding({})], me, "org member");
    expect(removal.title).toBe("Remove org member from engineering?");
    expect(removal.description).toContain("You are in engineering, so this applies to you.");
    expect(removal.description).not.toContain("this page");
  });

  it("keeps the plain wording for someone else", () => {
    const removal = describeRemoval(otherAdmin, [binding({}), otherAdmin], me, "org admin");
    expect(removal).toEqual({
      title: "Remove org admin from priya@example.com?",
      description: "They lose the access this role granted across the organisation.",
      blocked: false,
    });
  });
});
