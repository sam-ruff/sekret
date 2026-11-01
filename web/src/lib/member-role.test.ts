import { describe, expect, it, vi } from "vitest";
import { ApiError } from "@/api/client";
import type { Membership } from "@/api/types";
import { changeMemberRole, RoleChangeIncomplete, type MemberApi } from "./member-role";

const member: Membership = {
  created_at: 0,
  principal_id: "u1",
  principal_kind: "user",
  principal_name: "Alex",
  role: "viewer",
};

function fakeApi(overrides: Partial<MemberApi> = {}) {
  const calls: string[] = [];
  const api: MemberApi = {
    addMember: vi.fn(async (_project, body) => {
      calls.push(`add ${body.role}`);
    }),
    removeMember: vi.fn(async (_project, _kind, _id, role) => {
      calls.push(`remove ${role}`);
    }),
    ...overrides,
  };
  return { api, calls };
}

const names = (slug: string) => ({ viewer: "Viewer", developer: "Developer" })[slug] ?? slug;

describe("changeMemberRole", () => {
  it("adds the new role before removing the old one", async () => {
    const { api, calls } = fakeApi();
    await changeMemberRole(api, "storefront", member, "developer");
    expect(calls).toEqual(["add developer", "remove viewer"]);
    expect(api.addMember).toHaveBeenCalledWith("storefront", { principal_kind: "user", principal_id: "u1", role: "developer" });
    expect(api.removeMember).toHaveBeenCalledWith("storefront", "user", "u1", "viewer");
  });

  it("does nothing when the role is unchanged", async () => {
    const { api, calls } = fakeApi();
    await changeMemberRole(api, "storefront", member, "viewer");
    expect(calls).toEqual([]);
  });

  it("leaves the old role alone when adding the new one fails", async () => {
    const refused = new ApiError("that role grants more than you hold", 403, "privilege_escalation");
    const { api } = fakeApi({ addMember: vi.fn(async () => Promise.reject(refused)) });
    await expect(changeMemberRole(api, "storefront", member, "developer")).rejects.toBe(refused);
    expect(api.removeMember).not.toHaveBeenCalled();
  });

  it("says plainly that both roles are held when removing the old one fails", async () => {
    const { api } = fakeApi({
      removeMember: vi.fn(async () => Promise.reject(new ApiError("not allowed", 403, "forbidden"))),
    });
    const change = changeMemberRole(api, "storefront", member, "developer", names);
    await expect(change).rejects.toBeInstanceOf(RoleChangeIncomplete);
    await expect(change).rejects.toThrow(
      /^Alex now has the Developer role, but the Viewer role could not be removed \(.+\)\. They hold both until you remove Viewer from the list\.$/,
    );
  });
});
