import { describe, expect, it } from "vitest";
import type { Membership, Project } from "@/api/types";
import { projectAccessRows } from "./project-access-model";

const project = (slug: string, name: string): Project => ({ id: `p-${slug}`, slug, name, description: "", created_at: 0 });
const member = (principal_kind: Membership["principal_kind"], principal_id: string, role: string): Membership => ({
  principal_kind,
  principal_id,
  principal_name: principal_id,
  role,
  created_at: 0,
});

describe("projectAccessRows", () => {
  it("lists the identity's roles, member projects first, and marks projects whose members are hidden", () => {
    const rows = projectAccessRows(
      "id-1",
      [project("zeta", "Zeta"), project("alpha", "Alpha"), project("hidden", "Hidden"), project("beta", "Beta")],
      [
        [member("identity", "id-1", "viewer"), member("identity", "id-1", "deployer")],
        [member("identity", "id-2", "admin")],
        undefined,
        [member("user", "id-1", "admin")],
      ],
    );
    expect(rows.map((r) => [r.project.slug, r.roles])).toEqual([
      ["zeta", ["viewer", "deployer"]],
      ["alpha", []],
      ["beta", []],
      ["hidden", null],
    ]);
  });
});
