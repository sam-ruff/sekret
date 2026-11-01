import { describe, expect, it } from "vitest";
import { mockBodyLimit } from "./server";

describe("mockBodyLimit", () => {
  it("mirrors the server's per-route write limits", () => {
    const env = "/api/v1/projects/app/environments/dev";
    expect(mockBodyLimit(`${env}/secrets/batch`)).toBe(4 * 1024 * 1024);
    expect(mockBodyLimit(`${env}/secrets/DB_URL`)).toBe(1024 * 1024);
    expect(mockBodyLimit("/api/v1/projects/app/roles/ops")).toBe(1024 * 1024);
    expect(mockBodyLimit("/api/v1/identities/id/auth/kubernetes")).toBe(1024 * 1024);
    expect(mockBodyLimit("/api/v1/projects/app/logo")).toBe(512 * 1024);
    expect(mockBodyLimit("/api/v1/projects/app/members")).toBe(256 * 1024);
  });
});
