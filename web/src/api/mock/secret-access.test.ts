import { describe, expect, it } from "vitest";
import { MockBackend, MockError } from "./backend";
import { emptyState, seededState } from "./seed";
import type { MockState } from "./state";

function setup() {
  const state = emptyState(1_000_000);
  const clock = { now: 1_000_000 };
  const b = new MockBackend(state, () => (clock.now += 1));
  b.createProject({ slug: "app", name: "App", description: "" });
  b.batchWrite("app", "prod", { path: "/", upserts: [{ key: "STRIPE", value: "sk_live" }, { key: "OPEN", value: "o" }] });
  const pod = b.createIdentity({ name: "payments-pod", description: "" });
  return { b, state, pod: pod.id };
}

function failure(fn: () => unknown): { status: number; code: string } | undefined {
  try {
    fn();
  } catch (error) {
    if (error instanceof MockError) return { status: error.status, code: error.code };
    throw error;
  }
  return undefined;
}

/** Leaves the caller a developer in the project, off every list and no admin. */
function asDeveloper(state: MockState): void {
  state.orgBindings = [];
  state.memberships = state.memberships.map((m) => ({ ...m, role: "developer" }));
}

describe("per-secret access in the mock", () => {
  it("is off by default and restricting needs it on", () => {
    const { b } = setup();
    expect(b.getProject("app").secret_access).toBe(false);
    expect(b.getSecretAccessSetting("app")).toEqual({ enabled: false, restricted: [], restricted_count: 0 });
    expect(failure(() => b.changeSecretAccess("app", "prod", "STRIPE", "/", { restricted: true }))).toEqual({
      status: 409,
      code: "secret_access_off",
    });
    expect(failure(() => b.setSecret("app", "prod", "NEW", "/", { value: "x", restricted: true }))?.code).toBe(
      "secret_access_off",
    );
  });

  it("refuses turning the setting off while anything is restricted", () => {
    const { b } = setup();
    b.putSecretAccessSetting("app", true);
    b.changeSecretAccess("app", "prod", "STRIPE", "/", { restricted: true });
    expect(failure(() => b.putSecretAccessSetting("app", false))).toEqual({ status: 409, code: "secrets_restricted" });
    expect(b.getSecretAccessSetting("app").restricted).toEqual([
      { environment: "prod", path: "/", key: "STRIPE", deleted: false, grants: 0 },
    ]);
    b.changeSecretAccess("app", "prod", "STRIPE", "/", { restricted: false });
    expect(b.putSecretAccessSetting("app", false).enabled).toBe(false);
  });

  it("grants always include read, replace on regrant and go on revoke", () => {
    const { b, pod } = setup();
    b.putSecretAccessSetting("app", true);
    const granted = b.changeSecretAccess("app", "prod", "STRIPE", "/", {
      restricted: true,
      grant: [
        { principal_kind: "identity", principal_id: pod, actions: ["read-value"] },
        { principal_kind: "group", principal_id: "finance", actions: [] },
      ],
    });
    expect(granted.restricted).toBe(true);
    expect(granted.grants.map((g) => [g.principal_name, g.actions])).toEqual([
      ["finance", ["read"]],
      ["payments-pod", ["read", "read-value"]],
    ]);
    const regranted = b.changeSecretAccess("app", "prod", "STRIPE", "/", {
      grant: [{ principal_kind: "identity", principal_id: pod, actions: ["edit"] }],
      revoke: [{ principal_kind: "group", principal_id: "finance" }],
    });
    expect(regranted.grants.map((g) => g.actions)).toEqual([["read", "edit"]]);
    expect(failure(() => b.changeSecretAccess("app", "prod", "STRIPE", "/", {
      grant: [{ principal_kind: "group", principal_id: "ops", actions: ["create"] }],
    }))?.status).toBe(400);
    expect(failure(() => b.changeSecretAccess("app", "prod", "STRIPE", "/", {
      grant: [{ principal_kind: "identity", principal_id: "nobody", actions: [] }],
    }))?.status).toBe(400);
    b.deleteIdentity(pod);
    expect(b.getSecretAccess("app", "prod", "STRIPE", "/").grants).toEqual([]);
  });

  it("hides a restricted secret from someone off its list and narrows those on it", () => {
    const { b, state } = setup();
    b.putSecretAccessSetting("app", true);
    b.changeSecretAccess("app", "prod", "STRIPE", "/", { restricted: true });
    asDeveloper(state);
    expect(b.listSecrets("app", "prod", "/", false).secrets.map((s) => s.key)).toEqual(["OPEN"]);
    expect(failure(() => b.getSecret("app", "prod", "STRIPE", "/"))?.status).toBe(404);
    expect(failure(() => b.setSecret("app", "prod", "STRIPE", "/", { value: "x" }))?.status).toBe(404);
    expect(failure(() => b.deleteSecret("app", "prod", "STRIPE", "/"))?.status).toBe(404);
    expect(failure(() => b.getSecretAccess("app", "prod", "STRIPE", "/"))?.status).toBe(403);
    expect(b.permissions("app").manages_secret_access).toBe(false);

    state.grants.push({
      secretId: state.secrets.find((s) => s.key === "STRIPE")?.id ?? "",
      principal_kind: "user",
      principal_id: state.me.id,
      actions: ["read"],
      created_at: 1,
    });
    const listed = b.getSecret("app", "prod", "STRIPE", "/");
    expect(listed.restricted).toBe(true);
    expect(listed.value).toBeNull();
    expect(listed.value_hidden).toBe(true);
    expect(failure(() => b.setSecret("app", "prod", "STRIPE", "/", { value: "x" }))?.status).toBe(403);
  });

  it("creates restricted secrets for admins only and never flips the flag on a write", () => {
    const { b, state } = setup();
    b.putSecretAccessSetting("app", true);
    b.setSecret("app", "prod", "NEW", "/", { value: "x", restricted: true });
    expect(b.getSecret("app", "prod", "NEW", "/").restricted).toBe(true);
    expect(failure(() => b.setSecret("app", "prod", "NEW", "/", { value: "y", restricted: false }))?.status).toBe(400);
    asDeveloper(state);
    expect(failure(() => b.setSecret("app", "prod", "OTHER", "/", { value: "x", restricted: true }))?.status).toBe(403);
  });

  it("seeds one project with a restricted secret and leaves the others off", () => {
    const b = new MockBackend(seededState(2_000_000_000), () => 2_000_000_000);
    const setting = b.getSecretAccessSetting("storefront");
    expect(setting.enabled).toBe(true);
    expect(setting.restricted).toEqual([
      { environment: "prod", path: "/", key: "STRIPE_SECRET_KEY", deleted: false, grants: 2 },
    ]);
    expect(b.getProject("payments-api").secret_access).toBe(false);
  });
});
