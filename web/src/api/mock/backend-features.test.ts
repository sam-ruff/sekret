import { describe, expect, it } from "vitest";
import { alphabet } from "./generate";
import { decodeCursor, encodeCursor, MockBackend, MockError, ROTATION_ACTOR } from "./backend";
import { emptyState, seededState } from "./seed";
import { hostileState } from "./seed-hostile";
import type { MockState } from "./state";

const DAY = 86400;
const PNG = Uint8Array.from(
  atob(
    "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAgUlEQVR4nO3YwRGAIBQDURqwbwuwX21BPsHFYTOTo5J3hHZc5/3nNnqAAHqAAHqAAHqAAHqAAHqAgPQP32RJQCXLAEaCAxLBAMl8DpgRAeT4KkKAAAECBAjo/mgWorJjX0AaUd2w930ggRg92ztxBZI8z3chugLoCqArgK4AugLoPhP8iC+M1/dWAAAAAElFTkSuQmCC",
  ),
  (c) => c.charCodeAt(0),
);

function setup(state: MockState = emptyState(1_000_000)) {
  const clock = { now: 1_000_000 };
  const b = new MockBackend(state, () => (clock.now += 1));
  b.createProject({ slug: "app", name: "App", description: "" });
  return { b, clock, state };
}

function status(fn: () => unknown): number | undefined {
  try {
    fn();
  } catch (error) {
    if (error instanceof MockError) return error.status;
    throw error;
  }
  return undefined;
}

/** Drops the caller's organisation roles and leaves them a single built-in project role. */
function asViewer(state: MockState, role = "viewer"): void {
  state.orgBindings = [];
  state.memberships = state.memberships.map((m) => ({ ...m, role }));
}

describe("audit queries", () => {
  const seeded = () => new MockBackend(seededState(2_000_000_000), () => 2_000_000_000);

  it("seeds enough history to page and filter", () => {
    const page = seeded().orgAudit({});
    expect(page.total).toBeGreaterThanOrEqual(120);
    expect(page.entries).toHaveLength(50);
    expect(page.next_cursor).toBeTruthy();
  });

  it("filters by prefix, kind, environment, key, path and time", () => {
    const b = seeded();
    const all = b.orgAudit({ limit: 500 }).entries;
    const check = (query: Parameters<MockBackend["orgAudit"]>[0], keep: (e: (typeof all)[number]) => boolean) => {
      const page = b.orgAudit({ ...query, limit: 500 });
      expect(page.entries.map((e) => e.id)).toEqual(all.filter(keep).map((e) => e.id));
      expect(page.total).toBe(page.entries.length);
      expect(page.total).toBeGreaterThan(0);
    };
    check({ action: "secret." }, (e) => e.action.startsWith("secret."));
    check({ actor_kind: "identity" }, (e) => e.actor_kind === "identity");
    check({ environment: "prod" }, (e) => e.environment === "prod");
    check({ key: "HSM_PIN" }, (e) => e.secret_key === "HSM_PIN");
    check({ path: "/pay" }, (e) => (e.path ?? "").startsWith("/pay"));
    const middle = all[Math.floor(all.length / 2)].created_at;
    check({ since: middle }, (e) => e.created_at >= middle);
    check({ until: middle }, (e) => e.created_at <= middle);
  });

  it("searches case-insensitively across actor, target and address", () => {
    const b = seeded();
    expect(b.orgAudit({ q: "BILLING-WORKER" }).entries.every((e) => e.actor_name === "billing-worker")).toBe(true);
    expect(b.orgAudit({ q: "10.20." }).entries.every((e) => e.ip.startsWith("10.20."))).toBe(true);
    expect(b.orgAudit({ q: "zzz-nothing" })).toEqual({ entries: [], total: 0, next_cursor: null });
  });

  it("pages oldest first without gaps or repeats", () => {
    const b = seeded();
    const everything = b.orgAudit({ order: "asc", limit: 500 }).entries.map((e) => e.id);
    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const page = b.orgAudit({ order: "asc", limit: 37, cursor });
      seen.push(...page.entries.map((e) => e.id));
      cursor = page.next_cursor ?? undefined;
    } while (cursor);
    expect(seen).toEqual(everything);
  });

  it("clamps the page size and refuses a bad cursor", () => {
    const b = seeded();
    expect(b.orgAudit({ limit: 0 }).entries).toHaveLength(1);
    expect(status(() => b.orgAudit({ cursor: "not a cursor!" }))).toBe(400);
    expect(decodeCursor(encodeCursor(1700000000, "audit-00ab"))).toEqual([1700000000, "audit-00ab"]);
  });

  it("needs the organisation audit subject for the organisation log", () => {
    const { b, state } = setup();
    expect(b.orgAudit({}).total).toBeGreaterThan(0);
    asViewer(state, "developer");
    expect(status(() => b.orgAudit({}))).toBe(403);
    expect(b.projectAudit("app", {}).total).toBeGreaterThan(0);
  });
});

describe("user and identity lists", () => {
  const b = new MockBackend(seededState(2_000_000_000), () => 2_000_000_000);

  it("pages users with a total", () => {
    const first = b.listUsers({ limit: 25 });
    const second = b.listUsers({ limit: 25, offset: 25 });
    expect(first.total).toBeGreaterThanOrEqual(40);
    expect(first.items).toHaveLength(25);
    expect(second.items).toHaveLength(first.total - 25);
    expect(new Set([...first.items, ...second.items].map((u) => u.id)).size).toBe(first.total);
  });

  it("sorts users case-insensitively in either direction", () => {
    const names = b.listUsers({ limit: 500 }).items.map((u) => u.name.toLowerCase());
    expect(names).toEqual([...names].sort());
    const logins = b.listUsers({ sort: "last_login", order: "desc", limit: 500 }).items.map((u) => u.last_login_at);
    expect(logins).toEqual([...logins].sort((x, y) => y - x));
    const emails = b.listUsers({ sort: "email", order: "desc", limit: 500 }).items.map((u) => u.email);
    expect(emails).toEqual([...emails].sort().reverse());
  });

  it("filters users by text and status", () => {
    expect(b.listUsers({ q: "PRIYA@" }).items.map((u) => u.id)).toEqual(["user-priya"]);
    const disabled = b.listUsers({ status: "disabled", limit: 500 });
    expect(disabled.total).toBeGreaterThan(0);
    expect(disabled.items.every((u) => u.disabled)).toBe(true);
    expect(b.listUsers({ q: "finance", limit: 500 }).items.every((u) => u.groups.includes("finance"))).toBe(true);
  });

  it("pages, searches and sorts identities", () => {
    const all = b.listIdentities({ limit: 500 });
    expect(all.total).toBeGreaterThanOrEqual(30);
    expect(b.listIdentities({ limit: 25 }).items.map((i) => i.name)).toContain("github-deploy");
    expect(b.listIdentities({ q: "AUTOMATION", limit: 500 }).total).toBe(30);
    const created = b.listIdentities({ sort: "created", order: "desc", limit: 500 }).items.map((i) => i.created_at);
    expect(created).toEqual([...created].sort((x, y) => y - x));
    expect(b.listIdentities({ status: "active", limit: 500 }).items.every((i) => !i.disabled)).toBe(true);
  });
});

describe("project logos", () => {
  it("stores a valid image and serves it from a versioned URL", () => {
    const { b } = setup();
    const project = b.putLogo("app", PNG);
    expect(project.logo_url).toMatch(/^\/api\/v1\/projects\/proj-[^/]+\/logo\?v=\d+$/);
    expect(b.getLogo("app")).toEqual({ contentType: "image/png", bytes: PNG });
    const replaced = b.putLogo("app", PNG);
    expect(replaced.logo_url).not.toBe(project.logo_url);
    expect(b.listProjects()[0].logo_url).toBe(replaced.logo_url);
  });

  it("keeps the re-encoded PNG when one is supplied", () => {
    const { b } = setup();
    const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>');
    b.putLogo("app", svg, PNG);
    expect(b.getLogo("app")).toEqual({ contentType: "image/png", bytes: PNG });
  });

  it("refuses large and invalid files with the server's status codes", () => {
    const { b } = setup();
    const big = new Uint8Array(512 * 1024 + 1);
    big.set(PNG);
    expect(status(() => b.putLogo("app", big))).toBe(413);
    expect(status(() => b.putLogo("app", new TextEncoder().encode("hello")))).toBe(400);
    expect(status(() => b.putLogo("app", PNG.subarray(0, 40)))).toBe(400);
    expect(status(() => b.getLogo("app"))).toBe(404);
  });

  it("removes the logo and needs settings edit", () => {
    const { b, state } = setup();
    b.putLogo("app", PNG);
    expect(b.deleteLogo("app").logo_url).toBeNull();
    expect(status(() => b.getLogo("app"))).toBe(404);
    asViewer(state);
    expect(status(() => b.putLogo("app", PNG))).toBe(403);
  });
});

describe("generation and rotation", () => {
  const value = (b: MockBackend, key: string) => b.getSecret("app", "dev", key, "/").value ?? "";

  it("generates with the requested charset and length", () => {
    const { b } = setup();
    for (const charset of ["alphanumeric", "symbols", "hex", "base64url", "numeric"] as const) {
      const key = `K_${charset.toUpperCase()}`;
      expect(b.generateSecret("app", "dev", key, "/", { generator: { length: 200, charset }, comment: "" }).created).toEqual([key]);
      const generated = value(b, key);
      expect(generated).toHaveLength(200);
      expect([...generated].every((c) => alphabet(charset).includes(c))).toBe(true);
    }
  });

  it("falls back to the policy generator, then 32 alphanumeric", () => {
    const { b } = setup();
    b.generateSecret("app", "dev", "PLAIN", "/", { comment: "" });
    expect(value(b, "PLAIN")).toMatch(/^[A-Za-z0-9]{32}$/);
    b.putProjectPolicy("app", { generator: { length: 12, charset: "numeric" }, rotation_days: null });
    b.generateSecret("app", "dev", "PIN", "/", {});
    expect(value(b, "PIN")).toMatch(/^\d{12}$/);
    expect(status(() => b.generateSecret("app", "dev", "SHORT", "/", { generator: { length: 4, charset: "hex" } }))).toBe(400);
  });

  it("marks generated values, and a typed value clears the mark", () => {
    const { b } = setup();
    b.generateSecret("app", "dev", "TOKEN", "/", { comment: "first" });
    expect(b.getSecret("app", "dev", "TOKEN", "/").generated).toBe(true);
    b.setSecret("app", "dev", "TOKEN", "/", { value: "typed", comment: "" });
    expect(b.getSecret("app", "dev", "TOKEN", "/").generated).toBe(false);
    b.rollback("app", "dev", "TOKEN", "/", 1);
    expect(b.getSecret("app", "dev", "TOKEN", "/").generated).toBe(true);
    expect(b.orgAudit({ action: "secret.generate" }).total).toBe(1);
  });

  it("only schedules rotation for generated values", () => {
    const { b } = setup();
    b.setSecret("app", "dev", "TYPED", "/", { value: "x", comment: "" });
    b.putSecretPolicy("app", "dev", "TYPED", "/", { mode: "custom", generator: null, rotation_days: 7 });
    const typed = b.getSecretPolicy("app", "dev", "TYPED", "/");
    expect(typed.effective.rotation_days).toBe(7);
    expect(typed.generated).toBe(false);
    expect(typed.next_rotation_at).toBeNull();

    b.generateSecret("app", "dev", "TYPED", "/", {});
    const generated = b.getSecret("app", "dev", "TYPED", "/");
    expect(generated.next_rotation_at).toBe(generated.updated_at + 7 * DAY);
  });

  it("inherits the project policy until a secret sets its own", () => {
    const { b } = setup();
    b.generateSecret("app", "dev", "A", "/", {});
    expect(b.getSecretPolicy("app", "dev", "A", "/")).toMatchObject({ setting: { mode: "inherit" }, next_rotation_at: null });
    b.putProjectPolicy("app", { generator: null, rotation_days: 30 });
    expect(b.getSecretPolicy("app", "dev", "A", "/").effective.rotation_days).toBe(30);
    b.putSecretPolicy("app", "dev", "A", "/", { mode: "custom", generator: null, rotation_days: null });
    expect(b.getSecretPolicy("app", "dev", "A", "/")).toMatchObject({ setting: { mode: "custom" }, next_rotation_at: null });
    b.putSecretPolicy("app", "dev", "A", "/", { mode: "inherit" });
    expect(b.getSecretPolicy("app", "dev", "A", "/").effective.rotation_days).toBe(30);
  });

  it("stores an all-off project policy as off and validates bounds", () => {
    const { b } = setup();
    expect(b.getProjectPolicy("app")).toEqual({ generator: null, rotation_days: null });
    expect(b.putProjectPolicy("app", { rotation_days: 5 })).toEqual({ generator: null, rotation_days: 5 });
    b.putProjectPolicy("app", {});
    expect(b.getProjectPolicy("app")).toEqual({ generator: null, rotation_days: null });
    expect(status(() => b.putProjectPolicy("app", { rotation_days: 0 }))).toBe(400);
    expect(status(() => b.putProjectPolicy("app", { generator: { length: 513 } }))).toBe(400);
  });

  it("rotates due values as the automatic rotation identity", () => {
    const { b, clock } = setup();
    b.generateSecret("app", "dev", "DUE", "/", {});
    b.putSecretPolicy("app", "dev", "DUE", "/", { mode: "custom", generator: { length: 10, charset: "hex" }, rotation_days: 1 });
    const before = value(b, "DUE");
    expect(b.rotateDue(clock.now)).toEqual([]);
    clock.now += DAY + 10;
    expect(b.rotateDue(clock.now)).toEqual(["app/dev/DUE"]);
    expect(value(b, "DUE")).not.toBe(before);
    expect(value(b, "DUE")).toMatch(/^[0-9a-f]{10}$/);
    const [entry] = b.orgAudit({ action: "secret.rotate" }).entries;
    expect(entry).toMatchObject({ actor_kind: "identity", actor_id: ROTATION_ACTOR.id, secret_key: "DUE" });
  });

  it("needs secrets edit to generate or change a policy, and settings edit for the project policy", () => {
    const { b, state } = setup();
    b.setSecret("app", "dev", "K", "/", { value: "v", comment: "" });
    asViewer(state);
    expect(status(() => b.generateSecret("app", "dev", "K", "/", {}))).toBe(403);
    expect(status(() => b.putSecretPolicy("app", "dev", "K", "/", { mode: "inherit" }))).toBe(403);
    expect(status(() => b.putProjectPolicy("app", {}))).toBe(403);
    expect(b.getSecretPolicy("app", "dev", "K", "/").setting).toEqual({ mode: "inherit" });
  });
});

describe("hostile seed", () => {
  it("builds on the normal seed and includes markup in displayed fields", () => {
    const state = hostileState(2_000_000_000);
    expect(state.projects.some((p) => p.name.includes("<img"))).toBe(true);
    expect(state.users.some((u) => u.name.includes("onerror"))).toBe(true);
    expect(state.audit.some((e) => e.actor_name.includes("<img"))).toBe(true);
  });
});
