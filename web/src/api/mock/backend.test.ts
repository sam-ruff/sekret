import { describe, expect, it } from "vitest";
import { MockBackend, MockError } from "./backend";
import { emptyState } from "./seed";
import { REDACTED_CREDENTIAL, type AuthMethodConfig } from "../types";

function backend() {
  let clock = 1_000;
  const b = new MockBackend(emptyState(clock), () => (clock += 1));
  b.createProject({ slug: "app", name: "App", description: "" });
  return b;
}

const at = (b: MockBackend) => ({
  write: (upserts: { key: string; value: string }[]) =>
    b.batchWrite("app", "dev", { path: "/", upserts: upserts.map((u) => ({ ...u, comment: "", tags: null })), deletes: [] }),
});

describe("mock backend", () => {
  it("reports unchanged writes without a new snapshot", () => {
    const b = backend();
    expect(at(b).write([{ key: "A", value: "1" }]).created).toEqual(["A"]);
    const again = at(b).write([{ key: "A", value: "1" }]);
    expect(again.unchanged).toEqual(["A"]);
    expect(again.snapshot_id).toBeNull();
    expect(b.listSnapshots("app", "dev")).toHaveLength(1);
  });

  it("refuses to delete an environment that still holds secrets", () => {
    const b = backend();
    at(b).write([{ key: "A", value: "1" }]);
    expect(() => b.deleteEnvironment("app", "dev")).toThrow(MockError);
    b.batchWrite("app", "dev", { path: "/", upserts: [], deletes: ["A"] });
    b.deleteEnvironment("app", "dev");
    expect(b.listEnvironments("app").map((e) => e.slug)).not.toContain("dev");
  });

  it("rolls back by writing a new version", () => {
    const b = backend();
    at(b).write([{ key: "A", value: "1" }]);
    at(b).write([{ key: "A", value: "2" }]);
    b.rollback("app", "dev", "A", "/", 1);
    const versions = b.listVersions("app", "dev", "A", "/", true);
    expect(versions.map((v) => [v.version, v.value])).toEqual([
      [3, "1"],
      [2, "2"],
      [1, "1"],
    ]);
  });

  it("previews and restores a snapshot", () => {
    const b = backend();
    const first = at(b).write([{ key: "A", value: "1" }]).snapshot_id ?? "";
    at(b).write([
      { key: "A", value: "2" },
      { key: "B", value: "x" },
    ]);
    const detail = b.getSnapshot("app", "dev", first, "/");
    expect(detail.changes.map((c) => [c.key, c.kind])).toEqual([
      ["A", "changed"],
      ["B", "removed"],
    ]);
    const result = b.restoreSnapshot("app", "dev", first, "/");
    expect(result.updated).toEqual(["/A"]);
    expect(result.deleted).toEqual(["/B"]);
    const after = b.listSecrets("app", "dev", "/", true).secrets;
    expect(after.map((s) => [s.key, s.value])).toEqual([["A", "1"]]);
  });

  it("refuses roles that would escalate access", () => {
    const b = backend();
    b.putRole("app", "no-prod", {
      name: "No prod",
      description: "",
      rules: [{ effect: "deny", subject: "secrets", actions: ["read-value"], conditions: { environments: ["prod"], paths: [], keys: [], tags: [] } }],
    });
    b.addMember("app", { principal_kind: "user", principal_id: "user-sam", role: "no-prod" });
    expect(() =>
      b.putRole("app", "reader", { name: "Reader", description: "", rules: [{ effect: "allow", subject: "secrets", actions: ["read-value"] }] }),
    ).toThrow(MockError);
  });

  describe("Kubernetes reviewer token", () => {
    const k8s = (reviewer_jwt?: string | null, max_token_lifetime?: number): AuthMethodConfig => ({
      kind: "kubernetes",
      mode: "token-review",
      host: "https://k8s.example:6443",
      namespaces: ["billing"],
      service_accounts: ["worker"],
      audiences: ["sekret"],
      ...(reviewer_jwt === undefined ? {} : { reviewer_jwt }),
      ...(max_token_lifetime === undefined ? {} : { max_token_lifetime }),
    });
    const stored = (b: MockBackend, id: string) => {
      const method = b.listAuthMethods(id).find((m) => m.kind === "kubernetes");
      return method?.kind === "kubernetes" ? method.reviewer_jwt : undefined;
    };
    const setup = () => {
      const b = backend();
      const { id } = b.createIdentity({ name: "worker", description: "" });
      return { b, id };
    };

    it("redacts a stored token on read", () => {
      const { b, id } = setup();
      b.putAuthMethod(id, "kubernetes", k8s("eyJ.real.token"));
      expect(stored(b, id)).toBe(REDACTED_CREDENTIAL);
    });

    it("keeps the stored token when the marker is sent back", () => {
      const { b, id } = setup();
      b.putAuthMethod(id, "kubernetes", k8s("eyJ.real.token"));
      b.putAuthMethod(id, "kubernetes", k8s(REDACTED_CREDENTIAL));
      expect(stored(b, id)).toBe(REDACTED_CREDENTIAL);
    });

    it("stores the token lifetime, defaulting to an hour, and refuses less than a second", () => {
      const { b, id } = setup();
      const lifetime = () => {
        const method = b.listAuthMethods(id).find((m) => m.kind === "kubernetes");
        return method?.kind === "kubernetes" ? method.max_token_lifetime : undefined;
      };
      b.putAuthMethod(id, "kubernetes", k8s("eyJ.real.token", 600));
      expect(lifetime()).toBe(600);
      b.putAuthMethod(id, "kubernetes", k8s(REDACTED_CREDENTIAL));
      expect(lifetime()).toBe(3600);
      expect(() => b.putAuthMethod(id, "kubernetes", k8s(REDACTED_CREDENTIAL, 0))).toThrow(MockError);
    });

    it("clears the token when it is empty or omitted", () => {
      const { b, id } = setup();
      b.putAuthMethod(id, "kubernetes", k8s("eyJ.real.token"));
      b.putAuthMethod(id, "kubernetes", k8s(""));
      expect(stored(b, id)).toBeNull();
      b.putAuthMethod(id, "kubernetes", k8s("eyJ.real.token"));
      b.putAuthMethod(id, "kubernetes", k8s());
      expect(stored(b, id)).toBeNull();
    });

    it("refuses the marker when nothing is stored", () => {
      const { b, id } = setup();
      expect(() => b.putAuthMethod(id, "kubernetes", k8s(REDACTED_CREDENTIAL))).toThrow(/no stored reviewer token/);
    });
  });

  it("pages the audit log without skipping entries that share a second", () => {
    const clock = 1_000;
    const b = new MockBackend(emptyState(clock), () => clock);
    b.createProject({ slug: "app", name: "App", description: "" });
    for (const key of ["A", "B", "C", "D"]) at(b).write([{ key, value: "1" }]);
    const all = b.orgAudit({}).entries;
    expect(new Set(all.map((e) => e.created_at)).size).toBe(1);

    for (const order of ["desc", "asc"] as const) {
      const seen: string[] = [];
      let cursor: string | undefined;
      do {
        const page = b.orgAudit({ cursor, order, limit: 2 });
        expect(page.total).toBe(all.length);
        seen.push(...page.entries.map((e) => e.id));
        cursor = page.next_cursor ?? undefined;
      } while (cursor);
      const expected = all.map((e) => e.id);
      expect(seen).toEqual(order === "desc" ? expected : [...expected].reverse());
    }
  });

  it("hides values the caller cannot read", () => {
    const b = backend();
    b.batchWrite("app", "prod", { path: "/", upserts: [{ key: "K", value: "v", comment: "", tags: null }], deletes: [] });
    b.putRole("app", "no-prod", {
      name: "No prod",
      description: "",
      rules: [{ effect: "deny", subject: "secrets", actions: ["read-value"], conditions: { environments: ["prod"], paths: [], keys: [], tags: [] } }],
    });
    b.addMember("app", { principal_kind: "user", principal_id: "user-sam", role: "no-prod" });
    const [secret] = b.listSecrets("app", "prod", "/", true).secrets;
    expect(secret.value_hidden).toBe(true);
    expect(secret.value).toBeNull();
  });
});
