import { describe, expect, it } from "vitest";
import { MAX_HISTORY_PAGE, MockBackend, MockError } from "./backend";
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

  it("pages history like the server, newest first, with a before cursor", () => {
    const b = backend();
    for (let i = 1; i <= 5; i++) at(b).write([{ key: "A", value: String(i) }]);
    const page = (limit?: number, before?: number) =>
      b.listVersions("app", "dev", "A", "/", false, { limit, before }).map((v) => v.version);
    expect(page()).toEqual([5, 4, 3, 2, 1]);
    expect(page(2)).toEqual([5, 4]);
    expect(page(2, 4)).toEqual([3, 2]);
    expect(page(2, 2)).toEqual([1]);
    expect(page(2, 1)).toEqual([]);
    expect(() => page(0)).toThrow(MockError);
    expect(() => page(MAX_HISTORY_PAGE + 1)).toThrow(MockError);
    expect(() => page(2, Number.NaN)).toThrow(MockError);
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
    const reader = { name: "Reader", description: "", rules: [{ effect: "allow" as const, subject: "secrets" as const, actions: ["read-value" as const] }] };
    // An org admin is judged by the org-admin role alone, so a deny bound to them does not stop them.
    expect(() => b.putRole("app", "reader", reader)).not.toThrow();
    b.setMyOrgRole("org-member");
    expect(() => b.putRole("app", "reader-2", reader)).toThrow(MockError);
  });

  it("lets only an admin bind deny rules to an admin", () => {
    const b = backend();
    const deny = { effect: "deny" as const, subject: "secrets" as const, actions: ["read-value" as const] };
    b.putOrgRole("org-no-values", {
      name: "No identities",
      description: "",
      rules: [{ effect: "deny", subject: "identities", actions: ["delete"] }],
    });
    b.putRole("app", "no-values", { name: "No values", description: "", rules: [deny] });
    // The org admin may.
    expect(() => b.addOrgBinding({ principal_kind: "user", principal_id: "user-sam", role: "org-no-values" })).not.toThrow();
    b.addMember("app", { principal_kind: "group", principal_id: "ops", role: "admin" });
    // Sam may add members here, but is no longer an admin of any kind.
    b.putRole("app", "manager", { name: "Manager", description: "", rules: [{ effect: "allow", subject: "members", actions: ["read", "create"] }] });
    b.addMember("app", { principal_kind: "user", principal_id: "user-sam", role: "manager" });
    b.removeMember("app", "user", "user-sam", "admin");
    b.setMyOrgRole("org-member");
    let refused: unknown;
    try {
      b.addMember("app", { principal_kind: "group", principal_id: "ops", role: "no-values" });
    } catch (error) {
      refused = error;
    }
    expect(refused).toMatchObject({ status: 403, code: "escalation", message: "only an admin can bind deny rules to an admin" });
  });

  it("refuses role conditions that can never match, as the server does", () => {
    const b = backend();
    const rule = (conditions: { paths?: string[]; keys?: string[] }) => ({
      name: "Odd",
      description: "",
      rules: [{ effect: "allow" as const, subject: "secrets" as const, actions: ["read" as const], conditions: { environments: [], tags: [], paths: [], keys: [], ...conditions } }],
    });
    expect(() => b.putRole("app", "odd", rule({ paths: ["payments/**"] }))).toThrow(/path condition "payments\/\*\*" can never match/);
    expect(() => b.putRole("app", "odd", rule({ keys: ["1DB"] }))).toThrow(/key condition "1DB" can never match/);
    expect(() => b.putRole("app", "odd", rule({ paths: ["/payments/**"], keys: ["DB_*"] }))).not.toThrow();
  });

  it("refuses to list secrets for a caller whose roles hold too many patterns", () => {
    const b = backend();
    const paths = Array.from({ length: 401 }, (_, i) => `/f${i}`);
    b.putRole("app", "many", {
      name: "Many",
      description: "",
      rules: [{ effect: "allow", subject: "secrets", actions: ["read"], conditions: { environments: [], tags: [], keys: [], paths } }],
    });
    b.addMember("app", { principal_kind: "user", principal_id: "user-sam", role: "many" });
    let refused: unknown;
    try {
      b.listSecrets("app", "dev", "/", false);
    } catch (error) {
      refused = error;
    }
    expect(refused).toMatchObject({ status: 400, code: "too_many_patterns" });
  });

  describe("OIDC auth method", () => {
    const oidc = (overrides: Partial<Extract<AuthMethodConfig, { kind: "oidc" }>> = {}): AuthMethodConfig => ({
      kind: "oidc",
      issuer: "https://issuer.example.com",
      jwks_url: null,
      bindings: { audiences: ["sekret"], subjects: ["ci:*"], claims: {} },
      ...overrides,
    });
    const setup = () => {
      const b = backend();
      const { id } = b.createIdentity({ name: "ci", description: "" });
      const lifetime = () => {
        const method = b.listAuthMethods(id).find((m) => m.kind === "oidc");
        return method?.kind === "oidc" ? method.max_token_lifetime : undefined;
      };
      return { b, id, lifetime };
    };

    it("stores the token lifetime, defaulting to an hour, between a second and ten years", () => {
      const { b, id, lifetime } = setup();
      b.putAuthMethod(id, "oidc", oidc());
      expect(lifetime()).toBe(3600);
      b.putAuthMethod(id, "oidc", oidc({ max_token_lifetime: 900 }));
      expect(lifetime()).toBe(900);
      expect(() => b.putAuthMethod(id, "oidc", oidc({ max_token_lifetime: 0 }))).toThrow(/between 1 second and 10 years/);
      expect(() => b.putAuthMethod(id, "oidc", oidc({ max_token_lifetime: 315_360_001 }))).toThrow(MockError);
    });

    it.each(["https://169.254.169.254", "http://[::ffff:169.254.169.254]/", "https://[fd00:ec2::254]/", "https://100.100.100.200"])(
      "refuses a URL at the cloud metadata address %s",
      (url) => {
        const { b, id } = setup();
        expect(() => b.putAuthMethod(id, "oidc", oidc({ jwks_url: url }))).toThrow(`url not allowed: ${url}`);
        expect(() => b.putAuthMethod(id, "oidc", oidc({ issuer: url }))).toThrow(/url not allowed/);
      },
    );
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
      expect(() => b.putAuthMethod(id, "kubernetes", k8s(REDACTED_CREDENTIAL, 315_360_001))).toThrow(MockError);
    });

    it("refuses an API server at a cloud metadata address", () => {
      const { b, id } = setup();
      const metadataHost: AuthMethodConfig = {
        kind: "kubernetes",
        mode: "token-review",
        host: "https://169.254.169.254",
        reviewer_jwt: "eyJ.real.token",
        namespaces: ["billing"],
        service_accounts: ["worker"],
        audiences: ["sekret"],
      };
      expect(() => b.putAuthMethod(id, "kubernetes", metadataHost)).toThrow(/url not allowed/);
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
