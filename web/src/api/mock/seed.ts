import type { Me, User } from "../types";
import { fromBase64, MockBackend } from "./backend";
import type { MockState } from "./state";

const DAY = 24 * 3600;

/** A small seeded generator, so the seed is identical on every load and tests stay deterministic. */
function seededRandom(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(random: () => number, items: readonly T[]): T {
  return items[Math.floor(random() * items.length)];
}

const FIRST_NAMES = [
  "Aisha", "Ben", "Carys", "Dev", "Eilidh", "Femi", "Grace", "Hamza", "Isla", "Jack", "Kofi", "Leah", "Mohammed",
  "Niamh", "Oscar", "Poppy", "Rhys", "Saoirse", "Tariq", "Una", "Vikram", "Wren", "Yusuf", "Zara",
];
const LAST_NAMES = [
  "Ahmed", "Brennan", "Clarke", "Davies", "Evans", "Fraser", "Gill", "Hughes", "Iqbal", "Jones", "Kaur", "Lewis",
  "MacLeod", "Nolan", "Owusu", "Patel", "Quinn", "Reid", "Singh", "Thomas", "Walsh", "Young",
];
const GROUPS = ["engineering", "platform", "finance", "support", "security", "data"];

const IDENTITY_NAMES = [
  "ansible-runner", "argo-cd", "backup-agent", "cert-renewer", "cron-reports", "data-pipeline", "etl-nightly",
  "feature-flags-sync", "grafana-agent", "helm-releases", "inventory-sync", "jenkins-legacy", "k6-load-tests",
  "kafka-connect", "log-shipper", "metrics-exporter", "nightly-backup", "nomad-jobs", "ops-bot",
  "payments-reconciler", "prometheus-scraper", "queue-worker", "release-bot", "renovate", "search-indexer",
  "staging-seeder", "terraform-cloud", "uptime-checker", "vault-migrator", "webhook-relay",
];

// A 48px PNG, the format the server stores every logo in.
const PAYMENTS_LOGO =
  "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAgUlEQVR4nO3YwRGAIBQDURqwbwuwX21BPsHFYTOTo5J3hHZc5/3nNnqAAHqAAHqAAHqAAHqAAHqAgPQP32RJQCXLAEaCAxLBAMl8DpgRAeT4KkKAAAECBAjo/mgWorJjX0AaUd2w930ggRg92ztxBZI8z3chugLoCqArgK4AugLoPhP8iC+M1/dWAAAAAElFTkSuQmCC";

const me: Me = {
  kind: "user",
  id: "user-sam",
  name: "Sam Taylor",
  email: "sam@example.com",
  groups: ["engineering", "platform"],
  org_rules: [],
};

function users(start: number): User[] {
  const person = (id: string, name: string, email: string, groups: string[], ago: number, disabled = false): User => ({
    id,
    name,
    email,
    groups,
    disabled,
    created_at: start - ago * DAY,
    last_login_at: start - Math.floor(ago / 3) * DAY,
  });
  const random = seededRandom(7);
  const others = Array.from({ length: 38 }, (_, i) => {
    const first = FIRST_NAMES[i % FIRST_NAMES.length];
    const last = LAST_NAMES[(i * 7) % LAST_NAMES.length];
    const handle = `${first}.${last}`.toLowerCase();
    const groups = Array.from(new Set([pick(random, GROUPS), pick(random, GROUPS)])).sort();
    return person(`user-${handle.replace(".", "-")}`, `${first} ${last}`, `${handle}@example.com`, groups, 5 + Math.floor(random() * 300), i % 9 === 4);
  });
  return [
    person(me.id, me.name, me.email, me.groups, 90),
    person("user-priya", "Priya Shah", "priya@example.com", ["engineering"], 60),
    person("user-tom", "Tom Okafor", "tom@example.com", ["finance"], 45),
    person("user-lena", "Lena Novak", "lena@example.com", ["platform"], 30, true),
    ...others,
  ];
}

export function emptyState(start: number): MockState {
  return {
    signedOut: false,
    seq: 0,
    me,
    users: users(start),
    projects: [],
    environments: [],
    folders: [],
    secrets: [],
    snapshots: [],
    memberships: [],
    roles: {},
    orgBindings: [{ principal_kind: "user", principal_id: me.id, role: "org-admin" }],
    identities: [],
    authMethods: {},
    clientSecrets: {},
    audit: [],
    logos: {},
    projectPolicies: {},
  };
}

/** Builds a realistic organisation by replaying writes through the fake so history and snapshots line up. */
export function seededState(realNow: number): MockState {
  let clock = realNow - 30 * DAY;
  const state = emptyState(realNow);
  const backend = new MockBackend(state, () => clock);
  const later = (seconds: number) => {
    clock += seconds;
  };

  backend.createProject({ slug: "storefront", name: "Storefront", description: "Customer facing web shop" });
  later(3600);
  const dev = "dev";
  backend.batchWrite("storefront", dev, {
    path: "/",
    upserts: [
      { key: "DATABASE_URL", value: "postgres://shop:devpass@localhost:5432/shop", comment: "Local database", tags: ["database"] },
      { key: "REDIS_URL", value: "redis://localhost:6379/0", comment: "" },
      { key: "STRIPE_SECRET_KEY", value: "sk_test_51Hxdev0000", comment: "Stripe test mode", tags: ["payments"] },
      { key: "LOG_LEVEL", value: "debug", comment: "" },
    ],
  });
  later(DAY);
  backend.batchWrite("storefront", "staging", {
    path: "/",
    upserts: [
      { key: "DATABASE_URL", value: "postgres://shop:stagingpass@db.staging:5432/shop", comment: "", tags: ["database"] },
      { key: "REDIS_URL", value: "redis://cache.staging:6379/0", comment: "" },
      { key: "STRIPE_SECRET_KEY", value: "sk_test_51Hxstaging", comment: "", tags: ["payments"] },
    ],
  });
  later(DAY);
  backend.batchWrite("storefront", "prod", {
    path: "/",
    upserts: [
      { key: "DATABASE_URL", value: "postgres://shop:Pr0d-s3cret@db.internal:5432/shop", comment: "Primary cluster", tags: ["database"] },
      { key: "STRIPE_SECRET_KEY", value: "sk_live_51Hxlive", comment: "Live keys, rotate quarterly", tags: ["payments"] },
      { key: "SENTRY_DSN", value: "https://abc123@o1.ingest.sentry.io/42", comment: "" },
    ],
  });
  later(2 * DAY);
  backend.setSecret("storefront", dev, "LOG_LEVEL", "/", { value: "info", comment: "Too noisy" });
  later(DAY);
  backend.setSecret("storefront", dev, "LOG_LEVEL", "/", { value: "warn", comment: "" });
  later(3600);
  backend.batchWrite("storefront", dev, {
    path: "/payments",
    upserts: [
      { key: "WEBHOOK_SECRET", value: "whsec_dev_123", comment: "", tags: ["payments"] },
      { key: "PAYPAL_CLIENT_ID", value: "paypal-dev-client", comment: "" },
    ],
  });
  later(3600);
  backend.createFolder("storefront", dev, "/payments/legacy");
  backend.createFolder("storefront", dev, "/email");
  later(DAY);
  backend.batchWrite("storefront", dev, {
    path: "/email",
    upserts: [{ key: "SMTP_PASSWORD", value: "smtp-dev-pass", comment: "Mailhog" }],
  });
  later(DAY);
  backend.batchWrite("storefront", dev, { path: "/", upserts: [{ key: "FEATURE_FLAGS", value: "checkout-v2,new-search", comment: "" }] });

  later(DAY);
  backend.createProject({
    slug: "payments-api",
    name: "Payments API",
    description: "Card processing service",
    environments: [
      { slug: "dev", name: "Development" },
      { slug: "prod", name: "Production" },
    ],
  });
  backend.batchWrite("payments-api", "dev", {
    path: "/",
    upserts: [
      { key: "ACQUIRER_API_KEY", value: "acq-dev-123", comment: "" },
      { key: "HSM_PIN", value: "0000", comment: "Dev HSM" },
    ],
  });
  backend.batchWrite("payments-api", "prod", {
    path: "/",
    upserts: [
      { key: "ACQUIRER_API_KEY", value: "acq-live-9f8e7d", comment: "" },
      { key: "HSM_PIN", value: "8462", comment: "" },
    ],
  });
  // Shows conditional rules: production values stay hidden from this user even as an org admin.
  backend.putRole("payments-api", "no-prod-values", {
    name: "No production values",
    description: "Everything except reading production secret values",
    rules: [
      {
        effect: "deny",
        subject: "secrets",
        actions: ["read-value"],
        conditions: { environments: ["prod"], paths: [], keys: [], tags: [] },
      },
    ],
  });
  backend.addMember("payments-api", { principal_kind: "user", principal_id: "user-priya", role: "developer" });
  backend.addMember("payments-api", { principal_kind: "group", principal_id: "finance", role: "viewer" });
  backend.addMember("payments-api", { principal_kind: "user", principal_id: me.id, role: "no-prod-values" });

  later(DAY);
  const ci = backend.createIdentity({ name: "github-deploy", description: "Deploys storefront from GitHub Actions" });
  backend.putAuthMethod(ci.id, "oidc", {
    kind: "oidc",
    issuer: "https://token.actions.githubusercontent.com",
    jwks_url: null,
    bindings: {
      audiences: ["sekret"],
      subjects: ["repo:example/storefront:ref:refs/heads/main"],
      claims: { repository_owner: ["example"] },
    },
  });
  backend.addMember("storefront", { principal_kind: "identity", principal_id: ci.id, role: "viewer" });
  const worker = backend.createIdentity({
    name: "billing-worker",
    description: "Kubernetes batch jobs",
    token_ttl: 900,
    token_max_ttl: 3600,
    trusted_cidrs: ["10.0.0.0/8"],
  });
  backend.putAuthMethod(worker.id, "kubernetes", {
    kind: "kubernetes",
    mode: "token-review",
    host: "https://kubernetes.internal.example.com:6443",
    reviewer_jwt: "eyJhbGciOiJSUzI1NiIsImtpZCI6InJldmlld2VyIn0.mock-reviewer-token.signature",
    namespaces: ["billing"],
    service_accounts: ["billing-worker", "billing-cron-*"],
    audiences: ["sekret"],
  });
  backend.putAuthMethod(worker.id, "universal", { kind: "universal" });
  backend.createClientSecret(worker.id, { description: "Initial secret", ttl: null, max_uses: null });
  backend.addOrgBinding({ principal_kind: "group", principal_id: "engineering", role: "org-member" });
  backend.addOrgBinding({ principal_kind: "user", principal_id: "user-priya", role: "org-member" });

  later(DAY);
  seedGeneratedSecrets(backend, later);
  const machines = seedIdentities(backend, state, realNow);
  const rotationStart = clock;
  for (let t = rotationStart; t < realNow - 3600; t += DAY) {
    clock = t;
    backend.rotateDue(t);
  }
  seedActivity(backend, state, realNow, (t) => {
    clock = t;
  }, [ci.id, worker.id, ...machines]);

  state.audit.sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
  state.signedOut = false;
  return state;
}

function seedGeneratedSecrets(backend: MockBackend, later: (seconds: number) => void): void {
  backend.putProjectPolicy("payments-api", { generator: { length: 40, charset: "symbols" }, rotation_days: 30 });
  backend.putLogo("payments-api", fromBase64(PAYMENTS_LOGO));

  backend.generateSecret("storefront", "dev", "SESSION_SECRET", "/", {
    generator: { length: 64, charset: "hex" },
    comment: "Signs session cookies",
  });
  backend.putSecretPolicy("storefront", "dev", "SESSION_SECRET", "/", {
    mode: "custom",
    generator: { length: 64, charset: "hex" },
    rotation_days: 30,
  });
  later(3600);
  backend.generateSecret("storefront", "staging", "CSRF_SECRET", "/", { generator: null, comment: "" });
  backend.putSecretPolicy("storefront", "staging", "CSRF_SECRET", "/", {
    mode: "custom",
    generator: { length: 32, charset: "base64url" },
    rotation_days: 7,
  });
  later(3600);
  backend.generateSecret("payments-api", "dev", "WEBHOOK_SIGNING_KEY", "/", { comment: "Inherits the project policy" });
}

function seedIdentities(backend: MockBackend, state: MockState, realNow: number): string[] {
  const random = seededRandom(11);
  return IDENTITY_NAMES.map((name, i) => {
    const identity = backend.createIdentity({ name, description: `${name.replace(/-/g, " ")} automation` });
    if (i % 3 === 0) backend.putAuthMethod(identity.id, "universal", { kind: "universal" });
    backend.updateIdentity(identity.id, {
      name,
      description: identity.description,
      token_ttl: identity.token_ttl,
      token_max_ttl: identity.token_max_ttl,
      trusted_cidrs: [],
      disabled: i % 7 === 3,
    });
    const stored = state.identities.find((x) => x.id === identity.id);
    if (stored) stored.created_at = realNow - Math.floor(random() * 200 + 2) * DAY;
    return identity.id;
  });
}

/** Everyday reads and logins from people and machines, so the audit log has enough to filter and page. */
function seedActivity(
  backend: MockBackend,
  state: MockState,
  realNow: number,
  setClock: (t: number) => void,
  machineIds: string[],
): void {
  const random = seededRandom(23);
  const people = state.users.filter((u) => !u.disabled).slice(0, 12);
  const projects = state.projects.map((p) => ({
    id: p.id,
    envs: state.environments.filter((e) => e.projectId === p.id).map((e) => e.slug),
  }));
  const paths = ["/", "/", "/", "/payments", "/email"];
  const keys = ["DATABASE_URL", "STRIPE_SECRET_KEY", "REDIS_URL", "SESSION_SECRET", "HSM_PIN"];
  const start = realNow - 30 * DAY;

  for (let i = 0; i < 150; i += 1) {
    setClock(start + Math.floor(random() * (30 * DAY - 3600)));
    const project = pick(random, projects);
    const environment = pick(random, project.envs);
    const machine = random() < 0.45;
    const actor = machine
      ? (() => {
          const id = pick(random, machineIds);
          const identity = state.identities.find((x) => x.id === id);
          return { kind: "identity", id, name: identity?.name ?? id, ip: `10.20.${Math.floor(random() * 8)}.${Math.floor(random() * 250) + 2}` };
        })()
      : (() => {
          const user = pick(random, people);
          return { kind: "user", id: user.id, name: user.email, ip: `192.0.2.${Math.floor(random() * 250) + 2}` };
        })();
    const roll = random();
    if (machine && roll < 0.3) {
      backend.recordAudit("auth.machine-login", actor, {}, { method: pick(random, ["oidc", "kubernetes", "universal"]) });
    } else if (roll < 0.75) {
      backend.recordAudit("secret.read", actor, { project_id: project.id, environment, path: pick(random, paths) }, {
        count: Math.floor(random() * 6) + 1,
        recursive: random() < 0.3,
      });
    } else if (roll < 0.9 || machine) {
      backend.recordAudit("secret.history-read", actor, {
        project_id: project.id,
        environment,
        path: "/",
        secret_key: pick(random, keys),
      });
    } else {
      backend.recordAudit("auth.cli-approve", actor);
    }
  }
}
