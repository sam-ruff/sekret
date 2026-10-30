import { MockBackend } from "./backend";
import { HOSTILE as X, HOSTILE_PROJECT, HOSTILE_SECRET } from "./hostile-values";
import { seededState } from "./seed";
import type { MockState } from "./state";

/**
 * The normal seed plus markup and script URLs in every field the UI displays. Some of these the
 * real server would refuse, such as keys and folder names; they are written straight into the
 * state so the UI is tested even if validation were ever loosened.
 */
export function hostileState(realNow: number): MockState {
  const state = seededState(realNow);
  let clock = realNow - 3 * 24 * 3600;
  const b = new MockBackend(state, () => (clock += 60));

  state.users.push({
    id: "user-hostile",
    name: X.img,
    email: `hostile@example.com${X.svg}`,
    groups: [X.script, X.js],
    disabled: false,
    created_at: clock,
    last_login_at: clock,
  });

  const identity = b.createIdentity({ name: X.svg, description: X.img });
  state.authMethods[identity.id] = [
    {
      kind: "oidc",
      issuer: X.js,
      jwks_url: X.js,
      bindings: { audiences: [X.img], subjects: [X.script], claims: { [X.svg]: [X.img] } },
    },
    {
      kind: "kubernetes",
      mode: "token-review",
      host: X.js,
      ca_cert: X.script,
      reviewer_jwt: null,
      namespaces: [X.img],
      service_accounts: [X.svg],
      audiences: [X.script],
    },
  ];

  b.createProject({
    slug: HOSTILE_PROJECT,
    name: X.img,
    description: X.script,
    environments: [{ slug: "dev", name: X.svg }],
  });
  b.batchWrite(HOSTILE_PROJECT, "dev", { path: "/", upserts: [{ key: HOSTILE_SECRET, value: X.img, comment: X.script }] });
  b.batchWrite(HOSTILE_PROJECT, "dev", { path: "/", upserts: [{ key: HOSTILE_SECRET, value: `${X.svg}\n${X.js}`, comment: X.svg }] });
  b.batchWrite(HOSTILE_PROJECT, "dev", { path: "/", upserts: [{ key: "LINK", value: X.js, comment: "" }] });

  const env = state.environments.find((e) => e.slug === "dev" && state.projects.some((p) => p.id === e.projectId && p.slug === HOSTILE_PROJECT));
  const project = state.projects.find((p) => p.slug === HOSTILE_PROJECT);
  if (env && project) {
    for (const secret of state.secrets.filter((s) => s.envId === env.id)) {
      for (const version of secret.versions) version.tags = [X.svg];
    }
    state.secrets.push({
      id: "sec-hostile-key",
      envId: env.id,
      path: "/",
      key: X.img,
      versions: [{ version: 1, value: X.script, comment: X.img, tags: [], actor: X.svg, created_at: clock }],
    });
    state.folders.push({ envId: env.id, path: `/${X.img}`, created_at: clock });
    const latest = state.snapshots.find((s) => s.envId === env.id);
    if (latest) latest.reason = X.img;

    b.recordAudit(
      "secret.read",
      { kind: "user", id: X.js, name: X.img, ip: X.svg },
      { project_id: project.id, environment: X.svg, path: `/${X.img}`, secret_key: X.script },
      { note: X.img, nested: { html: X.script }, list: [X.svg, X.js] },
    );
  }

  b.putRole(HOSTILE_PROJECT, "hostile-role", {
    name: X.img,
    description: X.script,
    rules: [{ effect: "allow", subject: "secrets", actions: ["read"] }],
  });
  b.addMember(HOSTILE_PROJECT, { principal_kind: "group", principal_id: X.svg, role: "viewer" });
  b.addMember(HOSTILE_PROJECT, { principal_kind: "identity", principal_id: identity.id, role: "viewer" });
  b.addOrgBinding({ principal_kind: "group", principal_id: X.script, role: "org-member" });

  state.audit.sort((a, b2) => b2.created_at - a.created_at || (a.id < b2.id ? 1 : a.id > b2.id ? -1 : 0));
  return state;
}
