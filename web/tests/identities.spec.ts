import { expect, test } from "./fixture";
import { expectToast, failNext, navigate } from "./helpers";

const CONFIGURED = /^\s*Configured/;

test("creates an identity and configures every auth method", async ({ page }) => {
  await page.goto("/projects");
  await navigate(page, "nav-identities");
  await expect(page.getByTestId("identity-row-github-deploy")).toBeVisible();

  await page.getByTestId("new-identity").click();
  await page.getByTestId("identity-name").fill("deploy-bot");
  await page.getByTestId("identity-cidrs-input").fill("10.20.0.0/16");
  await page.getByTestId("identity-cidrs-input").press("Enter");
  await page.getByTestId("identity-create-submit").click();
  await expect(page).toHaveURL(/\/org\/identities\/[^/]+\/auth$/);

  // OIDC with the GitHub Actions preset.
  const oidc = page.getByTestId("auth-method-oidc");
  await expect(oidc.getByTestId("auth-method-oidc-status")).toHaveText(/Not configured/);
  // Unconfigured methods start collapsed.
  await expect(oidc.getByTestId("oidc-form")).toHaveCount(0);
  await expect(page.getByTestId("k8s-host")).toHaveCount(0);
  await oidc.getByTestId("auth-method-oidc-setup").click();
  await oidc.getByTestId("oidc-preset-github").click();
  await expect(oidc.getByTestId("oidc-issuer")).toHaveValue("https://token.actions.githubusercontent.com");
  await expect(oidc.getByTestId("oidc-subjects")).toContainText("repo:");
  await oidc.getByTestId("oidc-save").click();
  await expectToast(page, /saved/);
  await expect(oidc.getByTestId("auth-method-oidc-status")).toHaveText(CONFIGURED);

  // Kubernetes in JWKS mode.
  const k8s = page.getByTestId("auth-method-kubernetes");
  await k8s.getByTestId("auth-method-kubernetes-setup").click();
  await k8s.getByTestId("k8s-mode").click();
  await page.getByTestId("k8s-mode-jwks").click();
  await k8s.getByTestId("k8s-issuer").fill("https://kubernetes.default.svc.cluster.local");
  await k8s.getByTestId("k8s-jwks-url").fill("https://cluster.example.com/openid/v1/jwks");
  await k8s.getByTestId("k8s-namespaces-input").fill("billing");
  await k8s.getByTestId("k8s-namespaces-input").press("Enter");
  await k8s.getByTestId("k8s-service-accounts-input").fill("worker-*");
  await k8s.getByTestId("k8s-service-accounts-input").press("Enter");
  await expect(k8s.getByTestId("k8s-audiences")).toContainText("sekret");
  await k8s.getByTestId("k8s-save").click();
  await expect(k8s.getByTestId("auth-method-kubernetes-status")).toHaveText(CONFIGURED);

  // Universal auth and a client secret shown once.
  const universal = page.getByTestId("auth-method-universal");
  await universal.getByTestId("universal-enable").click();
  await expect(universal.getByTestId("auth-method-universal-status")).toHaveText(CONFIGURED);
  await universal.getByTestId("new-client-secret").click();
  await page.getByTestId("client-secret-description").fill("CI runner");
  await page.getByTestId("client-secret-create").click();
  const once = page.getByTestId("client-secret-once-dialog");
  await expect(once).toContainText("You will not see this secret again");
  const value = once.getByTestId("client-secret-value");
  await expect(value).toHaveValue(/^sks_/);
  // Shown in a field writing assistants and spellcheckers are told to leave alone.
  await expect(value).toHaveAttribute("spellcheck", "false");
  await expect(value).toHaveAttribute("data-gramm", "false");
  await expect(value).toHaveAttribute("readonly", "");
  await once.getByTestId("client-secret-done").click();
  await expect(universal.getByTestId("client-secrets")).toContainText("CI runner");

  await page.getByTestId("identity-tab-usage").click();
  await expect(page.getByTestId("snippet-github-actions")).toContainText("id-token: write");
});

test("the usage tab lists the identity's projects and links to where access is granted", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  await page.getByTestId("identity-tab-usage").click();
  await expect(page.getByTestId("topbar-section")).toHaveText("Machine identities");
  await expect(page.getByTestId("topbar-item")).toHaveText("github-deploy");
  const card = page.getByTestId("identity-projects");
  await expect(card.getByTestId("identity-project-storefront").getByTestId("role-label-name")).toHaveText("viewer");
  await expect(card.getByTestId("identity-project-payments-api")).toContainText("No access");
  await card.getByTestId("identity-project-manage-payments-api").click();
  await expect(page).toHaveURL(/\/projects\/payments-api\/settings\/members$/);
});

test("the usage tab leads with snippets for methods that are set up and tucks the rest away", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  await page.getByTestId("identity-tab-usage").click();
  // Only OIDC is set up on this identity.
  await expect(page.getByTestId("snippet-github-actions")).toBeVisible();
  await expect(page.getByTestId("snippet-cli-universal")).toBeHidden();
  const rest = page.getByTestId("usage-not-set-up");
  await expect(rest).toContainText("2 snippets need an auth method this identity does not have yet.");
  await rest.getByTestId("usage-not-set-up-toggle").click();
  await expect(page.getByTestId("snippet-cli-universal")).toContainText("Needs the universal auth method, which is not set up.");
  await rest.getByTestId("usage-set-up-auth").click();
  await expect(page).toHaveURL(/\/org\/identities\/[^/]+\/auth$/);
});

test("the client secret expiry takes units, suggests one, and explains a bad entry", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  await page.getByTestId("auth-method-universal").getByTestId("new-client-secret").click();
  const dialog = page.getByTestId("create-client-secret-dialog");
  await dialog.getByLabel("Expires after").fill("later");
  await expect(dialog.getByTestId("client-secret-ttl-error")).toHaveText("Enter a duration such as 3600, 12h or 90d.");
  await expect(dialog.getByTestId("client-secret-create")).toBeDisabled();
  await dialog.getByTestId("client-secret-ttl-30d").click();
  await expect(dialog.getByLabel("Expires after")).toHaveValue("30d");
  await expect(dialog.getByTestId("client-secret-ttl-help")).toHaveText("30 days");
  await dialog.getByTestId("client-secret-create").click();
  await page.getByTestId("client-secret-once-dialog").getByTestId("client-secret-done").click();
});

test("the audit log names identities and roles instead of showing their IDs", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  await page.getByTestId("auth-method-universal").getByTestId("new-client-secret").click();
  await page.getByTestId("client-secret-description").fill("named in the log");
  await page.getByTestId("client-secret-create").click();
  await page.getByTestId("client-secret-once-dialog").getByTestId("client-secret-done").click();

  await page.goto("/org/audit");
  const detail = page
    .getByTestId("audit-row")
    .filter({ has: page.locator('[data-action="identity.client-secret-create"]') })
    .first()
    .getByTestId("audit-detail");
  await expect(detail).toHaveText(/^Client secret starting sks_\S+ for billing-worker$/);
  const details = await page.getByTestId("audit-detail").allTextContents();
  expect(details.filter((d) => /identity: |kind: universal/.test(d))).toEqual([]);
});

test("OIDC claim globs are named after their claim, and a bad network says why by the field", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  const cidrs = page.getByLabel("Allowed networks (CIDR ranges)");
  await cidrs.fill("not a range");
  await cidrs.press("Enter");
  const problem = page.getByTestId("identity-cidrs-problem");
  await expect(problem).toHaveText("Use a range such as 10.0.0.0/8 or 192.168.1.5/32");
  await expect(cidrs).toHaveAttribute("aria-invalid", "true");
  await expect(cidrs).toHaveAttribute("aria-describedby", (await problem.getAttribute("id")) ?? "missing");

  await page.getByTestId("identity-tab-auth").click();
  await expect(page.getByTestId("auth-method-oidc").getByLabel("Globs for claim repository_owner")).toBeVisible();
});

test("long OIDC subjects wrap inside the form instead of widening it", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  await page.getByTestId("identity-tab-auth").click();
  const oidc = page.getByTestId("auth-method-oidc");
  const subjects = oidc.getByTestId("oidc-subjects");
  await subjects.getByTestId("oidc-subjects-input").fill("repo:example/a-very-long-repository-name-for-wrapping:ref:refs/heads/main");
  await subjects.getByTestId("oidc-subjects-input").press("Enter");
  const form = await oidc.getByTestId("oidc-form").boundingBox();
  expect(form).not.toBeNull();
  for (const id of ["oidc-issuer", "oidc-jwks-url", "oidc-audiences", "oidc-subjects"]) {
    const box = await oidc.getByTestId(id).boundingBox();
    expect(box).not.toBeNull();
    if (!box || !form) continue;
    expect(box.x + box.width).toBeLessThanOrEqual(form.x + form.width + 1);
  }
});

test("sets the longest OIDC token lifetime, which survives a reload", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  await page.getByTestId("identity-tab-auth").click();
  const oidc = page.getByTestId("auth-method-oidc");
  const lifetime = oidc.getByLabel("Longest OIDC token accepted");
  await expect(lifetime).toHaveValue("15m");
  await expect(oidc.getByTestId("oidc-max-lifetime-help")).toHaveText(
    "Tokens valid for longer than this, or without an iat claim, are refused: 15 minutes.",
  );
  await lifetime.fill("999999999999");
  await expect(oidc.getByTestId("oidc-max-lifetime-error")).toHaveText(
    "Enter a duration such as 3600, 30m, 1h or 7d, from 1 second up to 10 years.",
  );
  await expect(oidc.getByTestId("oidc-save")).toBeDisabled();
  await lifetime.fill("2h");
  await oidc.getByTestId("oidc-save").click();
  await expectToast(page, "OIDC saved");
  await page.reload();
  await expect(page.getByTestId("auth-method-oidc").getByTestId("oidc-max-lifetime")).toHaveValue("2h");
  await expect(page.getByTestId("auth-method-oidc").getByTestId("oidc-max-lifetime-help")).toContainText("2 hours");
});

test("a cloud metadata URL is flagged by the field, and the server's refusal reads plainly", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  await page.getByTestId("identity-tab-auth").click();
  const oidc = page.getByTestId("auth-method-oidc");
  await oidc.getByTestId("oidc-jwks-url").fill("http://169.254.169.254/latest/meta-data");
  await expect(oidc.getByTestId("oidc-jwks-url-error")).toContainText("That is a cloud metadata address");
  await expect(oidc.getByTestId("oidc-save")).toBeDisabled();

  // A name that resolves to a metadata address is only caught by the server.
  await oidc.getByTestId("oidc-jwks-url").fill("https://metadata.example.internal/keys");
  await failNext(page, "PUT", "/auth/oidc$", 400, "bad_request", "url not allowed: https://metadata.example.internal/keys");
  await oidc.getByTestId("oidc-save").click();
  await expectToast(page, "The server will not contact https://metadata.example.internal/keys.");
});

test("rejects an OIDC binding without a subject or claim", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  const oidc = page.getByTestId("auth-method-oidc");
  await oidc.getByTestId("auth-method-oidc-setup").click();
  // Nothing to warn about until there is an issuer.
  await expect(oidc.getByTestId("oidc-unbounded")).toHaveCount(0);
  await oidc.getByTestId("oidc-issuer").fill("https://issuer.example.com");
  await expect(oidc.getByTestId("oidc-unbounded")).toBeVisible();
  await expect(oidc.getByTestId("oidc-save")).toBeDisabled();
  // Cancel folds the form away again.
  await oidc.getByTestId("oidc-cancel").click();
  await expect(oidc.getByTestId("oidc-form")).toHaveCount(0);
  await expect(oidc.getByTestId("auth-method-oidc-setup")).toBeVisible();
});

test("keeps, replaces and clears a stored Kubernetes reviewer token", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  const k8s = page.getByTestId("auth-method-kubernetes");
  await expect(k8s.getByTestId("k8s-reviewer-jwt-stored")).toContainText("Token stored");
  await expect(k8s.getByTestId("k8s-reviewer-jwt")).toHaveCount(0);

  // Saving untouched keeps the stored token and the custom token lifetime.
  await expect(k8s.getByTestId("k8s-max-lifetime")).toHaveValue("10m");
  await k8s.getByTestId("k8s-save").click();
  await expectToast(page, /saved/);
  await expect(k8s.getByTestId("k8s-reviewer-jwt-stored")).toBeVisible();
  await page.reload();
  await expect(page.getByTestId("auth-method-kubernetes").getByTestId("k8s-max-lifetime")).toHaveValue("10m");

  // Replacing with a new token stores it without echoing it back.
  await k8s.getByTestId("k8s-reviewer-jwt-replace").click();
  await expect(k8s.getByTestId("k8s-reviewer-jwt")).toHaveAttribute("data-gramm", "false");
  await expect(k8s.getByTestId("k8s-reviewer-jwt")).toHaveAttribute("autocomplete", "off");
  await k8s.getByTestId("k8s-reviewer-jwt").fill("eyJhbGciOiJSUzI1NiJ9.rotated.sig");
  await k8s.getByTestId("k8s-save").click();
  await expect(k8s.getByTestId("k8s-reviewer-jwt-stored")).toBeVisible();
  await expect(k8s.getByText("eyJhbGciOiJSUzI1NiJ9.rotated.sig")).toHaveCount(0);

  // Replacing with nothing clears it.
  await k8s.getByTestId("k8s-reviewer-jwt-replace").click();
  await k8s.getByTestId("k8s-save").click();
  await expect(k8s.getByTestId("k8s-reviewer-jwt")).toHaveValue("");
  await expect(k8s.getByTestId("k8s-reviewer-jwt-stored")).toHaveCount(0);
});

test("labels token lifetimes in plain words", async ({ page }) => {
  await page.goto("/org/identities");
  await expect(page.getByTestId("identity-link-github-deploy")).toBeVisible();
  await expect(page.locator("body")).not.toContainText("TTL");
  await page.getByTestId("identity-link-github-deploy").click();
  const form = page.getByTestId("identity-details-form");
  await expect(form.getByLabel("Token lifetime")).toHaveValue("1h");
  await expect(form.getByLabel("Longest renewed lifetime")).toHaveValue("1d");
  await form.getByTestId("identity-ttl").fill("5400");
  await expect(form.getByTestId("identity-ttl-hint")).toHaveText("How long each token lasts: 1 hour 30 minutes.");
  await form.getByTestId("identity-ttl").fill("1h 30m");
  await expect(form.getByTestId("identity-ttl-hint")).toHaveText("How long each token lasts: 1 hour 30 minutes.");
  await form.getByTestId("identity-ttl").fill("soon");
  await expect(form.getByTestId("identity-ttl-problem")).toHaveText(
    "Enter each lifetime as a duration such as 3600, 30m, 1h or 7d",
  );
  await expect(form.getByTestId("identity-ttl")).toHaveAttribute("aria-invalid", "true");
  await expect(form).not.toContainText("TTL");

  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  const k8s = page.getByTestId("auth-method-kubernetes");
  const lifetime = k8s.getByLabel("Longest Kubernetes token accepted");
  await expect(lifetime).toHaveValue("10m");
  await expect(k8s.getByTestId("k8s-max-lifetime-help")).toHaveText(
    "Kubernetes tokens valid for longer than this are refused: 10 minutes (600 seconds). Keep pods' projected token expirationSeconds at or below it.",
  );
  await lifetime.fill("soon");
  await expect(k8s.getByTestId("k8s-max-lifetime-error")).toHaveText(
    "Enter a duration such as 3600, 30m, 1h or 7d, from 1 second up to 10 years.",
  );
  await expect(lifetime).toHaveAttribute("aria-describedby", "k8s-max-lifetime-error");
  await expect(k8s.getByTestId("k8s-save")).toHaveText("Save Kubernetes settings");
  await expect(k8s.getByTestId("k8s-save")).toBeDisabled();
});

test("takes the reviewer token in a masked text field password managers skip", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  const k8s = page.getByTestId("auth-method-kubernetes");
  await k8s.getByTestId("k8s-reviewer-jwt-replace").click();
  const field = k8s.getByTestId("k8s-reviewer-jwt");
  await expect(field).toHaveAttribute("type", "text");
  for (const [name, value] of [
    ["data-1p-ignore", "true"],
    ["data-lpignore", "true"],
    ["data-bwignore", "true"],
    ["data-form-type", "other"],
  ]) {
    await expect(field).toHaveAttribute(name, value);
  }
  expect(await field.evaluate((el) => getComputedStyle(el).getPropertyValue("-webkit-text-security"))).toBe("disc");
});

test("a later copy of the client id is not wiped by the client secret's timer", async ({ page }) => {
  await page.addInitScript(() => {
    let contents = "";
    Object.defineProperty(navigator, "clipboard", {
      value: {
        writeText: (text: string) => {
          contents = text;
          return Promise.resolve();
        },
        readText: () => Promise.resolve(contents),
      },
      configurable: true,
    });
    (window as unknown as { readClipboard: () => string }).readClipboard = () => contents;
  });
  await page.clock.install();
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  await page.getByTestId("identity-tab-auth").click();
  const universal = page.getByTestId("auth-method-universal");
  const status = universal.getByTestId("auth-method-universal-status");
  await expect(status).toBeVisible();
  if ((await status.textContent())?.includes("Not configured")) await universal.getByTestId("universal-enable").click();
  await universal.getByTestId("new-client-secret").click();
  await page.getByTestId("client-secret-create").click();
  const once = page.getByTestId("client-secret-once-dialog");
  await once.getByTestId("client-secret-copy").click();
  await once.getByTestId("client-id-copy").click();
  const clientId = await page.evaluate(() => (window as unknown as { readClipboard: () => string }).readClipboard());
  expect(clientId).not.toMatch(/^sks_/);
  await page.clock.fastForward(46_000);
  await page.clock.runFor(100);
  expect(await page.evaluate(() => (window as unknown as { readClipboard: () => string }).readClipboard())).toBe(clientId);
  await expect(page.locator("[data-sonner-toast]").filter({ hasText: "Clipboard not cleared" })).toHaveCount(0);
});

test("edits identity settings and revokes tokens", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  const form = page.getByTestId("identity-details-form");
  // Nothing to save until something changes.
  await expect(form.getByTestId("identity-save")).toBeDisabled();
  // The same lifetime written another way is not a change.
  await form.getByTestId("identity-ttl").fill("3600");
  await expect(form.getByTestId("identity-save")).toBeDisabled();
  await form.getByTestId("identity-ttl").fill("1800");
  await expect(form.getByTestId("identity-save")).toBeEnabled();
  await form.getByTestId("identity-disabled").click();
  await form.getByTestId("identity-save").click();
  await expectToast(page, /saved/i);
  await expect(form.getByTestId("identity-save")).toBeDisabled();
  await page.reload();
  await expect(page.getByTestId("identity-details-form").getByTestId("identity-ttl")).toHaveValue("30m");
  await expect(page.getByText("Removes its auth methods, client secrets and memberships.")).toBeVisible();

  await page.getByTestId("revoke-tokens").click();
  await page.getByTestId("confirm-action").click();
  await expectToast(page, /revoked/i);
});

test("a client secret that expires millions of years away can still be seen and revoked", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("new-identity").click();
  await expect(page.getByTestId("identity-blocker")).toHaveText("Give the identity a name to continue.");
  await page.getByTestId("identity-name").fill("far-future");
  await expect(page.getByTestId("identity-blocker")).toHaveCount(0);
  await page.getByTestId("identity-create-submit").click();
  await expect(page).toHaveURL(/\/auth$/);

  const universal = page.getByTestId("auth-method-universal");
  await universal.getByTestId("universal-enable").click();
  await universal.getByTestId("new-client-secret").click();
  await page.getByTestId("client-secret-ttl").fill("100000000000000");
  await page.getByTestId("client-secret-create").click();
  await page.getByTestId("client-secret-once-dialog").getByTestId("client-secret-done").click();

  const secrets = universal.getByTestId("client-secrets");
  await expect(secrets).toContainText("Unknown date");
  await expect(page.getByTestId("app-error")).toHaveCount(0);
  await secrets.getByTestId("client-secret-revoke").click();
  await page.getByTestId("confirm-action").click();
  await expectToast(page, "Client secret revoked");
  await expect(secrets).toContainText("Revoked");
  // The other tabs still work.
  await page.getByTestId("identity-tab-details").click();
  await expect(page.getByTestId("identity-details-form")).toBeVisible();
});

test("the allowed networks field is named in plain words", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-github-deploy").click();
  const form = page.getByTestId("identity-details-form");
  await expect(form.getByLabel("Allowed networks (CIDR ranges)")).toBeVisible();
  await expect(form.getByLabel("Disable sign-ins for this identity")).toBeVisible();
  await expect(form).not.toContainText("CIDRs");
});
