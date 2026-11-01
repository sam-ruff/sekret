import { expect, test } from "@playwright/test";
import { expectToast, navigate } from "./helpers";

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
  await oidc.getByTestId("oidc-preset-github").click();
  await expect(oidc.getByTestId("oidc-issuer")).toHaveValue("https://token.actions.githubusercontent.com");
  await expect(oidc.getByTestId("oidc-subjects")).toContainText("repo:");
  await oidc.getByTestId("oidc-save").click();
  await expectToast(page, /saved/);
  await expect(oidc.getByTestId("auth-method-oidc-status")).toHaveText(CONFIGURED);

  // Kubernetes in JWKS mode.
  const k8s = page.getByTestId("auth-method-kubernetes");
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

test("rejects an OIDC binding without a subject or claim", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  const oidc = page.getByTestId("auth-method-oidc");
  await oidc.getByTestId("oidc-issuer").fill("https://issuer.example.com");
  await expect(oidc.getByTestId("oidc-save")).toBeDisabled();
});

test("keeps, replaces and clears a stored Kubernetes reviewer token", async ({ page }) => {
  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  const k8s = page.getByTestId("auth-method-kubernetes");
  await expect(k8s.getByTestId("k8s-reviewer-jwt-stored")).toContainText("Token stored");
  await expect(k8s.getByTestId("k8s-reviewer-jwt")).toHaveCount(0);

  // Saving untouched keeps the stored token and the custom token lifetime.
  await expect(k8s.getByTestId("k8s-max-lifetime")).toHaveValue("600");
  await k8s.getByTestId("k8s-save").click();
  await expectToast(page, /saved/);
  await expect(k8s.getByTestId("k8s-reviewer-jwt-stored")).toBeVisible();
  await page.reload();
  await expect(page.getByTestId("auth-method-kubernetes").getByTestId("k8s-max-lifetime")).toHaveValue("600");

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
  await expect(form.getByLabel("Token lifetime (seconds)")).toBeVisible();
  await expect(form.getByLabel("Longest renewed lifetime (seconds)")).toBeVisible();
  await form.getByTestId("identity-ttl").fill("5400");
  await expect(form.getByTestId("identity-ttl-hint")).toHaveText("How long each token lasts: 1 hour 30 minutes.");
  await expect(form).not.toContainText("TTL");

  await page.goto("/org/identities");
  await page.getByTestId("identity-link-billing-worker").click();
  await page.getByTestId("identity-tab-auth").click();
  const k8s = page.getByTestId("auth-method-kubernetes");
  const lifetime = k8s.getByLabel("Longest Kubernetes token accepted (seconds)");
  await expect(lifetime).toHaveValue("600");
  await expect(k8s.getByTestId("k8s-max-lifetime-help")).toHaveText(
    "Kubernetes tokens valid for longer than this are refused: 10 minutes. Keep pods' projected token expirationSeconds at or below it.",
  );
  await lifetime.fill("soon");
  await expect(k8s.getByTestId("k8s-max-lifetime-error")).toHaveText("Enter a whole number of seconds, 1 or more.");
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
  await form.getByTestId("identity-ttl").fill("1800");
  await form.getByTestId("identity-disabled").click();
  await form.getByTestId("identity-save").click();
  await expectToast(page, /saved/i);

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
  await expect(form).toContainText("refuse new sign-ins");
  await expect(form).not.toContainText("CIDRs");
});
