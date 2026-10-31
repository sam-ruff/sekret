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
