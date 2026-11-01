import { expect, test } from "@playwright/test";
import { unique } from "./helpers";

test("saves the longest OIDC token lifetime and flags a cloud metadata URL", async ({ page }) => {
  const name = unique("e2e-oidc");
  await page.goto("/org/identities");
  await page.getByTestId("new-identity").click();
  await page.getByTestId("identity-name").fill(name);
  await page.getByTestId("identity-create-submit").click();
  await expect(page).toHaveURL(/\/org\/identities\/[^/]+\/auth$/);

  const oidc = page.getByTestId("auth-method-oidc");
  await oidc.getByTestId("oidc-preset-github").click();
  await expect(oidc.getByTestId("oidc-max-lifetime")).toHaveValue("3600");
  await oidc.getByTestId("oidc-jwks-url").fill("http://169.254.169.254/latest/meta-data");
  await expect(oidc.getByTestId("oidc-jwks-url-error")).toContainText("cloud metadata address");
  await expect(oidc.getByTestId("oidc-save")).toBeDisabled();
  await oidc.getByTestId("oidc-jwks-url").fill("");
  await oidc.getByTestId("oidc-max-lifetime").fill("600");
  await oidc.getByTestId("oidc-save").click();
  await expect(oidc.getByTestId("auth-method-oidc-status")).toHaveText(/^\s*Configured/);

  await page.reload();
  await expect(page.getByTestId("auth-method-oidc").getByTestId("oidc-max-lifetime")).toHaveValue("600");

  await page.getByTestId("identity-tab-details").click();
  await page.getByTestId("identity-delete").click();
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/org\/identities$/);
});

test("creates an identity with universal auth and a client secret", async ({ page }) => {
  const name = unique("e2e-bot");
  await page.goto("/org/identities");
  await page.getByTestId("new-identity").click();
  await page.getByTestId("identity-name").fill(name);
  await page.getByTestId("identity-create-submit").click();
  await expect(page).toHaveURL(/\/org\/identities\/[^/]+\/auth$/);

  const oidc = page.getByTestId("auth-method-oidc");
  await oidc.getByTestId("oidc-preset-github").click();
  await oidc.getByTestId("oidc-save").click();
  await expect(oidc.getByTestId("auth-method-oidc-status")).toHaveText(/^\s*Configured/);

  const universal = page.getByTestId("auth-method-universal");
  await universal.getByTestId("universal-enable").click();
  await universal.getByTestId("new-client-secret").click();
  await page.getByTestId("client-secret-description").fill("live test");
  await page.getByTestId("client-secret-create").click();
  const once = page.getByTestId("client-secret-once-dialog");
  await expect(once).toContainText("You will not see this secret again");
  await expect(once.getByTestId("client-secret-value")).toHaveValue(/^sks_/);
  await once.getByTestId("client-secret-done").click();
  await expect(universal.getByTestId("client-secrets")).toContainText("live test");

  await page.getByTestId("identity-tab-details").click();
  await page.getByTestId("identity-delete").click();
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/org\/identities$/);
  await expect(page.getByTestId(`identity-row-${name}`)).toHaveCount(0);
});
