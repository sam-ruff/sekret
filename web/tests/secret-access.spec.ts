import type { Page } from "@playwright/test";
import { expect, test } from "./fixture";
import { expectToast, secretRow } from "./helpers";

async function openSecrets(page: Page, env = "prod", project = "storefront") {
  await page.goto(`/projects/${project}/secrets/${env}`);
  await expect(page.getByTestId("secrets-table")).toBeVisible();
}

async function openAccess(page: Page, key: string) {
  await expect(page.getByTestId("secret-drawer")).toHaveCount(0);
  await secretRow(page, key).getByTestId("secret-key").click();
  const access = page.getByTestId("secret-drawer").getByTestId("access-section");
  await expect(access.getByTestId("access-restricted")).toBeVisible();
  return access;
}

async function closeDrawer(page: Page) {
  const drawer = page.getByTestId("secret-drawer");
  await expect(async () => {
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0, { timeout: 1000 });
  }).toPass();
}

async function openSetting(page: Page, project = "storefront") {
  await page.goto(`/projects/${project}/settings/general`);
  const card = page.getByTestId("secret-access-setting");
  await expect(card.getByTestId("secret-access-enabled")).toBeVisible();
  return card;
}

test("a restricted secret is marked in the list and shows its access list", async ({ page }) => {
  await openSecrets(page);
  const badge = secretRow(page, "STRIPE_SECRET_KEY").getByTestId("secret-restricted-badge");
  await expect(badge).toHaveText("Restricted");
  await expect(secretRow(page, "DATABASE_URL").getByTestId("secret-restricted-badge")).toHaveCount(0);

  const access = await openAccess(page, "STRIPE_SECRET_KEY");
  await expect(access.getByTestId("access-restricted")).toBeChecked();
  await expect(access.getByTestId("access-grant-github-deploy")).toBeVisible();
  await expect(access.getByTestId("access-grant-github-deploy").getByTestId("access-action-github-deploy-read-value")).toBeChecked();
  await expect(access.getByTestId("access-grant-finance").getByTestId("access-action-finance-read-value")).not.toBeChecked();
});

test("grants, widens and revokes entries on a secret's list", async ({ page }) => {
  await openSecrets(page);
  const access = await openAccess(page, "STRIPE_SECRET_KEY");
  await access.getByTestId("access-kind-group").click();
  await access.getByTestId("access-group").fill("ops");
  await access.getByTestId("access-new-read-value").click();
  await access.getByTestId("access-new-edit").click();
  await access.getByTestId("access-add-submit").click();
  const ops = access.getByTestId("access-grant-ops");
  await expect(ops.getByTestId("access-action-ops-edit")).toBeChecked();
  await expect(ops.getByTestId("access-action-ops-read-value")).not.toBeChecked();

  await ops.getByTestId("access-action-ops-delete").click();
  await expect(ops.getByTestId("access-action-ops-delete")).toBeChecked();

  await access.getByTestId("access-revoke-finance").click();
  await expect(access.getByTestId("access-grant-finance")).toHaveCount(0);

  await access.getByTestId("access-kind-identity").click();
  await access.getByTestId("access-principal").click();
  await page.getByTestId("access-principal-search").fill("billing");
  await page.getByTestId("principal-option-billing-worker").click();
  await access.getByTestId("access-add-submit").click();
  await expect(access.getByTestId("access-grant-billing-worker")).toBeVisible();
});

test("turning the setting off is refused while a secret is restricted", async ({ page }) => {
  let card = await openSetting(page);
  await expect(card.getByTestId("secret-access-enabled")).toBeChecked();
  await expect(card.getByTestId("secret-access-restricted")).toContainText("STRIPE_SECRET_KEY");
  await card.getByTestId("secret-access-enabled").click();
  await expect(card.getByTestId("secret-access-refused")).toContainText("1 secret in this project is restricted");
  await expect(card.getByTestId("secret-access-enabled")).toBeChecked();

  await openSecrets(page);
  const access = await openAccess(page, "STRIPE_SECRET_KEY");
  await access.getByTestId("access-restricted").click();
  // Unrestricting clears the list, so it asks first and names who goes.
  const confirm = page.getByTestId("access-unrestrict-confirm");
  await expect(confirm).toContainText("finance, github-deploy");
  await confirm.getByTestId("confirm-action").click();
  await expect(access.getByTestId("access-restricted")).not.toBeChecked();
  await expect(access.getByTestId("access-empty")).toHaveText("No one is on the list.");
  await closeDrawer(page);
  await expect(secretRow(page, "STRIPE_SECRET_KEY").getByTestId("secret-restricted-badge")).toHaveCount(0);

  card = await openSetting(page);
  await expect(card.getByTestId("secret-access-none")).toBeVisible();
  await card.getByTestId("secret-access-enabled").click();
  await expectToast(page, "Per-secret access turned off");
  await expect(card.getByTestId("secret-access-enabled")).not.toBeChecked();

  // With the setting off, a secret cannot be restricted and the list cannot grow.
  await openSecrets(page);
  const off = await openAccess(page, "STRIPE_SECRET_KEY");
  await expect(off.getByTestId("access-restricted")).toBeDisabled();
  await expect(off.getByTestId("access-off")).toBeVisible();
  await expect(off.getByTestId("access-add")).toHaveCount(0);
});

test("restricts a secret from its drawer while the setting is on", async ({ page }) => {
  await openSecrets(page);
  const access = await openAccess(page, "SENTRY_DSN");
  await expect(access.getByTestId("access-restricted")).not.toBeChecked();
  await expect(access.getByTestId("access-empty")).toHaveText("No one is on the list.");
  await access.getByTestId("access-restricted").click();
  await expect(access.getByTestId("access-restricted")).toBeChecked();
  await expect(access.getByTestId("access-empty")).toContainText("only admins can reach it");
  await closeDrawer(page);
  await expect(secretRow(page, "SENTRY_DSN").getByTestId("secret-restricted-badge")).toBeVisible();
});

test("creates a secret restricted from the start", async ({ page }) => {
  await openSecrets(page);
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await form.getByTestId("secret-key-input").fill("PAYOUT_TOKEN");
  await form.getByTestId("secret-value-input").fill("tok_live");
  await form.getByTestId("secret-restricted-input").click();
  await form.getByTestId("secret-save").click();
  await expectToast(page, "Added PAYOUT_TOKEN");
  await expect(secretRow(page, "PAYOUT_TOKEN").getByTestId("secret-restricted-badge")).toBeVisible();
});

test("generates a secret restricted from the start", async ({ page }) => {
  await openSecrets(page);
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await form.getByTestId("secret-key-input").fill("WEBHOOK_KEY");
  await form.getByTestId("secret-generate").click();
  await form.getByTestId("secret-restricted-input").click();
  await form.getByTestId("secret-save").click();
  await expectToast(page, "Generated WEBHOOK_KEY");
  await expect(secretRow(page, "WEBHOOK_KEY").getByTestId("secret-restricted-badge")).toBeVisible();
});

test("a project with the setting off offers no restriction", async ({ page }) => {
  const card = await openSetting(page, "payments-api");
  await expect(card.getByTestId("secret-access-enabled")).not.toBeChecked();
  await openSecrets(page, "dev", "payments-api");
  await page.getByTestId("add-secret").click();
  await expect(page.getByTestId("new-secret-form").getByTestId("secret-key-input")).toBeVisible();
  await expect(page.getByTestId("secret-restricted-input")).toHaveCount(0);
});
