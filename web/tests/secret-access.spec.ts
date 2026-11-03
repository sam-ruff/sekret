import type { Page } from "@playwright/test";
import { expect, test } from "./fixture";
import { expectToast, secretRow } from "./helpers";

async function openSecrets(page: Page, env = "prod", project = "storefront", query = "") {
  await page.goto(`/projects/${project}/secrets/${env}${query}`);
  await expect(page.getByTestId("secrets-table")).toBeVisible();
}

async function openAccess(page: Page, key: string) {
  await expect(page.getByTestId("secret-drawer")).toHaveCount(0);
  await secretRow(page, key).getByTestId("secret-key").click();
  const access = page.getByTestId("secret-drawer").getByTestId("access-section");
  await expect(access.getByTestId("access-restricted").or(access.getByTestId("access-off"))).toBeVisible();
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
  await expect(badge).toContainText("Restricted");
  await expect(secretRow(page, "DATABASE_URL").getByTestId("secret-restricted-badge")).toHaveCount(0);

  const access = await openAccess(page, "STRIPE_SECRET_KEY");
  await expect(access.getByTestId("access-restricted")).toBeChecked();
  const deploy = access.getByTestId("access-grant-github-deploy");
  await expect(deploy.getByRole("checkbox", { name: "Read value for github-deploy" })).toBeChecked();
  await expect(deploy.getByRole("checkbox", { name: "Read name for github-deploy" })).toBeDisabled();
  await expect(access.getByRole("checkbox", { name: "Read value for finance" })).not.toBeChecked();
});

test("grants, widens and revokes entries, saying so and keeping keyboard focus", async ({ page }) => {
  await openSecrets(page);
  const access = await openAccess(page, "STRIPE_SECRET_KEY");
  await access.getByTestId("access-kind-group").click();
  await access.getByTestId("access-group").fill("ops");
  await access.getByTestId("access-new-read-value").click();
  await access.getByTestId("access-new-edit").click();
  await access.getByTestId("access-add-submit").click();
  await expectToast(page, "Added ops");
  await expect(access.getByTestId("access-announce")).toHaveText("Added ops");
  const ops = access.getByTestId("access-grant-ops");
  await expect(ops.getByTestId("access-action-ops-edit")).toBeChecked();
  await expect(ops.getByTestId("access-action-ops-read-value")).not.toBeChecked();

  // Toggled from the keyboard, the checkbox keeps focus while the change saves.
  const remove = ops.getByTestId("access-action-ops-delete");
  await remove.focus();
  await page.keyboard.press("Space");
  await expect(remove).toBeChecked();
  await expect(remove).toBeFocused();

  // Removing an entry moves focus to the next entry's remove button; groups sort before identities.
  await access.getByTestId("access-revoke-finance").click();
  await expect(access.getByTestId("access-grant-finance")).toHaveCount(0);
  await expectToast(page, "Removed finance");
  await expect(access.getByTestId("access-revoke-ops")).toBeFocused();
  // Removing the last row focuses the one before it, and an empty list moves on to adding someone.
  await access.getByTestId("access-revoke-github-deploy").click();
  await expect(access.getByTestId("access-grant-github-deploy")).toHaveCount(0);
  await expect(access.getByTestId("access-revoke-ops")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(access.getByTestId("access-grant-ops")).toHaveCount(0);
  await expect(access.getByText("Add to the list")).toBeFocused();

  await access.getByTestId("access-kind-identity").click();
  await access.getByTestId("access-principal").click();
  await page.getByTestId("access-principal-search").fill("billing");
  await page.getByTestId("principal-option-billing-worker").click();
  await access.getByTestId("access-add-submit").click();
  await expect(access.getByTestId("access-grant-billing-worker")).toBeVisible();
});

test("typing a name and pressing Enter at once never picks a stale match", async ({ page }) => {
  await openSecrets(page);
  const access = await openAccess(page, "STRIPE_SECRET_KEY");
  await access.getByTestId("access-principal").click();
  const search = page.getByTestId("access-principal-search");
  await expect(page.getByTestId("principal-option-ansible-runner")).toBeVisible();
  await search.fill("webhook");
  await page.keyboard.press("Enter");
  // Either nothing was picked yet, or the right one was; never the first of the old list.
  await expect(access.getByTestId("access-principal")).not.toContainText("ansible-runner");
  await expect(page.getByTestId("principal-searching")).toHaveCount(0);
  if (await search.isVisible()) await page.keyboard.press("Enter");
  await expect(access.getByTestId("access-principal")).toHaveText("webhook-relay");
});

test("the members dialog picker waits for the search too", async ({ page }) => {
  await page.goto("/projects/storefront/settings/members");
  await page.getByTestId("add-member").click();
  await page.getByTestId("member-principal").click();
  const search = page.getByTestId("member-principal-search");
  await expect(page.getByRole("option").first()).toBeVisible();
  await search.fill("priya");
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("member-principal")).not.toContainText("Aisha");
  await expect(page.getByTestId("principal-searching")).toHaveCount(0);
  if (await search.isVisible()) await page.keyboard.press("Enter");
  await expect(page.getByTestId("member-principal")).toHaveText("Priya Shah");
});

test("unrestricting always asks first, naming the first few on the list", async ({ page }) => {
  await openSecrets(page);
  const access = await openAccess(page, "STRIPE_SECRET_KEY");
  for (const group of ["ops", "sre", "audit"]) {
    await access.getByTestId("access-kind-group").click();
    await access.getByTestId("access-group").fill(group);
    await access.getByTestId("access-add-submit").click();
    await expect(access.getByTestId(`access-grant-${group}`)).toBeVisible();
  }
  await access.getByTestId("access-restricted").click();
  const confirm = page.getByTestId("access-unrestrict-confirm");
  await expect(confirm).toContainText("Everyone whose role allows it can read STRIPE_SECRET_KEY again");
  await expect(confirm).toContainText("and 2 more");
  await confirm.getByTestId("confirm-cancel").click();
  await expect(access.getByTestId("access-restricted")).toBeChecked();
  await closeDrawer(page);

  // Even with nobody on the list, opening a secret up is confirmed.
  const sentry = await openAccess(page, "SENTRY_DSN");
  await sentry.getByTestId("access-restricted").click();
  await expect(sentry.getByTestId("access-restricted")).toBeChecked();
  await sentry.getByTestId("access-restricted").click();
  await expect(page.getByTestId("access-unrestrict-confirm")).not.toContainText("cleared");
  await page.getByTestId("access-unrestrict-confirm").getByTestId("confirm-action").click();
  await expect(sentry.getByTestId("access-restricted")).not.toBeChecked();
});

test("turning the setting off is refused while a secret is restricted, and confirmed once allowed", async ({ page }) => {
  let card = await openSetting(page);
  await expect(card.getByTestId("secret-access-enabled")).toBeChecked();
  await expect(card.getByTestId("secret-access-restricted")).toContainText("STRIPE_SECRET_KEY");
  await card.getByTestId("secret-access-enabled").click();
  await page.getByTestId("secret-access-off-confirm").getByTestId("confirm-action").click();
  await expect(card.getByTestId("secret-access-refused")).toContainText("1 secret in this project is restricted");
  await expect(card.getByTestId("secret-access-enabled")).toBeChecked();

  // The restricted secret's row opens its drawer at the access section.
  await card.getByTestId("secret-access-open-prod-STRIPE_SECRET_KEY").click();
  const access = page.getByTestId("secret-drawer").getByTestId("access-section");
  await access.getByTestId("access-restricted").click();
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
  const off = page.getByTestId("secret-access-off-confirm");
  await expect(off).toContainText("including lists prepared on secrets that are still open");
  await off.getByTestId("confirm-action").click();
  await expectToast(page, "Per-secret access turned off");
  await expect(card.getByTestId("secret-access-enabled")).not.toBeChecked();

  // With the setting off and nobody listed, the drawer shows only the note.
  await openSecrets(page);
  const drawer = await openAccess(page, "STRIPE_SECRET_KEY");
  await expect(drawer.getByTestId("access-off")).toBeVisible();
  await expect(drawer.getByTestId("access-restricted")).toHaveCount(0);
  await expect(drawer.getByTestId("access-add")).toHaveCount(0);
});

test("restricts a secret from its drawer while the setting is on", async ({ page }) => {
  await openSecrets(page);
  const access = await openAccess(page, "SENTRY_DSN");
  await expect(access.getByTestId("access-restricted")).not.toBeChecked();
  await expect(access.getByTestId("access-empty")).toHaveText("No one is on the list.");
  await access.getByTestId("access-restricted").click();
  await expect(access.getByTestId("access-restricted")).toBeChecked();
  await expectToast(page, "Restricted SENTRY_DSN");
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

test("an old server that writes a restricted request open is called out, not reported as success", async ({ page }) => {
  await openSecrets(page, "prod", "storefront", "?mock-legacy-writes");
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await form.getByTestId("secret-key-input").fill("LEGACY_TOKEN");
  await form.getByTestId("secret-value-input").fill("tok");
  await form.getByTestId("secret-restricted-input").click();
  await form.getByTestId("secret-save").click();
  await expectToast(page, "did not confirm it is restricted");
  await expect(page.locator("[data-sonner-toast]").filter({ hasText: "Added LEGACY_TOKEN" })).toHaveCount(0);
  // The drawer opens at the access section, where the secret shows as open.
  const access = page.getByTestId("secret-drawer").getByTestId("access-section");
  await expect(access.getByTestId("access-restricted")).not.toBeChecked();
  await expect(secretRow(page, "LEGACY_TOKEN").getByTestId("secret-restricted-badge")).toHaveCount(0);
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
