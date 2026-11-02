import { expect, test, type Page } from "@playwright/test";
import { addSecret, createProject, unique } from "./helpers";

test.describe.configure({ mode: "serial" });

async function setting(page: Page, slug: string) {
  await page.goto(`/projects/${slug}/settings/general`);
  const card = page.getByTestId("secret-access-setting");
  await expect(card.getByTestId("secret-access-enabled")).toBeVisible();
  return card;
}

async function openAccess(page: Page, key: string) {
  await page.getByTestId(`secret-row-${key}`).getByTestId("secret-key").click();
  const access = page.getByTestId("secret-drawer").getByTestId("access-section");
  await expect(access.getByTestId("access-restricted")).toBeVisible();
  return access;
}

test("restricts a secret, manages its list and refuses turning the setting off while it is restricted", async ({ page }) => {
  const slug = await createProject(page, unique("E2E Access"));
  await addSecret(page, "PAYOUT_TOKEN", "tok_live");

  // Off by default, so the drawer cannot restrict yet.
  let access = await openAccess(page, "PAYOUT_TOKEN");
  await expect(access.getByTestId("access-restricted")).toBeDisabled();
  await expect(access.getByTestId("access-off")).toBeVisible();

  let card = await setting(page, slug);
  await expect(card.getByTestId("secret-access-enabled")).not.toBeChecked();
  await card.getByTestId("secret-access-enabled").click();
  await expect(card.getByTestId("secret-access-enabled")).toBeChecked();

  await page.goto(`/projects/${slug}/secrets/dev`);
  access = await openAccess(page, "PAYOUT_TOKEN");
  await access.getByTestId("access-restricted").click();
  await expect(access.getByTestId("access-restricted")).toBeChecked();
  await expect(access.getByTestId("access-empty")).toContainText("only admins can reach it");

  await access.getByTestId("access-kind-group").click();
  await access.getByTestId("access-group").fill("payments-team");
  await access.getByTestId("access-add-submit").click();
  const entry = access.getByTestId("access-grant-payments-team");
  await expect(entry.getByTestId("access-action-payments-team-read-value")).toBeChecked();
  await entry.getByTestId("access-action-payments-team-edit").click();
  await expect(entry.getByTestId("access-action-payments-team-edit")).toBeChecked();

  // The admin who restricted it still reads it, and the list shows it as restricted.
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("secret-drawer")).toBeHidden();
  await expect(page.getByTestId("secret-row-PAYOUT_TOKEN").getByTestId("secret-restricted-badge")).toBeVisible();

  card = await setting(page, slug);
  await expect(card.getByTestId("secret-access-restricted")).toContainText("PAYOUT_TOKEN");
  await card.getByTestId("secret-access-enabled").click();
  await expect(card.getByTestId("secret-access-refused")).toContainText("1 secret in this project is restricted");
  await expect(card.getByTestId("secret-access-enabled")).toBeChecked();

  await page.goto(`/projects/${slug}/secrets/dev`);
  access = await openAccess(page, "PAYOUT_TOKEN");
  await access.getByTestId("access-revoke-payments-team").click();
  await expect(access.getByTestId("access-grant-payments-team")).toHaveCount(0);
  await access.getByTestId("access-restricted").click();
  await expect(access.getByTestId("access-restricted")).not.toBeChecked();
  await page.keyboard.press("Escape");

  card = await setting(page, slug);
  await card.getByTestId("secret-access-enabled").click();
  await expect(card.getByTestId("secret-access-enabled")).not.toBeChecked();
  await expect(card.getByTestId("secret-access-none")).toBeVisible();

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});

test("creates a secret restricted from the start", async ({ page }) => {
  const slug = await createProject(page, unique("E2E Restricted"));
  const card = await setting(page, slug);
  await card.getByTestId("secret-access-enabled").click();
  await expect(card.getByTestId("secret-access-enabled")).toBeChecked();

  await page.goto(`/projects/${slug}/secrets/dev`);
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await form.getByTestId("secret-key-input").fill("SIGNING_KEY");
  await form.getByTestId("secret-value-input").fill("sk");
  await form.getByTestId("secret-restricted-input").click();
  await form.getByTestId("secret-save").click();
  await expect(page.getByTestId("secret-row-SIGNING_KEY").getByTestId("secret-restricted-badge")).toBeVisible();

  const access = await openAccess(page, "SIGNING_KEY");
  await expect(access.getByTestId("access-restricted")).toBeChecked();
  await access.getByTestId("access-restricted").click();
  await expect(access.getByTestId("access-restricted")).not.toBeChecked();
  await page.keyboard.press("Escape");

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});
