import { expect, test } from "@playwright/test";
import { createProject, unique } from "./helpers";

test("saves a custom role with a conditional deny and reloads it", async ({ page }) => {
  const slug = await createProject(page, unique("E2E Roles"));
  await page.goto(`/projects/${slug}/settings/roles`);
  await expect(page.getByTestId("role-row-admin")).toBeVisible();

  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  await editor.getByTestId("role-name").fill("Live reader");
  await editor.getByTestId("rule-secrets-read").click();
  await editor.getByTestId("rule-secrets-read-value").click();
  await editor.getByTestId("add-rule").click();
  await page.getByTestId("add-rule-secrets").click();
  const deny = editor.getByTestId("rule-secrets-extra");
  await deny.getByTestId("rule-secrets-extra-read-value").click();
  await deny.getByTestId("rule-secrets-extra-conditions-toggle").click();
  await deny.getByTestId("condition-env-secrets-prod").click();
  await editor.getByTestId("role-save").click();

  const row = page.getByTestId("role-row-live-reader");
  await expect(row).toBeVisible();
  await page.reload();
  await page.getByTestId("role-actions-live-reader").click();
  await page.getByTestId("role-edit").click();
  const reopened = page.getByTestId("role-editor");
  await expect(reopened.getByTestId("rule-secrets-read-value")).toBeChecked();
  await expect(reopened.getByTestId("rule-secrets-extra").getByTestId("condition-env-secrets-prod")).toBeChecked();
  await page.keyboard.press("Escape");

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});
