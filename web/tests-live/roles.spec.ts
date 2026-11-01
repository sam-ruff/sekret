import { expect, test } from "@playwright/test";
import { createProject, unique } from "./helpers";

test("changes a member's role in one step and shows role names", async ({ page }) => {
  const bot = unique("e2e-member");
  await page.goto("/org/identities");
  await page.getByTestId("new-identity").click();
  await page.getByTestId("identity-name").fill(bot);
  await page.getByTestId("identity-create-submit").click();
  await expect(page).toHaveURL(/\/org\/identities\/[^/]+\/auth$/);
  const identityUrl = page.url().replace(/\/auth$/, "");

  const slug = await createProject(page, unique("E2E Members"));
  await page.goto(`/projects/${slug}/settings/members`);
  await page.getByTestId("add-member").click();
  const dialog = page.getByTestId("add-member-dialog");
  await dialog.getByTestId("member-kind-identity").click();
  await dialog.getByTestId("member-principal").click();
  await page.getByTestId("member-principal-search").fill(bot);
  await page.getByTestId(`principal-option-${bot}`).click();
  await dialog.getByTestId("member-role").click();
  await page.getByRole("option", { name: "Viewer" }).click();
  await dialog.getByTestId("member-add-submit").click();

  const row = page.getByTestId(`member-row-${bot}`);
  await expect(row.getByTestId("role-label-name")).toHaveText("viewer");
  await row.getByTestId("member-change-role").click();
  const change = page.getByTestId("change-role-dialog");
  await change.getByTestId("change-role-select").click();
  await page.getByTestId("change-role-option-developer").click();
  await change.getByTestId("confirm-action").click();
  await expect(page.getByTestId(`member-row-${bot}`)).toHaveCount(1);
  await expect(page.getByTestId(`member-row-${bot}`).getByTestId("role-label-name")).toHaveText("developer");
  await page.reload();
  await expect(page.getByTestId(`member-row-${bot}`).getByTestId("role-label-name")).toHaveText("developer");

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
  await page.goto(identityUrl);
  await page.getByTestId("identity-delete").click();
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/org\/identities$/);
});

test("saves a custom role with a conditional deny and reloads it", async ({ page }) => {
  const slug = await createProject(page, unique("E2E Roles"));
  await page.goto(`/projects/${slug}/settings/roles`);
  await expect(page.getByTestId("role-row-admin")).toBeVisible();

  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  // Only the actions the server checks for each subject are offered.
  await expect(editor.getByTestId("rule-audit-log-read")).toBeVisible();
  await expect(editor.getByTestId("rule-audit-log-create")).toHaveCount(0);
  await expect(editor.getByTestId("rule-members-read-value")).toHaveCount(0);
  await expect(editor.getByTestId("rule-secrets-hint")).toContainText("Read value shows the secret itself");
  await expect(editor.getByTestId("role-blocker")).toBeVisible();
  await editor.getByTestId("role-name").fill("Live reader");
  await expect(editor.getByTestId("role-blocker")).toHaveCount(0);
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
