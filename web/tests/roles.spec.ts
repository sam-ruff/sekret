import { expect, test } from "@playwright/test";
import { expectToast } from "./helpers";

test("creates a custom project role with a conditional deny", async ({ page }) => {
  await page.goto("/projects/storefront/settings/roles");
  await expect(page.getByTestId("role-row-developer")).toBeVisible();
  await page.getByTestId("new-role").click();

  const editor = page.getByTestId("role-editor");
  await editor.getByTestId("role-name").fill("Release manager");
  await expect(editor.getByTestId("role-slug")).toHaveValue("release-manager");

  await editor.getByTestId("rule-secrets-read").click();
  await editor.getByTestId("rule-secrets-read-value").click();
  await editor.getByTestId("rule-snapshots-read").click();
  await editor.getByTestId("rule-snapshots-edit").click();

  await editor.getByTestId("add-rule").click();
  await page.getByTestId("add-rule-secrets").click();
  const deny = editor.getByTestId("rule-secrets-extra");
  await expect(deny.getByTestId("rule-secrets-extra-deny")).toHaveAttribute("data-state", "on");
  await deny.getByTestId("rule-secrets-extra-read-value").click();
  await deny.getByTestId("rule-secrets-extra-conditions-toggle").click();
  await deny.getByTestId("condition-env-secrets-prod").click();
  await deny.getByTestId("condition-keys-secrets-input").fill("STRIPE_*");
  await deny.getByTestId("condition-keys-secrets-input").press("Enter");

  await editor.getByTestId("role-save").click();
  await expectToast(page, "Saved Release manager");
  const row = page.getByTestId("role-row-release-manager");
  await expect(row).toContainText("3");

  await row.getByTestId("role-actions-release-manager").click();
  await page.getByTestId("role-edit").click();
  const reopened = page.getByTestId("role-editor");
  const reopenedDeny = reopened.getByTestId("rule-secrets-extra");
  await expect(reopenedDeny.getByTestId("condition-env-secrets-prod")).toBeChecked();
  await expect(reopenedDeny.getByTestId("condition-keys-secrets")).toContainText("STRIPE_*");
  await expect(reopened.getByTestId("rule-secrets-read-value")).toBeChecked();
});

test("offers only the actions each subject uses, and explains what reading values means", async ({ page }) => {
  await page.goto("/projects/storefront/settings/roles");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");

  await expect(editor.getByTestId("rule-secrets-hint")).toContainText("Read value shows the secret itself");
  for (const action of ["read", "read-value", "create", "edit", "delete"]) {
    await expect(editor.getByTestId(`rule-secrets-${action}`)).toBeVisible();
  }
  const audit = editor.getByTestId("rule-audit-log");
  await expect(audit.getByTestId("rule-audit-log-read")).toBeVisible();
  for (const action of ["read-value", "create", "edit", "delete"]) {
    await expect(audit.getByTestId(`rule-audit-log-${action}`)).toHaveCount(0);
  }
  await expect(editor.getByTestId("rule-secret-versions-create")).toHaveCount(0);
  await expect(editor.getByTestId("rule-secret-versions-read-value")).toBeVisible();
  await expect(editor.getByTestId("rule-members-read-value")).toHaveCount(0);
  await expect(editor.getByTestId("rule-snapshots-delete")).toHaveCount(0);
  await expect(editor.getByTestId("rule-snapshots-hint")).toContainText("Edit restores a snapshot");

  // The save button says why it is disabled.
  await expect(editor.getByTestId("role-save")).toBeDisabled();
  await expect(editor.getByTestId("role-blocker")).toHaveText("Give the role a name to save it.");
  await editor.getByTestId("role-name").fill("Auditor");
  await expect(editor.getByTestId("role-blocker")).toHaveCount(0);
  await expect(editor.getByTestId("role-save")).toBeEnabled();
});

test("the chosen effect stands out from the other", async ({ page }) => {
  await page.goto("/projects/storefront/settings/roles");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  const allow = editor.getByTestId("rule-secrets-allow");
  const deny = editor.getByTestId("rule-secrets-deny");
  await expect(allow).toHaveAttribute("data-state", "on");
  const background = (locator: typeof allow) => locator.evaluate((el) => getComputedStyle(el).backgroundColor);
  const unselected = await background(deny);
  expect(await background(allow)).not.toBe(unselected);
  await expect(allow.locator("svg")).toHaveCount(1);

  await deny.click();
  await expect(deny).toHaveAttribute("data-state", "on");
  expect(await background(deny)).not.toBe(await background(allow));
  await expect(allow.locator("svg")).toHaveCount(0);
});

test("built-in roles open read-only", async ({ page }) => {
  await page.goto("/projects/storefront/settings/roles");
  await page.getByTestId("role-actions-viewer").click();
  await page.getByTestId("role-view").click();
  const editor = page.getByTestId("role-editor");
  await expect(editor.getByTestId("rule-secrets-read")).toBeChecked();
  await expect(editor.getByTestId("rule-secrets-read")).toBeDisabled();
  await expect(editor.getByTestId("role-save")).toHaveCount(0);
});

test("explains when a role would escalate access", async ({ page }) => {
  // In this project the signed-in user may not read production values, so cannot grant reading values.
  await page.goto("/projects/payments-api/settings/roles");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  await editor.getByTestId("role-name").fill("Value reader");
  await editor.getByTestId("rule-secrets-read-value").click();
  await editor.getByTestId("role-save").click();
  await expect(editor.getByTestId("role-escalation")).toContainText("a role cannot grant more access than you have", {
    ignoreCase: true,
  });
});
