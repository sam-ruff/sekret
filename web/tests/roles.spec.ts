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
