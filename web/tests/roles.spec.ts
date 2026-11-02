import { expect, test } from "@playwright/test";
import { expectToast, failNext } from "./helpers";

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

test("asks before Escape or a click outside throws away a role being written", async ({ page }) => {
  await page.goto("/projects/storefront/settings/roles");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  // Nothing typed yet, so Escape just closes it.
  await page.keyboard.press("Escape");
  await expect(editor).toHaveCount(0);

  await page.getByTestId("new-role").click();
  await editor.getByTestId("role-name").fill("Half done");
  await editor.getByTestId("rule-secrets-read").click();
  await page.keyboard.press("Escape");
  const discard = page.getByTestId("discard-dialog");
  await discard.getByTestId("discard-keep").click();
  await expect(editor.getByTestId("role-name")).toHaveValue("Half done");
  await expect(editor.getByTestId("rule-secrets-read")).toBeChecked();

  await page.mouse.click(4, 4);
  await expect(discard).toBeVisible();
  await discard.getByTestId("discard-confirm").click();
  await expect(editor).toHaveCount(0);
  await expect(page.getByTestId("role-row-half-done")).toHaveCount(0);
});

test("each permission checkbox is named after its subject", async ({ page }) => {
  await page.goto("/projects/storefront/settings/roles");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  await expect(editor.getByRole("checkbox", { name: "Secrets: Read", exact: true })).toBeVisible();
  await expect(editor.getByRole("checkbox", { name: "Snapshots: Read", exact: true })).toBeVisible();
  await expect(editor.getByRole("checkbox", { name: "Read", exact: true })).toHaveCount(0);
});

test("role descriptions on phone cards sit under their label, left-aligned", async ({ page }) => {
  test.skip((page.viewportSize()?.width ?? 1280) >= 768, "Mobile layout only");
  await page.goto("/projects/storefront/settings/roles");
  const row = page.getByTestId("role-row-developer");
  const description = row.locator("td").filter({ hasText: "Description" });
  const align = await description.locator("div").first().evaluate((el) => getComputedStyle(el).textAlign);
  expect(align).not.toBe("right");
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

test("organisation access shows role names and describes what org roles can do", async ({ page }) => {
  await page.goto("/org/access");
  const binding = page.getByTestId("binding-row-user-sam@example.com-org-admin");
  await expect(binding.getByTestId("role-label-name")).toHaveText("org admin");
  await expect(binding.getByTestId("role-label-id")).toHaveText("org-admin");

  await page.getByTestId("access-tab-roles").click();
  await expect(page.getByTestId("roles-intro")).toContainText("organisation areas");
  await expect(page.getByTestId("roles-intro")).not.toContainText("folder, key or tag");

  await page.goto("/projects/storefront/settings/roles");
  await expect(page.getByTestId("roles-intro")).toContainText("environment, folder, key or tag");
});

test("the only org admin binding cannot be removed, and removing your own admin role says it is yours", async ({ page }) => {
  await page.goto("/org/access");
  const mine = page.getByTestId("binding-row-user-sam@example.com-org-admin");
  await mine.getByTestId("binding-remove").click();
  const dialog = page.getByTestId("binding-remove-confirm");
  await expect(dialog).toContainText("sam@example.com is the only org admin");
  await expect(dialog.getByTestId("binding-remove-description")).toContainText("Grant org admin to someone else first.");
  await expect(dialog.getByTestId("confirm-action")).toHaveCount(0);
  await dialog.getByTestId("confirm-cancel").click();

  // With a second admin, removing your own is allowed but worded for you.
  await page.getByTestId("binding-add").click();
  const add = page.getByTestId("add-binding-dialog");
  await add.getByTestId("binding-principal").click();
  await page.getByTestId("binding-principal-search").fill("priya");
  await page.getByTestId("principal-option-Priya Shah").click();
  await add.getByTestId("binding-role").click();
  await page.getByRole("option", { name: /org admin/i }).click();
  await add.getByTestId("binding-submit").click();
  await expect(page.getByTestId("binding-row-user-priya@example.com-org-admin")).toBeVisible();

  await mine.getByTestId("binding-remove").click();
  await expect(dialog).toContainText("Remove your own org admin role?");
  await expect(dialog.getByTestId("binding-remove-description")).toContainText("You may lose access to this page");
  await dialog.getByTestId("confirm-cancel").click();
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

test("an org admin is not held back by a deny when managing roles", async ({ page }) => {
  // The signed-in org admin may not read production values here, yet may still write any role.
  await page.goto("/projects/payments-api/settings/roles");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  await editor.getByTestId("role-name").fill("Value reader");
  await editor.getByTestId("rule-secrets-read-value").click();
  await editor.getByTestId("role-save").click();
  await expectToast(page, "Saved Value reader");
});

test("refuses path and key conditions that can never match before saving", async ({ page }) => {
  await page.goto("/projects/storefront/settings/roles");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  await editor.getByTestId("rule-secrets-conditions-toggle").click();
  await editor.getByTestId("condition-paths-secrets-input").fill("payments/**");
  await editor.getByTestId("condition-paths-secrets-input").press("Enter");
  await expect(editor.getByTestId("condition-paths-secrets-problem")).toContainText("This can never match");
  await editor.getByTestId("condition-keys-secrets-input").fill("1DB");
  await editor.getByTestId("condition-keys-secrets-input").press("Enter");
  await expect(editor.getByTestId("condition-keys-secrets-problem")).toContainText("keys start with a letter or _");
  await expect(editor.getByTestId("condition-paths-secrets-chip")).toHaveCount(0);
});

test("says plainly that only an admin can bind deny rules to an admin", async ({ page }) => {
  await page.goto("/org/access");
  await page.getByTestId("binding-add").click();
  const add = page.getByTestId("add-binding-dialog");
  await add.getByTestId("binding-principal").click();
  await page.getByTestId("binding-principal-search").fill("priya");
  await page.getByTestId("principal-option-Priya Shah").click();
  await add.getByTestId("binding-role").click();
  await page.getByRole("option", { name: /org member/i }).click();
  await failNext(page, "POST", "/org/bindings$", 403, "escalation", "only an admin can bind deny rules to an admin");
  await add.getByTestId("binding-submit").click();
  await expectToast(page, "Only an admin can give deny rules to an admin");
  // Not mistaken for granting more than the caller holds.
  await expect(add.getByTestId("binding-escalation")).toHaveCount(0);
});

test("explains when a role would escalate access", async ({ page }) => {
  // In this project the signed-in user may not read production values, so cannot grant reading values.
  await page.goto("/projects/payments-api/settings/roles?mock-org-role=org-member");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  await editor.getByTestId("role-name").fill("Value reader");
  await editor.getByTestId("rule-secrets-read-value").click();
  await editor.getByTestId("role-save").click();
  await expect(editor.getByTestId("role-escalation")).toContainText("a role cannot grant more access than you have", {
    ignoreCase: true,
  });
});

test("says when a role only takes access away", async ({ page }) => {
  await page.goto("/projects/storefront/settings/roles");
  await page.getByTestId("new-role").click();
  const editor = page.getByTestId("role-editor");
  await editor.getByTestId("role-name").fill("No values");
  await expect(editor.getByTestId("role-deny-only")).toHaveCount(0);

  await editor.getByTestId("add-rule").click();
  await page.getByTestId("add-rule-secrets").click();
  await editor.getByTestId("rule-secrets-extra").getByTestId("rule-secrets-extra-read-value").click();
  await expect(editor.getByTestId("role-deny-only")).toContainText("On its own it grants nothing");

  await editor.getByTestId("rule-secrets-read").click();
  await expect(editor.getByTestId("role-deny-only")).toHaveCount(0);
});
