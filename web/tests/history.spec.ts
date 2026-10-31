import { expect, test } from "@playwright/test";
import { expectToast, openProject, secretAction, secretRow } from "./helpers";

test("hides history values until asked, then diffs versions and rolls back", async ({ page }) => {
  await openProject(page);
  await secretAction(page, "LOG_LEVEL", "secret-history");

  const drawer = page.getByTestId("secret-drawer");
  await expect(drawer.getByTestId("version-list").locator("li")).toHaveCount(3);
  await expect(drawer.getByTestId("version-3")).toContainText("Current");

  // Nothing is shown until the reader asks, and asking is audited.
  await expect(drawer.getByTestId("history-values-hidden")).toContainText("recorded in the audit log");
  await expect(drawer.getByTestId("diff-output")).toHaveCount(0);
  await expect(drawer.getByTestId("version-value-3")).not.toContainText("warn");
  await expect(drawer).not.toContainText("debug");

  await drawer.getByTestId("history-values-toggle").click();
  const diff = drawer.getByTestId("diff-output");
  await expect(diff.locator('[data-kind="removed"]')).toHaveText(/info/);
  await expect(diff.locator('[data-kind="added"]')).toHaveText(/warn/);
  await expect(drawer.getByTestId("version-value-1")).toHaveText("debug");

  await drawer.getByTestId("diff-from").click();
  await page.getByRole("option", { name: "Version 1" }).click();
  await expect(diff.locator('[data-kind="removed"]')).toHaveText(/debug/);

  await drawer.getByTestId("rollback-1").click();
  await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
  await expectToast(page, "Rolled LOG_LEVEL back to version 1");
  await expect(drawer.getByTestId("version-4")).toContainText("rolled back to version 1");

  await drawer.getByRole("button", { name: "Close" }).click();
  await expect(drawer).toBeHidden();

  // Reopening starts hidden again.
  await secretAction(page, "LOG_LEVEL", "secret-history");
  await expect(drawer.getByTestId("history-values-hidden")).toBeVisible();
  await expect(drawer.getByTestId("diff-output")).toHaveCount(0);
  await drawer.getByRole("button", { name: "Close" }).click();

  await secretRow(page, "LOG_LEVEL").getByTestId("secret-reveal").click();
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("debug");

  await page.goto("/org/audit");
  await expect(page.getByTestId("audit-action").filter({ hasText: "secret.history-read" }).first()).toBeVisible();
});
