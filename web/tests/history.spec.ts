import { expect, test } from "@playwright/test";
import { expectToast, openProject, secretAction, secretRow } from "./helpers";

test("shows history, diffs versions and rolls back", async ({ page }) => {
  await openProject(page);
  await secretAction(page, "LOG_LEVEL", "secret-history");

  const drawer = page.getByTestId("secret-drawer");
  await expect(drawer.getByTestId("version-list").locator("li")).toHaveCount(3);
  await expect(drawer.getByTestId("version-3")).toContainText("Current");

  const diff = drawer.getByTestId("diff-output");
  await expect(diff.locator('[data-kind="removed"]')).toHaveText(/info/);
  await expect(diff.locator('[data-kind="added"]')).toHaveText(/warn/);

  await drawer.getByTestId("diff-from").click();
  await page.getByRole("option", { name: "Version 1" }).click();
  await expect(diff.locator('[data-kind="removed"]')).toHaveText(/debug/);

  await drawer.getByTestId("rollback-1").click();
  await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
  await expectToast(page, "Rolled LOG_LEVEL back to version 1");
  await expect(drawer.getByTestId("version-4")).toContainText("rolled back to version 1");

  await drawer.getByRole("button", { name: "Close" }).click();
  await expect(drawer).toBeHidden();
  await secretRow(page, "LOG_LEVEL").getByTestId("secret-reveal").click();
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("debug");
});
