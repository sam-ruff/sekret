import { expect, test } from "@playwright/test";
import { expectToast, navigate, openProject, secretRow } from "./helpers";

test("previews and restores a snapshot", async ({ page }) => {
  await openProject(page);
  await navigate(page, "nav-snapshots");
  await expect(page).toHaveURL(/\/snapshots\/dev/);

  const list = page.getByTestId("snapshot-list");
  await expect(list.locator("li").first()).toContainText("Latest");
  // The first write in dev, before LOG_LEVEL changed and the later secrets existed.
  await list.locator("li").last().getByRole("button").click();

  const sheet = page.getByTestId("snapshot-sheet");
  const changes = sheet.getByTestId("snapshot-changes");
  await expect(changes.getByTestId("change-LOG_LEVEL")).toContainText("Changed");
  await expect(changes.getByTestId("change-FEATURE_FLAGS")).toContainText("Removed");
  await expect(changes.getByTestId("change-WEBHOOK_SECRET")).toBeVisible();

  await sheet.getByTestId("restore-path").fill("/payments");
  await expect(changes.getByTestId("change-LOG_LEVEL")).toHaveCount(0);
  await expect(changes.getByTestId("change-WEBHOOK_SECRET")).toBeVisible();
  await sheet.getByTestId("restore-path").fill("/");

  await sheet.getByTestId("restore-snapshot").click();
  await page.getByTestId("restore-confirm").getByTestId("confirm-action").click();
  await expectToast(page, /Restored \d+ secrets/);

  await navigate(page, "nav-secrets");
  await expect(secretRow(page, "FEATURE_FLAGS")).toHaveCount(0);
  await secretRow(page, "LOG_LEVEL").getByTestId("secret-reveal").click();
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("debug");
});
