import { expect, test } from "@playwright/test";
import { expectToast, navigate, openProject, secretRow } from "./helpers";

test("previews and restores a snapshot", async ({ page }) => {
  await openProject(page);
  await navigate(page, "nav-snapshots");
  await expect(page).toHaveURL(/\/snapshots\/dev/);

  const list = page.getByTestId("snapshot-list");
  await expect(list.locator("li").first()).toContainText("Latest");
  // Titles leave out zero counts and wrap rather than cut off the folder.
  const titles = await list.getByTestId("snapshot-title").allTextContents();
  expect(titles.some((t) => / 0 (created|updated|deleted|added|changed)/.test(t) || /^0 /.test(t))).toBe(false);
  // Counts say what they count, and the top folder has the same name as in the breadcrumbs.
  expect(titles.filter((t) => /^\d/.test(t)).every((t) => /^\d+ secrets? /.test(t))).toBe(true);
  expect(titles.some((t) => t.includes("top folder"))).toBe(false);
  // The first write in dev, before LOG_LEVEL changed and the later secrets existed.
  await list.locator("li").last().getByRole("button").click();

  const sheet = page.getByTestId("snapshot-sheet");
  await expect(sheet).toBeVisible();
  // Nothing is typed into on opening, so no on-screen keyboard covers the changes.
  await expect(sheet.getByTestId("restore-path")).not.toBeFocused();
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
