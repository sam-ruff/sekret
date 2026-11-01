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
  // Removal reads as removing the secret, not deleting a version.
  await expect(changes.getByTestId("change-FEATURE_FLAGS").getByTestId("change-detail")).toHaveText(
    /^Would be removed \(currently version \d+\)$/,
  );
  await expect(changes.getByTestId("change-WEBHOOK_SECRET")).toBeVisible();

  // Existing folders are suggested, so the filter is not typed blind.
  const suggestions = await sheet.locator("#restore-path-folders option").evaluateAll((options) =>
    options.map((o) => (o as HTMLOptionElement).value),
  );
  expect(suggestions).toEqual(expect.arrayContaining(["/", "/payments"]));
  await expect(sheet.getByTestId("restore-path")).toHaveAttribute("list", "restore-path-folders");

  await sheet.getByTestId("restore-path").fill("/payments");
  await expect(changes.getByTestId("change-LOG_LEVEL")).toHaveCount(0);
  await expect(changes.getByTestId("change-WEBHOOK_SECRET")).toBeVisible();
  await sheet.getByTestId("restore-path").fill("/");
  await expect(changes.getByTestId("change-LOG_LEVEL")).toBeVisible();

  // A restore that removes secrets is styled and described as one.
  const restore = sheet.getByTestId("restore-snapshot");
  await expect(restore).toHaveAttribute("data-variant", "destructive");
  await restore.click();
  const confirm = page.getByTestId("restore-confirm");
  await expect(confirm).toContainText(/Restoring \/ in Development removes .*FEATURE_FLAGS/);
  await expect(confirm).toContainText("removed secrets keep their history");
  await expect(confirm).not.toContainText("will be written as new versions");
  await expect(confirm.getByTestId("confirm-action")).toHaveAttribute("data-variant", "destructive");
  await confirm.getByTestId("confirm-action").click();
  await expectToast(page, /Restored \d+ secrets/);

  await navigate(page, "nav-secrets");
  await expect(secretRow(page, "FEATURE_FLAGS")).toHaveCount(0);
  await secretRow(page, "LOG_LEVEL").getByTestId("secret-reveal").click();
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("debug");
});
