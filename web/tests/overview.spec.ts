import { expect, test } from "./fixture";
import { isMobile, navigate, openProject } from "./helpers";

test("highlights keys missing from some environments", async ({ page }) => {
  await openProject(page);
  await navigate(page, "nav-overview");

  const grid = page.getByTestId("overview-grid");
  await expect(grid.getByTestId("overview-env-dev")).toBeVisible();
  await expect(grid.getByTestId("overview-env-prod")).toBeVisible();

  await expect(grid.getByTestId("cell-DATABASE_URL-prod")).toHaveAttribute("data-present", "true");
  await expect(grid.getByTestId("overview-row-DATABASE_URL")).toHaveAttribute("data-missing", "false");
  await expect(grid.getByTestId("cell-REDIS_URL-prod")).toHaveAttribute("data-present", "false");
  await expect(grid.getByTestId("cell-REDIS_URL-prod")).toContainText("Missing");
  await expect(grid.getByTestId("overview-row-REDIS_URL")).toHaveAttribute("data-missing", "true");
  await expect(page.getByTestId("overview-summary")).toContainText("missing from at least one environment");

  await page.getByTestId("only-missing").click();
  await expect(grid.getByTestId("overview-row-DATABASE_URL")).toHaveCount(0);
  await expect(grid.getByTestId("overview-row-REDIS_URL")).toBeVisible();

  await page.getByTestId("overview-folder-payments").click();
  await expect(page.getByTestId("overview-grid").getByTestId("overview-row-WEBHOOK_SECRET")).toBeVisible();
});

test("an empty folder offers the next step instead of a dead end", async ({ page }) => {
  await page.goto("/projects/storefront/overview?path=%2Fnothing-here");
  const empty = page.getByTestId("overview-empty");
  await expect(empty).toContainText("No secrets in this folder");
  await expect(page.getByTestId("only-missing")).toHaveCount(0);

  await empty.getByTestId("overview-import").click();
  await expect(page).toHaveURL(/\/projects\/storefront\/secrets\/dev\?path=%2Fnothing-here$/);
  await expect(page.getByTestId("import-env-text")).toBeVisible();
  await page.keyboard.press("Escape");

  await page.goto("/projects/storefront/overview?path=%2Fnothing-here");
  await expect(page.getByTestId("overview-add-secret")).toHaveText("Add secret to Development");
  await page.getByTestId("overview-add-secret").click();
  await expect(page.getByTestId("new-secret-form").getByTestId("secret-key-input")).toHaveValue("");
  // A blank form starts at the key.
  await expect(page.getByTestId("new-secret-form").getByTestId("secret-key-input")).toBeFocused();
  await expect(page).toHaveURL(/\/secrets\/dev\?path=%2Fnothing-here$/);
});

test("a missing cell opens the add form with the key filled in", async ({ page }) => {
  await openProject(page);
  await navigate(page, "nav-overview");
  await page.getByTestId("cell-link-REDIS_URL-prod").click();

  await expect(page).toHaveURL(/\/secrets\/prod$/);
  const form = page.getByTestId("new-secret-form");
  await expect(form.getByTestId("secret-key-input")).toHaveValue("REDIS_URL");
  // The key is filled in, so the value is what is left to type.
  await expect(form.getByTestId("secret-value-input")).toBeFocused();
  await form.getByTestId("secret-value-input").fill("redis://prod:6379");
  await form.getByTestId("secret-save").click();
  await expect(page.getByTestId("secret-row-REDIS_URL")).toBeVisible();

  // A present cell just opens the environment.
  await navigate(page, "nav-overview");
  await page.getByTestId("cell-link-DATABASE_URL-prod").click();
  await expect(page).toHaveURL(/\/secrets\/prod$/);
  await expect(page.getByTestId("new-secret-form")).toHaveCount(0);
});

test("the swipe hint on phones sits above the grid, not under it", async ({ page }) => {
  test.skip(!isMobile(page), "the hint is only shown on narrow screens");
  await openProject(page);
  await navigate(page, "nav-overview");
  const hint = page.getByTestId("overview-swipe-hint");
  await expect(hint).toBeVisible();
  const hintBox = await hint.boundingBox();
  const gridBox = await page.getByTestId("overview-grid").boundingBox();
  expect(hintBox && gridBox && hintBox.y + hintBox.height <= gridBox.y).toBe(true);
});

test("a huge folder is drawn a page at a time in the overview and the restore preview", async ({ page }) => {
  await openProject(page);
  const lines = Array.from({ length: 150 }, (_, i) => `BULK_${String(i).padStart(3, "0")}=value-${i}`);
  await page.getByTestId("secrets-more").click();
  await page.getByTestId("import-env").click();
  await page.getByTestId("import-env-text").fill(lines.join("\n"));
  await page.getByTestId("import-env-submit").click();
  await expect(page.locator("[data-sonner-toast]").filter({ hasText: /Imported: 150 added/ })).toBeVisible();

  await navigate(page, "nav-overview");
  const grid = page.getByTestId("overview-grid");
  await expect(grid.locator('[data-testid^="overview-row-"]')).toHaveCount(100);
  await expect(page.getByTestId("overview-more-count")).toContainText("Showing 100 of");
  await page.getByTestId("overview-show-more").click();
  await expect(page.getByTestId("overview-show-more")).toHaveCount(0);
  await expect(grid.getByTestId("overview-row-BULK_149")).toBeVisible();

  // Restoring the snapshot from before the import would remove all 150, a page at a time.
  await navigate(page, "nav-snapshots");
  await page.getByTestId("snapshot-1").click();
  const sheet = page.getByTestId("snapshot-sheet");
  await expect(sheet.getByTestId("snapshot-changes").locator("li")).toHaveCount(100);
  await expect(sheet.getByTestId("changes-more-count")).toHaveText("Showing 100 of 150");
  await sheet.getByTestId("changes-show-more").click();
  await expect(sheet.getByTestId("snapshot-changes").locator("li")).toHaveCount(150);
  await expect(sheet.getByTestId("restore-snapshot")).toHaveText(/Restore 150 changes/);
});
