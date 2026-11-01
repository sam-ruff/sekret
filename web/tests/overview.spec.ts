import { expect, test } from "@playwright/test";
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

test("a missing cell opens the add form with the key filled in", async ({ page }) => {
  await openProject(page);
  await navigate(page, "nav-overview");
  await page.getByTestId("cell-link-REDIS_URL-prod").click();

  await expect(page).toHaveURL(/\/secrets\/prod$/);
  const form = page.getByTestId("new-secret-form");
  await expect(form.getByTestId("secret-key-input")).toHaveValue("REDIS_URL");
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
