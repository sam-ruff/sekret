import { expect, test } from "@playwright/test";
import { navigate, openProject } from "./helpers";

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
