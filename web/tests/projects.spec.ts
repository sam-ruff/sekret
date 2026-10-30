import { expect, test } from "@playwright/test";

test("lists the seeded projects", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/projects$/);
  await expect(page.getByTestId("project-card-storefront")).toBeVisible();
  await expect(page.getByTestId("project-card-payments-api")).toBeVisible();
});

test("creates a project with default environments", async ({ page }) => {
  await page.goto("/projects");
  await page.getByTestId("new-project").click();
  await page.getByTestId("project-name").fill("Inventory Service");
  await expect(page.getByTestId("project-slug")).toHaveValue("inventory-service");
  await page.getByTestId("create-project-submit").click();

  await expect(page).toHaveURL(/\/projects\/inventory-service\/secrets\/dev/);
  await expect(page.getByTestId("env-tab-dev")).toBeVisible();
  await expect(page.getByTestId("env-tab-staging")).toBeVisible();
  await expect(page.getByTestId("env-tab-prod")).toBeVisible();
  await expect(page.getByTestId("secrets-empty")).toBeVisible();
});

test("creates a project with custom environments", async ({ page }) => {
  await page.goto("/projects");
  await page.getByTestId("new-project").click();
  await page.getByTestId("project-name").fill("Edge");
  await page.getByTestId("custom-envs").click();
  const list = page.getByTestId("custom-env-list");
  await list.getByRole("button", { name: "Remove Staging" }).click();
  await page.getByTestId("add-env-row").click();
  await page.getByTestId("env-name-2").fill("QA");
  await page.getByTestId("create-project-submit").click();

  await expect(page).toHaveURL(/\/projects\/edge\/secrets\/dev/);
  await expect(page.getByTestId("env-tab-qa")).toBeVisible();
  await expect(page.getByTestId("env-tab-staging")).toHaveCount(0);
});
