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

test("the new project dialog says why it cannot be created yet", async ({ page }) => {
  await page.goto("/projects");
  await page.getByTestId("new-project").click();
  const submit = page.getByTestId("create-project-submit");
  await expect(submit).toBeDisabled();
  await expect(page.getByTestId("project-blocker")).toHaveText("Give the project a name to continue.");
  await page.getByTestId("project-name").fill("Edge");
  await page.getByTestId("project-slug").fill("-edge");
  await expect(page.getByTestId("project-blocker")).toContainText("Fix the ID to continue");
  await page.getByTestId("project-slug").fill("edge");
  await expect(page.getByTestId("project-blocker")).toHaveCount(0);
  await expect(submit).toBeEnabled();
});

test("the environment dialog explains an invalid ID", async ({ page }) => {
  await page.goto("/projects/storefront/settings/environments");
  await page.getByTestId("add-environment").click();
  const dialog = page.getByTestId("environment-dialog");
  await expect(dialog).toContainText("Each environment has its own values for every secret.");
  await dialog.getByTestId("env-name").fill("QA");
  await dialog.getByTestId("env-slug").fill("bad slug!");
  await expect(dialog.getByTestId("env-save")).toBeDisabled();
  await expect(dialog.getByTestId("env-blocker")).toHaveText(
    "IDs use lowercase letters, digits and dashes, starting with a letter or digit.",
  );
  await expect(dialog.getByTestId("env-slug")).toHaveAttribute("aria-invalid", "true");
  await dialog.getByTestId("env-slug").fill("qa");
  await expect(dialog.getByTestId("env-blocker")).toHaveCount(0);
  await expect(dialog.getByTestId("env-save")).toBeEnabled();
});

test("the delete project dialog restates what goes and labels its input", async ({ page }) => {
  await page.goto("/projects/storefront/settings/danger");
  await page.getByTestId("delete-project").click();
  const dialog = page.getByTestId("delete-project-confirm");
  await expect(dialog).toContainText("Every environment, secret, version, snapshot, member and custom role goes with it.");
  await expect(dialog.getByRole("textbox", { name: "Project ID to confirm deletion" })).toBeVisible();
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
