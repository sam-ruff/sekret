import { expect, test } from "@playwright/test";

test("a missing project explains itself and links back to the projects", async ({ page }) => {
  for (const section of ["secrets", "overview", "snapshots", "audit", "settings"]) {
    await page.goto(`/projects/nope/${section}`);
    await expect(page.getByTestId("project-missing")).toContainText("There is no project called nope");
    await expect(page.getByTestId("error-state")).toHaveCount(0);
  }
  // The header does not name the slug as if it were a project.
  await expect(page.getByRole("navigation", { name: "Location" })).not.toContainText("nope");
  await page.getByTestId("project-missing-back").click();
  await expect(page).toHaveURL(/\/projects$/);
  await expect(page.getByTestId("project-card-storefront")).toBeVisible();
});

test("a missing environment links to one that exists", async ({ page }) => {
  await page.goto("/projects/storefront/secrets/nope");
  await expect(page.getByTestId("environment-missing")).toContainText("There is no environment called nope");
  await page.getByTestId("environment-missing-back").click();
  await expect(page).toHaveURL(/\/projects\/storefront\/secrets\/dev$/);
  await expect(page.getByTestId("secrets-table")).toBeVisible();

  await page.goto("/projects/storefront/snapshots/nope");
  await expect(page.getByTestId("environment-missing")).toBeVisible();
  await page.getByTestId("environment-missing-back").click();
  await expect(page).toHaveURL(/\/projects\/storefront\/snapshots\/dev$/);
});

test("a missing machine identity links back to the list", async ({ page }) => {
  await page.goto("/org/identities/no-such-identity/auth");
  await expect(page.getByTestId("identity-missing")).toContainText("Identity not found");
  await page.getByTestId("identity-missing-back").click();
  await expect(page).toHaveURL(/\/org\/identities$/);
  await expect(page.getByTestId("identity-row-github-deploy")).toBeVisible();
});
