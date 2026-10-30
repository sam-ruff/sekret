import { expect, test } from "@playwright/test";
import { signInThroughKeycloak } from "./helpers";

test.describe("without a session", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("protected pages send the browser to the login page", async ({ page }) => {
    await page.goto("/org/identities");
    await expect(page).toHaveURL(/\/login\?return_to=%2Forg%2Fidentities/);
    await expect(page.getByTestId("sign-in")).toBeVisible();
  });

  test("signs in through Keycloak and returns to the requested page", async ({ page }) => {
    await signInThroughKeycloak(page, "/org/identities");
    await expect(page.getByTestId("page-title")).toHaveText("Machine identities");
    await page.getByTestId("user-menu").click();
    await expect(page.getByTestId("logout")).toBeVisible();
  });
});

test("the saved session reaches the API", async ({ page }) => {
  await page.goto("/projects");
  await expect(page.getByTestId("page-title")).toHaveText("Projects");
  await expect(page.getByTestId("error-state")).toHaveCount(0);
});
