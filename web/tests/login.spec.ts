import { expect, test } from "@playwright/test";

test("login page offers Keycloak sign-in", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByTestId("login-card")).toBeVisible();
  await expect(page.getByTestId("sign-in")).toHaveText(/Sign in with Keycloak/);
  await expect(page.getByTestId("login-error")).toHaveCount(0);
});

test("login page shows the error from a failed sign-in", async ({ page }) => {
  await page.goto("/login?error=state%20mismatch");
  await expect(page.getByTestId("login-error")).toContainText("state mismatch");
});

test("signing in returns to the requested page", async ({ page }) => {
  await page.goto("/login?return_to=%2Forg%2Fusers");
  await page.getByTestId("sign-in").click();
  await expect(page).toHaveURL(/\/org\/users$/);
});

test("signing out lands on the login page and protects the app", async ({ page }) => {
  await page.goto("/projects");
  await page.getByTestId("user-menu").click();
  await page.getByTestId("logout").click();
  await expect(page).toHaveURL(/\/login/);
  await page.goto("/projects");
  await expect(page).toHaveURL(/\/login\?return_to=%2Fprojects/);
});
