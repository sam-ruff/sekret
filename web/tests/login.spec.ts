import { expect, test } from "./fixture";

test("login page offers a generic sign-in on the shared standalone layout", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByTestId("login-card")).toBeVisible();
  await expect(page.getByTestId("sign-in")).toHaveText(/^Sign in$/);
  await expect(page.getByTestId("sign-in")).not.toContainText("Keycloak");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Sign in to sekret");
  await expect(page.getByTestId("login-card")).toContainText("Sign in with your organisation account to manage secrets.");
  await expect(page).toHaveTitle("Sign in · sekret");
  await expect(page.getByTestId("login-error")).toHaveCount(0);

  // Centred vertically at every width.
  const card = await page.getByTestId("login-card").boundingBox();
  const viewport = page.viewportSize();
  expect(card && viewport).toBeTruthy();
  if (card && viewport) {
    const above = card.y;
    const below = viewport.height - (card.y + card.height);
    expect(Math.abs(above - below)).toBeLessThan(4);
  }
});

test("login page explains a failed sign-in from its fixed code", async ({ page }) => {
  await page.goto("/login?error=not_allowed");
  await expect(page.getByTestId("login-error")).toContainText("Your account is not allowed to use sekret.");
  await page.goto("/login?error=other_browser");
  await expect(page.getByTestId("login-error")).toContainText("started in another browser");
});

test("login page never shows text an attacker put in the error parameter", async ({ page }) => {
  const lure = "Your account is locked. Call +44 20 7946 0000 to restore access.";
  await page.goto(`/login?error=${encodeURIComponent(lure)}`);
  await expect(page.getByTestId("login-error")).toContainText("Signing in did not work. Please try again.");
  await expect(page.getByTestId("login-card")).not.toContainText("7946");
  await expect(page.getByTestId("login-card")).not.toContainText("locked");
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
