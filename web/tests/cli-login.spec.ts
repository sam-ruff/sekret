import { expect, test } from "@playwright/test";

test("approves a CLI login after showing the code and warning", async ({ page }) => {
  await page.goto("/cli-login?code=BCDF-2345");
  await expect(page.getByTestId("cli-code")).toHaveText("BCDF-2345");
  await expect(page.getByTestId("cli-warning")).toContainText(
    "Only approve this if you just ran sekret login yourself and the code matches your terminal",
  );
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
});

test("sends the browser to sign in again when the server asks, then approves on return", async ({ page }) => {
  await page.goto("/cli-login?code=AUTH-2345");
  await expect(page).toHaveTitle("Approve CLI sign-in · sekret");
  // The mock signs in again at once and loads the same page with the code again.
  const reloaded = page.waitForEvent("load");
  await page.getByTestId("cli-approve").click();
  await reloaded;
  await expect(page).toHaveURL(/\/cli-login\?code=AUTH-2345$/);
  await expect(page.locator("[data-sonner-toast]")).toHaveCount(0);
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
});

test("cancelling approves nothing", async ({ page }) => {
  await page.goto("/cli-login?code=BCDF-2345");
  await page.getByTestId("cli-cancel").click();
  await expect(page.getByTestId("cli-cancelled")).toBeVisible();
  await expect(page.getByTestId("cli-approve")).toHaveCount(0);
});

test("an unknown code reports the server error", async ({ page }) => {
  await page.goto("/cli-login?code=XXXX-0000");
  await page.getByTestId("cli-approve").click();
  await expect(page.locator("[data-sonner-toast]").first()).toContainText("unknown or has expired", { ignoreCase: true });
  await expect(page.getByTestId("cli-approved")).toHaveCount(0);
});
