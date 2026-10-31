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

  test("signing out reaches Keycloak's logout, with no stop at the login page on the way", async ({ page }) => {
    await signInThroughKeycloak(page, "/projects");
    await expect(page.getByTestId("page-title")).toHaveText("Projects");
    await page.getByTestId("user-menu").click();
    const visited: string[] = [];
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) visited.push(new URL(frame.url()).pathname);
    });
    await page.getByTestId("logout").click();
    await page.waitForURL((url) => url.pathname.endsWith("/protocol/openid-connect/logout"), { timeout: 30_000 });
    expect(visited.find((path) => path !== "/projects")).toMatch(/\/protocol\/openid-connect\/logout$/);
    expect(visited).not.toContain("/login");

    // The sekret session is gone too.
    await page.goto("/org/identities");
    await expect(page).toHaveURL(/\/login\?return_to=%2Forg%2Fidentities/);
  });
});

test("the saved session reaches the API", async ({ page }) => {
  await page.goto("/projects");
  await expect(page.getByTestId("page-title")).toHaveText("Projects");
  await expect(page.getByTestId("error-state")).toHaveCount(0);
});
