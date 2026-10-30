import { expect, test as setup } from "@playwright/test";
import { signInThroughKeycloak } from "./helpers";

setup("sign in through Keycloak", async ({ page }) => {
  await signInThroughKeycloak(page);
  await expect(page.getByTestId("page-title")).toHaveText("Projects");
  await page.context().storageState({ path: "tests-live/.auth/state.json" });
});
