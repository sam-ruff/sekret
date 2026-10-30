import { expect, test } from "@playwright/test";
import { addSecret, createProject, editSecret, revealedValue, unique } from "./helpers";

test.describe.configure({ mode: "serial" });

test("creates a project, adds and updates a secret, then rolls it back", async ({ page }) => {
  const name = unique("E2E Live");
  const slug = await createProject(page, name);
  await expect(page.getByTestId("env-tab-staging")).toBeVisible();

  await addSecret(page, "LIVE_TOKEN", "first");
  await expect(await revealedValue(page, "LIVE_TOKEN")).toHaveText("first");

  await editSecret(page, "LIVE_TOKEN", "second");
  await expect(page.getByTestId("secret-row-LIVE_TOKEN").getByTestId("secret-value")).toHaveText("second");

  // History lists both versions and diffs them.
  await page.getByTestId("secret-row-LIVE_TOKEN").getByTestId("secret-key").click();
  const drawer = page.getByTestId("secret-drawer");
  await expect(drawer.getByTestId("version-2")).toContainText("Current");
  await expect(drawer.getByTestId("version-1")).toBeVisible();
  await expect(drawer.getByTestId("diff-output").locator('[data-kind="removed"]')).toHaveText(/first/);
  await expect(drawer.getByTestId("diff-output").locator('[data-kind="added"]')).toHaveText(/second/);

  await drawer.getByTestId("rollback-1").click();
  await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
  await expect(drawer.getByTestId("version-3")).toContainText("Current");
  await drawer.getByRole("button", { name: "Close" }).click();
  await expect(drawer).toBeHidden();

  await page.reload();
  await expect(await revealedValue(page, "LIVE_TOKEN")).toHaveText("first");

  // The overview shows the key present in dev and missing elsewhere.
  await page.goto(`/projects/${slug}/overview`);
  const grid = page.getByTestId("overview-grid");
  await expect(grid.getByTestId("cell-LIVE_TOKEN-dev")).toHaveAttribute("data-present", "true");
  await expect(grid.getByTestId("cell-LIVE_TOKEN-prod")).toHaveAttribute("data-present", "false");
  await expect(grid.getByTestId("overview-row-LIVE_TOKEN")).toHaveAttribute("data-missing", "true");

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});
