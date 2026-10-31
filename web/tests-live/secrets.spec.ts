import { expect, test, type Page } from "@playwright/test";
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
  // Values stay hidden until asked for.
  await expect(drawer.getByTestId("diff-output")).toHaveCount(0);
  await expect(drawer.getByTestId("version-value-1")).not.toContainText("first");
  await drawer.getByTestId("history-values-toggle").click();
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

/** Records every secrets API request the page makes from now on. */
function watchSecretRequests(page: Page): string[] {
  const seen: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.includes("/secrets")) seen.push(`${request.method()} ${url.pathname}${url.search}`);
  });
  return seen;
}

test("values stay in the environment they were revealed in, and one secret is fetched on its own", async ({ page }) => {
  const slug = await createProject(page, unique("E2E Reveal"));
  await addSecret(page, "SHARED_KEY", "dev-value");
  await page.getByTestId("env-tab-prod").click();
  await expect(page.getByTestId("env-tab-prod")).toHaveAttribute("aria-current", "page");
  await addSecret(page, "SHARED_KEY", "prod-value");
  await page.getByTestId("env-tab-dev").click();
  await expect(page.getByTestId("env-tab-dev")).toHaveAttribute("aria-current", "page");

  const requests = watchSecretRequests(page);
  await expect(await revealedValue(page, "SHARED_KEY")).toHaveText("dev-value");
  await editSecret(page, "SHARED_KEY", "dev-value-2");
  await expect(page.getByTestId("secret-row-SHARED_KEY").getByTestId("secret-value")).toHaveText("dev-value-2");
  // Revealing and editing fetched SHARED_KEY alone, never every value in the folder.
  expect(requests.filter((r) => r.includes("values=true"))).toEqual([]);
  expect(requests.some((r) => r.startsWith(`GET /api/v1/projects/${slug}/environments/dev/secrets/SHARED_KEY`))).toBe(true);

  const mark = requests.length;
  await page.getByTestId("env-tab-prod").click();
  await expect(page.getByTestId("env-tab-prod")).toHaveAttribute("aria-current", "page");
  const prodRow = page.getByTestId("secret-row-SHARED_KEY");
  await expect(prodRow.getByTestId("secret-reveal")).toHaveAttribute("aria-label", "Reveal SHARED_KEY");
  await expect(prodRow.getByTestId("secret-value")).not.toContainText("prod-value");
  const afterSwitch = requests.slice(mark);
  expect(afterSwitch.filter((r) => r.includes("values=true") || r.includes("/secrets/SHARED_KEY"))).toEqual([]);

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});
