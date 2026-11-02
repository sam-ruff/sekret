import { expect, test, type Page } from "@playwright/test";
import { addSecret, createProject, editSecret, revealedValue, unique } from "./helpers";

test.describe.configure({ mode: "serial" });

test("a restore that removes secrets names them and keeps their history", async ({ page }) => {
  const slug = await createProject(page, unique("E2E Restore"));
  await addSecret(page, "KEEP_ME", "one");
  await addSecret(page, "LATER_KEY", "two");

  await page.goto(`/projects/${slug}/snapshots/dev`);
  // The oldest snapshot is from before LATER_KEY existed.
  await page.getByTestId("snapshot-list").locator("li").last().getByRole("button").click();
  const sheet = page.getByTestId("snapshot-sheet");
  await expect(sheet.getByTestId("change-LATER_KEY").getByTestId("change-detail")).toHaveText(
    "Would be removed (currently version 1)",
  );
  const restore = sheet.getByTestId("restore-snapshot");
  await expect(restore).toHaveAttribute("data-variant", "destructive");
  await restore.click();
  const confirm = page.getByTestId("restore-confirm");
  await expect(confirm).toContainText("Restoring / in Development removes LATER_KEY.");
  await expect(confirm).toContainText("removed secrets keep their history");
  await confirm.getByTestId("confirm-action").click();
  await expect(sheet).toBeHidden();

  await page.goto(`/projects/${slug}/secrets/dev`);
  await expect(page.getByTestId("secret-row-KEEP_ME")).toBeVisible();
  await expect(page.getByTestId("secret-row-LATER_KEY")).toHaveCount(0);

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});

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

  // Escape closes only the confirm, leaving the drawer open with focus back on the button.
  await drawer.getByTestId("rollback-1").click();
  await expect(page.getByTestId("rollback-confirm")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("rollback-confirm")).toBeHidden();
  await expect(drawer).toBeVisible();
  await expect(drawer.getByTestId("rollback-1")).toBeFocused();

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

test("an edit waits for the value, and rotation and rollback keep the comment", async ({ page }) => {
  const slug = await createProject(page, unique("E2E Comment"));

  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await form.getByTestId("secret-key-input").fill("API_TOKEN");
  await form.getByTestId("secret-value-input").fill("keep-me");
  await form.getByTestId("secret-comment-input").fill("Vendor token");
  await form.getByTestId("secret-save").click();
  const row = page.getByTestId("secret-row-API_TOKEN");
  await expect(row.getByTestId("secret-comment")).toHaveText("Vendor token");

  // While the value cannot be read, the editor stays closed instead of starting empty.
  const valueUrl = (url: URL) => url.pathname === `/api/v1/projects/${slug}/environments/dev/secrets/API_TOKEN`;
  await page.route(valueUrl, (route) =>
    route.request().method() === "GET"
      ? route.fulfill({ status: 500, contentType: "application/json", body: '{"error":"internal","message":"try later"}' })
      : route.fallback(),
  );
  await row.getByTestId("secret-actions").click();
  await page.getByTestId("secret-edit").click();
  const failed = page.getByTestId("edit-load-failed-API_TOKEN");
  await expect(failed).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("edit-secret-API_TOKEN")).toHaveCount(0);
  await page.unroute(valueUrl);
  await failed.getByRole("button", { name: "Try again" }).click();

  const editor = page.getByTestId("edit-secret-API_TOKEN");
  await expect(editor.getByTestId("secret-value-input")).toHaveValue("keep-me");
  await editor.getByTestId("secret-comment-input").fill("Vendor token, renewed yearly");
  await editor.getByTestId("secret-save").click();
  await expect(editor).toBeHidden();
  await expect(await revealedValue(page, "API_TOKEN")).toHaveText("keep-me");

  // Rolling back keeps the restored version's comment, with the rollback in front.
  await row.getByTestId("secret-key").click();
  const drawer = page.getByTestId("secret-drawer");
  await drawer.getByTestId("rollback-1").click();
  await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
  await expect(drawer.getByTestId("version-3")).toContainText("rolled back to version 1: Vendor token");
  await drawer.getByRole("button", { name: "Close" }).click();
  await expect(drawer).toBeHidden();
  await expect(row.getByTestId("secret-comment")).toHaveText("rolled back to version 1: Vendor token");

  // Rotating by hand keeps the comment as it is.
  await row.getByTestId("secret-key").click();
  await expect(drawer.getByTestId("version-3")).toBeVisible();
  await drawer.getByTestId("policy-rotate-now").click();
  await page.getByTestId("rotate-confirm").getByTestId("confirm-action").click();
  await expect(drawer.getByTestId("version-4")).toContainText("Current");
  await expect(drawer.getByTestId("version-4")).toContainText("rolled back to version 1: Vendor token");
  await drawer.getByRole("button", { name: "Close" }).click();

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

test("a long history is fetched from the server a page at a time", async ({ page }) => {
  test.setTimeout(180_000);
  const slug = await createProject(page, unique("E2E History"));
  // Written through the API from the page, so the session cookie and CSRF header are the app's own.
  await page.evaluate(async (project) => {
    for (let i = 1; i <= 55; i++) {
      const response = await fetch(`/api/v1/projects/${project}/environments/dev/secrets/LONG_HISTORY?path=%2F`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "x-sekret-csrf": "1" },
        body: JSON.stringify({ value: `value-${i}`, comment: "", tags: [] }),
      });
      if (!response.ok) throw new Error(`write ${i} failed with ${response.status}`);
    }
  }, slug);
  await page.reload();

  const pages: string[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/LONG_HISTORY/versions")) pages.push(new URL(r.url()).search);
  });
  await page.getByTestId("secret-row-LONG_HISTORY").getByTestId("secret-key").click();
  const drawer = page.getByTestId("secret-drawer");
  const items = drawer.getByTestId("version-list").locator("li");
  await expect(items).toHaveCount(50);
  await drawer.getByTestId("history-values-toggle").click();
  await expect(drawer.getByTestId("version-value-55")).toHaveText("value-55");
  await drawer.getByTestId("history-load-older").click();
  await expect(items).toHaveCount(55);
  await expect(drawer.getByTestId("version-value-1")).toHaveText("value-1");
  await expect(drawer.getByTestId("history-load-older")).toHaveCount(0);
  expect(pages.every((q) => q.includes("limit=50"))).toBe(true);
  expect(pages.some((q) => q.includes("before=6"))).toBe(true);

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});

test("an environment with secrets cannot be deleted, and an empty one needs its ID typed", async ({ page }) => {
  const slug = await createProject(page, unique("E2E Envs"));
  await page.goto(`/projects/${slug}/secrets/staging`);
  await addSecret(page, "KEEP_ME", "here");

  await page.goto(`/projects/${slug}/settings/environments`);
  await page.getByTestId("env-delete-staging").click();
  const dialog = page.getByTestId("delete-env-confirm");
  await expect(dialog).toContainText("Staging is not empty");
  await expect(dialog.getByTestId("confirm-action")).toHaveCount(0);
  await dialog.getByTestId("confirm-cancel").click();

  await page.getByTestId("env-delete-prod").click();
  await expect(dialog.getByTestId("delete-env-contents")).toContainText("It holds no secrets you can see.");
  await expect(dialog.getByTestId("confirm-action")).toBeDisabled();
  await dialog.getByTestId("delete-env-slug").fill("prod");
  await dialog.getByTestId("confirm-action").click();
  await expect(page.getByTestId("env-delete-prod")).toHaveCount(0);

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});
