import { expect, test } from "@playwright/test";
import { expectToast, isMobile, openProject, secretAction, secretRow } from "./helpers";

test.beforeEach(async ({ page }) => {
  await openProject(page);
});

test("adds, edits, reveals and deletes a secret", async ({ page }) => {
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await form.getByTestId("secret-key-input").fill("NEW_API_TOKEN");
  await form.getByTestId("secret-value-input").fill("first-value");
  await form.getByTestId("secret-comment-input").fill("Issued by the vendor");
  await form.getByTestId("secret-tags-input").fill("vendor");
  await form.getByTestId("secret-tags-input").press("Enter");
  await form.getByTestId("secret-save").click();
  await expectToast(page, "Added NEW_API_TOKEN");

  const row = secretRow(page, "NEW_API_TOKEN");
  await expect(row.getByTestId("secret-comment")).toHaveText("Issued by the vendor");
  await expect(row.getByTestId("secret-tag-vendor")).toBeVisible();
  await expect(row.getByTestId("secret-value")).not.toContainText("first-value");

  await row.getByTestId("secret-reveal").click();
  await expect(row.getByTestId("secret-value")).toHaveText("first-value");

  await secretAction(page, "NEW_API_TOKEN", "secret-edit");
  const editor = page.getByTestId("edit-secret-NEW_API_TOKEN");
  await expect(editor.getByTestId("secret-value-input")).toHaveValue("first-value");
  await editor.getByTestId("secret-value-input").fill("second-value");
  await editor.getByTestId("secret-save").click();
  await expectToast(page, "Saved NEW_API_TOKEN");
  await expect(secretRow(page, "NEW_API_TOKEN").getByTestId("secret-value")).toHaveText("second-value");

  await secretAction(page, "NEW_API_TOKEN", "secret-delete");
  await page.getByTestId("confirm-action").click();
  await expectToast(page, "Deleted NEW_API_TOKEN");
  await expect(secretRow(page, "NEW_API_TOKEN")).toHaveCount(0);
});

test("rejects an invalid key before sending it", async ({ page }) => {
  await page.getByTestId("add-secret").click();
  await page.getByTestId("secret-key-input").fill("1BAD");
  await expect(page.getByTestId("secret-save")).toBeDisabled();
});

test("reveal all shows every value", async ({ page }) => {
  await page.getByTestId("reveal-all").click();
  await expect(secretRow(page, "REDIS_URL").getByTestId("secret-value")).toHaveText("redis://localhost:6379/0");
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("warn");
});

test("filters by key, comment or tag", async ({ page }) => {
  await page.getByTestId("secret-search").fill("database");
  await expect(secretRow(page, "DATABASE_URL")).toBeVisible();
  await expect(secretRow(page, "REDIS_URL")).toHaveCount(0);
  await page.getByTestId("secret-search").fill("zzz-nothing");
  await expect(page.getByTestId("no-search-results")).toBeVisible();
});

test("navigates folders with breadcrumbs", async ({ page }) => {
  await page.getByTestId("open-folder-payments").click();
  await expect(page).toHaveURL(/path=%2Fpayments/);
  await expect(page.getByTestId("current-folder")).toHaveText("payments");
  await expect(secretRow(page, "WEBHOOK_SECRET")).toBeVisible();

  await page.getByTestId("open-folder-legacy").click();
  await expect(page.getByTestId("current-folder")).toHaveText("legacy");
  await expect(page.getByTestId("secrets-empty")).toBeVisible();

  await page.getByTestId("crumb-root").click();
  await expect(secretRow(page, "DATABASE_URL")).toBeVisible();
});

test("creates and deletes a folder", async ({ page }) => {
  await page.getByTestId("secrets-more").click();
  await page.getByTestId("new-folder").click();
  await page.getByTestId("folder-name").fill("analytics");
  await page.getByTestId("folder-create").click();
  await expectToast(page, "Created /analytics");

  await page.getByTestId("delete-folder-analytics").click();
  const dialog = page.getByTestId("delete-folder-dialog");
  await expect(dialog.getByTestId("delete-folder-contents")).toContainText("holds no secrets");
  await dialog.getByTestId("confirm-action").click();
  await expectToast(page, "Deleted /analytics");
  await expect(page.getByTestId("folder-row-analytics")).toHaveCount(0);
});

test("does not offer to delete a folder that still has secrets, and says how many", async ({ page }) => {
  await page.getByTestId("delete-folder-payments").click();
  const dialog = page.getByTestId("delete-folder-dialog");
  await expect(dialog).toContainText("/payments is not empty");
  await expect(dialog.getByTestId("delete-folder-contents")).toContainText(/It still holds \d+ secrets?/);
  await expect(dialog.getByTestId("confirm-action")).toHaveCount(0);
  await dialog.getByTestId("confirm-cancel").click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByTestId("folder-row-payments")).toBeVisible();
});

test("imports a pasted .env file in one batch", async ({ page }) => {
  await page.getByTestId("secrets-more").click();
  await page.getByTestId("import-env").click();
  await page.getByTestId("import-env-text").fill(
    ['# copied from .env', "LOG_LEVEL=error", 'GREETING="hello # world"', "export PORT=8080", "not a pair"].join("\n"),
  );
  await expect(page.getByTestId("import-env-summary")).toContainText("3 found");
  await expect(page.getByTestId("import-env-summary")).toContainText("1 existing");
  await expect(page.getByTestId("import-env-issues")).toContainText("Line 5");
  await page.getByTestId("import-env-submit").click();
  await expectToast(page, "Imported: 2 added, 1 updated, 0 unchanged");

  await page.getByTestId("reveal-all").click();
  await expect(secretRow(page, "GREETING").getByTestId("secret-value")).toHaveText("hello # world");
  await expect(secretRow(page, "PORT").getByTestId("secret-value")).toHaveText("8080");
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("error");
});

test("names duplicate keys, the root folder, and imports from a chosen file", async ({ page }) => {
  await page.getByTestId("secrets-more").click();
  await page.getByTestId("import-env").click();
  const dialog = page.getByTestId("import-env-dialog");
  await expect(dialog.getByTestId("import-env-where")).toHaveText(
    "Secrets are written to Development, in folder /, as one change. Existing keys are updated.",
  );
  await dialog.getByTestId("import-env-text").fill(["API_URL=https://example.com", "B=1", "API_URL=dupe"].join("\n"));
  await expect(dialog.getByTestId("import-env-duplicates")).toContainText(
    "Line 3: API_URL is also on line 1. The value from line 3 is used.",
  );
  await expect(dialog.getByTestId("import-env-summary")).toContainText("2 found");

  await dialog.getByTestId("import-env-file").setInputFiles({
    name: "app.env",
    mimeType: "text/plain",
    buffer: Buffer.from("FROM_FILE=yes\nOTHER=1\n"),
  });
  await expect(dialog.getByTestId("import-env-text")).toHaveValue("FROM_FILE=yes\nOTHER=1\n");
  await expect(dialog.getByTestId("import-env-duplicates")).toHaveCount(0);
  await expect(dialog.getByTestId("import-env-choose")).toHaveText("Choose file…");
  await dialog.getByTestId("import-env-submit").click();
  await expectToast(page, "Imported: 2 added, 0 updated, 0 unchanged");
});

test("Escape closes the new secret editor, and the value field keeps password managers out", async ({ page }) => {
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  const value = form.getByTestId("secret-value-input");
  await expect(value).toHaveAttribute("data-1p-ignore", "true");
  await expect(value).toHaveAttribute("data-lpignore", "true");
  await expect(value).toHaveAttribute("data-bwignore", "true");
  await expect(value).toHaveAttribute("data-form-type", "other");
  await form.getByTestId("secret-key-input").fill("HALF_DONE");
  await form.getByTestId("secret-key-input").press("Escape");
  await expect(form).toHaveCount(0);
  await expect(page.getByTestId("add-secret")).toBeEnabled();
});

test("the add form says why it cannot be saved yet", async ({ page }) => {
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await expect(form.getByTestId("secret-save")).toBeDisabled();
  await expect(form.getByTestId("secret-blocker")).toHaveText("Enter a key to continue.");
  await form.getByTestId("secret-key-input").fill("9BAD");
  await expect(form.getByTestId("secret-blocker")).toHaveText("Fix the key to continue.");
  await form.getByTestId("secret-key-input").fill("GOOD_KEY");
  await expect(form.getByTestId("secret-blocker")).toHaveCount(0);
  await expect(form.getByTestId("secret-save")).toBeEnabled();
});

test("an import over the server's size limit says so plainly and keeps the dialog open", async ({ page }) => {
  // 80 values of 60,000 characters make a request of about 4.8 MB, over the 4 MiB batch limit.
  const value = "a".repeat(60_000);
  const lines = Array.from({ length: 80 }, (_, i) => `BIG_${i}=${value}`);
  await page.getByTestId("secrets-more").click();
  await page.getByTestId("import-env").click();
  await page.getByTestId("import-env-text").fill(lines.join("\n"));
  await page.getByTestId("import-env-submit").click();
  await expectToast(page, "That is too large for the server to accept. Make it smaller, or split it into several changes.");
  await expect(page.getByTestId("import-env-dialog")).toBeVisible();
  await expect(secretRow(page, "BIG_0")).toHaveCount(0);
});

test("a huge folder is drawn a page at a time and is too big to reveal all at once", async ({ page }) => {
  const lines = Array.from({ length: 150 }, (_, i) => `BULK_${String(i).padStart(3, "0")}=value-${i}`);
  await page.getByTestId("secrets-more").click();
  await page.getByTestId("import-env").click();
  await page.getByTestId("import-env-text").fill(lines.join("\n"));
  await page.getByTestId("import-env-submit").click();
  await expectToast(page, /Imported: 150 added/);

  const table = page.getByTestId("secrets-table");
  await expect(table.locator('[data-testid^="secret-row-"]')).toHaveCount(100 - (await table.locator('[data-testid^="folder-row-"]').count()));
  await expect(page.getByTestId("secrets-more-count")).toContainText("of");
  await page.getByTestId("secrets-show-more").click();
  await expect(page.getByTestId("secrets-show-more")).toHaveCount(0);
  await expect(secretRow(page, "BULK_149")).toBeVisible();

  await expect(page.getByTestId("reveal-all")).toBeDisabled();
  await page.getByTestId("reveal-all-limit").focus();
  await expect(page.getByRole("tooltip")).toContainText("too many to reveal at once");
  // One at a time still works.
  await secretRow(page, "BULK_007").getByTestId("secret-reveal").click();
  await expect(secretRow(page, "BULK_007").getByTestId("secret-value")).toHaveText("value-7");
});

test("the search box fits a phone with a short placeholder", async ({ page }) => {
  const search = page.getByTestId("secret-search");
  await expect(search).toHaveAttribute("placeholder", isMobile(page) ? "Search" : "Search keys, comments, tags");
  await expect(search).toHaveAccessibleName("Search keys, comments and tags");
});

test("new folders name the top folder / like every other path", async ({ page }) => {
  await page.getByTestId("secrets-more").click();
  await page.getByTestId("new-folder").click();
  await expect(page.getByTestId("new-folder-dialog")).toContainText("Created inside /.");
});

test("switches environments with the tabs", async ({ page }) => {
  await page.getByTestId("env-tab-prod").click();
  await expect(page).toHaveURL(/\/secrets\/prod/);
  await expect(secretRow(page, "SENTRY_DSN")).toBeVisible();
  await expect(secretRow(page, "LOG_LEVEL")).toHaveCount(0);
});

test("hides values the role cannot read", async ({ page }) => {
  await page.goto("/projects/payments-api/secrets/prod");
  const row = secretRow(page, "HSM_PIN");
  await expect(row.getByTestId("secret-value")).toContainText("No access to value");
  await expect(row.getByTestId("secret-reveal")).toBeDisabled();
});
