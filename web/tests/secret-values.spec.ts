import { expect, test, type Page } from "@playwright/test";
import { expectToast, openProject, secretAction, secretRow } from "./helpers";

const DEV_DATABASE_URL = "postgres://shop:devpass@localhost:5432/shop";
const PROD_PASSWORD = "Pr0d-s3cret";

/** The requests the fake server has answered since this page loaded. */
async function requestLog(page: Page): Promise<string[]> {
  return page.evaluate(async () => {
    const path = "/src/api/mock/server.ts";
    const mock = (await import(/* @vite-ignore */ path)) as { mockRequestLog: () => string[] };
    return mock.mockRequestLog();
  });
}

/** Requests made after `mark`, the length of the log at some earlier point. */
async function requestsSince(page: Page, mark: number): Promise<string[]> {
  return (await requestLog(page)).slice(mark);
}

const askedForValues = (requests: string[]) =>
  requests.filter((r) => /values=true/.test(r) || /\/secrets\/[A-Z_]+\?/.test(r));

test.describe("revealed values stay where they were revealed", () => {
  test.beforeEach(async ({ page }) => {
    await openProject(page);
  });

  test("a value revealed in dev is not revealed or fetched in prod", async ({ page }) => {
    const devRow = secretRow(page, "DATABASE_URL");
    await devRow.getByTestId("secret-reveal").click();
    await expect(devRow.getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);

    const mark = (await requestLog(page)).length;
    await page.getByTestId("env-tab-prod").click();
    await expect(page).toHaveURL(/\/secrets\/prod/);
    await expect(secretRow(page, "SENTRY_DSN")).toBeVisible();
    const prodRow = secretRow(page, "DATABASE_URL");
    await expect(prodRow).toBeVisible();
    await expect(prodRow.getByTestId("secret-reveal")).toHaveAttribute("aria-label", "Reveal DATABASE_URL");
    await expect(prodRow.getByTestId("secret-value")).not.toContainText(PROD_PASSWORD);
    await expect(page.getByTestId("secrets-table")).not.toContainText(PROD_PASSWORD);
    expect(askedForValues(await requestsSince(page, mark))).toEqual([]);
  });

  test("reveal all in dev does not carry over to prod", async ({ page }) => {
    await page.getByTestId("reveal-all").click();
    await expect(secretRow(page, "DATABASE_URL").getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);

    const mark = (await requestLog(page)).length;
    await page.getByTestId("env-tab-prod").click();
    await expect(secretRow(page, "SENTRY_DSN")).toBeVisible();
    await expect(page.getByTestId("reveal-all")).toHaveAttribute("aria-label", "Reveal all values");
    await expect(page.getByTestId("secrets-table")).not.toContainText(PROD_PASSWORD);
    expect(askedForValues(await requestsSince(page, mark))).toEqual([]);
  });

  test("a value revealed in one folder is not revealed in another", async ({ page }) => {
    await page.getByTestId("reveal-all").click();
    await expect(secretRow(page, "DATABASE_URL").getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);
    const mark = (await requestLog(page)).length;
    await page.getByTestId("open-folder-payments").click();
    await expect(secretRow(page, "WEBHOOK_SECRET")).toBeVisible();
    await expect(secretRow(page, "WEBHOOK_SECRET").getByTestId("secret-reveal")).toHaveAttribute(
      "aria-label",
      "Reveal WEBHOOK_SECRET",
    );
    expect(askedForValues(await requestsSince(page, mark))).toEqual([]);
  });

  test("history values shown in dev are not shown for the same key in prod", async ({ page }) => {
    await page.goto("/projects/storefront/secrets/prod");
    await expect(secretRow(page, "SENTRY_DSN")).toBeVisible();
    await page.getByTestId("env-tab-dev").click();
    await expect(secretRow(page, "LOG_LEVEL")).toBeVisible();
    await secretAction(page, "DATABASE_URL", "secret-history");
    const drawer = page.getByTestId("secret-drawer");
    await drawer.getByTestId("history-values-toggle").click();
    await expect(drawer.getByTestId("version-list")).toContainText("devpass");

    // Back to prod while the drawer still shows dev's history.
    const mark = (await requestLog(page)).length;
    await page.goBack();
    await expect(page).toHaveURL(/\/secrets\/prod/);
    await expect(secretRow(page, "SENTRY_DSN")).toBeVisible();
    await expect(page.getByTestId("secret-drawer")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText(PROD_PASSWORD);
    const since = await requestsSince(page, mark);
    expect(since.filter((r) => r.includes("/versions"))).toEqual([]);
    expect(askedForValues(since)).toEqual([]);
  });
});

test.describe("one secret's value is fetched on its own", () => {
  test.beforeEach(async ({ page }) => {
    await openProject(page);
  });

  test("revealing, copying and editing one secret fetch only that secret", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const mark = (await requestLog(page)).length;
    const row = secretRow(page, "REDIS_URL");
    await row.getByTestId("secret-reveal").click();
    await expect(row.getByTestId("secret-value")).toHaveText("redis://localhost:6379/0");

    await secretRow(page, "DATABASE_URL").getByTestId("secret-copy").click();
    await expectToast(page, "Copied to clipboard");

    await secretAction(page, "LOG_LEVEL", "secret-edit");
    await expect(page.getByTestId("edit-secret-LOG_LEVEL").getByTestId("secret-value-input")).toHaveValue("warn");

    const since = await requestsSince(page, mark);
    expect(since.filter((r) => r.includes("values=true"))).toEqual([]);
    expect(since).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^GET \/api\/v1\/projects\/storefront\/environments\/dev\/secrets\/REDIS_URL\?/),
        expect.stringMatching(/^GET \/api\/v1\/projects\/storefront\/environments\/dev\/secrets\/DATABASE_URL\?/),
        expect.stringMatching(/^GET \/api\/v1\/projects\/storefront\/environments\/dev\/secrets\/LOG_LEVEL\?/),
      ]),
    );
  });

  test("reveal all still fetches the folder in one request", async ({ page }) => {
    const mark = (await requestLog(page)).length;
    await page.getByTestId("reveal-all").click();
    await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("warn");
    // Hiding one key again keeps the rest revealed without fetching anything new.
    await secretRow(page, "LOG_LEVEL").getByTestId("secret-reveal").click();
    await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).not.toContainText("warn");
    await expect(secretRow(page, "REDIS_URL").getByTestId("secret-value")).toHaveText("redis://localhost:6379/0");
    const since = await requestsSince(page, mark);
    expect(since.filter((r) => r.includes("values=true"))).toHaveLength(1);
    expect(since.filter((r) => /\/secrets\/[A-Z_]+\?/.test(r))).toEqual([]);
  });
});

test.describe("secret fields", () => {
  test.beforeEach(async ({ page }) => {
    await openProject(page);
  });

  test("the value editor and .env import are kept from spellcheck and writing assistants", async ({ page }) => {
    await page.getByTestId("add-secret").click();
    const value = page.getByTestId("new-secret-form").getByTestId("secret-value-input");
    for (const [name, expected] of [
      ["spellcheck", "false"],
      ["autocomplete", "off"],
      ["autocorrect", "off"],
      ["autocapitalize", "off"],
      ["data-gramm", "false"],
      ["data-gramm_editor", "false"],
      ["data-enable-grammarly", "false"],
    ]) {
      await expect(value).toHaveAttribute(name, expected);
    }

    await page.getByTestId("secrets-more").click();
    await page.getByTestId("import-env").click();
    const pasted = page.getByTestId("import-env-text");
    await expect(pasted).toHaveAttribute("spellcheck", "false");
    await expect(pasted).toHaveAttribute("data-gramm", "false");
    await expect(pasted).toHaveAttribute("autocomplete", "off");
  });

  test("a pasted .env is cleared by Cancel and by Escape", async ({ page }) => {
    const dialog = page.getByTestId("import-env-dialog");
    await page.getByTestId("secrets-more").click();
    await page.getByTestId("import-env").click();
    await page.getByTestId("import-env-text").fill("API_TOKEN=pasted-secret");
    await expect(page.getByTestId("import-env-summary")).toContainText("1 found");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);

    await page.getByTestId("secrets-more").click();
    await page.getByTestId("import-env").click();
    await expect(page.getByTestId("import-env-text")).toHaveValue("");
    await page.getByTestId("import-env-text").fill("API_TOKEN=pasted-again");
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);

    // Not carried into another environment either.
    await page.getByTestId("env-tab-prod").click();
    await expect(secretRow(page, "SENTRY_DSN")).toBeVisible();
    await page.getByTestId("secrets-more").click();
    await page.getByTestId("import-env").click();
    await expect(page.getByTestId("import-env-text")).toHaveValue("");
    await expect(page.getByTestId("import-env-dialog")).not.toContainText("pasted");
  });
});
