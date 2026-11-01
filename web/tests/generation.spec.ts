import { expect, test, type Page } from "@playwright/test";
import { expectToast, openProject, secretAction, secretRow } from "./helpers";

async function reveal(page: Page, key: string): Promise<string> {
  const row = secretRow(page, key);
  const value = row.getByTestId("secret-value");
  if ((await row.getByTestId("secret-reveal").getAttribute("aria-label"))?.startsWith("Reveal")) {
    await row.getByTestId("secret-reveal").click();
  }
  await expect(value).toHaveText(/^[^•]+$/);
  return (await value.textContent()) ?? "";
}

async function closeDrawer(page: Page): Promise<void> {
  const drawer = page.getByTestId("secret-drawer");
  await expect(async () => {
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0, { timeout: 1000 });
  }).toPass();
}

async function openDrawer(page: Page, key: string) {
  await expect(page.getByTestId("secret-drawer")).toHaveCount(0);
  await secretRow(page, key).getByTestId("secret-key").click();
  const drawer = page.getByTestId("secret-drawer");
  await expect(drawer.getByTestId("policy-effective")).toBeVisible();
  return drawer;
}

test.beforeEach(async ({ page }) => {
  await openProject(page);
});

test("generates a new secret with the chosen length and characters", async ({ page }) => {
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await form.getByTestId("secret-key-input").fill("API_SIGNING_KEY");
  await form.getByTestId("secret-generate").click();
  await expect(form.getByTestId("secret-value-input")).toHaveCount(0);
  await form.getByTestId("generate-new-length").fill("4");
  await expect(form.getByTestId("secret-save")).toBeDisabled();
  await form.getByTestId("generate-new-length").fill("48");
  await form.getByTestId("generate-new-charset").click();
  await page.getByTestId("generate-new-charset-hex").click();
  await expect(form.getByTestId("secret-generator-summary")).toHaveText("48 hex characters");
  await form.getByTestId("secret-comment-input").fill("Signs outgoing webhooks");
  await form.getByTestId("secret-save").click();
  await expectToast(page, "Generated API_SIGNING_KEY");

  const row = secretRow(page, "API_SIGNING_KEY");
  await expect(row.getByTestId("secret-generated-badge")).toBeVisible();
  await expect(row.getByTestId("secret-comment")).toHaveText("Signs outgoing webhooks");
  expect(await reveal(page, "API_SIGNING_KEY")).toMatch(/^[0-9a-f]{48}$/);
});

test("generates a replacement value from the edit form and warns before typing over one", async ({ page }) => {
  await secretAction(page, "SESSION_SECRET", "secret-edit");
  const editor = page.getByTestId("edit-secret-SESSION_SECRET");
  await expect(editor.getByTestId("secret-generated-warning")).toContainText("automatic rotation stops");
  await editor.getByTestId("secret-generate").click();
  await expect(editor.getByTestId("secret-generated-warning")).toHaveCount(0);
  await editor.getByTestId("generate-SESSION_SECRET-charset").click();
  await page.getByTestId("generate-SESSION_SECRET-charset-numeric").click();
  await editor.getByTestId("generate-SESSION_SECRET-length").fill("12");
  await editor.getByTestId("secret-save").click();
  await expectToast(page, "Generated a new value for SESSION_SECRET");
  expect(await reveal(page, "SESSION_SECRET")).toMatch(/^\d{12}$/);
});

test("rotates a generated secret on demand", async ({ page }) => {
  await expect(secretRow(page, "SESSION_SECRET").getByTestId("secret-rotation-badge")).toContainText(/Rotates in \d+d/);
  const before = await reveal(page, "SESSION_SECRET");
  await secretAction(page, "SESSION_SECRET", "secret-rotate");
  await page.getByTestId("rotate-confirm").getByTestId("confirm-action").click();
  await expectToast(page, "Rotated SESSION_SECRET");
  // Its own policy says 64 hex characters, and a fresh value restarts the 30-day clock.
  await expect.poll(() => reveal(page, "SESSION_SECRET")).not.toBe(before);
  expect(await reveal(page, "SESSION_SECRET")).toMatch(/^[0-9a-f]{64}$/);
  await expect(secretRow(page, "SESSION_SECRET").getByTestId("secret-rotation-badge")).toContainText("Rotates in 30d");
});

test("offers Rotate now in the row menu only for generated values", async ({ page }) => {
  await secretRow(page, "LOG_LEVEL").getByTestId("secret-actions").click();
  await expect(page.getByTestId("secret-edit")).toBeVisible();
  await expect(page.getByTestId("secret-rotate")).toHaveCount(0);
  await page.keyboard.press("Escape");

  await secretAction(page, "SESSION_SECRET", "secret-rotate");
  const confirm = page.getByTestId("rotate-confirm");
  await expect(confirm.getByTestId("rotate-typed-warning")).toHaveCount(0);
  await expect(confirm.getByTestId("confirm-action")).toHaveText("Rotate now");
  await expect(confirm.getByTestId("confirm-action")).toHaveAttribute("data-variant", "default");
  await confirm.getByTestId("confirm-cancel").click();
  // Focus goes back to the row's menu button, which opened the dialog.
  await expect(secretRow(page, "SESSION_SECRET").getByTestId("secret-actions")).toBeFocused();
});

test("warns before rotating a typed value from the drawer, and says no generator is set", async ({ page }) => {
  const drawer = await openDrawer(page, "LOG_LEVEL");
  await expect(drawer.getByTestId("policy-effective-generator")).toHaveText(
    "No generator set; Rotate now would use the built-in default of 32 alphanumeric characters",
  );
  await drawer.getByTestId("policy-rotate-now").click();
  const confirm = page.getByTestId("rotate-confirm");
  await expect(confirm.getByTestId("rotate-typed-warning")).toContainText("The current value was typed or imported, not generated.");
  await expect(confirm.getByTestId("confirm-action")).toHaveText("Replace with a generated value");
  await expect(confirm.getByTestId("confirm-action")).toHaveAttribute("data-variant", "destructive");
  await confirm.getByTestId("confirm-cancel").click();
});

test("sets a custom policy that applies once the value is generated", async ({ page }) => {
  const drawer = await openDrawer(page, "DATABASE_URL");
  await expect(drawer.getByTestId("policy-mode-inherit")).toHaveAttribute("data-state", "on");
  await expect(drawer.getByTestId("policy-effective-rotation")).toHaveText("Not rotated automatically");
  await expect(drawer.getByTestId("policy-next-rotation")).toHaveText("The current value was typed or imported");

  await drawer.getByTestId("policy-mode-custom").click();
  await drawer.getByTestId("policy-length").fill("40");
  await drawer.getByTestId("policy-rotate").click();
  await drawer.getByTestId("policy-days").fill("0");
  await expect(drawer.getByTestId("policy-save")).toBeDisabled();
  await drawer.getByTestId("policy-days").fill("14");
  await drawer.getByTestId("policy-save").click();
  await expectToast(page, "Saved the policy for DATABASE_URL");
  await expect(drawer.getByTestId("policy-effective-rotation")).toHaveText("Rotated every 14 days");
  await expect(drawer.getByTestId("policy-not-generated")).toContainText("Rotation applies once a value is generated");

  await drawer.getByTestId("policy-rotate-now").click();
  await page.getByTestId("rotate-confirm").getByTestId("confirm-action").click();
  await expectToast(page, "Rotated DATABASE_URL");
  await expect(drawer.getByTestId("policy-next-rotation")).toContainText("in 14 days");
  await expect(drawer.getByTestId("policy-not-generated")).toHaveCount(0);
  await closeDrawer(page);
  await expect(secretRow(page, "DATABASE_URL").getByTestId("secret-rotation-badge")).toContainText("Rotates in 14d");
  expect(await reveal(page, "DATABASE_URL")).toHaveLength(40);
});

test("project defaults apply to secrets that inherit them", async ({ page }) => {
  await page.goto("/projects/storefront/settings/general");
  const card = page.getByTestId("secret-defaults");
  await expect(card.getByTestId("defaults-enabled")).not.toBeChecked();
  await expect(card.getByTestId("defaults-summary")).toContainText("Off");

  await card.getByTestId("defaults-enabled").click();
  await card.getByTestId("defaults-length").fill("24");
  await card.getByTestId("defaults-charset").click();
  await page.getByTestId("defaults-charset-symbols").click();
  await card.getByTestId("defaults-rotate").click();
  await card.getByTestId("defaults-days").fill("60");
  await expect(card.getByTestId("defaults-preview")).toContainText("24 letter, digit and symbol characters");
  await card.getByTestId("defaults-save").click();
  await expectToast(page, "Secret defaults saved");

  await page.reload();
  await expect(page.getByTestId("secret-defaults").getByTestId("defaults-enabled")).toBeChecked();
  await expect(page.getByTestId("secret-defaults").getByTestId("defaults-days")).toHaveValue("60");

  await page.goto("/projects/storefront/secrets/dev");
  const drawer = await openDrawer(page, "REDIS_URL");
  await expect(drawer.getByTestId("policy-effective-generator")).toHaveText("Generates 24 letter, digit and symbol characters");
  await expect(drawer.getByTestId("policy-effective-rotation")).toHaveText("Rotated every 60 days");
  await expect(drawer.getByTestId("policy-not-generated")).toBeVisible();

  // A secret with its own policy keeps it.
  await closeDrawer(page);
  const own = await openDrawer(page, "SESSION_SECRET");
  await expect(own.getByTestId("policy-mode-custom")).toHaveAttribute("data-state", "on");
  await expect(own.getByTestId("policy-effective-rotation")).toHaveText("Rotated every 30 days");

  // Turning the defaults off again.
  await page.goto("/projects/storefront/settings/general");
  await page.getByTestId("secret-defaults").getByTestId("defaults-enabled").click();
  await page.getByTestId("secret-defaults").getByTestId("defaults-save").click();
  await expectToast(page, "Secret defaults saved");
  await expect(page.getByTestId("secret-defaults").getByTestId("defaults-summary")).toContainText("Off");
});
