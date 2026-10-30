import { expect, test } from "@playwright/test";
import { LOGO_PNG, TRUNCATED_PNG } from "./fixtures/images";
import { expectToast, isMobile } from "./helpers";

const settings = "/projects/storefront/settings/general";

test("uploads a logo, shows it everywhere, then removes it", async ({ page }) => {
  await page.goto(settings);
  const card = page.getByTestId("logo-card");
  await expect(card.getByTestId("logo-preview-empty")).toBeVisible();

  await card.getByTestId("logo-input").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: LOGO_PNG });
  await expectToast(page, "Logo updated");
  const preview = card.getByTestId("logo-preview-image");
  await expect(preview).toBeVisible();
  await expect.poll(() => preview.evaluate((img: HTMLImageElement) => img.naturalWidth)).toBe(48);
  await expect(card.getByTestId("logo-upload")).toHaveText(/Replace/);
  await expect(page.getByTestId("header-logo")).toBeVisible();

  if (isMobile(page)) await page.getByTestId("sidebar-trigger").click();
  await expect(page.getByTestId("switcher-logo")).toBeVisible();
  if (isMobile(page)) await page.keyboard.press("Escape");

  await page.goto("/projects");
  await expect(page.getByTestId("project-card-storefront").getByTestId("project-logo")).toBeVisible();

  await page.goto(settings);
  await card.getByTestId("logo-remove").click();
  await expectToast(page, "Logo removed");
  await expect(card.getByTestId("logo-preview-empty")).toBeVisible();
  await expect(page.getByTestId("header-logo")).toHaveCount(0);
  await page.goto("/projects");
  await expect(page.getByTestId("project-card-storefront").getByTestId("project-logo-fallback")).toBeVisible();
});

test("refuses files that are not images before uploading", async ({ page }) => {
  await page.goto(settings);
  const card = page.getByTestId("logo-card");
  await card.getByTestId("logo-input").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("hello") });
  await expect(card.getByTestId("logo-error")).toContainText("Choose a PNG, JPEG, GIF, WebP or SVG image.");

  const huge = Buffer.concat([LOGO_PNG, Buffer.alloc(600 * 1024)]);
  await card.getByTestId("logo-input").setInputFiles({ name: "huge.png", mimeType: "image/png", buffer: huge });
  await expect(card.getByTestId("logo-error")).toContainText("at most 512 KiB");
  await expect(card.getByTestId("logo-preview-empty")).toBeVisible();
});

test("shows the server's message for an image it cannot read", async ({ page }) => {
  await page.goto(settings);
  const card = page.getByTestId("logo-card");
  await card.getByTestId("logo-input").setInputFiles({ name: "broken.png", mimeType: "image/png", buffer: TRUNCATED_PNG });
  await expect(card.getByTestId("logo-error")).toContainText("The image could not be read");
  await expect(card.getByTestId("logo-preview-empty")).toBeVisible();
});

test("shows a seeded logo on the project card", async ({ page }) => {
  await page.goto("/projects");
  await expect(page.getByTestId("project-card-payments-api").getByTestId("project-logo")).toBeVisible();
  await expect(page.getByTestId("project-card-storefront").getByTestId("project-logo-fallback")).toBeVisible();
});
