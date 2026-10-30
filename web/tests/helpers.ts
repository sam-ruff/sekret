import { expect, type Locator, type Page } from "@playwright/test";

export function isMobile(page: Page): boolean {
  return (page.viewportSize()?.width ?? 1280) < 768;
}

/** Follows a sidebar link, opening the mobile sheet first when the sidebar is collapsed into one. */
export async function navigate(page: Page, testId: string): Promise<void> {
  if (isMobile(page)) {
    await page.getByTestId("sidebar-trigger").click();
  }
  await page.getByTestId(testId).click();
}

export async function openProject(page: Page, slug = "storefront"): Promise<void> {
  await page.goto("/projects");
  await page.getByTestId(`project-card-${slug}`).click();
  await expect(page.getByTestId("env-tabs")).toBeVisible();
}

export function secretRow(page: Page, key: string): Locator {
  return page.getByTestId(`secret-row-${key}`);
}

export async function secretAction(
  page: Page,
  key: string,
  action: "secret-edit" | "secret-history" | "secret-delete" | "secret-rotate",
) {
  await secretRow(page, key).getByTestId("secret-actions").click();
  await page.getByTestId(action).click();
}

export async function expectToast(page: Page, text: string | RegExp): Promise<void> {
  await expect(page.locator("[data-sonner-toast]").filter({ hasText: text }).first()).toBeVisible();
}
