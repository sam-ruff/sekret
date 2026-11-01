import { expect, test } from "@playwright/test";
import { isMobile } from "./helpers";

test("settings tabs that do not fit show an arrow that scrolls to them", async ({ page }) => {
  test.skip(!isMobile(page), "Mobile layout only");
  await page.goto("/projects/storefront/settings/general");
  const danger = page.getByRole("link", { name: "Danger zone" });
  await expect(danger).not.toBeInViewport({ ratio: 1 });
  await expect(page.getByTestId("tabs-scroll-left")).toHaveCount(0);
  await page.getByTestId("tabs-scroll-right").click();
  await expect(danger).toBeInViewport({ ratio: 1 });
  await expect(page.getByTestId("tabs-scroll-left")).toBeVisible();
  await expect(page.getByTestId("tabs-scroll-right")).toHaveCount(0);
});

test("toasts sit at the bottom on pages and move to the top only while a drawer is open", async ({ page }) => {
  test.skip(!isMobile(page), "Mobile layout only");
  const height = page.viewportSize()?.height ?? 0;
  const toastTop = async (text: string) => {
    const toast = page.locator("[data-sonner-toast]").filter({ hasText: text }).first();
    await expect(toast).toBeVisible();
    return (await toast.boundingBox())?.y ?? -1;
  };

  await page.goto("/projects");
  await page.getByTestId("new-project").click();
  await page.getByTestId("project-name").fill("Toasty");
  await page.getByTestId("create-project-submit").click();
  await expect(page.getByTestId("page-title")).toBeVisible();
  // Below the page title, so it never hides it.
  expect(await toastTop("Created Toasty")).toBeGreaterThan(height / 2);

  await page.goto("/projects/storefront/secrets/dev");
  await page.getByTestId("secret-row-LOG_LEVEL").getByTestId("secret-key").click();
  await page.getByTestId("history-values-toggle").click();
  await page.getByTestId("rollback-1").click();
  await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
  // The drawer keeps its actions at the bottom, so here the toast goes above them.
  expect(await toastTop("Rolled LOG_LEVEL back to version 1")).toBeLessThan(height / 2);
});

test("the sidebar becomes a sheet on narrow screens", async ({ page }) => {
  test.skip(!isMobile(page), "Mobile layout only");
  await page.goto("/projects/storefront/secrets/dev");

  await expect(page.getByTestId("nav-identities")).toBeHidden();
  await page.getByTestId("sidebar-trigger").click();
  const sheet = page.locator('[data-mobile="true"]');
  await expect(sheet).toBeVisible();
  await sheet.getByTestId("nav-overview").click();
  await expect(page).toHaveURL(/\/overview/);
  await expect(sheet).toBeHidden();

  await page.getByTestId("sidebar-trigger").click();
  await page.getByTestId("nav-identities").click();
  await expect(page).toHaveURL(/\/org\/identities/);
  await expect(page.getByTestId("page-title")).toHaveText("Machine identities");
});

test("tables become stacked cards without horizontal scrolling", async ({ page }) => {
  test.skip(!isMobile(page), "Mobile layout only");
  await page.goto("/projects/storefront/settings/members");
  await expect(page.getByTestId("add-member")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test("the sidebar links to the documentation in a new tab", async ({ page }) => {
  await page.goto("/projects");
  if (isMobile(page)) await page.getByTestId("sidebar-trigger").click();
  const docs = page.getByTestId("nav-docs");
  await expect(docs).toBeVisible();
  await expect(docs).toHaveAttribute("href", "https://sam-ruff.github.io/sekret/");
  await expect(docs).toHaveAttribute("target", "_blank");
  await expect(docs).toHaveAttribute("rel", /noopener/);
});

test("tells the two audit logs apart and has one main region with a skip link to it", async ({ page }) => {
  await page.goto("/projects/storefront/secrets/dev");
  await expect(page.locator("main")).toHaveCount(1);
  await expect(page.getByRole("main")).toHaveAttribute("id", "main-content");

  await page.keyboard.press("Tab");
  const skip = page.getByTestId("skip-link");
  await expect(skip).toBeFocused();
  await expect(skip).toHaveText("Skip to content");
  await expect(skip).toBeInViewport();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("main")).toBeFocused();

  if (isMobile(page)) await page.getByTestId("sidebar-trigger").click();
  await expect(page.getByTestId("nav-project-audit")).toHaveText("Project audit log");
  await expect(page.getByTestId("nav-org-audit")).toHaveText("Organisation audit log");
});

test("the sidebar collapses to icons on desktop", async ({ page }) => {
  test.skip(isMobile(page), "Desktop layout only");
  await page.goto("/projects");
  const sidebar = page.locator('[data-slot="sidebar"][data-state]');
  await expect(sidebar).toHaveAttribute("data-state", "expanded");
  await page.getByTestId("sidebar-trigger").click();
  await expect(sidebar).toHaveAttribute("data-state", "collapsed");
  await expect(page.getByTestId("nav-projects")).toBeVisible();
});
