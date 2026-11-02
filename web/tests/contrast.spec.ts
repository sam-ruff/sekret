import type { Locator, Page } from "@playwright/test";
import { expect, test } from "./fixture";
import { isMobile } from "./helpers";

/** WCAG AA for normal-sized text. */
const AA = 4.5;

/**
 * The contrast ratio between an element's text and what is drawn behind it, compositing every
 * translucent background up the tree. Colours are turned into sRGB by a canvas, so any CSS colour
 * the browser understands, oklch included, works.
 */
async function contrastOf(locator: Locator, part: "color" | "borderTopColor" = "color"): Promise<number> {
  return locator.evaluate((el, part) => {
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 1;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) throw new Error("no canvas");
    const rgba = (color: string): [number, number, number, number] => {
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = "#000";
      ctx.fillStyle = color;
      ctx.fillRect(0, 0, 1, 1);
      const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data;
      return [r, g, b, a / 255];
    };
    const over = (top: number[], bottom: number[]) => [0, 1, 2].map((i) => top[i] * top[3] + bottom[i] * (1 - top[3]));

    const layers: [number, number, number, number][] = [];
    for (let node: Element | null = el; node; node = node.parentElement) {
      const bg = rgba(getComputedStyle(node).backgroundColor);
      if (bg[3] > 0) layers.push(bg);
      if (bg[3] >= 1) break;
    }
    let behind = [255, 255, 255];
    for (const layer of layers.reverse()) behind = over(layer, behind);
    const text = over(rgba(getComputedStyle(el)[part]), behind);

    const luminance = (c: number[]) => {
      const [r, g, b] = c.map((v) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const [hi, lo] = [luminance(text), luminance(behind)].sort((a, b) => b - a);
    return (hi + 0.05) / (lo + 0.05);
  }, part);
}

/** WCAG 1.4.11 for the outlines of controls. */
const NON_TEXT = 3;

async function useTheme(page: Page, theme: "light" | "dark"): Promise<void> {
  await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
}

for (const theme of ["light", "dark"] as const) {
  test.describe(`${theme} theme`, () => {
    test.beforeEach(async ({ page }) => useTheme(page, theme));

    test("destructive alert text meets AA", async ({ page }) => {
      await page.goto("/login?error=state_mismatch");
      const description = page.getByTestId("login-error").locator("[data-slot=alert-description]");
      await expect(description).toBeVisible();
      expect(await contrastOf(description)).toBeGreaterThanOrEqual(AA);
    });

    test("the primary button keeps AA on hover, and hover darkens it", async ({ page }) => {
      test.skip(isMobile(page), "Touch screens have no hover");
      await page.goto("/login");
      const button = page.getByTestId("sign-in");
      await expect(button).toBeVisible();
      const before = await contrastOf(button);
      const restingBg = await button.evaluate((el) => getComputedStyle(el).backgroundColor);
      await button.hover();
      await expect.poll(() => button.evaluate((el) => getComputedStyle(el).backgroundColor)).not.toBe(restingBg);
      const hovered = await contrastOf(button);
      expect(before).toBeGreaterThanOrEqual(AA);
      expect(hovered).toBeGreaterThanOrEqual(AA);
      const lightness = (color: string) => Number(/oklch\(([\d.]+)/.exec(color)?.[1] ?? "NaN");
      const hoverBg = await button.evaluate((el) => getComputedStyle(el).backgroundColor);
      if (!Number.isNaN(lightness(restingBg)) && !Number.isNaN(lightness(hoverBg))) {
        expect(lightness(hoverBg)).toBeLessThan(lightness(restingBg));
      }
    });

    test("the inactive Danger zone tab and the users list initials meet AA", async ({ page }) => {
      await page.goto("/projects/storefront/settings/general");
      const danger = page.getByRole("link", { name: "Danger zone" });
      await expect(danger).not.toHaveAttribute("aria-current", "page");
      expect(await contrastOf(danger)).toBeGreaterThanOrEqual(AA);

      await page.goto("/org/users");
      const initials = page.getByTestId("user-avatar-initials").first();
      await expect(initials).toBeVisible();
      expect(await contrastOf(initials)).toBeGreaterThanOrEqual(AA);
    });

    test("removed diff lines and the snapshot Changed badge meet AA", async ({ page }) => {
      await page.goto("/projects/storefront/secrets/dev");
      await page.getByTestId("secret-row-LOG_LEVEL").getByTestId("secret-key").click();
      await page.getByTestId("history-values-toggle").click();
      const removed = page.getByTestId("diff-output").locator('[data-kind="removed"]').first();
      await expect(removed).toBeVisible();
      expect(await contrastOf(removed)).toBeGreaterThanOrEqual(AA);

      await page.goto("/projects/storefront/snapshots/dev");
      await page.getByTestId("snapshot-list").locator("li").last().getByRole("button").click();
      const changed = page.getByTestId("change-LOG_LEVEL").locator("[data-slot=badge]");
      await expect(changed).toContainText("Changed");
      expect(await contrastOf(changed)).toBeGreaterThanOrEqual(AA);
    });

    test("diff markers, success toasts and selected toggles meet AA", async ({ page }) => {
      await page.goto("/projects/storefront/secrets/dev");
      await page.getByTestId("secret-row-LOG_LEVEL").getByTestId("secret-key").click();
      await page.getByTestId("history-values-toggle").click();
      const marker = page.getByTestId("diff-output").locator('[data-kind="removed"] span').first();
      await expect(marker).toHaveText("-");
      expect(await contrastOf(marker)).toBeGreaterThanOrEqual(AA);
      // Project default is the selected toggle in the drawer's generation settings.
      const selected = page.getByTestId("policy-mode-inherit");
      await expect(selected).toHaveAttribute("data-state", "on");
      expect(await contrastOf(selected)).toBeGreaterThanOrEqual(AA);
      await page.getByTestId("rollback-1").click();
      await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
      const toast = page.locator('[data-sonner-toast][data-type="success"] [data-title]').first();
      await expect(toast).toHaveText("Rolled LOG_LEVEL back to version 1");
      // The toast slides in; wait for it to settle before measuring.
      await expect.poll(() => toast.evaluate((el) => getComputedStyle(el.closest("[data-sonner-toast]") ?? el).opacity)).toBe("1");
      expect(await contrastOf(toast)).toBeGreaterThanOrEqual(AA);
    });

    test("empty text fields and selects have outlines that stand out from the card", async ({ page }) => {
      await page.goto("/projects/storefront/settings/roles");
      await page.getByTestId("new-role").click();
      const name = page.getByTestId("role-name");
      await expect(name).toBeVisible();
      await expect(name).toHaveValue("");
      expect(await contrastOf(name, "borderTopColor")).toBeGreaterThanOrEqual(NON_TEXT);

      await page.goto("/projects/storefront/secrets/dev?add=");
      const key = page.getByTestId("secret-key-input");
      await expect(key).toBeVisible();
      expect(await contrastOf(key, "borderTopColor")).toBeGreaterThanOrEqual(NON_TEXT);
    });

    test("avatar initials and the Configured badge meet AA", async ({ page }) => {
      await page.goto("/org/identities");
      await page.getByTestId("identity-link-billing-worker").click();
      await page.getByTestId("identity-tab-auth").click();
      const badge = page.getByTestId("auth-method-kubernetes-status");
      await expect(badge).toContainText("Configured");
      expect(await contrastOf(badge)).toBeGreaterThanOrEqual(AA);
      const initials = page.getByTestId("user-initials");
      await expect(initials).toBeVisible();
      expect(await contrastOf(initials)).toBeGreaterThanOrEqual(AA);
    });
  });
}
