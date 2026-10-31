import { expect, test, type Locator, type Page } from "@playwright/test";
import { isMobile } from "./helpers";

/** WCAG AA for normal-sized text. */
const AA = 4.5;

/**
 * The contrast ratio between an element's text and what is drawn behind it, compositing every
 * translucent background up the tree. Colours are turned into sRGB by a canvas, so any CSS colour
 * the browser understands, oklch included, works.
 */
async function contrastOf(locator: Locator): Promise<number> {
  return locator.evaluate((el) => {
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
    const text = over(rgba(getComputedStyle(el).color), behind);

    const luminance = (c: number[]) => {
      const [r, g, b] = c.map((v) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const [hi, lo] = [luminance(text), luminance(behind)].sort((a, b) => b - a);
    return (hi + 0.05) / (lo + 0.05);
  });
}

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
