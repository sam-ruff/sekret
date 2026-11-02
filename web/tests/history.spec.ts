import type { Page } from "@playwright/test";
import { expect, test } from "./fixture";
import { expectToast, openProject, secretAction, secretRow } from "./helpers";

test.describe("on a 390 pixel phone", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("the history drawer fits with long values shown", async ({ page }) => {
    await page.goto("/projects/storefront/secrets/staging");
    await secretAction(page, "CSRF_SECRET", "secret-history");
    const drawer = page.getByTestId("secret-drawer");
    await expect(drawer.getByTestId("secret-drawer-where")).toHaveText("Staging · /");
    await drawer.getByTestId("history-values-toggle").click();
    await expect(drawer.getByTestId("diff-output")).toBeVisible();

    const box = await drawer.boundingBox();
    expect(box?.width).toBe(390);
    const overflow = await drawer.evaluate((sheet) => {
      const viewport = sheet.querySelector<HTMLElement>("[data-slot=scroll-area-viewport]");
      const sheetRight = sheet.getBoundingClientRect().right;
      // Anything drawn past the drawer's right edge, or a viewport wider than it shows.
      const beyond = [...sheet.querySelectorAll<HTMLElement>("*")].filter((el) => el.getBoundingClientRect().right > sheetRight + 1);
      return {
        viewport: viewport ? viewport.scrollWidth - viewport.clientWidth : -1,
        beyond: beyond.map((el) => el.getAttribute("data-testid") ?? el.tagName),
      };
    });
    expect(overflow.viewport).toBeLessThanOrEqual(0);
    expect(overflow.beyond).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
  });
});

/** Writes `count` versions of a new secret straight through the mock server. */
async function writeVersions(page: Page, key: string, count: number): Promise<void> {
  await page.evaluate(
    async ({ key, count }) => {
      const path = "/src/api/mock/server.ts";
      const mock = (await import(/* @vite-ignore */ path)) as { mockFetch: (request: Request) => Promise<Response> };
      for (let i = 1; i <= count; i++) {
        const response = await mock.mockFetch(
          new Request(`${location.origin}/api/v1/projects/storefront/environments/dev/secrets/${key}?path=%2F`, {
            method: "PUT",
            headers: { "Content-Type": "application/json", "x-sekret-csrf": "1" },
            body: JSON.stringify({ value: `value-${i}`, comment: `write ${i}`, tags: [] }),
          }),
        );
        if (!response.ok) throw new Error(`write ${i} failed with ${response.status}`);
      }
    },
    { key, count },
  );
}

test("a long history loads a page at a time, with values for every page loaded", async ({ page }) => {
  test.setTimeout(90_000);
  await openProject(page);
  await writeVersions(page, "LONG_HISTORY", 55);
  await page.reload();
  await secretAction(page, "LONG_HISTORY", "secret-history");
  const drawer = page.getByTestId("secret-drawer");
  const items = drawer.getByTestId("version-list").locator("li");
  await expect(items).toHaveCount(50);
  await expect(drawer.getByTestId("version-55")).toBeVisible();
  await expect(drawer.getByTestId("version-5")).toHaveCount(0);
  await expect(drawer.getByTestId("history-shown-count")).toHaveText("Showing the newest 50 versions");

  await drawer.getByTestId("history-values-toggle").click();
  await expect(drawer.getByTestId("version-value-6")).toHaveText("value-6");
  await drawer.getByTestId("history-load-older").click();
  await expect(items).toHaveCount(55);
  await expect(drawer.getByTestId("version-value-1")).toHaveText("value-1");
  await expect(drawer.getByTestId("history-load-older")).toHaveCount(0);

  // The diff offers every loaded version, the oldest included.
  await drawer.getByTestId("diff-from").click();
  await expect(page.getByRole("option", { name: "Version 1", exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
});

test.describe("on a wide screen", () => {
  test.skip(({ isMobile }) => isMobile, "the drawer is full width on phones");

  test("the history drawer uses the wider width meant for diffs", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await openProject(page);
    await secretAction(page, "LOG_LEVEL", "secret-history");
    const box = await page.getByTestId("secret-drawer").boundingBox();
    expect(box?.width).toBeGreaterThan(550);
  });
});

test("opens on the history, with rotation settings below it, and returns focus to the row on close", async ({ page }) => {
  await openProject(page);
  await secretAction(page, "LOG_LEVEL", "secret-history");
  const drawer = page.getByTestId("secret-drawer");
  const versions = drawer.getByTestId("version-list");
  await expect(versions).toBeInViewport();
  const historyTop = (await versions.boundingBox())?.y ?? Infinity;
  const policyTop = (await drawer.getByTestId("policy-section").boundingBox())?.y ?? -Infinity;
  expect(historyTop).toBeLessThan(policyTop);

  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-actions")).toBeFocused();

  // Opened from the key name, focus goes back to the key name.
  await secretRow(page, "LOG_LEVEL").getByTestId("secret-key").click();
  await expect(versions).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-key")).toBeFocused();
});

test("offers no comparison for a secret with a single version", async ({ page }) => {
  await page.goto("/projects/payments-api/secrets/dev");
  await secretAction(page, "WEBHOOK_SIGNING_KEY", "secret-history");
  const drawer = page.getByTestId("secret-drawer");
  await expect(drawer.getByTestId("version-list").locator("li")).toHaveCount(1);
  await drawer.getByTestId("history-values-toggle").click();
  await expect(drawer.getByTestId("version-value-1")).not.toContainText("•");
  await expect(drawer.getByTestId("compare-section")).toHaveCount(0);
  await expect(drawer).not.toContainText("Compare versions");
});

test("says when two versions are too different to compare instead of failing", async ({ page }) => {
  await openProject(page);
  // Two versions of nearly 64 KiB with no line in common, written straight to the fake server.
  await page.evaluate(async () => {
    const path = "/src/api/mock/server.ts";
    const mock = (await import(/* @vite-ignore */ path)) as { mockFetch: (r: Request) => Promise<Response> };
    for (const line of ["a", "b"]) {
      await mock.mockFetch(
        new Request(`${location.origin}/api/v1/projects/storefront/environments/dev/secrets/BIG_BLOB`, {
          method: "PUT",
          headers: { "x-sekret-csrf": "1", "content-type": "application/json" },
          body: JSON.stringify({ value: `${line}\n`.repeat(30_000) }),
        }),
      );
    }
  });
  await page.reload();

  await secretAction(page, "BIG_BLOB", "secret-history");
  const drawer = page.getByTestId("secret-drawer");
  await drawer.getByTestId("history-values-toggle").click();
  await expect(drawer.getByTestId("diff-too-large")).toContainText("too many lines to compare");
  await expect(page.getByTestId("app-error")).toHaveCount(0);
  await expect(drawer.getByTestId("version-2")).toBeVisible();
});

test("the row menu says the drawer holds rotation too, and a cancelled confirm gives focus back", async ({ page }) => {
  await openProject(page);
  await secretRow(page, "LOG_LEVEL").getByTestId("secret-actions").click();
  await expect(page.getByTestId("secret-history")).toHaveText("History and rotation");
  await page.getByTestId("secret-history").click();
  const drawer = page.getByTestId("secret-drawer");
  await expect(drawer.getByTestId("version-list")).toBeVisible();

  const rollback = drawer.getByTestId("rollback-2");
  await rollback.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("rollback-confirm").getByTestId("confirm-cancel")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("rollback-confirm")).toHaveCount(0);
  await expect(rollback).toBeFocused();
  await expect(drawer).toBeVisible();

  // Rotate now asks in a dialog over the drawer; Escape closes only that dialog.
  await drawer.getByTestId("policy-rotate-now").click();
  const rotate = page.getByRole("alertdialog");
  await expect(rotate).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(rotate).toHaveCount(0);
  await expect(drawer).toBeVisible();
});

test("revealed values are hidden as soon as the page is hidden", async ({ page }) => {
  await openProject(page);
  const row = secretRow(page, "LOG_LEVEL");
  await row.getByTestId("secret-reveal").click();
  await expect(row.getByTestId("secret-value")).toHaveText("warn");
  await secretAction(page, "LOG_LEVEL", "secret-history");
  const drawer = page.getByTestId("secret-drawer");
  await drawer.getByTestId("history-values-toggle").click();
  await expect(drawer.getByTestId("version-value-1")).toHaveText("debug");

  // As on switching tab or app.
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(drawer.getByTestId("history-values-hidden")).toBeVisible();
  await expect(drawer).not.toContainText("debug");
  await drawer.getByRole("button", { name: "Close" }).click();
  await expect(row.getByTestId("secret-value")).not.toHaveText("warn");
});

test("hides history values until asked, then diffs versions and rolls back", async ({ page }) => {
  await openProject(page);
  await secretAction(page, "LOG_LEVEL", "secret-history");

  const drawer = page.getByTestId("secret-drawer");
  await expect(drawer.getByTestId("version-list").locator("li")).toHaveCount(3);
  await expect(drawer.getByTestId("version-3")).toContainText("Current");

  // Nothing is shown until the reader asks, and asking is audited.
  await expect(drawer.getByTestId("history-values-hidden")).toContainText("recorded in the audit log");
  await expect(drawer.getByTestId("diff-output")).toHaveCount(0);
  await expect(drawer.getByTestId("version-value-3")).not.toContainText("warn");
  await expect(drawer).not.toContainText("debug");

  await drawer.getByTestId("history-values-toggle").click();
  const diff = drawer.getByTestId("diff-output");
  await expect(diff.locator('[data-kind="removed"]')).toHaveText(/info/);
  await expect(diff.locator('[data-kind="added"]')).toHaveText(/warn/);
  await expect(drawer.getByTestId("version-value-1")).toHaveText("debug");

  await drawer.getByTestId("diff-from").click();
  await page.getByRole("option", { name: "Version 1" }).click();
  await expect(diff.locator('[data-kind="removed"]')).toHaveText(/debug/);

  // History comes first and the comparison sits under it.
  const listTop = (await drawer.getByTestId("version-list").boundingBox())?.y ?? Infinity;
  const compareTop = (await drawer.getByTestId("compare-section").boundingBox())?.y ?? -Infinity;
  expect(listTop).toBeLessThan(compareTop);

  await drawer.getByTestId("rollback-2").click();
  await expect(page.getByTestId("rollback-confirm")).toContainText(
    "LOG_LEVEL gets a new version with the value and tags from version 2. The current value stays in history.",
  );
  await expect(page.getByTestId("rollback-confirm")).not.toContainText("Its comment becomes");
  await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
  await expectToast(page, "Rolled LOG_LEVEL back to version 2");
  // The restored version's comment comes back with the rollback noted in front of it.
  await expect(drawer.getByTestId("version-4")).toContainText("rolled back to version 2: Too noisy");
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-comment")).toHaveText("rolled back to version 2: Too noisy");

  await drawer.getByTestId("rollback-1").click();
  await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
  await expectToast(page, "Rolled LOG_LEVEL back to version 1");
  await expect(drawer.getByTestId("version-5")).toContainText("rolled back to version 1");
  // Rolling back to a version that matches the current one would change nothing, so it is not offered.
  await expect(drawer.getByTestId("same-as-current-1")).toHaveText("Same as current");
  await expect(drawer.getByTestId("rollback-1")).toHaveCount(0);
  await expect(drawer.getByTestId("rollback-2")).toBeVisible();

  await drawer.getByRole("button", { name: "Close" }).click();
  await expect(drawer).toBeHidden();

  // Reopening starts hidden again.
  await secretAction(page, "LOG_LEVEL", "secret-history");
  await expect(drawer.getByTestId("history-values-hidden")).toBeVisible();
  await expect(drawer.getByTestId("diff-output")).toHaveCount(0);
  await drawer.getByRole("button", { name: "Close" }).click();

  await secretRow(page, "LOG_LEVEL").getByTestId("secret-reveal").click();
  await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("debug");

  await page.goto("/org/audit");
  await expect(page.locator('[data-testid="audit-action"][data-action="secret.history-read"]').first()).toHaveText(
    "Viewed history values",
  );
});
