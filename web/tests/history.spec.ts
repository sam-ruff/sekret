import { expect, test } from "@playwright/test";
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

  await drawer.getByTestId("rollback-1").click();
  await page.getByTestId("rollback-confirm").getByTestId("confirm-action").click();
  await expectToast(page, "Rolled LOG_LEVEL back to version 1");
  await expect(drawer.getByTestId("version-4")).toContainText("rolled back to version 1");
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
