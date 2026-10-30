import { expect, test, type Page } from "@playwright/test";

/** Waits until the results for the current filters have arrived. */
async function settled(page: Page): Promise<void> {
  const total = page.getByTestId("audit-total");
  await expect(total).toHaveAttribute("data-filters", new URL(page.url()).searchParams.toString());
  await expect(total).toHaveAttribute("data-fetching", "false");
}

async function total(page: Page): Promise<number> {
  await settled(page);
  const text = (await page.getByTestId("audit-total").textContent()) ?? "";
  return Number(text.match(/\d+/)?.[0] ?? NaN);
}

/** Picks a filter option, then waits for the URL to change and the matching results to load. */
async function choose(page: Page, trigger: string, option: string, url: RegExp): Promise<void> {
  await page.getByTestId(trigger).click();
  await page.getByTestId(option).click();
  await expect(page).toHaveURL(url);
  await settled(page);
}

test("pages through the organisation log with the cursor", async ({ page }) => {
  await page.goto("/org/audit");
  await expect(page.getByTestId("audit-total")).toHaveText(/\d+ entries/);
  const all = await total(page);
  expect(all).toBeGreaterThanOrEqual(120);

  const rows = page.getByTestId("audit-row");
  await expect(rows).toHaveCount(50);
  await expect(page.getByTestId("audit-shown")).toHaveText(`Showing 50 of ${all}`);
  await page.getByTestId("audit-load-more").click();
  await expect(rows).toHaveCount(100);
  await page.getByTestId("audit-load-more").click();
  await expect(rows).toHaveCount(Math.min(150, all));

  // Newest first means every timestamp is no later than the one above it.
  const times = await page.getByTestId("audit-when").evaluateAll((els) => els.map((el) => Number(el.getAttribute("data-at"))));
  expect(times).toEqual([...times].sort((a, b) => b - a));
});

test("filters by category, actor kind and search, keeping them in the URL", async ({ page }) => {
  await page.goto("/org/audit");
  await expect(page.getByTestId("audit-total")).toHaveText(/\d+ entries/);
  const all = await total(page);

  await choose(page, "audit-action-filter", "audit-action-secret", /action=secret\./);
  await expect.poll(() => total(page)).toBeLessThan(all);
  const actions = await page.getByTestId("audit-action").allTextContents();
  expect(actions.every((a) => a.startsWith("secret."))).toBe(true);

  await choose(page, "audit-actor-kind", "audit-actor-kind-identity", /actor_kind=identity/);
  await expect(page.getByTestId("audit-row").first()).toBeVisible();
  const kinds = await page.getByTestId("audit-actor").evaluateAll((els) => els.map((el) => el.getAttribute("data-kind")));
  expect(new Set(kinds)).toEqual(new Set(["identity"]));

  await page.getByTestId("audit-search").fill("billing-worker");
  await expect(page).toHaveURL(/q=billing-worker/);
  const filtered = await total(page);
  const actors = await page.getByTestId("audit-actor").allTextContents();
  expect(actors.every((a) => a === "billing-worker")).toBe(true);

  await page.reload();
  await expect(page.getByTestId("audit-search")).toHaveValue("billing-worker");
  await expect(page.getByTestId("audit-action-filter")).toContainText("Secrets");
  await expect.poll(() => total(page)).toBe(filtered);

  await page.getByTestId("audit-clear").first().click();
  await expect(page.getByTestId("audit-search")).toHaveValue("");
  await expect.poll(() => total(page)).toBe(all);
  await expect(page).not.toHaveURL(/action=/);
});

test("sorts oldest first and filters to a date range", async ({ page }) => {
  await page.goto("/org/audit");
  await page.getByTestId("audit-order").click();
  await expect(page).toHaveURL(/order=asc/);
  await settled(page);
  await expect(page.getByTestId("audit-order")).toHaveText(/Oldest first/);
  const times = await page.getByTestId("audit-when").evaluateAll((els) => els.map((el) => Number(el.getAttribute("data-at"))));
  expect(times.length).toBeGreaterThan(1);
  expect(times).toEqual([...times].sort((a, b) => a - b));

  await page.getByTestId("audit-date").click();
  await page.getByTestId("audit-date-7d").click();
  await expect(page.getByTestId("audit-date")).toHaveText(/Last 7 days/);
  await expect(page).toHaveURL(/from=\d{4}-\d{2}-\d{2}&to=/);
  await settled(page);
  const week = Date.now() / 1000 - 8 * 86400;
  const recent = await page.getByTestId("audit-when").evaluateAll((els) => els.map((el) => Number(el.getAttribute("data-at"))));
  expect(recent.every((t) => t > week)).toBe(true);

  await page.getByTestId("audit-date").click();
  await page.getByTestId("audit-from").fill("2001-01-01");
  await page.getByTestId("audit-to").fill("2001-01-31");
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("audit-empty")).toContainText("No matching activity");
  await expect(page.getByTestId("audit-total")).toHaveText("0 entries");
  await page.getByTestId("audit-empty").getByRole("button", { name: "Clear filters" }).click();
  await expect(page.getByTestId("audit-row").first()).toBeVisible();
  await expect(page).toHaveURL(/order=asc/);
});

test("filters a project's log by environment and by clicking an actor", async ({ page }) => {
  await page.goto("/projects/storefront/audit");
  await expect(page.getByTestId("audit-total")).toHaveText(/\d+ entries/);
  const all = await total(page);

  await choose(page, "audit-environment", "audit-environment-prod", /env=prod/);
  await expect.poll(() => total(page)).toBeLessThan(all);
  const targets = await page.getByTestId("audit-target").allTextContents();
  expect(targets.every((t) => t.startsWith("prod"))).toBe(true);

  const actor = page.getByTestId("audit-actor").first();
  const name = (await actor.textContent()) ?? "";
  await actor.click();
  await expect(page.getByTestId("audit-chip-actor")).toContainText(name);
  await settled(page);
  const actors = await page.getByTestId("audit-actor").allTextContents();
  expect(actors.every((a) => a === name)).toBe(true);
  await page.getByTestId("audit-chip-actor").getByRole("button").click();
  await expect(page.getByTestId("audit-chip-actor")).toHaveCount(0);
});
