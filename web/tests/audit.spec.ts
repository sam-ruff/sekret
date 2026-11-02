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

test("rows name actions in plain words and describe details without raw JSON", async ({ page }) => {
  await page.goto("/org/audit");
  await settled(page);
  const actions = page.getByTestId("audit-action");
  await expect(actions.first()).toBeVisible();
  const labels = await actions.allTextContents();
  // Labels are words, with the raw code kept in the tooltip for CLI users.
  expect(labels.every((label) => !/^[a-z]+\.[a-z_.-]+$/.test(label))).toBe(true);
  const codes = await actions.evaluateAll((els) => els.map((el) => el.getAttribute("title") ?? ""));
  expect(codes.every((code) => /^[a-z]+\.[a-z_.-]+$/.test(code))).toBe(true);
  const details = await page.getByTestId("audit-detail").allTextContents();
  expect(details.some((detail) => detail.includes('{"'))).toBe(false);
  expect(details.some((detail) => /^method: /.test(detail))).toBe(false);
});

test("the organisation log names each entry's project and links to that project's log", async ({ page }) => {
  await page.goto("/org/audit?action=secret.");
  await settled(page);
  const rows = page.getByTestId("audit-row");
  await expect(rows.first()).toBeVisible();
  const projects = await page.getByTestId("audit-project").allTextContents();
  expect(projects.length).toBe(await rows.count());
  expect(new Set(projects)).toEqual(new Set(["Storefront", "Payments API"]));

  // Payments API has no /payments folder or DATABASE_URL, so its entries never name them.
  const payments = rows.filter({ has: page.getByTestId("audit-project").getByText("Payments API", { exact: true }) });
  const targets = await payments.getByTestId("audit-target").allTextContents();
  expect(targets.length).toBeGreaterThan(0);
  expect(targets.some((t) => t.includes("/payments") || t.includes("DATABASE_URL"))).toBe(false);

  await payments.first().getByTestId("audit-project").click();
  await expect(page).toHaveURL(/\/projects\/payments-api\/audit$/);
  await expect(page.getByTestId("audit-project")).toHaveCount(0);
});

test("the project of a project settings entry is named in the organisation log", async ({ page }) => {
  await page.goto("/org/audit?action=project.");
  await settled(page);
  const row = page.getByTestId("audit-row").filter({ has: page.locator('[data-action="project.create"]') }).first();
  await expect(row.getByTestId("audit-project")).toHaveText(/Storefront|Payments API/);
});

test("disabled machine identities and ones without project access never read secrets in the log", async ({ page }) => {
  for (const name of ["cert-renewer", "inventory-sync"]) {
    await page.goto(`/org/audit?q=${name}`);
    await settled(page);
    await expect(page.getByTestId("audit-actor").filter({ hasText: name })).toHaveCount(0);
  }
  await page.goto("/org/audit?q=billing-worker&action=secret.");
  await settled(page);
  const projects = await page.getByTestId("audit-project").allTextContents();
  expect(projects.every((p) => p === "Payments API")).toBe(true);
});

test("a reader without access to the organisation log sees why, not a toolbar that does nothing", async ({ page }) => {
  await page.goto("/org/audit?mock-org-role=org-member");
  await expect(page.getByTestId("audit-no-access")).toContainText("Only organisation admins");
  await expect(page.getByTestId("audit-search")).toHaveCount(0);
  await expect(page.getByTestId("audit-total")).toHaveCount(0);
});

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
  const actions = await page.getByTestId("audit-action").evaluateAll((els) => els.map((el) => el.getAttribute("data-action") ?? ""));
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
  await expect(page.getByTestId("audit-empty")).toContainText("Try a wider date range");
  await expect(page.getByTestId("audit-total")).toHaveText("0 entries");
  // One Clear filters button, in the empty card, rather than two.
  await expect(page.getByRole("button", { name: "Clear filters" })).toHaveCount(1);
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

test("explains plainly when some secrets are hidden, so key and folder filters are refused", async ({ page }) => {
  // The signed-in user cannot see some production key names in this project.
  await page.goto("/projects/payments-api/audit?key=HSM_PIN");
  const notice = page.getByTestId("audit-filter-hidden");
  await expect(notice).toContainText("Cannot filter by key or folder here");
  await expect(page.getByTestId("error-state")).toHaveCount(0);
  await expect(page.getByTestId("audit-search")).toHaveAttribute("placeholder", "Search actions, people, addresses");

  await page.getByTestId("audit-filter-hidden-clear").click();
  await expect(page).not.toHaveURL(/key=/);
  await expect(notice).toHaveCount(0);
  await expect(page.getByTestId("audit-total")).toHaveText(/\d+ entries/);

  // In an environment the user can read in full, keys are searchable again.
  await choose(page, "audit-environment", "audit-environment-dev", /env=dev/);
  await expect(page.getByTestId("audit-search")).toHaveAttribute("placeholder", "Search actions, people, keys, addresses");
});

test("says why a search finds no key names when some secrets are hidden", async ({ page }) => {
  await page.goto("/projects/payments-api/audit?q=HSM_PIN");
  const empty = page.getByTestId("audit-empty");
  await expect(empty).toContainText("No matching activity");
  await expect(empty).toContainText("Key names and folders are not searched because some secrets in this log are hidden from you.");

  // A search that does match something still says what it skipped.
  await page.getByTestId("audit-search").fill("secret");
  await expect(page.getByTestId("audit-keys-skipped")).toBeVisible();

  // In an environment the user can read in full, the key is found and nothing is said.
  await choose(page, "audit-environment", "audit-environment-dev", /env=dev/);
  await page.getByTestId("audit-search").fill("HSM_PIN");
  await expect(page.getByTestId("audit-total")).toHaveText(/[1-9]\d* entr/);
  await expect(page.getByTestId("audit-keys-skipped")).toHaveCount(0);
});

test("lets a reader who sees everything filter by key", async ({ page }) => {
  await page.goto("/projects/storefront/audit?key=DATABASE_URL");
  await expect(page.getByTestId("audit-chip-key")).toContainText("DATABASE_URL");
  await expect(page.getByTestId("audit-total")).toHaveText(/[1-9]\d* entr/);
  await expect(page.getByTestId("audit-filter-hidden")).toHaveCount(0);
});
