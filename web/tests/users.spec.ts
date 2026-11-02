import type { Page } from "@playwright/test";
import { expect, test } from "./fixture";
import { expectToast, isMobile } from "./helpers";

/** Waits until the list shows results for the query now in the URL. */
async function settled(page: Page, testId: string): Promise<void> {
  const pagination = page.getByTestId(testId);
  await expect(pagination).toHaveAttribute("data-filters", new URL(page.url()).searchParams.toString());
  await expect(pagination).toHaveAttribute("data-fetching", "false");
}

async function rowIds(page: Page, prefix: string): Promise<string[]> {
  const ids = await page.locator(`[data-testid^="${prefix}"]`).evaluateAll((els) => els.map((el) => el.getAttribute("data-testid") ?? ""));
  return ids.map((id) => id.slice(prefix.length));
}

test("pages, searches and filters users on the server", async ({ page }) => {
  await page.goto("/org/users");
  const summary = page.getByTestId("users-pagination-summary");
  await expect(summary).toHaveText("Showing 1-25 of 42");
  await expect(page.locator('[data-testid^="user-row-"]')).toHaveCount(25);

  await page.getByTestId("users-pagination-next").click();
  await expect(page).toHaveURL(/page=2/);
  await expect(summary).toHaveText("Showing 26-42 of 42");
  await expect(page.locator('[data-testid^="user-row-"]')).toHaveCount(17);

  await page.getByTestId("users-search").fill("priya");
  await expect(page).toHaveURL(/q=priya/);
  await expect(page).not.toHaveURL(/page=/);
  await expect(summary).toHaveText("Showing 1-1 of 1");
  await expect(page.getByTestId("user-row-priya@example.com")).toBeVisible();

  await page.getByTestId("users-search").fill("nobody-matches-this");
  await expect(page.getByTestId("users-no-matches")).toBeVisible();
  await page.getByTestId("users-no-matches").getByRole("button", { name: "Clear filters" }).click();
  await expect(page.getByTestId("users-search")).toHaveValue("");
  await expect(summary).toHaveText("Showing 1-25 of 42");

  await page.getByTestId("users-status").click();
  await page.getByTestId("users-status-disabled").click();
  await expect(page).toHaveURL(/status=disabled/);
  await settled(page, "users-pagination");
  const rows = page.locator('[data-testid^="user-row-"]');
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);
  await expect(page.getByTestId("user-disabled-badge")).toHaveCount(count);
});

test("sorts users by email in both directions", async ({ page }) => {
  await page.goto("/org/users");
  await settled(page, "users-pagination");
  if (isMobile(page)) {
    await page.getByTestId("users-sort").click();
    await page.getByRole("option", { name: "Email", exact: true }).click();
  } else {
    await page.getByTestId("users-sort-email").click();
  }
  await expect(page).toHaveURL(/sort=email/);
  await settled(page, "users-pagination");
  const ascending = await rowIds(page, "user-row-");
  expect(ascending).toEqual([...ascending].sort());

  if (isMobile(page)) {
    await page.getByTestId("users-sort").click();
    await page.getByRole("option", { name: "Email, reversed" }).click();
  } else {
    await page.getByTestId("users-sort-email").click();
  }
  await expect(page).toHaveURL(/order=desc/);
  await settled(page, "users-pagination");
  const descending = await rowIds(page, "user-row-");
  expect(descending).toEqual([...descending].sort().reverse());
  expect(descending[0]).not.toEqual(ascending[0]);
});

test("pages, searches and sorts machine identities", async ({ page }) => {
  await page.goto("/org/identities");
  const summary = page.getByTestId("identities-pagination-summary");
  await expect(summary).toHaveText("Showing 1-25 of 32");
  await expect(page.getByTestId("identity-row-github-deploy")).toBeVisible();

  await page.getByTestId("identities-pagination-next").click();
  await expect(summary).toHaveText("Showing 26-32 of 32");
  await page.getByTestId("identities-pagination-previous").click();
  await expect(summary).toHaveText("Showing 1-25 of 32");

  await page.getByTestId("identities-search").fill("kafka");
  await expect(summary).toHaveText("Showing 1-1 of 1");
  await expect(page.getByTestId("identity-row-kafka-connect")).toBeVisible();

  await page.getByTestId("identities-search").fill("");
  await expect(page).not.toHaveURL(/q=/);
  if (!isMobile(page)) {
    await page.getByTestId("identities-sort-created").click();
    await expect(page).toHaveURL(/sort=created/);
    await settled(page, "identities-pagination");
    await expect(page.getByTestId("identities-sort-created")).toHaveAttribute("data-order", "desc");
  }
});

test("the member picker searches users on the server", async ({ page }) => {
  await page.goto("/projects/storefront/settings/members");
  await page.getByTestId("add-member").click();
  const dialog = page.getByTestId("add-member-dialog");
  await expect(dialog.getByTestId("member-add-submit")).toBeDisabled();
  await expect(dialog.getByTestId("member-blocker")).toHaveText("Choose a user to continue.");
  await expect(page.getByTestId("members-help")).not.toContainText("add them again");
  await dialog.getByTestId("member-principal").click();
  await expect(page.getByTestId("principal-more")).toContainText("Showing 20 of");

  await page.getByTestId("member-principal-search").fill("zara");
  await expect(page.getByTestId("principal-more")).toHaveCount(0);
  await page.getByTestId("principal-option-Zara Hughes").click();
  await expect(dialog.getByTestId("member-principal")).toHaveText(/Zara Hughes/);
  await expect(dialog.getByTestId("member-blocker")).toHaveCount(0);
  await dialog.getByTestId("member-add-submit").click();
  await expectToast(page, "Member added");
  await expect(page.getByTestId("member-row-zara.hughes@example.com")).toBeVisible();
});

test("changes a member's role in one step and shows role names", async ({ page }) => {
  await page.goto("/projects/storefront/settings/members");
  const row = page.getByTestId("member-row-github-deploy");
  await expect(row.getByTestId("role-label-name")).toHaveText("viewer");
  await row.getByTestId("member-change-role").click();
  const dialog = page.getByTestId("change-role-dialog");
  await expect(dialog.getByTestId("confirm-action")).toBeDisabled();
  await dialog.getByTestId("change-role-select").click();
  await page.getByTestId("change-role-option-developer").click();
  await dialog.getByTestId("confirm-action").click();
  await expectToast(page, "github-deploy now has the developer role");
  // The old role is gone rather than held alongside the new one.
  await expect(page.getByTestId("member-row-github-deploy")).toHaveCount(1);
  await expect(page.getByTestId("member-row-github-deploy").getByTestId("role-label-name")).toHaveText("developer");
});

test("says clearly when a role change only half finished", async ({ page }) => {
  await page.goto("/projects/storefront/settings/members");
  await expect(page.getByTestId("member-row-github-deploy")).toBeVisible();
  await page.evaluate(async () => {
    const path = "/src/api/mock/server.ts";
    const mock = (await import(/* @vite-ignore */ path)) as {
      mockFailNext: (method: string, path: string, status: number, code: string, message: string) => void;
    };
    mock.mockFailNext("DELETE", "/members/", 500, "internal", "the database is busy");
  });
  await page.getByTestId("member-row-github-deploy").getByTestId("member-change-role").click();
  const dialog = page.getByTestId("change-role-dialog");
  await dialog.getByTestId("change-role-select").click();
  await page.getByTestId("change-role-option-developer").click();
  await dialog.getByTestId("confirm-action").click();
  await expectToast(page, /github-deploy now has the developer role, but the viewer role could not be removed/);
  await expectToast(page, "They hold both until you remove viewer from the list.");
  await expect(dialog).toHaveCount(0);
  // Both rows show, so the old one can be removed by hand.
  await expect(page.getByTestId("member-row-github-deploy")).toHaveCount(2);
});

test("the member picker finds machine identities beyond the first page", async ({ page }) => {
  await page.goto("/projects/storefront/settings/members");
  await page.getByTestId("add-member").click();
  const dialog = page.getByTestId("add-member-dialog");
  await expect(dialog.getByTestId("member-kind-identity")).toHaveText("Machine identity");
  await dialog.getByTestId("member-kind-identity").click();
  await dialog.getByTestId("member-principal").click();
  await page.getByTestId("member-principal-search").fill("webhook");
  await page.getByTestId("principal-option-webhook-relay").click();
  await dialog.getByTestId("member-add-submit").click();
  await expect(page.getByTestId("member-row-webhook-relay")).toBeVisible();
});
