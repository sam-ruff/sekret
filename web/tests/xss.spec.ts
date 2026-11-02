import type { Page } from "@playwright/test";
import { expect, test } from "./fixture";
import {
  HOSTILE as X,
  HOSTILE_PROJECT,
  HOSTILE_SECRET,
  HOSTILE_SEED,
  HOSTILE_SEED_FLAG,
} from "../src/api/mock/hostile-values";
import { expectToast, secretRow } from "./helpers";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(
    ([flag, value]) => window.sessionStorage.setItem(flag, value),
    [HOSTILE_SEED_FLAG, HOSTILE_SEED] as const,
  );
  page.on("dialog", (dialog) => {
    throw new Error(`Unexpected dialog: ${dialog.message()}`);
  });
});

async function expectNoXss(page: Page): Promise<void> {
  // An injected onerror runs when its image settles, so wait until every image has loaded or failed.
  await page.waitForFunction(() => Array.from(document.images).every((image) => image.complete), undefined, {
    timeout: 15_000,
  });
  expect(await page.evaluate(() => (window as unknown as { __xss?: unknown }).__xss)).toBeUndefined();
  expect(await page.locator("main script, main svg[onload], img[onerror]").count()).toBe(0);
}

async function expectLiteral(page: Page, text: string): Promise<void> {
  await expect(page.getByText(text, { exact: false }).first()).toBeVisible();
}

const base = `/projects/${HOSTILE_PROJECT}`;

test("project names, descriptions and environments render as text", async ({ page }) => {
  await page.goto("/projects");
  const card = page.getByTestId(`project-card-${HOSTILE_PROJECT}`);
  await expect(card).toContainText(X.img);
  await expect(card).toContainText(X.script);
  await expectNoXss(page);

  await card.click();
  await expect(page.getByTestId("env-tab-dev")).toContainText(X.svg);
  await expect(page.getByRole("navigation", { name: "Location" })).toContainText(X.img);
  await expectNoXss(page);
});

test("secret keys, values, comments, tags, folders, history and diff render as text", async ({ page }) => {
  await page.goto(`${base}/secrets/dev`);
  const row = secretRow(page, HOSTILE_SECRET);
  await expect(row.getByTestId("secret-comment")).toHaveText(X.svg);
  await expect(row.getByTestId(`secret-tag-${X.svg}`)).toHaveText(X.svg);
  await expect(secretRow(page, X.img).getByTestId("secret-key")).toHaveText(X.img);
  await expect(page.getByTestId(`folder-row-${X.img}`)).toContainText(X.img);

  await page.getByTestId("reveal-all").click();
  await expect(row.getByTestId("secret-value")).toContainText(X.svg);
  await expect(secretRow(page, "LINK").getByTestId("secret-value")).toHaveText(X.js);
  await expect(secretRow(page, X.img).getByTestId("secret-value")).toHaveText(X.script);
  await expectNoXss(page);

  await row.getByTestId("secret-key").click();
  const drawer = page.getByTestId("secret-drawer");
  await drawer.getByTestId("history-values-toggle").click();
  await expect(drawer.getByTestId("diff-output")).toContainText(X.img);
  await expect(drawer.getByTestId("diff-output")).toContainText(X.svg);
  await expect(drawer.getByTestId("version-1")).toContainText(X.img);
  await expect(drawer.getByTestId("version-1")).toContainText(X.script);
  await expectNoXss(page);
  await page.keyboard.press("Escape");

  // The server refuses the hostile tag; its error comes back as a toast.
  await secretRow(page, HOSTILE_SECRET).getByTestId("secret-actions").click();
  await page.getByTestId("secret-edit").click();
  const editor = page.getByTestId(`edit-secret-${HOSTILE_SECRET}`);
  await expect(editor.getByTestId("secret-value-input")).toHaveValue(`${X.svg}\n${X.js}`);
  await editor.getByTestId("secret-comment-input").fill(X.img);
  await editor.getByTestId("secret-save").click();
  await expectToast(page, /tags must be/i);
  await expectNoXss(page);
});

test("overview and snapshots render hostile names and reasons as text", async ({ page }) => {
  await page.goto(`${base}/overview`);
  await expect(page.getByTestId("overview-grid")).toContainText(X.img);
  await expectNoXss(page);

  await page.goto(`${base}/snapshots/dev`);
  const list = page.getByTestId("snapshot-list");
  await expect(list).toContainText(X.img);
  await list.locator("li").first().getByRole("button").click();
  await expect(page.getByTestId("snapshot-sheet")).toBeVisible();
  await expectNoXss(page);
});

test("audit entries render actors, targets, addresses and detail as text", async ({ page }) => {
  for (const path of [`${base}/audit`, "/org/audit"]) {
    await page.goto(path);
    const row = page.getByTestId("audit-row").filter({ has: page.getByTestId("audit-actor").filter({ hasText: X.img }) }).first();
    await expect(row).toBeVisible();
    await expect(row.getByTestId("audit-target")).toContainText(X.script);
    await expect(row).toContainText(X.svg);
    await expect(row).toContainText(X.js);
    await expectNoXss(page);
  }

  // Filtering by the hostile actor puts their id into the URL and a chip.
  await page.getByTestId("audit-actor").filter({ hasText: X.img }).first().click();
  await expect(page.getByTestId("audit-chip-actor")).toContainText(X.img);
  await page.getByTestId("audit-search").fill(X.script);
  await expect(page.getByTestId("audit-total")).toHaveText("1 entry");
  await expectNoXss(page);
});

test("settings render hostile roles, members and environments as text", async ({ page }) => {
  await page.goto(`${base}/settings/general`);
  await expect(page.getByTestId("settings-name")).toHaveValue(X.img);
  await expectNoXss(page);

  await page.goto(`${base}/settings/environments`);
  await expectLiteral(page, X.svg);
  await expectNoXss(page);

  await page.goto(`${base}/settings/members`);
  await expect(page.getByTestId(`member-row-${X.svg}`).filter({ hasText: "Group" })).toBeVisible();
  await expect(page.getByTestId(`member-row-${X.svg}`).filter({ hasText: "Machine identity" })).toBeVisible();
  await expectNoXss(page);

  await page.goto(`${base}/settings/roles`);
  const role = page.getByTestId("role-row-hostile-role");
  await expect(role).toContainText(X.img);
  await page.getByTestId("role-actions-hostile-role").click();
  await page.getByTestId("role-edit").click();
  await expect(page.getByTestId("role-editor").getByTestId("role-name")).toHaveValue(X.img);
  await expectNoXss(page);
});

test("users, identities, auth methods and access render as text", async ({ page }) => {
  await page.goto("/org/users");
  const user = page.getByTestId(`user-row-hostile@example.com${X.svg}`);
  await expect(user.getByTestId("user-name")).toHaveText(X.img);
  await expect(user).toContainText(X.script);
  await user.getByTestId("user-toggle-disabled").click();
  await page.getByTestId("confirm-action").click();
  await expectToast(page, `${X.img} disabled`);
  await expectNoXss(page);

  await page.goto("/org/identities");
  const identity = page.getByTestId(`identity-row-${X.svg}`);
  await expect(identity).toContainText(X.img);
  await page.getByTestId(`identity-link-${X.svg}`).click();
  await expectLiteral(page, X.svg);
  await expectNoXss(page);

  await page.getByTestId("identity-tab-auth").click();
  await expect(page.getByTestId("oidc-issuer")).toHaveValue(X.js);
  await expect(page.getByTestId("auth-method-kubernetes")).toContainText(X.svg);
  await expectNoXss(page);

  await page.getByTestId("identity-tab-usage").click();
  await expectNoXss(page);

  await page.goto("/org/access");
  await expectLiteral(page, X.script);
  await expectNoXss(page);
});

test("markup in the CLI login link is never rendered or prefilled", async ({ page }) => {
  await page.goto(`/cli-login?code=${encodeURIComponent(X.img)}`);
  await expect(page.getByTestId("cli-unknown")).toBeVisible();
  // An unknown request offers nothing to type into, let alone prefilled.
  await expect(page.getByTestId("cli-code-input")).toHaveCount(0);
  await expect(page.getByTestId("cli-login")).not.toContainText("ONERROR", { ignoreCase: true });
  await expectNoXss(page);
});

test("a return address that leaves the origin is ignored", async ({ page }) => {
  await page.goto(`/login?return_to=${encodeURIComponent("/\\evil.example/")}`);
  await page.getByTestId("sign-in").click();
  await expect(page).toHaveURL(/\/projects$/);
  await expectNoXss(page);
});
