import { expect, test, type Page } from "@playwright/test";
import { expectToast, isMobile, navigate } from "./helpers";

const SETUP_CODE = "MOCK-SETUP-CODE";
const PASSPHRASE = "correct horse battery staple";
const STRONG = "plum orbit gravel lantern";

async function fillSetup(page: Page, passphrase: string, code = SETUP_CODE): Promise<void> {
  await page.getByTestId("setup-code").fill(code);
  await page.getByTestId("setup-passphrase").fill(passphrase);
  await page.getByTestId("setup-confirm").fill(passphrase);
}

async function unlock(page: Page, passphrase: string): Promise<void> {
  await page.getByTestId("unlock-passphrase").fill(passphrase);
  await page.getByTestId("unlock-submit").click();
}

/** Seals the fake server behind the app's back, as another admin or a restart would. */
async function sealBehindTheScenes(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const path = "/src/api/mock/server.ts";
    const mock = (await import(/* @vite-ignore */ path)) as { mockSealServer: () => void };
    mock.mockSealServer();
  });
}

test.describe("first-boot setup", () => {
  test("defaults to manual, refuses a weak passphrase and shows the admin token once", async ({ page }) => {
    await page.goto("/projects?mock-state=uninitialised");
    await expect(page).toHaveURL(/\/setup$/);
    await expect(page.getByTestId("sidebar")).toHaveCount(0);
    await expect(page.getByTestId("setup-policy-manual")).toHaveAttribute("data-state", "checked");
    await expect(page.getByTestId("setup-policy-card-manual")).toContainText("Most secure");
    await expect(page.getByTestId("no-recovery")).toContainText("There is no recovery.");
    await expect(page.getByTestId("unlock-docs-link")).toHaveAttribute("href", /unlocking\/$/);

    await fillSetup(page, "password1234");
    const meter = page.getByTestId("setup-meter");
    await expect(meter).toHaveAttribute("data-acceptable", "false");
    await expect(page.getByTestId("setup-meter-feedback")).toContainText("commonly used password");
    await expect(page.getByTestId("setup-submit")).toBeDisabled();

    await page.getByTestId("setup-passphrase").fill(STRONG);
    await expect(page.getByTestId("setup-mismatch")).toBeVisible();
    await page.getByTestId("setup-confirm").fill(STRONG);
    await expect(meter).toHaveAttribute("data-acceptable", "true");

    await page.getByTestId("setup-code").fill("WRONG-CODE");
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("setup-code-error")).toContainText("setup code is wrong");

    await page.getByTestId("setup-code").fill(SETUP_CODE);
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("admin-token")).toHaveText(/^skt_[0-9a-f]{48}$/);
    await expect(page.getByTestId("admin-token-copy")).toBeVisible();

    await page.reload();
    await expect(page.getByTestId("setup-already")).toBeVisible();
    await expect(page.getByTestId("admin-token")).toHaveCount(0);

    await page.goto("/org/server");
    await expect(page.getByTestId("server-policy")).toHaveText("Manual");
  });

  for (const [policy, label] of [
    ["remember", "Remember"],
    ["passphrase-file", "Passphrase file"],
  ] as const) {
    test(`sets up with the ${policy} policy`, async ({ page }) => {
      await page.goto("/?mock-state=uninitialised");
      await fillSetup(page, STRONG);
      await page.getByTestId(`setup-policy-card-${policy}`).click();
      await expect(page.getByTestId(`setup-policy-${policy}`)).toHaveAttribute("data-state", "checked");
      await expect(page.getByTestId("setup-policy-manual")).toHaveAttribute("data-state", "unchecked");
      await page.getByTestId("setup-submit").click();
      await expect(page.getByTestId("setup-done")).toBeVisible();
      await page.getByTestId("setup-continue").click();
      await expect(page).toHaveURL(/\/login$/);

      await page.goto("/org/server");
      await expect(page.getByTestId("server-policy")).toHaveText(label);
    });
  }

  test("shows a policy fixed in configuration as read-only", async ({ page }) => {
    await page.goto("/?mock-state=uninitialised&mock-unlock=remember");
    await expect(page.getByTestId("setup-policy-configured")).toContainText("set in the server configuration");
    await expect(page.getByTestId("setup-policy-options")).toHaveCount(0);
  });

  test("points to the host when web setup is off", async ({ page }) => {
    await page.goto("/projects?mock-state=uninitialised&mock-web-setup=false");
    await expect(page).toHaveURL(/\/setup$/);
    await expect(page.getByTestId("setup-disabled")).toContainText("This server is set up from its configuration");
    await expect(page.getByTestId("setup-disabled")).toContainText("sekret admin init");
    await expect(page.getByTestId("setup-code")).toHaveCount(0);
  });
});

test.describe("unlocking", () => {
  test("refuses a wrong passphrase, then returns to the page after the right one", async ({ page }) => {
    await page.goto("/org/users?mock-state=sealed");
    await expect(page).toHaveURL(/\/unlock\?return_to=%2Forg%2Fusers$/);
    await expect(page.getByTestId("sidebar")).toHaveCount(0);
    await expect(page.getByTestId("unlock-card")).toContainText("sekret restarted and needs its passphrase");
    await expect(page.getByTestId("unlock-policy")).toContainText("Unlock policy: manual");

    await unlock(page, "not the passphrase");
    await expect(page.getByTestId("unlock-wrong")).toBeVisible();
    await expect(page).toHaveURL(/\/unlock/);

    await unlock(page, PASSPHRASE);
    await expect(page).toHaveURL(/\/org\/users$/);
    await expect(page.getByTestId("page-title")).toHaveText("Users");
  });

  test("explains a lost remembered unlock", async ({ page }) => {
    await page.goto("/?mock-state=sealed&mock-unlock=remember");
    await expect(page.getByTestId("unlock-policy")).toContainText(
      "The remembered unlock was lost; unlocking now will remember it again.",
    );
  });

  test("reports rate limiting inline", async ({ page }) => {
    await page.goto("/?mock-state=sealed");
    for (let i = 0; i < 5; i += 1) {
      await unlock(page, `wrong ${i}`);
      await expect(page.getByTestId("unlock-wrong")).toBeVisible();
    }
    await unlock(page, "wrong again");
    await expect(page.getByTestId("unlock-limited")).toContainText("Too many attempts");
  });

  test("moves an open tab to the unlock page when the server is sealed mid-session", async ({ page }) => {
    await page.goto("/projects");
    await expect(page.getByTestId("project-card-storefront")).toBeVisible();
    await sealBehindTheScenes(page);
    await page.getByTestId("project-card-storefront").click();
    await expect(page).toHaveURL(/\/unlock\?return_to=%2Fprojects%2Fstorefront%2Fsecrets/);
    await unlock(page, PASSPHRASE);
    await expect(page).toHaveURL(/\/projects\/storefront\/secrets/);
    await expect(page.getByTestId("env-tabs")).toBeVisible();
  });
});

test.describe("server page", () => {
  test("seals the server after confirming", async ({ page }) => {
    await page.goto("/projects");
    await navigate(page, "nav-server");
    await expect(page.getByTestId("server-state")).toHaveText("Unlocked");
    await expect(page.getByTestId("server-mode")).toHaveText("Passphrase");
    await expect(page.getByTestId("server-version")).toHaveText("0.0.0-mock");

    await page.getByTestId("seal-now").click();
    const dialog = page.getByTestId("seal-dialog");
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();

    await page.getByTestId("seal-now").click();
    await dialog.getByTestId("confirm-action").click();
    await expect(page).toHaveURL(/\/unlock\?return_to=%2Forg%2Fserver$/);
    await unlock(page, PASSPHRASE);
    await expect(page.getByTestId("server-state")).toHaveText("Unlocked");
  });

  test("changes the passphrase", async ({ page }) => {
    await page.goto("/org/server");
    const card = page.getByTestId("server-passphrase");
    await card.getByTestId("current-passphrase").fill("not it");
    await card.getByTestId("change-passphrase").fill("password1234");
    await card.getByTestId("change-confirm").fill("password1234");
    await expect(card.getByTestId("change-meter-feedback")).toContainText("commonly used password");
    await expect(card.getByTestId("change-submit")).toBeDisabled();

    await card.getByTestId("change-passphrase").fill(STRONG);
    await card.getByTestId("change-confirm").fill(STRONG);
    await card.getByTestId("change-submit").click();
    await expect(card.getByTestId("current-passphrase-wrong")).toBeVisible();

    await card.getByTestId("current-passphrase").fill(PASSPHRASE);
    await card.getByTestId("change-submit").click();
    await expectToast(page, "Passphrase changed");
    await expect(card.getByTestId("current-passphrase")).toHaveValue("");

    await page.getByTestId("seal-now").click();
    await page.getByTestId("seal-dialog").getByTestId("confirm-action").click();
    await unlock(page, PASSPHRASE);
    await expect(page.getByTestId("unlock-wrong")).toBeVisible();
    await unlock(page, STRONG);
    await expect(page).toHaveURL(/\/org\/server$/);
  });

  test("changes the unlock policy and forgets a remembered unlock", async ({ page }) => {
    await page.goto("/org/server");
    await expect(page.getByTestId("server-policy-manual")).toHaveAttribute("data-state", "checked");
    await expect(page.getByTestId("policy-save")).toBeDisabled();
    await expect(page.getByTestId("forget-unlock")).toHaveCount(0);

    await page.getByTestId("server-policy-card-remember").click();
    await page.getByTestId("policy-save").click();
    await expectToast(page, "Unlock policy saved");
    await expect(page.getByTestId("server-policy")).toHaveText("Remember");
    await expect(page.getByTestId("server-remembered")).toContainText("Yes");

    await page.getByTestId("forget-unlock").click();
    await expectToast(page, "Remembered unlock forgotten");
    await expect(page.getByTestId("server-remembered")).toHaveText("No");
    await expect(page.getByTestId("forget-unlock")).toHaveCount(0);
  });

  test("shows a configured policy read-only", async ({ page }) => {
    await page.goto("/org/server?mock-unlock=passphrase-file");
    await expect(page.getByTestId("server-policy")).toContainText("Passphrase file (set in configuration)");
    await expect(page.getByTestId("server-policy-configured")).toContainText("cannot be changed here");
    await expect(page.getByTestId("policy-save")).toHaveCount(0);
  });

  test("downloads an encrypted backup", async ({ page }) => {
    await page.goto("/org/server");
    await expect(page.getByTestId("server-backup")).toContainText("needs the passphrase");
    const download = page.waitForEvent("download");
    await page.getByTestId("backup-download").click();
    expect((await download).suggestedFilename()).toMatch(/^sekret-backup-\d{8}T\d{6}Z\.skb$/);
  });

  test("is hidden from people who are not admins", async ({ page }) => {
    await page.goto("/projects?mock-org-role=org-member");
    if (isMobile(page)) await page.getByTestId("sidebar-trigger").click();
    await expect(page.getByTestId("nav-projects")).toBeVisible();
    await expect(page.getByTestId("nav-server")).toHaveCount(0);

    await page.goto("/org/server");
    await expect(page.getByTestId("error-state")).toContainText("Only organisation admins and backup readers");
    await expect(page.getByTestId("seal-now")).toHaveCount(0);
  });

  test("offers backup readers only the download", async ({ page }) => {
    await page.goto("/org/server?mock-org-role=backup-reader");
    await expect(page.getByTestId("backup-download")).toBeVisible();
    await expect(page.getByTestId("seal-now")).toHaveCount(0);
    await expect(page.getByTestId("server-passphrase")).toHaveCount(0);
    await expect(page.getByTestId("server-unlock-policy")).toHaveCount(0);
  });
});
