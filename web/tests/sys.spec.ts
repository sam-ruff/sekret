import { expect, test, type Page } from "@playwright/test";
import { expectToast, isMobile, navigate, openProject, secretRow } from "./helpers";

const SETUP_CODE = "MOCK-SETUP-CODE";
const PASSPHRASE = "correct horse battery staple";
const STRONG = "plum orbit gravel lantern";
const KDF_BUSY = "mock kdf busy";
/** The mock's stand-in for a seal mark that could not be updated. */
const STALE_MARK = "stale mark copper lantern harbour ferry";

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

/** The fake server's answers to a backup by GET, by POST without the CSRF header, and by POST with it. */
async function backupStatuses(page: Page): Promise<number[]> {
  return page.evaluate(async () => {
    const path = "/src/api/mock/server.ts";
    const mock = (await import(/* @vite-ignore */ path)) as { mockFetch: (request: Request) => Promise<Response> };
    const url = `${location.origin}/api/v1/sys/backup`;
    const get = await mock.mockFetch(new Request(url));
    const bare = await mock.mockFetch(new Request(url, { method: "POST" }));
    const sent = await mock.mockFetch(new Request(url, { method: "POST", headers: { "x-sekret-csrf": "1" } }));
    return [get.status, bare.status, sent.status];
  });
}

/** What the fake server tells a caller with no session. */
async function publicStatus(page: Page): Promise<unknown> {
  return page.evaluate(async () => {
    const path = "/src/api/mock/server.ts";
    const mock = (await import(/* @vite-ignore */ path)) as { mockFetch: (request: Request) => Promise<Response> };
    const response = await mock.mockFetch(new Request(`${location.origin}/api/v1/sys/status`));
    return response.json() as Promise<unknown>;
  });
}

/** A clipboard the test can read, and that reports reading as already allowed. */
async function fakeClipboard(page: Page): Promise<void> {
  await page.addInitScript(() => {
    let contents = "";
    const clipboard = {
      writeText: (text: string) => {
        contents = text;
        return Promise.resolve();
      },
      readText: () => Promise.resolve(contents),
    };
    Object.defineProperty(navigator, "clipboard", { value: clipboard, configurable: true });
    (window as unknown as { readClipboard: () => string }).readClipboard = () => contents;
  });
}

const clipboardText = (page: Page) => page.evaluate(() => (window as unknown as { readClipboard: () => string }).readClipboard());

test.describe("first-boot setup", () => {
  test("defaults to manual, refuses a weak passphrase and shows the admin token once", async ({ page }) => {
    await page.goto("/projects?mock-state=uninitialised");
    await expect(page).toHaveURL(/\/setup$/);
    await expect(page).toHaveTitle("Set up · sekret");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Set up sekret");
    await expect(page.getByTestId("sidebar")).toHaveCount(0);
    await expect(page.getByTestId("setup-policy-manual")).toHaveAttribute("data-state", "checked");
    await expect(page.getByTestId("setup-policy-card-manual")).toContainText("Default, most secure");
    await expect(page.getByTestId("setup-policy-card-manual")).toContainText("Pair it with an alert");
    await expect(page.getByTestId("no-recovery")).toContainText("There is no recovery.");
    await expect(page.getByTestId("no-recovery")).toContainText("Store it in a password manager.");
    await expect(page.getByTestId("unlock-docs-link")).toHaveAttribute("href", /unlocking\/$/);
    await expect(page.getByTestId("setup-blocker")).toHaveText("Enter the setup code to continue.");

    await fillSetup(page, "password1234");
    const meter = page.getByTestId("setup-meter");
    await expect(meter).toHaveAttribute("data-acceptable", "false");
    await expect(page.getByTestId("setup-meter-feedback")).toContainText("commonly used password");
    await expect(page.getByTestId("setup-meter-region")).toHaveAttribute("aria-live", "polite");
    await expect(page.getByTestId("setup-passphrase")).toHaveAttribute("aria-describedby", "setup-meter");
    await expect(page.getByTestId("setup-submit")).toBeDisabled();
    await expect(page.getByTestId("setup-blocker")).toHaveText("Choose a stronger passphrase to continue.");

    await page.getByTestId("setup-passphrase").fill(STRONG);
    await expect(page.getByTestId("setup-mismatch")).toBeVisible();
    await expect(page.getByTestId("setup-confirm")).toHaveAttribute("aria-describedby", "setup-mismatch");
    await page.getByTestId("setup-confirm").fill(STRONG);
    await expect(meter).toHaveAttribute("data-acceptable", "true");
    await expect(meter).toContainText("Strong enough");

    await page.getByTestId("setup-code").fill("WRONG-CODE");
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("setup-code-error")).toHaveText(
      "That setup code is wrong. Check the latest one in the server log.",
    );
    await expect(page.getByTestId("setup-code")).toBeFocused();

    await page.getByTestId("setup-code").fill(SETUP_CODE);
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("admin-token")).toHaveText(/^skt_[0-9a-f]{48}$/);
    await expect(page.getByTestId("admin-token-copy")).toBeVisible();
    await expect(page.getByTestId("admin-token-help")).toContainText(
      /Copy this token now\. It is shown once and expires in 1 hour \(\d{2}:\d{2}\)\./,
    );
    await expect(page.getByTestId("admin-token-help")).toContainText("It lets the CLI act as an organisation admin");
    // The expiry is said once, in the warning.
    await expect(page.getByTestId("admin-token-expiry")).toHaveCount(0);
    await expect(page.getByTestId("admin-token-cli")).toContainText("export SEKRET_URL=");
    await expect(page.getByTestId("admin-token-cli")).toContainText("export SEKRET_TOKEN=<token>");
    await expect(page.getByTestId("admin-token-cli-copy")).toBeVisible();
    await expect(page.getByTestId("setup-continue")).toHaveText("I have saved it, continue");

    await page.reload();
    await expect(page.getByTestId("setup-already")).toBeVisible();
    await expect(page.getByTestId("admin-token")).toHaveCount(0);

    await page.goto("/org/server");
    await expect(page.getByTestId("server-policy")).toHaveText("Manual");
  });

  test("clears the copied admin token from the clipboard after 45 seconds", async ({ page }) => {
    await fakeClipboard(page);
    await page.clock.install();
    await page.goto("/?mock-state=uninitialised");
    await fillSetup(page, STRONG);
    await page.getByTestId("setup-submit").click();
    const token = (await page.getByTestId("admin-token").textContent()) ?? "";
    await page.getByTestId("admin-token-copy").click();
    await expectToast(page, "Copied to clipboard");
    expect(await clipboardText(page)).toBe(token);

    await page.clock.fastForward(44_000);
    expect(await clipboardText(page)).toBe(token);
    await page.clock.fastForward(2_000);
    await expect.poll(() => clipboardText(page)).toBe("");
  });

  test("copies the CLI commands with the real token, and clears them like the token", async ({ page }) => {
    await fakeClipboard(page);
    await page.clock.install();
    await page.goto("/?mock-state=uninitialised");
    await expect(page.getByTestId("setup-meter")).toHaveCSS("font-size", "14px");
    await fillSetup(page, STRONG);
    await page.getByTestId("setup-submit").click();
    const token = (await page.getByTestId("admin-token").textContent()) ?? "";
    await page.getByTestId("admin-token-cli-copy").click();
    await expectToast(page, "Copied to clipboard");
    const origin = new URL(page.url()).origin;
    expect(await clipboardText(page)).toBe(`export SEKRET_URL=${origin}\nexport SEKRET_TOKEN=${token}`);
    await page.clock.fastForward(46_000);
    await expect.poll(() => clipboardText(page)).toBe("");
  });

  test("lets each new passphrase field be shown on its own", async ({ page }) => {
    await page.goto("/?mock-state=uninitialised");
    await page.getByTestId("setup-passphrase-toggle").click();
    await expect(page.getByTestId("setup-passphrase")).toHaveAttribute("type", "text");
    await expect(page.getByTestId("setup-confirm")).toHaveAttribute("type", "password");
    await expect(page.getByTestId("setup-confirm-toggle")).toHaveAccessibleName("Show passphrase");
    await expect(page.getByTestId("setup-passphrase-toggle")).toHaveAccessibleName("Hide passphrase");
  });

  for (const [policy, label, needs] of [
    ["remember", "Remember", "seal.remember_file"],
    ["passphrase-file", "Passphrase file", "Without it the server stays locked."],
  ] as const) {
    test(`sets up with the ${policy} policy`, async ({ page }) => {
      await page.goto("/?mock-state=uninitialised");
      await fillSetup(page, STRONG);
      await expect(page.getByTestId("setup-policy-needs")).toHaveCount(0);
      await page.getByTestId(`setup-policy-card-${policy}`).click();
      await expect(page.getByTestId(`setup-policy-${policy}`)).toHaveAttribute("data-state", "checked");
      await expect(page.getByTestId("setup-policy-manual")).toHaveAttribute("data-state", "unchecked");
      await expect(page.getByTestId("setup-policy-needs")).toContainText(needs);
      await page.getByTestId("setup-submit").click();
      await expect(page.getByTestId("setup-done")).toBeVisible();
      await page.getByTestId("setup-continue").click();
      await expect(page).toHaveURL(/\/login$/);

      await page.goto("/org/server");
      await expect(page.getByTestId("server-policy")).toHaveText(label);
    });
  }

  test("names the radio cards and shows a visible focus ring on the whole card", async ({ page }) => {
    await page.goto("/?mock-state=uninitialised");
    const radio = page.getByRole("radio", { name: "Remember" });
    await expect(radio).toHaveAttribute("aria-describedby", "setup-policy-remember-text");
    await page.getByTestId("setup-policy-manual").focus();
    await page.keyboard.press("ArrowDown");
    await expect(radio).toBeFocused();
    const ring = await page
      .getByTestId("setup-policy-card-remember")
      .evaluate((card) => getComputedStyle(card).boxShadow);
    expect(ring).not.toBe("none");
  });

  test("offers Remember only when the server has a remember file", async ({ page }) => {
    await page.goto("/?mock-state=uninitialised&mock-remember-file=false");
    await expect(page.getByTestId("setup-policy-remember")).toBeDisabled();
    await expect(page.getByTestId("setup-policy-unavailable")).toContainText("does not set seal.remember_file");
    // Clicking the greyed-out card changes nothing.
    await page.getByTestId("setup-policy-card-remember").click({ force: true });
    await expect(page.getByTestId("setup-policy-manual")).toHaveAttribute("data-state", "checked");
    await expect(page.getByTestId("setup-policy-passphrase-file")).toBeEnabled();
  });

  test("says web sign-in is not ready when the server has no sign-in provider", async ({ page }) => {
    await page.goto("/?mock-state=uninitialised&mock-oidc=false");
    await fillSetup(page, STRONG);
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("setup-no-oidc")).toContainText("Web sign-in is not set up yet");
    await expect(page.getByTestId("setup-oidc-docs-link")).toHaveAttribute("target", "_blank");
    await page.getByTestId("setup-continue").click();
    await expect(page.getByTestId("oidc-disabled")).toBeVisible();
  });

  test("shows a policy fixed in configuration by name before setup", async ({ page }) => {
    await page.goto("/?mock-state=uninitialised&mock-unlock=remember");
    await expect(page.getByTestId("setup-policy-configured")).toContainText("Remember");
    await expect(page.getByTestId("setup-policy-configured")).toContainText("Set in the server configuration");
    await expect(page.getByTestId("setup-policy-options")).toHaveCount(0);
  });

  test("skips the passphrase when the configuration names a key file", async ({ page }) => {
    await page.goto("/?mock-state=uninitialised&mock-seal-mode=key-file");
    await expect(page.getByTestId("setup-key-file")).toContainText("root key file");
    await expect(page.getByTestId("setup-passphrase")).toHaveCount(0);
    await expect(page.getByTestId("setup-policy-options")).toHaveCount(0);
    await page.getByTestId("setup-code").fill(SETUP_CODE);
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("admin-token")).toBeVisible();
  });

  test("points to the host without a setup code when web setup is off", async ({ page }) => {
    await page.goto("/projects?mock-state=uninitialised&mock-web-setup=false");
    await expect(page).toHaveURL(/\/setup$/);
    await expect(page.getByTestId("setup-disabled")).toContainText(
      "Web setup is turned off. Run sekret admin init on the host, then restart the server. Reload this page once it is done.",
    );
    await expect(page.getByTestId("setup-code")).toHaveCount(0);
  });
});

test.describe("unlocking", () => {
  test("refuses a wrong passphrase, then returns to the page after the right one", async ({ page }) => {
    await page.goto("/org/users?mock-state=sealed");
    await expect(page).toHaveURL(/\/unlock\?return_to=%2Forg%2Fusers$/);
    await expect(page).toHaveTitle("Unlock · sekret");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Unlock sekret");
    await expect(page.getByTestId("sidebar")).toHaveCount(0);
    await expect(page.getByTestId("unlock-description")).toHaveText(
      "The server was locked while you were using it. The server is locked, so secrets cannot be read. Someone with the server passphrase needs to unlock it.",
    );
    await expect(page.getByTestId("unlock-card")).not.toContainText("restarted");

    // The passphrase can be shown to check it, and hidden again.
    const field = page.getByTestId("unlock-passphrase");
    await field.fill("typed");
    await page.getByRole("button", { name: "Show passphrase" }).click();
    await expect(field).toHaveAttribute("type", "text");
    await page.getByRole("button", { name: "Hide passphrase" }).click();
    await expect(field).toHaveAttribute("type", "password");
    await field.fill("");

    await page.getByTestId("unlock-submit").click();
    await expect(page.getByTestId("unlock-empty")).toHaveText("Enter the passphrase to unlock.");

    await unlock(page, "not the passphrase");
    await expect(page.getByTestId("unlock-wrong")).toBeVisible();
    await expect(page.getByTestId("unlock-passphrase")).toHaveAttribute("aria-describedby", "unlock-passphrase-error");
    await expect(page).toHaveURL(/\/unlock/);

    await unlock(page, PASSPHRASE);
    await expect(page).toHaveURL(/\/org\/users$/);
    await expect(page.getByTestId("page-title")).toHaveText("Users");
    await expect(page).toHaveTitle("Users · sekret");
  });

  test("shows nothing the public status holds back about how the server unlocks", async ({ page }) => {
    await page.goto("/?mock-state=sealed&mock-unlock=remember");
    await expect(page.getByTestId("unlock-card")).toBeVisible();
    await expect(page.getByTestId("unlock-card")).not.toContainText(/remember|policy/i);
    expect(await publicStatus(page)).toMatchObject({
      state: "sealed",
      seal_mode: null,
      unlock_policy: null,
      remembered: false,
      unsealed_by: null,
    });
  });

  test("counts down after too many wrong passphrases and keeps the button disabled", async ({ page }) => {
    await page.goto("/?mock-state=sealed");
    for (let i = 0; i < 5; i += 1) {
      await unlock(page, `wrong ${i}`);
      await expect(page.getByTestId("unlock-wrong")).toBeVisible();
    }
    await unlock(page, PASSPHRASE);
    await expect(page.getByTestId("unlock-backoff")).toContainText(
      "Too many wrong passphrasesWait a few seconds, then try again.",
    );
    await expect(page.getByTestId("unlock-countdown")).toHaveText(/^[1-3]$/);
    // The alert's accessible text stays fixed while the number ticks.
    await expect(page.getByTestId("unlock-countdown-text")).toHaveAttribute("aria-hidden", "true");
    await expect(page.getByTestId("unlock-submit")).toBeDisabled();
    const over = page.getByTestId("unlock-backoff-over");
    await expect(over).toContainText("You can try again now.", { timeout: 6_000 });
    await expect(over).toHaveAttribute("role", "status");
    await expect(page.getByTestId("unlock-backoff")).toHaveCount(0);
    await expect(page.getByTestId("unlock-submit")).toBeEnabled();
    await page.getByTestId("unlock-submit").click();
    await expect(page).toHaveURL(/\/projects$/);
  });

  test("explains the lock to anyone and lets them sign out instead", async ({ page }) => {
    await page.goto("/?mock-state=sealed");
    await expect(page.getByTestId("unlock-description")).toHaveText(
      "The server is locked, so secrets cannot be read. Someone with the server passphrase needs to unlock it.",
    );
    await page.getByTestId("unlock-sign-out").click();
    // Signed out, the login page still sits behind the locked server.
    await expect(page).toHaveURL(/\/unlock/);
    await expect(page.getByTestId("unlock-card")).toBeVisible();
    await unlock(page, PASSPHRASE);
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByTestId("sign-in")).toBeVisible();
    await page.goto("/projects");
    await expect(page).toHaveURL(/\/login\?return_to=%2Fprojects/);
  });

  test("asks to wait while another unlock is running", async ({ page }) => {
    await page.goto("/?mock-state=sealed");
    await unlock(page, KDF_BUSY);
    await expect(page.getByTestId("unlock-busy")).toContainText("Another unlock is in progress. Try again in a moment.");
    await expect(page.getByTestId("unlock-submit")).toBeEnabled();
  });

  test("explains a key the server does not recognise after the database was replaced", async ({ page }) => {
    await page.goto("/?mock-state=sealed");
    await unlock(page, "mock restored database");
    const alert = page.getByTestId("unlock-key-not-recognised");
    await expect(alert).toContainText("This passphrase opened a key this server does not recognise");
    await expect(alert).toContainText("sekret admin reset-epoch");
    await expect(page.getByTestId("unlock-card")).toBeVisible();
  });

  test("moves an open tab to the unlock page when the server is sealed mid-session, forgetting revealed values", async ({
    page,
  }) => {
    await openProject(page);
    const row = secretRow(page, "LOG_LEVEL");
    await row.getByTestId("secret-reveal").click();
    await expect(row.getByTestId("secret-value")).toHaveText("warn");

    await sealBehindTheScenes(page);
    await page.getByTestId("env-tab-staging").click();
    await expect(page).toHaveURL(/\/unlock\?return_to=%2Fprojects%2Fstorefront%2Fsecrets%2Fstaging/);
    await unlock(page, PASSPHRASE);
    await expect(page).toHaveURL(/\/projects\/storefront\/secrets\/staging/);
    // Reveals normally survive switching environments; the lock cleared them.
    await page.getByTestId("env-tab-dev").click();
    await expect(secretRow(page, "LOG_LEVEL")).toBeVisible();
    await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).not.toHaveText("warn");
  });

  test("notices a lock while values are revealed without any click", async ({ page }) => {
    await page.clock.install();
    await openProject(page);
    await secretRow(page, "LOG_LEVEL").getByTestId("secret-reveal").click();
    await expect(secretRow(page, "LOG_LEVEL").getByTestId("secret-value")).toHaveText("warn");
    await sealBehindTheScenes(page);
    await page.clock.fastForward(16_000);
    await expect(page).toHaveURL(/\/unlock\?return_to=/);
  });
});

test.describe("server page", () => {
  test("locks the server after confirming", async ({ page }) => {
    await page.goto("/projects");
    await navigate(page, "nav-server");
    await expect(page).toHaveTitle("Server · sekret");
    await expect(page.getByTestId("server-state")).toHaveText("Unlocked");
    await expect(page.getByTestId("server-mode")).toHaveText("Passphrase");
    await expect(page.getByTestId("server-status")).toContainText("Protected by");
    await expect(page.getByTestId("server-unsealed-by")).toHaveText("Passphrase, typed by a person");
    await expect(page.getByTestId("server-version")).toHaveText("0.0.0-mock");
    await expect(page.getByTestId("server-status")).toContainText("Lock (seal) the server");
    await expect(page.getByTestId("lock-help")).toContainText("Locking drops the key from memory straight away.");
    await expect(page.getByTestId("server-key-file-override")).toHaveCount(0);

    await page.getByTestId("seal-now").click();
    const dialog = page.getByTestId("seal-dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("Lock the server now?");
    // Nothing is remembered, so the dialog does not say a restart unlocks it.
    await expect(dialog).not.toContainText("remembered unlock");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();

    await page.getByTestId("seal-now").click();
    await dialog.getByTestId("confirm-action").click();
    await expect(page).toHaveURL(/\/unlock\?return_to=%2Forg%2Fserver$/);
    await unlock(page, PASSPHRASE);
    await expect(page.getByTestId("server-state")).toHaveText("Unlocked");
  });

  test("warns when a key file unlocked a passphrase server", async ({ page }) => {
    await page.goto("/org/server?mock-unsealed-by=key-file");
    await expect(page.getByTestId("server-unsealed-by")).toHaveText("Root key file");
    await expect(page.getByTestId("server-key-file-override")).toContainText("A key file unlocked this server");
  });

  test("changes the passphrase", async ({ page }) => {
    await page.goto("/org/server");
    const card = page.getByTestId("server-passphrase");
    const confirmChange = page.getByTestId("change-passphrase-dialog");
    await expect(card.getByTestId("change-passphrase-help").locator("p").first()).toHaveText(
      "Every secret is re-encrypted. Backups made before this still need the old passphrase.",
    );
    await expect(card.getByTestId("change-passphrase-help")).toContainText("A remembered unlock is forgotten");
    await expect(card.getByTestId("change-blocker")).toHaveText("Enter the current passphrase to continue.");
    await card.getByTestId("current-passphrase").fill("not it");
    await card.getByTestId("change-passphrase").fill("password1234");
    await card.getByTestId("change-confirm").fill("password1234");
    await expect(card.getByTestId("change-meter-feedback")).toContainText("commonly used password");
    await expect(card.getByTestId("change-submit")).toBeDisabled();

    await card.getByTestId("change-passphrase").fill(STRONG);
    await card.getByTestId("change-confirm").fill(STRONG);
    await card.getByTestId("change-submit").click();
    await expect(confirmChange).toContainText("Change the passphrase now?");
    await confirmChange.getByRole("button", { name: "Cancel" }).click();
    await expect(confirmChange).toBeHidden();
    await expect(card.getByTestId("current-passphrase-wrong")).toHaveCount(0);

    await card.getByTestId("change-submit").click();
    await confirmChange.getByTestId("confirm-action").click();
    await expect(card.getByTestId("current-passphrase-wrong")).toBeVisible();
    await expect(card.getByTestId("current-passphrase")).toHaveAttribute("aria-describedby", "current-passphrase-error");

    await card.getByTestId("current-passphrase").fill(PASSPHRASE);
    await card.getByTestId("change-submit").click();
    await confirmChange.getByTestId("confirm-action").click();
    await expectToast(page, "Passphrase changed");
    await expect(card.getByTestId("current-passphrase")).toHaveValue("");

    await page.getByTestId("seal-now").click();
    await page.getByTestId("seal-dialog").getByTestId("confirm-action").click();
    await unlock(page, PASSPHRASE);
    await expect(page.getByTestId("unlock-wrong")).toBeVisible();
    await unlock(page, STRONG);
    await expect(page).toHaveURL(/\/org\/server$/);
  });

  test("says a change went through but the host needs a repair when the seal mark is stale", async ({ page }) => {
    await page.goto("/org/server");
    const card = page.getByTestId("server-passphrase");
    await card.getByTestId("current-passphrase").fill(PASSPHRASE);
    await card.getByTestId("change-passphrase").fill(STALE_MARK);
    await card.getByTestId("change-confirm").fill(STALE_MARK);
    await card.getByTestId("change-submit").click();
    await page.getByTestId("change-passphrase-dialog").getByTestId("confirm-action").click();

    const changed = card.getByTestId("change-mark-stale");
    await expect(changed).toContainText("The new passphrase was saved, but the host needs a repair");
    await expect(changed).toContainText("sekret admin reset-epoch");
    await expect(card.getByTestId("change-error")).toHaveCount(0);
    await expect(card.getByTestId("current-passphrase")).toHaveValue("");

    // The unlock policy change is saved too, and the dialog closes rather than offering a retry.
    await page.getByTestId("server-policy-card-remember").click();
    await page.getByTestId("policy-save").click();
    const dialog = page.getByTestId("policy-dialog");
    await dialog.getByTestId("policy-passphrase").fill(STALE_MARK);
    await dialog.getByTestId("confirm-action").click();
    await expect(dialog).toBeHidden();
    await expect(page.getByTestId("policy-mark-stale")).toContainText("The unlock policy was saved");
    await expect(page.getByTestId("server-policy")).toHaveText(/Remember/);

    // The passphrase really changed.
    await page.getByTestId("seal-now").click();
    await page.getByTestId("seal-dialog").getByTestId("confirm-action").click();
    await unlock(page, STALE_MARK);
    await expect(page).toHaveURL(/\/org\/server$/);
  });

  test("disables Remember on the server page when no remember file is configured", async ({ page }) => {
    await page.goto("/org/server?mock-remember-file=false");
    await expect(page.getByTestId("server-policy-remember")).toBeDisabled();
    await expect(page.getByTestId("server-policy-unavailable")).toBeVisible();
    await expect(page.getByTestId("server-policy-passphrase-file")).toBeEnabled();
  });

  test("confirms a weaker policy with the passphrase, and forgets a remembered unlock only after confirming", async ({
    page,
  }) => {
    await page.goto("/org/server");
    await expect(page.getByTestId("server-policy-manual")).toHaveAttribute("data-state", "checked");
    await expect(page.getByTestId("policy-save")).toBeDisabled();
    await expect(page.getByTestId("policy-save-hint")).toHaveText("Choose a different policy to save.");
    await expect(page.getByTestId("forget-unlock")).toHaveCount(0);

    await page.getByTestId("server-policy-card-remember").click();
    // The note sits inside the chosen card, not below all of them.
    await expect(page.getByTestId("server-policy-card-remember").getByTestId("server-policy-needs")).toContainText(
      "seal.remember_file",
    );
    await expect(page.getByTestId("server-policy-needs")).toHaveCount(1);
    await expect(page.getByTestId("server-policy-card-remember")).toContainText(
      "unless the key file is also protected with a separate secret (see the docs)",
    );
    await page.getByTestId("policy-save").click();
    const dialog = page.getByTestId("policy-dialog");
    await expect(dialog).toContainText("Confirm with the current passphrase. This lets the server unlock without a person.");
    await dialog.getByTestId("confirm-action").click();
    await expect(dialog.getByTestId("policy-passphrase-error")).toHaveText("Enter the current passphrase.");
    await dialog.getByTestId("policy-passphrase").fill("not it");
    await dialog.getByTestId("confirm-action").click();
    await expect(dialog.getByTestId("policy-passphrase-error")).toHaveText("That passphrase is wrong.");
    await expect(page.getByTestId("server-policy")).toHaveText("Manual");

    // Enter in the passphrase field confirms, beside the hidden username field.
    await dialog.getByTestId("policy-passphrase").fill(PASSPHRASE);
    await dialog.getByTestId("policy-passphrase").press("Enter");
    await expect(dialog).toBeHidden();
    await expectToast(page, "Unlock policy saved");
    await expect(page.getByTestId("server-policy")).toHaveText("Remember");
    await expect(page.getByTestId("server-remembered")).toContainText("yes");
    await expect(page.getByTestId("server-remembered-box")).toContainText("Locking the server does not forget this.");
    await expect(page.getByTestId("server-remembered")).toHaveCount(1);

    await page.getByTestId("forget-unlock").click();
    const forget = page.getByTestId("forget-dialog");
    await expect(forget).toContainText("Forget the remembered unlock?");
    await expect(forget).toContainText("The key file is deleted.");
    await forget.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByTestId("server-remembered")).toContainText("yes");

    await page.getByTestId("forget-unlock").click();
    await forget.getByTestId("confirm-action").click();
    await expectToast(page, "Remembered unlock forgotten");
    await expect(page.getByTestId("server-remembered")).toHaveText("Remembered: no");
    await expect(page.getByTestId("forget-unlock")).toHaveCount(0);

    // Going back to manual needs no passphrase.
    await page.getByTestId("server-policy-card-manual").click();
    await page.getByTestId("policy-save").click();
    await expect(page.getByTestId("policy-dialog")).toHaveCount(0);
    await expect(page.getByTestId("server-policy")).toHaveText("Manual");
  });

  test("keeps a remembered unlock through locking", async ({ page }) => {
    await page.goto("/org/server");
    await page.getByTestId("server-policy-card-remember").click();
    await page.getByTestId("policy-save").click();
    await page.getByTestId("policy-passphrase").fill(PASSPHRASE);
    await page.getByTestId("policy-dialog").getByTestId("confirm-action").click();
    await expect(page.getByTestId("server-remembered")).toContainText("yes");

    await page.getByTestId("seal-now").click();
    await expect(page.getByTestId("seal-dialog")).toContainText("A remembered unlock still unlocks it after a restart.");
    await page.getByTestId("seal-dialog").getByTestId("confirm-action").click();
    await expect(page.getByTestId("unlock-card")).toBeVisible();
    await unlock(page, PASSPHRASE);
    await expect(page.getByTestId("server-remembered")).toContainText("yes");
  });

  test("shows a configured policy read-only", async ({ page }) => {
    await page.goto("/org/server?mock-unlock=passphrase-file");
    await expect(page.getByTestId("server-policy")).toContainText("Passphrase file (set in configuration)");
    await expect(page.getByTestId("server-policy-configured")).toContainText("cannot be changed here");
    await expect(page.getByTestId("server-policy-configured-needs")).toContainText("SEKRET_UNLOCK_PASSPHRASE");
    await expect(page.getByTestId("policy-save")).toHaveCount(0);
  });

  test("downloads an encrypted backup with POST and the CSRF header", async ({ page }) => {
    await page.goto("/org/server");
    await expect(page.getByTestId("server-backup")).toContainText("needs the passphrase");
    const download = page.waitForEvent("download");
    await page.getByTestId("backup-download").click();
    expect((await download).suggestedFilename()).toMatch(/^sekret-backup-\d{8}T\d{6}Z\.skb$/);

    expect(await backupStatuses(page)).toEqual([405, 403, 200]);
  });

  test("is hidden from people who are not admins", async ({ page }) => {
    await page.goto("/projects?mock-org-role=org-member");
    if (isMobile(page)) await page.getByTestId("sidebar-trigger").click();
    await expect(page.getByTestId("nav-projects")).toBeVisible();
    await expect(page.getByTestId("nav-server")).toHaveCount(0);

    await page.goto("/org/server");
    await expect(page.getByTestId("error-state")).toContainText("Only organisation admins and backup readers");
    await expect(page.getByTestId("page-title")).toHaveText("Server");
    await expect(page.getByText("download encrypted backups")).toHaveCount(0);
    const width = await page.getByTestId("error-state").evaluate((el) => el.parentElement?.getBoundingClientRect().width ?? 0);
    expect(width).toBeLessThanOrEqual(768);
    await expect(page.getByTestId("seal-now")).toHaveCount(0);
  });

  test("offers backup readers only the download, with a fitting description", async ({ page }) => {
    await page.goto("/org/server?mock-org-role=backup-reader");
    await expect(page.getByTestId("backup-download")).toBeVisible();
    await expect(page.getByText("See whether this sekret server is unlocked and download encrypted backups.")).toBeVisible();
    await expect(page.getByTestId("seal-now")).toHaveCount(0);
    await expect(page.getByTestId("server-passphrase")).toHaveCount(0);
    await expect(page.getByTestId("server-unlock-policy")).toHaveCount(0);
    // Only the public status: how it was unlocked and how it is protected stay with admins.
    await expect(page.getByTestId("server-state")).toHaveText("Unlocked");
    await expect(page.getByTestId("server-status-help")).toHaveText("Whether the server is unlocked.");
    await expect(page.getByTestId("server-unsealed-by")).toHaveCount(0);
    await expect(page.getByTestId("server-mode")).toHaveCount(0);
    await expect(page.getByTestId("server-backup")).toContainText("the passphrase or root key file");
  });

  test("reads how the server was unlocked from the admin detail", async ({ page }) => {
    await page.goto("/org/server?mock-unsealed-by=remember");
    await expect(page.getByTestId("server-unsealed-by")).toHaveText("Remembered unlock");
    await expect(page.getByTestId("server-mode")).toHaveText("Passphrase");
    const status = (await publicStatus(page)) as { unsealed_by: unknown };
    expect(status.unsealed_by).toBeNull();
  });
});

test("the documentation link says it opens a new tab", async ({ page }) => {
  await page.goto("/projects");
  if (isMobile(page)) await page.getByTestId("sidebar-trigger").click();
  const link = page.getByTestId("nav-docs");
  await expect(link).toHaveAttribute("target", "_blank");
  await expect(link.getByTestId("nav-docs-external")).toBeVisible();
  await expect(link).toContainText("(opens in a new tab)");
});
