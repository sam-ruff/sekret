import { expect, test, type Page } from "@playwright/test";
import { expectToast, openProject, secretRow } from "./helpers";

const DEV_DATABASE_URL = "postgres://shop:devpass@localhost:5432/shop";
const PASSPHRASE = "correct horse battery staple";

interface TestWindow {
  readClipboard: () => string;
  testFocused: boolean;
  testCanRead: boolean;
}

/**
 * A clipboard the test can read, a focus state the test controls, and a clipboard-read permission
 * that is granted only when `testCanRead` is set.
 */
async function controlledClipboard(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const w = window as unknown as TestWindow;
    let contents = "";
    w.testFocused = true;
    w.testCanRead = false;
    w.readClipboard = () => contents;
    const clipboard = {
      writeText: (text: string) => {
        contents = text;
        return Promise.resolve();
      },
      readText: () => Promise.resolve(contents),
    };
    Object.defineProperty(navigator, "clipboard", { value: clipboard, configurable: true });
    document.hasFocus = () => w.testFocused;
    const query = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = (descriptor: PermissionDescriptor) =>
      descriptor.name === ("clipboard-read" as PermissionName)
        ? Promise.resolve({ state: w.testCanRead ? "granted" : "prompt" } as PermissionStatus)
        : query(descriptor);
  });
}

const clipboardText = (page: Page) => page.evaluate(() => (window as unknown as TestWindow).readClipboard());

async function leaveTab(page: Page): Promise<void> {
  await page.evaluate(() => {
    (window as unknown as TestWindow).testFocused = false;
    window.dispatchEvent(new Event("blur"));
  });
}

async function returnToTab(page: Page, canRead: boolean): Promise<void> {
  await page.evaluate((read) => {
    const w = window as unknown as TestWindow;
    w.testCanRead = read;
    w.testFocused = true;
    window.dispatchEvent(new Event("focus"));
  }, canRead);
}

test.describe("clipboard clearing in a background tab", () => {
  test.beforeEach(async ({ page }) => {
    await controlledClipboard(page);
    await page.clock.install();
    await openProject(page);
    await secretRow(page, "DATABASE_URL").getByTestId("secret-copy").click();
    await expectToast(page, "Copied to clipboard");
    expect(await clipboardText(page)).toBe(DEV_DATABASE_URL);
  });

  test("waits for the tab to come back, then clears when it may check the clipboard", async ({ page }) => {
    await leaveTab(page);
    await page.clock.fastForward(46_000);
    expect(await clipboardText(page)).toBe(DEV_DATABASE_URL);

    await returnToTab(page, true);
    await expect.poll(() => clipboardText(page)).toBe("");
    await expect(page.locator("[data-sonner-toast]").filter({ hasText: "Clipboard not cleared" })).toHaveCount(0);
  });

  test("says so when it comes back but cannot tell whether the clipboard still holds the secret", async ({ page }) => {
    await leaveTab(page);
    await page.clock.fastForward(46_000);
    await returnToTab(page, false);
    await expectToast(page, "Clipboard not cleared; clear it yourself");
    expect(await clipboardText(page)).toBe(DEV_DATABASE_URL);
  });
});

test.describe("other tabs", () => {
  test("drop what they hold and go to sign in when one tab signs out", async ({ page, context }) => {
    await openProject(page);
    const other = await context.newPage();
    await openProject(other);
    await secretRow(other, "DATABASE_URL").getByTestId("secret-reveal").click();
    await expect(secretRow(other, "DATABASE_URL").getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);

    await page.getByTestId("user-menu").click();
    await page.getByTestId("logout").click();
    await expect(page).toHaveURL(/\/login/);
    await expect(other).toHaveURL(/\/login\?return_to=%2Fprojects%2Fstorefront%2Fsecrets%2Fdev/);
    await expect(other.locator("body")).not.toContainText(DEV_DATABASE_URL);
  });

  test("lock at once when one tab seals the server", async ({ page, context }) => {
    await page.goto("/org/server");
    await expect(page.getByTestId("seal-now")).toBeVisible();
    const other = await context.newPage();
    await openProject(other);
    await secretRow(other, "DATABASE_URL").getByTestId("secret-reveal").click();
    await expect(secretRow(other, "DATABASE_URL").getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);
    // Each mock tab keeps its own fake server, so this one is sealed quietly, as the shared real one would be.
    await other.evaluate(async () => {
      const path = "/src/api/mock/server.ts";
      const mock = (await import(/* @vite-ignore */ path)) as { mockSealServer: () => void };
      mock.mockSealServer();
    });

    await page.getByTestId("seal-now").click();
    await page.getByTestId("seal-dialog").getByTestId("confirm-action").click();
    await expect(page).toHaveURL(/\/unlock/);
    // Well before the other tab's own 15 second check would notice.
    await expect(other).toHaveURL(/\/unlock/, { timeout: 5_000 });
    await expect(other.locator("body")).not.toContainText(DEV_DATABASE_URL);
    await other.getByTestId("unlock-passphrase").fill(PASSPHRASE);
    await other.getByTestId("unlock-submit").click();
    await expect(secretRow(other, "DATABASE_URL").getByTestId("secret-value")).not.toContainText(DEV_DATABASE_URL);
  });
});

test.describe("signing out", () => {
  test("continues to the identity provider's logout once, with nothing in between", async ({ page }) => {
    const IDP = "https://idp.example.test/logout";
    await page.route(`${IDP}**`, (route) =>
      route.fulfill({ contentType: "text/html", body: "<title>Signed out</title><p id=idp>Signed out of the provider</p>" }),
    );
    await controlledClipboard(page);
    await page.goto("/projects?mock-idp-logout=1");
    await openProject(page);
    await secretRow(page, "DATABASE_URL").getByTestId("secret-copy").click();
    await expectToast(page, "Copied to clipboard");
    expect(await clipboardText(page)).toBe(DEV_DATABASE_URL);

    const visited: string[] = [];
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) visited.push(frame.url());
    });
    await page.getByTestId("user-menu").click();
    await page.getByTestId("logout").click();
    await expect(page.locator("#idp")).toHaveText("Signed out of the provider");
    expect(visited).toEqual([IDP]);
  });

  test("clears a copied secret before leaving", async ({ page }) => {
    await controlledClipboard(page);
    await openProject(page);
    await secretRow(page, "DATABASE_URL").getByTestId("secret-copy").click();
    await expectToast(page, "Copied to clipboard");
    // Read the clipboard from inside the page just before it goes.
    await page.evaluate(() => {
      window.addEventListener("pagehide", () => {
        sessionStorage.setItem("clipboard-at-exit", (window as unknown as TestWindow).readClipboard());
      });
    });
    await page.getByTestId("user-menu").click();
    await page.getByTestId("logout").click();
    await expect(page).toHaveURL(/\/login/);
    expect(await page.evaluate(() => sessionStorage.getItem("clipboard-at-exit"))).toBe("");
  });
});

test.describe("revealed values", () => {
  test("hide themselves after three idle minutes", async ({ page }) => {
    await page.clock.install();
    await openProject(page);
    const row = secretRow(page, "DATABASE_URL");
    await row.getByTestId("secret-reveal").click();
    await expect(row.getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);
    await page.clock.fastForward(170_000);
    await expect(row.getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);
    await page.clock.fastForward(11_000);
    await expect(row.getByTestId("secret-value")).not.toContainText(DEV_DATABASE_URL);
    await expect(page.locator("body")).not.toContainText(DEV_DATABASE_URL);
  });

  test("go when the session ends while they are shown", async ({ page }) => {
    await page.clock.install();
    await openProject(page);
    const row = secretRow(page, "DATABASE_URL");
    await row.getByTestId("secret-reveal").click();
    await expect(row.getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);
    // The session ends elsewhere; nothing on the page is clicked.
    await page.evaluate(async () => {
      const path = "/src/api/mock/server.ts";
      const mock = (await import(/* @vite-ignore */ path)) as { mockFetch: (r: Request) => Promise<Response> };
      await mock.mockFetch(new Request(`${location.origin}/auth/logout`, { method: "POST", headers: { "x-sekret-csrf": "1" } }));
    });
    await page.clock.fastForward(16_000);
    await expect(page).toHaveURL(/\/login\?return_to=/);
    await expect(page.locator("body")).not.toContainText(DEV_DATABASE_URL);
  });

  test("are dropped before the browser stores the page away", async ({ page }) => {
    await openProject(page);
    const row = secretRow(page, "DATABASE_URL");
    await row.getByTestId("secret-reveal").click();
    await expect(row.getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);
    const html = await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
      // Read in the same task, as the browser would snapshot it.
      return document.body.innerHTML;
    });
    expect(html).not.toContain(DEV_DATABASE_URL);
    expect(html).toContain("status-gate-loading");
  });

  test("are dropped when another tab signs in as someone else", async ({ page }) => {
    await openProject(page);
    const row = secretRow(page, "DATABASE_URL");
    await row.getByTestId("secret-reveal").click();
    await expect(row.getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);

    const signInElsewhere = (user: string) =>
      page.evaluate((id) => {
        const channel = new BroadcastChannel("sekret-tabs");
        channel.postMessage({ kind: "signed-in", user: id });
        channel.close();
      }, user);

    // The same person signing in elsewhere changes nothing here.
    const myId = await page.evaluate(async () => {
      const path = "/src/api/mock/server.ts";
      const mock = (await import(/* @vite-ignore */ path)) as { mockFetch: (r: Request) => Promise<Response> };
      const me = (await (await mock.mockFetch(new Request(`${location.origin}/api/v1/me`))).json()) as { id: string };
      return me.id;
    });
    await signInElsewhere(myId);
    await page.waitForTimeout(300);
    await expect(row.getByTestId("secret-value")).toHaveText(DEV_DATABASE_URL);

    const reloaded = page.waitForEvent("load");
    await signInElsewhere("someone-else-entirely");
    await reloaded;
    await expect(secretRow(page, "DATABASE_URL")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(DEV_DATABASE_URL);
  });
});

test("a page restored from the back-forward cache reloads", async ({ page }) => {
  await page.goto("/projects");
  await expect(page.getByTestId("project-card-storefront")).toBeVisible();
  await page.evaluate(() => {
    (window as unknown as { beforeRestore: boolean }).beforeRestore = true;
  });
  const reloaded = page.waitForEvent("load");
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })));
  await reloaded;
  expect(await page.evaluate(() => (window as unknown as { beforeRestore?: boolean }).beforeRestore)).toBeUndefined();
});