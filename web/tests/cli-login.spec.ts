import { expect, test, type Page } from "@playwright/test";

/** What every pending login in the fake says about where it came from. */
const MOCK_ADDRESS = "203.0.113.24";
const MOCK_AGENT = "sekret/0.0.0-mock (linux; x86_64)";
/** The fake says codes starting `SAME` came from this browser's own address, and any other from elsewhere. */
const SAME = "SAME-2345";
const ELSEWHERE = "BCDF-2345";

async function typeCode(page: Page, code: string): Promise<void> {
  await page.getByTestId("cli-code-input").fill(code);
}

/** Every request the fake answered in this page. */
async function requests(page: Page): Promise<string[]> {
  return page.evaluate(async () => {
    const path = "/src/api/mock/server.ts";
    const mock = (await import(/* @vite-ignore */ path)) as { mockRequestLog: () => string[] };
    return mock.mockRequestLog();
  });
}

test("shows where the request came from and approves only after the code is typed", async ({ page }) => {
  await page.goto(`/cli-login?code=${SAME}`);
  await expect(page.getByTestId("cli-warning")).toContainText("Only approve a sign-in you started");
  await expect(page.getByTestId("cli-warning")).toContainText("Someone who sends you this link gets access as you");
  const request = page.getByTestId("cli-request");
  await expect(request.getByTestId("cli-request-ip")).toHaveText(MOCK_ADDRESS);
  await expect(request.getByTestId("cli-request-agent")).toHaveText(MOCK_AGENT);
  await expect(request).toContainText("Program (reported by the requester, can be faked)");
  await expect(request.getByTestId("cli-request-age")).toHaveText("1 minute ago");
  await expect(request.getByTestId("cli-request-expires")).toHaveText(/^in 9 minutes \(\d{2}:\d{2}\)$/);
  // Same network, so no extra check is asked for.
  await expect(page.getByTestId("cli-other-address")).toHaveCount(0);

  // The link's code is not shown or filled in: the person has to read it off their own terminal.
  await expect(page.getByTestId("cli-login")).not.toContainText(SAME);
  await expect(page.getByTestId("cli-code-input")).toHaveValue("");
  await expect(page.getByTestId("cli-approve")).toBeDisabled();

  await typeCode(page, "same 2345");
  await expect(page.getByTestId("cli-approve")).toBeEnabled();
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
  await expect(page.getByTestId("cli-request")).toHaveCount(0);
});

test("a request from another network needs a strong warning and an extra tick", async ({ page }) => {
  await page.goto(`/cli-login?code=${ELSEWHERE}`);
  const warning = page.getByTestId("cli-other-address");
  await expect(warning).toContainText("This sign-in came from a different network");
  await typeCode(page, ELSEWHERE);
  await expect(page.getByTestId("cli-approve")).toBeDisabled();
  await page.getByTestId("cli-code-input").press("Enter");
  await expect(page.getByTestId("cli-approved")).toHaveCount(0);

  await warning.getByText("I started this sign-in myself on that machine").click();
  await expect(page.getByTestId("cli-confirm-own")).toHaveAttribute("data-state", "checked");
  await expect(page.getByTestId("cli-approve")).toBeEnabled();
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
});

test("a phishing link cannot be approved with a code that is not the link's", async ({ page }) => {
  await page.goto(`/cli-login?code=${SAME}`);
  await expect(page.getByTestId("cli-request")).toBeVisible();
  await typeCode(page, "GHJK-6789");
  await expect(page.getByTestId("cli-code-mismatch")).toContainText("That is not the code for this request");
  await expect(page.getByTestId("cli-code-input")).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByTestId("cli-approve")).toBeDisabled();
  await page.getByTestId("cli-code-input").press("Enter");
  await expect(page.getByTestId("cli-approved")).toHaveCount(0);
});

test("without a code in the link, typing one looks the request up", async ({ page }) => {
  await page.goto("/cli-login");
  await expect(page.getByTestId("cli-request")).toHaveCount(0);
  await expect(page.getByTestId("cli-approve")).toBeDisabled();
  // Nothing is shown below yet, so the warning does not point at it.
  await expect(page.getByTestId("cli-warning-text")).toContainText("check the address and program that appear");
  await expect(page.getByTestId("cli-warning-text")).not.toContainText("below");
  await typeCode(page, SAME);
  await expect(page.getByTestId("cli-warning-text")).toContainText("below are yours");
  await expect(page.getByTestId("cli-request-ip")).toHaveText(MOCK_ADDRESS);
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
});

test("sends the browser to sign in again when the server asks, then asks for the code once more", async ({ page }) => {
  await page.goto("/cli-login?code=AUTH-2345");
  await expect(page).toHaveTitle("Approve CLI sign-in · sekret");
  await expect(page.getByTestId("cli-signed-in-again")).toHaveCount(0);
  await typeCode(page, "AUTH-2345");
  await page.getByTestId("cli-confirm-own").click();
  // The mock signs in again at once and loads the same page with the code again.
  const reloaded = page.waitForEvent("load");
  await page.getByTestId("cli-approve").click();
  await reloaded;
  await expect(page).toHaveURL(/\/cli-login\?code=AUTH-2345$/);
  await expect(page.locator("[data-sonner-toast]")).toHaveCount(0);
  await expect(page.getByTestId("cli-signed-in-again")).toHaveText(
    "You are signed in again. Type the code from your terminal once more to approve.",
  );
  // The typed code is asked for again after the round trip.
  await expect(page.getByTestId("cli-code-input")).toHaveValue("");
  await typeCode(page, "AUTH-2345");
  await page.getByTestId("cli-confirm-own").click();
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
  // A later visit is not the return from signing in.
  await page.goto("/cli-login?code=AUTH-2345");
  await expect(page.getByTestId("cli-unknown")).toBeVisible();
  await expect(page.getByTestId("cli-signed-in-again")).toHaveCount(0);
});

test("cancelling refuses the request on the server", async ({ page }) => {
  await page.goto(`/cli-login?code=${SAME}`);
  await typeCode(page, SAME);
  await expect(page.getByTestId("cli-cancel")).toHaveText("Deny");
  await page.getByTestId("cli-cancel").click();
  await expect(page.getByTestId("cli-cancelled")).toContainText("Denied");
  await expect(page.getByTestId("cli-cancelled")).toContainText("the terminal that asked is told the sign-in was refused");
  await expect(page.getByTestId("cli-approve")).toHaveCount(0);
  expect(await requests(page)).toContain("POST /api/v1/auth/cli/deny");
  // The request is gone, so the same link now says it has ended.
  await page.goto(`/cli-login?code=${SAME}`);
  await expect(page.getByTestId("cli-unknown")).toBeVisible();
});

test("a request that has ended says only that, with nothing to type or approve", async ({ page }) => {
  await page.goto("/cli-login?code=XXXX-0000");
  const ended = page.getByTestId("cli-unknown");
  await expect(ended).toHaveText(
    "This sign-in request has endedIt expired, was already used or refused, or the link is wrong. Run sekret login again to get a new link.",
  );
  await page.getByTestId("cli-go-home").click();
  await expect(page).not.toHaveURL(/cli-login/);
  await expect(page.getByTestId("cli-code-input")).toHaveCount(0);
  await expect(page.getByTestId("cli-approve")).toHaveCount(0);
  await expect(page.getByTestId("cli-warning")).toHaveCount(0);
});

test("the code field is kept away from spellcheck, autocomplete and password managers", async ({ page }) => {
  await page.goto(`/cli-login?code=${SAME}`);
  const input = page.getByTestId("cli-code-input");
  await expect(input).toHaveAttribute("autocomplete", "off");
  await expect(input).toHaveAttribute("spellcheck", "false");
  await expect(input).toHaveAttribute("data-1p-ignore", "true");
  await expect(input).toHaveAttribute("data-bwignore", "true");
});
