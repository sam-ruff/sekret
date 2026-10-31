import { expect, test, type Page } from "@playwright/test";

/** What every pending login in the fake says about where it came from. */
const MOCK_ADDRESS = "203.0.113.24";
const MOCK_AGENT = "sekret/0.0.0-mock (linux; x86_64)";

async function typeCode(page: Page, code: string): Promise<void> {
  await page.getByTestId("cli-code-input").fill(code);
}

test("shows where the request came from and approves only after the code is typed", async ({ page }) => {
  await page.goto("/cli-login?code=BCDF-2345");
  await expect(page.getByTestId("cli-warning")).toContainText("Only approve a sign-in you started");
  await expect(page.getByTestId("cli-warning")).toContainText("Someone who sends you this link gets access as you");
  const request = page.getByTestId("cli-request");
  await expect(request.getByTestId("cli-request-ip")).toHaveText(MOCK_ADDRESS);
  await expect(request.getByTestId("cli-request-agent")).toHaveText(MOCK_AGENT);
  await expect(request.getByTestId("cli-request-age")).toHaveText("1 minute ago");
  await expect(request.getByTestId("cli-request-expires")).not.toBeEmpty();

  // The link's code is not shown or filled in: the person has to read it off their own terminal.
  await expect(page.getByTestId("cli-login")).not.toContainText("BCDF-2345");
  await expect(page.getByTestId("cli-code-input")).toHaveValue("");
  await expect(page.getByTestId("cli-approve")).toBeDisabled();

  await typeCode(page, "bcdf 2345");
  await expect(page.getByTestId("cli-approve")).toBeEnabled();
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
  await expect(page.getByTestId("cli-request")).toHaveCount(0);
});

test("a phishing link cannot be approved with a code that is not the link's", async ({ page }) => {
  await page.goto("/cli-login?code=BCDF-2345");
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
  await typeCode(page, "BCDF-2345");
  await expect(page.getByTestId("cli-request-ip")).toHaveText(MOCK_ADDRESS);
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
});

test("sends the browser to sign in again when the server asks, then approves on return", async ({ page }) => {
  await page.goto("/cli-login?code=AUTH-2345");
  await expect(page).toHaveTitle("Approve CLI sign-in · sekret");
  await typeCode(page, "AUTH-2345");
  // The mock signs in again at once and loads the same page with the code again.
  const reloaded = page.waitForEvent("load");
  await page.getByTestId("cli-approve").click();
  await reloaded;
  await expect(page).toHaveURL(/\/cli-login\?code=AUTH-2345$/);
  await expect(page.locator("[data-sonner-toast]")).toHaveCount(0);
  // The typed code is asked for again after the round trip.
  await expect(page.getByTestId("cli-code-input")).toHaveValue("");
  await typeCode(page, "AUTH-2345");
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();
});

test("cancelling approves nothing", async ({ page }) => {
  await page.goto("/cli-login?code=BCDF-2345");
  await typeCode(page, "BCDF-2345");
  await page.getByTestId("cli-cancel").click();
  await expect(page.getByTestId("cli-cancelled")).toBeVisible();
  await expect(page.getByTestId("cli-approve")).toHaveCount(0);
});

test("an unknown or expired code says so and offers nothing to approve", async ({ page }) => {
  await page.goto("/cli-login?code=XXXX-0000");
  await expect(page.getByTestId("cli-unknown")).toContainText("No sign-in waiting for this code");
  await typeCode(page, "XXXX-0000");
  await expect(page.getByTestId("cli-approve")).toBeDisabled();
});

test("the code field is kept away from spellcheck and autocomplete", async ({ page }) => {
  await page.goto("/cli-login?code=BCDF-2345");
  const input = page.getByTestId("cli-code-input");
  await expect(input).toHaveAttribute("autocomplete", "off");
  await expect(input).toHaveAttribute("spellcheck", "false");
});
