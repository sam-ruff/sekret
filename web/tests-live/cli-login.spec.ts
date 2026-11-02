import { expect, test, type APIRequestContext, type APIResponse, type Page } from "@playwright/test";

interface CliStart {
  device_code: string;
  user_code: string;
  verification_url: string;
}

/** The live server is shared by every test, so sign-ins elsewhere can use up this address's allowance. */
const RATE_LIMIT_DEADLINE_MS = 45_000;

/**
 * Sends a request, waiting and trying again while the server answers 429. Waits as long as
 * `Retry-After` says, or a few seconds when it says nothing, since the allowance refills steadily.
 */
async function withinRateLimit(send: () => Promise<APIResponse>): Promise<APIResponse> {
  const deadline = Date.now() + RATE_LIMIT_DEADLINE_MS;
  for (;;) {
    const response = await send();
    if (response.status() !== 429 || Date.now() > deadline) return response;
    const seconds = Number(response.headers()["retry-after"]);
    await new Promise((resolve) => setTimeout(resolve, (Number.isFinite(seconds) && seconds > 0 ? seconds : 3) * 1000));
  }
}

/** Starts a CLI login the way `sekret login` does, without a session. */
async function startCliLogin(request: APIRequestContext): Promise<CliStart> {
  const response = await withinRateLimit(() =>
    request.post("/api/v1/auth/cli/start", { headers: { "user-agent": "sekret-live-test/1.0" } }),
  );
  expect(response.status()).toBe(200);
  return (await response.json()) as CliStart;
}

function pollCli(request: APIRequestContext, deviceCode: string): Promise<APIResponse> {
  return withinRateLimit(() => request.post("/api/v1/auth/cli/poll", { data: { device_code: deviceCode } }));
}

/** A well-formed code that is not `code`, for checking a mismatch without starting a second login. */
function otherCode(code: string): string {
  const first = code[0] === "B" ? "C" : "B";
  return `${first}${code.slice(1)}`;
}

function pathOf(url: string): string {
  const parsed = new URL(url);
  return `${parsed.pathname}${parsed.search}`;
}

/** Opens the approval page, pressing "Try again" while the page's own lookup is rate limited. */
async function openApproval(page: Page, url: string): Promise<void> {
  await page.goto(pathOf(url));
  const deadline = Date.now() + RATE_LIMIT_DEADLINE_MS;
  const shown = page.getByTestId("cli-request").or(page.getByTestId("cli-unknown")).or(page.getByTestId("error-state"));
  for (;;) {
    await expect(shown.first()).toBeVisible();
    const limited = page.getByTestId("error-state").filter({ hasText: /too many|slow down/i });
    if ((await limited.count()) === 0 || Date.now() > deadline) return;
    await page.waitForTimeout(3_000);
    // The page may have retried on its own while we waited.
    const retry = limited.getByRole("button", { name: "Try again" });
    if ((await retry.count()) > 0) await retry.click();
  }
}

/** Clicks a button that posts to `path`, clicking again while the server answers 429. */
async function clickWithinRateLimit(page: Page, testId: string, path: string): Promise<void> {
  const deadline = Date.now() + RATE_LIMIT_DEADLINE_MS;
  for (;;) {
    const [response] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith(path) && r.request().method() === "POST"),
      page.getByTestId(testId).click(),
    ]);
    if (response.status() !== 429 || Date.now() > deadline) return;
    const seconds = Number(response.headers()["retry-after"]);
    await page.waitForTimeout((Number.isFinite(seconds) && seconds > 0 ? seconds : 3) * 1000);
  }
}

test("shows where a CLI login came from and approves it only with the typed code", async ({ page, playwright, baseURL }) => {
  const cli = await playwright.request.newContext({ baseURL });
  const started = await startCliLogin(cli);
  expect(started.verification_url).toContain(`code=${started.user_code}`);

  await openApproval(page, started.verification_url);
  const details = page.getByTestId("cli-request");
  await expect(details.getByTestId("cli-request-ip")).toHaveText(/[0-9a-f.:]+/);
  await expect(details.getByTestId("cli-request-agent")).toHaveText("sekret-live-test/1.0");
  await expect(details.getByTestId("cli-request-age")).toHaveText("just now");
  // Near midnight the expiry falls tomorrow, so the date is shown as well.
  await expect(details.getByTestId("cli-request-expires")).toHaveText(
    /^in \d+ minutes? \((\d{1,2} \w{3} \d{4}, )?\d{2}:\d{2}\)$/,
  );
  await expect(details.getByTestId("cli-request-agent-note")).toHaveText("Reported by the requester, so it can be faked.");
  // The CLI and this browser are on the same machine, so there is no different-network warning.
  await expect(page.getByTestId("cli-other-address")).toHaveCount(0);
  // The code in the link is not shown or filled in.
  await expect(page.getByTestId("cli-login")).not.toContainText(started.user_code);
  await expect(page.getByTestId("cli-code-input")).toHaveValue("");
  await expect(page.getByTestId("cli-approve")).toBeDisabled();

  await page.getByTestId("cli-code-input").fill(started.user_code.toLowerCase());
  await clickWithinRateLimit(page, "cli-approve", "/api/v1/auth/cli/approve");
  await expect(page.getByTestId("cli-approved")).toBeVisible();

  const poll = await pollCli(cli, started.device_code);
  expect(poll.status()).toBe(200);
  const token = (await poll.json()) as { access_token: string };
  expect(token.access_token).toBeTruthy();
  await cli.dispose();
});

test("the server says whether the request came from this browser's address", async ({ page, playwright, baseURL }) => {
  const cli = await playwright.request.newContext({ baseURL });
  const started = await startCliLogin(cli);
  const pending = await withinRateLimit(() =>
    page.request.get(`/api/v1/auth/cli/pending?code=${encodeURIComponent(started.user_code)}`),
  );
  expect(pending.status()).toBe(200);
  const body = (await pending.json()) as { same_address: boolean };
  expect(body.same_address).toBe(true);
  await cli.dispose();
});

test("cancelling refuses the CLI login, so the terminal stops waiting", async ({ page, playwright, baseURL }) => {
  const cli = await playwright.request.newContext({ baseURL });
  const started = await startCliLogin(cli);
  await openApproval(page, started.verification_url);
  await expect(page.getByTestId("cli-request")).toBeVisible();
  await clickWithinRateLimit(page, "cli-cancel", "/api/v1/auth/cli/deny");
  await expect(page.getByTestId("cli-cancelled")).toContainText("the terminal that asked is told the sign-in was refused");

  const poll = await pollCli(cli, started.device_code);
  expect(poll.status()).not.toBe(200);
  expect(poll.status()).not.toBe(429);
  // Reopening the link says the request has ended.
  await openApproval(page, started.verification_url);
  await expect(page.getByTestId("cli-unknown")).toContainText("This sign-in request has ended");
  await expect(page.getByTestId("cli-code-input")).toHaveCount(0);
  await cli.dispose();
});

test("a link to someone else's CLI login cannot be approved with a different code", async ({ page, playwright, baseURL }) => {
  const cli = await playwright.request.newContext({ baseURL });
  const theirs = await startCliLogin(cli);

  await openApproval(page, theirs.verification_url);
  await expect(page.getByTestId("cli-request")).toBeVisible();
  await page.getByTestId("cli-code-input").fill(otherCode(theirs.user_code));
  await expect(page.getByTestId("cli-code-mismatch")).toBeVisible();
  await expect(page.getByTestId("cli-approve")).toBeDisabled();

  // The server itself refuses an approval without the typed code, whatever the page does.
  const bare = await page.request.post("/api/v1/auth/cli/approve", {
    headers: { "x-sekret-csrf": "1" },
    data: { user_code: theirs.user_code },
  });
  expect(bare.ok()).toBe(false);
  const poll = await pollCli(cli, theirs.device_code);
  expect(poll.status()).not.toBe(200);
  expect(poll.status()).not.toBe(429);
  await cli.dispose();
});
