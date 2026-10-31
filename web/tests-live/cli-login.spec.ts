import { expect, test, type APIRequestContext } from "@playwright/test";

interface CliStart {
  device_code: string;
  user_code: string;
  verification_url: string;
}

/** Starts a CLI login the way `sekret login` does, without a session. */
async function startCliLogin(request: APIRequestContext): Promise<CliStart> {
  const response = await request.post("/api/v1/auth/cli/start", { headers: { "user-agent": "sekret-live-test/1.0" } });
  expect(response.status()).toBe(200);
  return (await response.json()) as CliStart;
}

function pathOf(url: string): string {
  const parsed = new URL(url);
  return `${parsed.pathname}${parsed.search}`;
}

test("shows where a CLI login came from and approves it only with the typed code", async ({ page, playwright, baseURL }) => {
  const cli = await playwright.request.newContext({ baseURL });
  const started = await startCliLogin(cli);
  expect(started.verification_url).toContain(`code=${started.user_code}`);

  await page.goto(pathOf(started.verification_url));
  const details = page.getByTestId("cli-request");
  await expect(details.getByTestId("cli-request-ip")).toHaveText(/[0-9a-f.:]+/);
  await expect(details.getByTestId("cli-request-agent")).toHaveText("sekret-live-test/1.0");
  await expect(details.getByTestId("cli-request-age")).toHaveText("just now");
  await expect(details.getByTestId("cli-request-expires")).toHaveText(/^in \d+ minutes? \(\d{2}:\d{2}\)$/);
  await expect(details).toContainText("Program (reported by the requester, can be faked)");
  // The CLI and this browser are on the same machine, so there is no different-network warning.
  await expect(page.getByTestId("cli-other-address")).toHaveCount(0);
  // The code in the link is not shown or filled in.
  await expect(page.getByTestId("cli-login")).not.toContainText(started.user_code);
  await expect(page.getByTestId("cli-code-input")).toHaveValue("");
  await expect(page.getByTestId("cli-approve")).toBeDisabled();

  await page.getByTestId("cli-code-input").fill(started.user_code.toLowerCase());
  await page.getByTestId("cli-approve").click();
  await expect(page.getByTestId("cli-approved")).toBeVisible();

  const poll = await cli.post("/api/v1/auth/cli/poll", { data: { device_code: started.device_code } });
  expect(poll.status()).toBe(200);
  const token = (await poll.json()) as { access_token: string };
  expect(token.access_token).toBeTruthy();
  await cli.dispose();
});

test("the server says whether the request came from this browser's address", async ({ page, playwright, baseURL }) => {
  const cli = await playwright.request.newContext({ baseURL });
  const started = await startCliLogin(cli);
  const pending = await page.request.get(`/api/v1/auth/cli/pending?code=${encodeURIComponent(started.user_code)}`);
  expect(pending.status()).toBe(200);
  const body = (await pending.json()) as { same_address: boolean };
  expect(body.same_address).toBe(true);
  await cli.dispose();
});

test("cancelling refuses the CLI login, so the terminal stops waiting", async ({ page, playwright, baseURL }) => {
  const cli = await playwright.request.newContext({ baseURL });
  const started = await startCliLogin(cli);
  await page.goto(pathOf(started.verification_url));
  await expect(page.getByTestId("cli-request")).toBeVisible();
  await page.getByTestId("cli-cancel").click();
  await expect(page.getByTestId("cli-cancelled")).toContainText("the terminal that asked is told the sign-in was refused");

  const poll = await cli.post("/api/v1/auth/cli/poll", { data: { device_code: started.device_code } });
  expect(poll.status()).not.toBe(200);
  // Reopening the link says the request has ended.
  await page.goto(pathOf(started.verification_url));
  await expect(page.getByTestId("cli-unknown")).toContainText("This sign-in request has ended");
  await expect(page.getByTestId("cli-code-input")).toHaveCount(0);
  await cli.dispose();
});

test("a link to someone else's CLI login cannot be approved with a different code", async ({ page, playwright, baseURL }) => {
  const cli = await playwright.request.newContext({ baseURL });
  const theirs = await startCliLogin(cli);
  const mine = await startCliLogin(cli);

  await page.goto(pathOf(theirs.verification_url));
  await expect(page.getByTestId("cli-request")).toBeVisible();
  await page.getByTestId("cli-code-input").fill(mine.user_code);
  await expect(page.getByTestId("cli-code-mismatch")).toBeVisible();
  await expect(page.getByTestId("cli-approve")).toBeDisabled();

  // The server itself refuses an approval without the typed code, whatever the page does.
  const bare = await page.request.post("/api/v1/auth/cli/approve", {
    headers: { "x-sekret-csrf": "1" },
    data: { user_code: theirs.user_code },
  });
  expect(bare.ok()).toBe(false);
  const poll = await cli.post("/api/v1/auth/cli/poll", { data: { device_code: theirs.device_code } });
  expect(poll.status()).not.toBe(200);
  await cli.dispose();
});
