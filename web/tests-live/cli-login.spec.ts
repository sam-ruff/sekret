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
