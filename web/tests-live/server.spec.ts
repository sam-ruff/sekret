import { expect, test } from "@playwright/test";

const passphrase = process.env.SEKRET_E2E_PASSPHRASE;

test("asks for a backup with POST, and the server refuses GET and a POST without the CSRF header", async ({ page }) => {
  await page.goto("/org/server");
  await expect(page).toHaveTitle("Server · sekret");

  // The page's own session cookie, without the interface's header.
  expect((await page.request.get("/api/v1/sys/backup")).status()).toBe(405);
  expect((await page.request.post("/api/v1/sys/backup")).status()).toBe(403);
  const sent = await page.request.post("/api/v1/sys/backup", { headers: { "x-sekret-csrf": "1" } });
  // API backups need SQLite; a Postgres server answers 501 and points at pg_dump.
  expect([200, 501]).toContain(sent.status());

  const request = page.waitForRequest((r) => r.url().endsWith("/api/v1/sys/backup"));
  if (sent.status() === 200) {
    const download = page.waitForEvent("download");
    await page.getByTestId("backup-download").click();
    expect((await download).suggestedFilename()).toMatch(/^sekret-backup-\d{8}T\d{6}Z\.skb$/);
  } else {
    await page.getByTestId("backup-download").click();
    await expect(page.locator("[data-sonner-toast]").filter({ hasText: "pg_dump" }).first()).toBeVisible();
  }
  const made = await request;
  expect(made.method()).toBe("POST");
  expect(made.headers()["x-sekret-csrf"]).toBe("1");
});

test("confirms a weaker unlock policy with the current passphrase", async ({ page }) => {
  test.skip(!passphrase, "only a passphrase-mode server has an unlock policy");
  await page.goto("/org/server");
  await expect(page.getByTestId("server-policy")).toHaveText("Manual");

  await page.getByTestId("server-policy-card-passphrase-file").click();
  await expect(page.getByTestId("server-policy-needs")).toContainText("seal.passphrase_file");
  await page.getByTestId("policy-save").click();
  const dialog = page.getByTestId("policy-dialog");
  await expect(dialog).toContainText("Confirm with the current passphrase.");

  await dialog.getByTestId("policy-passphrase").fill("not the passphrase at all");
  await dialog.getByTestId("confirm-action").click();
  await expect(dialog.getByTestId("policy-passphrase-error")).toHaveText("That passphrase is wrong.", { timeout: 30_000 });
  await expect(page.getByTestId("server-policy")).toHaveText("Manual");

  await dialog.getByTestId("policy-passphrase").fill(passphrase ?? "");
  // A wrong passphrase can start a short backoff on the server; try again until it passes.
  await expect(async () => {
    if (await dialog.isVisible()) await dialog.getByTestId("confirm-action").click();
    await expect(page.getByTestId("server-policy")).toHaveText("Passphrase file", { timeout: 5_000 });
  }).toPass({ timeout: 45_000 });

  // Back to manual, which needs no passphrase, so later tests and the next run start the same way.
  await page.getByTestId("server-policy-card-manual").click();
  await page.getByTestId("policy-save").click();
  await expect(page.getByTestId("policy-dialog")).toHaveCount(0);
  await expect(page.getByTestId("server-policy")).toHaveText("Manual");
});
