import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, test, type APIRequestContext } from "@playwright/test";

// A server of its own, started without a key file, so it boots uninitialised and needs setting up.
const BIN = process.env.SEKRET_BIN ?? path.resolve(import.meta.dirname, "../../target/x86_64-unknown-linux-musl/release/sekret");
const PASSPHRASE = "plum orbit gravel lantern";

test.use({ storageState: { cookies: [], origins: [] } });

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

class FreshServer {
  readonly url: string;
  readonly codeFile: string;
  private readonly args: string[];
  private process?: ChildProcess;
  private log = "";

  constructor(dir: string, port: number) {
    this.url = `http://127.0.0.1:${port}`;
    this.codeFile = path.join(dir, "setup-code");
    this.args = [
      "server",
      "--listen",
      `127.0.0.1:${port}`,
      "--public-url",
      this.url,
      "--database-url",
      `sqlite://${path.join(dir, "sekret.db")}?mode=rwc`,
      "--setup-code-file",
      this.codeFile,
    ];
  }

  async start(request: APIRequestContext): Promise<void> {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("SEKRET_")));
    this.process = spawn(BIN, this.args, { env: { ...env, SEKRET_LOG: "info" }, stdio: ["ignore", "pipe", "pipe"] });
    const keep = (chunk: Buffer) => {
      this.log += chunk.toString();
    };
    this.process.stdout?.on("data", keep);
    this.process.stderr?.on("data", keep);
    await expect
      .poll(async () => (await request.get(`${this.url}/api/v1/health`).catch(() => null))?.status(), {
        timeout: 20_000,
        message: "the server did not start; its log is attached on failure",
      })
      .toBe(200)
      .catch((error: unknown) => {
        throw new Error(`${String(error)}\n${this.log}`);
      });
  }

  async stop(): Promise<void> {
    const running = this.process;
    if (!running || running.exitCode !== null) return;
    const exited = new Promise((resolve) => running.once("exit", resolve));
    running.kill("SIGTERM");
    await exited;
  }

  async state(request: APIRequestContext): Promise<string> {
    const response = await request.get(`${this.url}/api/v1/sys/status`);
    return ((await response.json()) as { state: string }).state;
  }
}

test("sets up a new server in the browser, then unlocks it after a restart and after sealing", async ({ page, request }) => {
  const dir = mkdtempSync(path.join(tmpdir(), "sekret-seal-"));
  const server = new FreshServer(dir, await freePort());
  try {
    await server.start(request);
    expect(await server.state(request)).toBe("uninitialised");
    const code = readFileSync(server.codeFile, "utf8").trim();

    await page.goto(`${server.url}/projects`);
    await expect(page).toHaveURL(/\/setup$/);
    await expect(page.getByTestId("setup-policy-manual")).toHaveAttribute("data-state", "checked");
    await page.getByTestId("setup-code").fill(code);
    await page.getByTestId("setup-passphrase").fill(PASSPHRASE);
    await page.getByTestId("setup-confirm").fill(PASSPHRASE);
    await expect(page.getByTestId("setup-meter")).toHaveAttribute("data-acceptable", "true");
    await page.getByTestId("setup-submit").click();
    const token = (await page.getByTestId("admin-token").textContent({ timeout: 30_000 })) ?? "";
    expect(token).toMatch(/^skt_/);
    expect(await server.state(request)).toBe("unsealed");

    await server.stop();
    await server.start(request);
    expect(await server.state(request)).toBe("sealed");

    await page.goto(`${server.url}/projects`);
    await expect(page).toHaveURL(/\/unlock\?return_to=%2Fprojects$/);
    // The public status no longer says how the server unlocks, so the page does not either.
    await expect(page.getByTestId("unlock-card")).not.toContainText(/policy|remember/i);
    await page.getByTestId("unlock-passphrase").fill("not the passphrase");
    await page.getByTestId("unlock-submit").click();
    await expect(page.getByTestId("unlock-wrong")).toBeVisible({ timeout: 30_000 });
    await page.getByTestId("unlock-passphrase").fill(PASSPHRASE);
    await page.getByTestId("unlock-submit").click();
    // Unlocked, the app returns to the projects page, which asks this session-less browser to sign in.
    await expect(page).toHaveURL(/\/login\?return_to=%2Fprojects$/, { timeout: 30_000 });
    expect(await server.state(request)).toBe("unsealed");

    const sealed = await request.post(`${server.url}/api/v1/sys/seal`, { headers: { Authorization: `Bearer ${token}` } });
    expect(sealed.status()).toBe(200);
    await page.goto(`${server.url}/org/users`);
    await expect(page).toHaveURL(/\/unlock\?return_to=%2Forg%2Fusers$/);
    await page.getByTestId("unlock-passphrase").fill(PASSPHRASE);
    await page.getByTestId("unlock-submit").click();
    await expect(page).toHaveURL(/\/login\?return_to=%2Forg%2Fusers$/, { timeout: 30_000 });
    expect(await server.state(request)).toBe("unsealed");
  } finally {
    await server.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
