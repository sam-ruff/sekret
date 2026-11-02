import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.SEKRET_E2E_PORT ?? 5174);
const ci = !!process.env.CI;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: ci,
  retries: ci ? 2 : 0,
  // The runners are shared and the dev server compiles modules on first request, so CI runs
  // fewer browsers at once and gives each step more time.
  workers: ci ? 2 : undefined,
  timeout: ci ? 60_000 : 30_000,
  expect: { timeout: ci ? 15_000 : 5_000 },
  reporter: ci ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://localhost:${port}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 900 } } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: `npm run dev:mock -- --port ${port} --strictPort`,
    url: `http://localhost:${port}`,
    reuseExistingServer: !ci,
    timeout: 120_000,
  },
});
