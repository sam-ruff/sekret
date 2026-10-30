import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.SEKRET_E2E_URL;
if (!baseURL) {
  throw new Error("Set SEKRET_E2E_URL to the sekret server under test, for example http://localhost:8080");
}

export default defineConfig({
  testDir: "./tests-live",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report-live" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "setup",
      testMatch: /auth\.setup\.ts/,
      use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 900 } },
    },
    {
      name: "live-desktop",
      dependencies: ["setup"],
      testIgnore: /auth\.setup\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1366, height: 900 },
        storageState: "tests-live/.auth/state.json",
      },
    },
    {
      name: "live-mobile",
      dependencies: ["live-desktop"],
      testIgnore: /auth\.setup\.ts/,
      use: { ...devices["Pixel 7"], storageState: "tests-live/.auth/state.json" },
    },
  ],
});
