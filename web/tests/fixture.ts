import { test as base, expect } from "@playwright/test";

/**
 * Chromium aborts every request in flight with net::ERR_NETWORK_CHANGED whenever the host's
 * addresses change, as they do when a wifi router renews IPv6 lifetimes or Docker adds a bridge.
 * A page whose modules were cut off never starts. So every request to the dev server is fetched by
 * the test runner instead and handed to the page, which keeps Chromium's own sockets out of it.
 */
export const test = base.extend<{ fetchThroughRunner: void }>({
  fetchThroughRunner: [
    async ({ page, baseURL }, use) => {
      const origin = new URL(baseURL ?? "http://localhost").origin;
      await page.route(
        (url) => url.origin === origin,
        async (route) => {
          const response = await route.fetch({ maxRedirects: 0 });
          await route.fulfill({ response });
        },
      );
      await use();
    },
    { auto: true },
  ],
});

export { expect };
