import { expect, type Page } from "@playwright/test";

export function credentials(): { username: string; password: string } {
  const username = process.env.SEKRET_E2E_USER;
  const password = process.env.SEKRET_E2E_PASSWORD;
  if (!username || !password) throw new Error("Set SEKRET_E2E_USER and SEKRET_E2E_PASSWORD");
  return { username, password };
}

/** A short suffix so repeated runs against the same server do not collide. */
export function unique(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}${Math.floor(Math.random() * 1296).toString(36)}`;
}

export async function signInThroughKeycloak(page: Page, returnTo = "/projects"): Promise<void> {
  const { username, password } = credentials();
  await page.goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
  await page.getByTestId("sign-in").click();
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.locator("#kc-login").click();
  await page.waitForURL((url) => url.pathname === returnTo, { timeout: 30_000 });
}

export async function createProject(page: Page, name: string): Promise<string> {
  await page.goto("/projects");
  await page.getByTestId("new-project").click();
  await page.getByTestId("project-name").fill(name);
  const slug = await page.getByTestId("project-slug").inputValue();
  await page.getByTestId("create-project-submit").click();
  await expect(page).toHaveURL(new RegExp(`/projects/${slug}/secrets/dev`));
  return slug;
}

export async function addSecret(page: Page, key: string, value: string): Promise<void> {
  await page.getByTestId("add-secret").click();
  const form = page.getByTestId("new-secret-form");
  await form.getByTestId("secret-key-input").fill(key);
  await form.getByTestId("secret-value-input").fill(value);
  await form.getByTestId("secret-save").click();
  await expect(page.getByTestId(`secret-row-${key}`)).toBeVisible();
}

export async function editSecret(page: Page, key: string, value: string): Promise<void> {
  const row = page.getByTestId(`secret-row-${key}`);
  await row.getByTestId("secret-actions").click();
  await page.getByTestId("secret-edit").click();
  const editor = page.getByTestId(`edit-secret-${key}`);
  await editor.getByTestId("secret-value-input").fill(value);
  await editor.getByTestId("secret-save").click();
  await expect(editor).toBeHidden();
}

export async function revealedValue(page: Page, key: string) {
  const row = page.getByTestId(`secret-row-${key}`);
  await row.getByTestId("secret-reveal").click();
  return row.getByTestId("secret-value");
}
