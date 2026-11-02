import { expect, test } from "@playwright/test";
import { addSecret, createProject, unique } from "./helpers";

test("missing projects, environments and identities offer a way back", async ({ page }) => {
  const missing = unique("no-such-project");
  await page.goto(`/projects/${missing}/secrets`);
  await expect(page.getByTestId("project-missing")).toContainText(`There is no project called "${missing}"`);
  await expect(page.getByRole("navigation", { name: "Location" })).not.toContainText(missing);
  await page.getByTestId("project-missing-back").click();
  await expect(page).toHaveURL(/\/projects$/);

  await page.goto("/org/identities/00000000-0000-0000-0000-000000000000");
  await expect(page.getByTestId("identity-missing")).toBeVisible();
  await page.getByTestId("identity-missing-back").click();
  await expect(page).toHaveURL(/\/org\/identities$/);
});

test("a missing overview cell opens the add form for that key, and the audit log reads in words", async ({ page }) => {
  const name = unique("E2E Overview");
  const slug = await createProject(page, name);
  await page.goto(`/projects/${slug}/secrets/nope`);
  await expect(page.getByTestId("environment-missing")).toBeVisible();
  await page.getByTestId("environment-missing-back").click();
  await expect(page).toHaveURL(new RegExp(`/projects/${slug}/secrets/dev$`));

  await addSecret(page, "ONLY_IN_DEV", "dev-value");
  await page.goto(`/projects/${slug}/overview`);
  const missingCell = page.locator('[data-testid^="cell-link-ONLY_IN_DEV-"]').filter({ hasText: "Missing" }).first();
  await missingCell.click();
  const form = page.getByTestId("new-secret-form");
  await expect(form.getByTestId("secret-key-input")).toHaveValue("ONLY_IN_DEV");
  await form.getByTestId("secret-value-input").fill("other-value");
  await form.getByTestId("secret-save").click();
  await expect(page.getByTestId("secret-row-ONLY_IN_DEV")).toBeVisible();

  await page.goto(`/projects/${slug}/audit`);
  const write = page.locator('[data-testid="audit-action"][data-action="secret.write"]').first();
  await expect(write).toHaveText("Changed secrets");
  const details = await page.getByTestId("audit-detail").allTextContents();
  expect(details.some((detail) => detail.includes('{"'))).toBe(false);
  // The tab names the project, so several open projects can be told apart.
  await expect(page).toHaveTitle(`Audit log · ${name} · sekret`);

  // The organisation log names the project each entry belongs to, and links to that project's log.
  await page.goto(`/org/audit?action=project.create`);
  const project = page.getByTestId("audit-project").filter({ hasText: name }).first();
  await expect(project).toHaveText(name);
  await project.click();
  await expect(page).toHaveURL(new RegExp(`/projects/${slug}/audit$`));

  await page.goto(`/projects/${slug}/settings/danger`);
  await page.getByTestId("delete-project").click();
  await page.getByTestId("delete-project-slug").fill(slug);
  await page.getByTestId("confirm-action").click();
  await expect(page).toHaveURL(/\/projects$/);
});
