import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { MaskedSecretInput, PassphraseInput, SecretInput, SecretTextarea } from "./secret-field";

function expectSecretAttributes(field: HTMLElement) {
  expect(field).toHaveAttribute("spellcheck", "false");
  expect(field).toHaveAttribute("autocorrect", "off");
  expect(field).toHaveAttribute("autocapitalize", "off");
  expect(field).toHaveAttribute("data-gramm", "false");
  expect(field).toHaveAttribute("data-gramm_editor", "false");
  expect(field).toHaveAttribute("data-enable-grammarly", "false");
}

const PASSWORD_MANAGER_ATTRIBUTES = [
  ["data-1p-ignore", "true"],
  ["data-lpignore", "true"],
  ["data-bwignore", "true"],
  ["data-form-type", "other"],
] as const;

describe("secret fields", () => {
  it("turn off spellcheck, autocorrect, autocomplete, Grammarly and password managers", () => {
    render(
      <>
        <SecretInput data-testid="input" />
        <SecretTextarea data-testid="area" />
        <MaskedSecretInput data-testid="masked" />
      </>,
    );
    for (const id of ["input", "area", "masked"]) {
      expectSecretAttributes(screen.getByTestId(id));
      expect(screen.getByTestId(id)).toHaveAttribute("autocomplete", "off");
      for (const [name, value] of PASSWORD_MANAGER_ATTRIBUTES) expect(screen.getByTestId(id)).toHaveAttribute(name, value);
    }
  });

  it("draws a token as dots without making it a password field", () => {
    render(<MaskedSecretInput data-testid="masked" />);
    expect(screen.getByTestId("masked")).toHaveAttribute("type", "text");
    expect(screen.getByTestId("masked").className).toContain("[-webkit-text-security:disc]");
  });

  it("lets a password manager keep the passphrase, which can be shown and hidden", async () => {
    const user = userEvent.setup();
    render(<PassphraseInput id="p" data-testid="pass" autoComplete="current-password" defaultValue="hunter2 hunter2" />);
    const field = screen.getByTestId("pass");
    expectSecretAttributes(field);
    for (const [name] of PASSWORD_MANAGER_ATTRIBUTES) expect(field).not.toHaveAttribute(name);
    expect(field).toHaveAttribute("type", "password");
    await user.click(screen.getByRole("button", { name: "Show passphrase" }));
    expect(field).toHaveAttribute("type", "text");
    await user.click(screen.getByRole("button", { name: "Hide passphrase" }));
    expect(field).toHaveAttribute("type", "password");
  });

  it("keep a password manager hint but never let spellcheck back on", () => {
    render(
      <>
        <SecretInput data-testid="pass" type="password" autoComplete="current-password" spellCheck />
        <SecretTextarea data-testid="area" autoComplete="on" spellCheck autoCorrect="on" />
      </>,
    );
    expect(screen.getByTestId("pass")).toHaveAttribute("autocomplete", "current-password");
    expectSecretAttributes(screen.getByTestId("pass"));
    expect(screen.getByTestId("area")).toHaveAttribute("autocomplete", "off");
    expectSecretAttributes(screen.getByTestId("area"));
  });
});
