import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SecretInput, SecretTextarea } from "./secret-field";

function expectSecretAttributes(field: HTMLElement) {
  expect(field).toHaveAttribute("spellcheck", "false");
  expect(field).toHaveAttribute("autocorrect", "off");
  expect(field).toHaveAttribute("autocapitalize", "off");
  expect(field).toHaveAttribute("data-gramm", "false");
  expect(field).toHaveAttribute("data-gramm_editor", "false");
  expect(field).toHaveAttribute("data-enable-grammarly", "false");
}

describe("secret fields", () => {
  it("turn off spellcheck, autocorrect, autocomplete and Grammarly", () => {
    render(
      <>
        <SecretInput data-testid="input" />
        <SecretTextarea data-testid="area" />
      </>,
    );
    for (const id of ["input", "area"]) {
      expectSecretAttributes(screen.getByTestId(id));
      expect(screen.getByTestId(id)).toHaveAttribute("autocomplete", "off");
    }
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
