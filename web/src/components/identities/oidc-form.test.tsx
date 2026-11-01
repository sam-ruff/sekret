import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { OidcAuthConfig } from "@/api/types";
import { OidcForm } from "./oidc-form";

const config = (overrides: Partial<OidcAuthConfig> = {}): OidcAuthConfig => ({
  issuer: "https://token.actions.githubusercontent.com",
  jwks_url: null,
  bindings: { audiences: ["sekret"], subjects: ["repo:example/app:*"], claims: {} },
  ...overrides,
});

function renderForm(initial?: OidcAuthConfig) {
  const onSave = vi.fn<(config: OidcAuthConfig) => void>();
  render(<OidcForm initial={initial} busy={false} onSave={onSave} />);
  const saved = () => onSave.mock.calls.at(-1)?.[0];
  return { onSave, saved };
}

describe("OidcForm token lifetime", () => {
  it("defaults to an hour and says tokens without iat are refused", async () => {
    const { saved } = renderForm(config());
    const field = screen.getByLabelText("Longest OIDC token accepted");
    expect(field).toHaveValue("1h");
    expect(screen.getByTestId("oidc-max-lifetime-help")).toHaveTextContent(
      "Tokens valid for longer than this, or without an iat claim, are refused: 1 hour.",
    );
    await userEvent.click(screen.getByTestId("oidc-save"));
    expect(saved()?.max_token_lifetime).toBe(3600);
  });

  it("keeps a stored lifetime and sends a changed one", async () => {
    const { saved } = renderForm(config({ max_token_lifetime: 900 }));
    const field = screen.getByTestId("oidc-max-lifetime");
    expect(field).toHaveValue("15m");
    await userEvent.clear(field);
    await userEvent.type(field, "300");
    await userEvent.click(screen.getByTestId("oidc-save"));
    expect(saved()).toMatchObject({ max_token_lifetime: 300, issuer: "https://token.actions.githubusercontent.com" });
    await userEvent.clear(field);
    await userEvent.type(field, "2h 30m");
    expect(screen.getByTestId("oidc-max-lifetime-help")).toHaveTextContent("2 hours 30 minutes");
    await userEvent.click(screen.getByTestId("oidc-save"));
    expect(saved()?.max_token_lifetime).toBe(9000);
  });

  it.each(["0", "soon", "1.5h", "315360001", "11y"])("refuses %j, above ten years or not a duration", async (text) => {
    const { onSave } = renderForm(config());
    const field = screen.getByTestId("oidc-max-lifetime");
    await userEvent.clear(field);
    await userEvent.type(field, text);
    const error = screen.getByTestId("oidc-max-lifetime-error");
    expect(error).toHaveTextContent("Enter a duration such as 3600, 30m, 1h or 7d, from 1 second up to 10 years.");
    expect(field).toHaveAttribute("aria-describedby", "oidc-max-lifetime-error");
    expect(screen.getByTestId("oidc-save")).toBeDisabled();
    expect(onSave).not.toHaveBeenCalled();
  });
});

describe("OidcForm claims", () => {
  it("names each claim's glob input after the claim", async () => {
    renderForm(config({ bindings: { audiences: ["sekret"], subjects: [], claims: { repository_owner: ["acme"] } } }));
    expect(screen.getByLabelText("Globs for claim repository_owner")).toBeInTheDocument();
  });
});

describe("OidcForm URLs", () => {
  it("flags an issuer or JWKS URL at a cloud metadata address by the field", async () => {
    renderForm(config());
    await userEvent.type(screen.getByTestId("oidc-jwks-url"), "http://169.254.169.254/latest");
    expect(screen.getByTestId("oidc-jwks-url-error")).toHaveTextContent("That is a cloud metadata address");
    expect(screen.getByTestId("oidc-save")).toBeDisabled();

    await userEvent.clear(screen.getByTestId("oidc-jwks-url"));
    expect(screen.queryByTestId("oidc-jwks-url-error")).toBeNull();
    expect(screen.getByTestId("oidc-save")).toBeEnabled();
  });
});
