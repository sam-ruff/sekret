import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { REDACTED_CREDENTIAL, type KubernetesAuthConfig } from "@/api/types";
import { KubernetesForm } from "./kubernetes-form";

const config = (reviewer_jwt: string | null): KubernetesAuthConfig => ({
  mode: "token-review",
  host: "https://k8s.example:6443",
  reviewer_jwt,
  namespaces: ["billing"],
  service_accounts: ["worker"],
  audiences: ["sekret"],
});

function renderForm(initial?: KubernetesAuthConfig) {
  const onSave = vi.fn<(config: KubernetesAuthConfig) => void>();
  render(<KubernetesForm initial={initial} busy={false} onSave={onSave} />);
  const saved = () => onSave.mock.calls.at(-1)?.[0];
  return { onSave, saved };
}

describe("KubernetesForm reviewer token", () => {
  it("shows a stored token without echoing the marker and sends the marker back", async () => {
    const { saved } = renderForm(config(REDACTED_CREDENTIAL));
    expect(screen.getByTestId("k8s-reviewer-jwt-stored")).toHaveTextContent("Token stored");
    expect(screen.queryByDisplayValue(REDACTED_CREDENTIAL)).toBeNull();
    expect(screen.queryByTestId("k8s-reviewer-jwt")).toBeNull();

    await userEvent.click(screen.getByTestId("k8s-save"));
    expect(saved()?.reviewer_jwt).toBe(REDACTED_CREDENTIAL);
  });

  it("replaces a stored token with a new one", async () => {
    const { saved } = renderForm(config(REDACTED_CREDENTIAL));
    await userEvent.click(screen.getByTestId("k8s-reviewer-jwt-replace"));
    await userEvent.type(screen.getByTestId("k8s-reviewer-jwt"), "eyJ.new.token");
    await userEvent.click(screen.getByTestId("k8s-save"));
    expect(saved()?.reviewer_jwt).toBe("eyJ.new.token");
  });

  it("clears a stored token when the replacement is left empty", async () => {
    const { saved } = renderForm(config(REDACTED_CREDENTIAL));
    await userEvent.click(screen.getByTestId("k8s-reviewer-jwt-replace"));
    await userEvent.click(screen.getByTestId("k8s-save"));
    expect(saved()?.reviewer_jwt).toBeNull();
  });

  it("can go back to keeping the stored token", async () => {
    const { saved } = renderForm(config(REDACTED_CREDENTIAL));
    await userEvent.click(screen.getByTestId("k8s-reviewer-jwt-replace"));
    await userEvent.type(screen.getByTestId("k8s-reviewer-jwt"), "typo");
    await userEvent.click(screen.getByTestId("k8s-reviewer-jwt-keep"));
    await userEvent.click(screen.getByTestId("k8s-save"));
    expect(saved()?.reviewer_jwt).toBe(REDACTED_CREDENTIAL);
  });

  it("takes a token on a new configuration", async () => {
    const { saved } = renderForm(config(null));
    expect(screen.queryByTestId("k8s-reviewer-jwt-keep")).toBeNull();
    await userEvent.type(screen.getByTestId("k8s-reviewer-jwt"), "  eyJ.first  ");
    await userEvent.click(screen.getByTestId("k8s-save"));
    expect(saved()?.reviewer_jwt).toBe("eyJ.first");
  });

  it("keeps a custom maximum token lifetime when editing other fields", async () => {
    const { saved } = renderForm({ ...config(REDACTED_CREDENTIAL), max_token_lifetime: 600 });
    expect(screen.getByTestId("k8s-max-lifetime")).toHaveValue("600");
    await userEvent.clear(screen.getByTestId("k8s-host"));
    await userEvent.type(screen.getByTestId("k8s-host"), "https://other.example:6443");
    await userEvent.click(screen.getByTestId("k8s-save"));
    expect(saved()).toMatchObject({ host: "https://other.example:6443", max_token_lifetime: 600 });
  });

  it("defaults the lifetime to an hour and refuses anything but whole seconds", async () => {
    const { saved, onSave } = renderForm(config(null));
    const field = screen.getByTestId("k8s-max-lifetime");
    expect(field).toHaveValue("3600");
    await userEvent.clear(field);
    await userEvent.type(field, "0");
    expect(screen.getByTestId("k8s-save")).toBeDisabled();
    expect(screen.getByText("Enter a whole number of seconds, 1 or more.")).toBeInTheDocument();
    await userEvent.clear(field);
    await userEvent.type(field, "900");
    await userEvent.click(screen.getByTestId("k8s-save"));
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(saved()?.max_token_lifetime).toBe(900);
  });

  it("explains the auth-delegator binding", () => {
    renderForm();
    expect(screen.getByText("system:auth-delegator")).toBeInTheDocument();
  });
});
