import { act, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { REDACTED_CREDENTIAL, type KubernetesAuthConfig } from "@/api/types";
import { renderWithProviders } from "@/test/render";
import { KubernetesForm } from "./kubernetes-form";

// Lets a test say the page has gone idle without waiting three minutes.
const idle = vi.hoisted(() => ({ fire: undefined as (() => void) | undefined }));
vi.mock("@/hooks/use-idle", () => ({
  useIdle: (active: boolean, onIdle: () => void) => {
    idle.fire = active ? onIdle : undefined;
  },
}));

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
  renderWithProviders(<KubernetesForm initial={initial} busy={false} onSave={onSave} />);
  const saved = () => onSave.mock.calls.at(-1)?.[0];
  return { onSave, saved };
}

describe("KubernetesForm reviewer token", () => {
  it("drops a pasted token after the page sits idle and goes back to the stored one", async () => {
    renderForm(config(REDACTED_CREDENTIAL));
    await userEvent.click(screen.getByTestId("k8s-reviewer-jwt-replace"));
    await userEvent.type(screen.getByTestId("k8s-reviewer-jwt"), "eyJ.pasted.token");
    expect(idle.fire).toBeDefined();

    act(() => idle.fire?.());
    expect(screen.queryByTestId("k8s-reviewer-jwt")).toBeNull();
    expect(screen.getByTestId("k8s-reviewer-jwt-stored")).toHaveTextContent("Token stored");
    expect(screen.queryByDisplayValue("eyJ.pasted.token")).toBeNull();
  });

  it("does not watch for idle while no token is typed", () => {
    renderForm(config(null));
    expect(idle.fire).toBeUndefined();
  });

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
    expect(screen.getByLabelText("Longest Kubernetes token accepted (seconds)")).toBe(field);
    expect(screen.getByTestId("k8s-max-lifetime-help")).toHaveTextContent(
      "Kubernetes tokens valid for longer than this are refused: 1 hour. Keep pods' projected token expirationSeconds at or below it.",
    );
    expect(screen.getByTestId("k8s-save")).toHaveTextContent("Save Kubernetes settings");
    await userEvent.clear(field);
    await userEvent.type(field, "0");
    expect(screen.getByTestId("k8s-save")).toBeDisabled();
    const error = screen.getByTestId("k8s-max-lifetime-error");
    expect(error).toHaveTextContent("Enter a whole number of seconds, from 1 up to 10 years.");
    expect(error).toHaveAttribute("role", "alert");
    expect(field).toHaveAttribute("aria-describedby", "k8s-max-lifetime-error");
    await userEvent.clear(field);
    await userEvent.type(field, "900");
    await userEvent.click(screen.getByTestId("k8s-save"));
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(saved()?.max_token_lifetime).toBe(900);
  });

  it("flags an API server at a cloud metadata address before saving", async () => {
    renderForm(config(REDACTED_CREDENTIAL));
    const host = screen.getByTestId("k8s-host");
    await userEvent.clear(host);
    await userEvent.type(host, "https://169.254.169.254");
    expect(screen.getByTestId("k8s-host-error")).toHaveTextContent("That is a cloud metadata address");
    expect(host).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByTestId("k8s-save")).toBeDisabled();
  });

  it("takes the reviewer token in a masked text field that password managers leave alone", async () => {
    renderForm(config(null));
    const field = screen.getByTestId("k8s-reviewer-jwt");
    expect(field).toHaveAttribute("type", "text");
    expect(field).toHaveAttribute("data-1p-ignore", "true");
    expect(field).toHaveAttribute("data-lpignore", "true");
    expect(field.className).toContain("[-webkit-text-security:disc]");
  });

  it("explains the auth-delegator binding", () => {
    renderForm();
    expect(screen.getByText("system:auth-delegator")).toBeInTheDocument();
  });
});
