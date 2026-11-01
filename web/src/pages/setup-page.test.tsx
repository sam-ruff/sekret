import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { SysStatus } from "@/api/types";
import { keys } from "@/hooks/queries";
import { renderWithProviders, testQueryClient } from "@/test/render";
import { SetupPage } from "./setup-page";

vi.mock("@/api/endpoints", () => ({ api: { init: vi.fn(), sysStatus: vi.fn(), authConfig: vi.fn() } }));

// Lets a test say the page has gone idle without waiting three minutes.
const idle = vi.hoisted(() => ({ fire: undefined as (() => void) | undefined }));
vi.mock("@/hooks/use-idle", () => ({
  useIdle: (active: boolean, onIdle: () => void) => {
    idle.fire = active ? onIdle : undefined;
  },
}));
// The local meter likes every passphrase here, so only the server can refuse one.
vi.mock("@/hooks/use-passphrase-strength", () => ({
  usePassphraseStrength: () => ({ score: 4, acceptable: true, warning: null, suggestions: [] }),
}));

const init = vi.mocked(api.init);
const authConfig = vi.mocked(api.authConfig);

const uninitialised: SysStatus = {
  state: "uninitialised",
  seal_mode: null,
  unlock_policy: null,
  configured: false,
  remembered: false,
  unsealed_by: null,
  web_setup: true,
  version: "1.0.0",
};

function renderSetup(status: SysStatus = uninitialised) {
  const client = testQueryClient();
  client.setQueryData(keys.sysStatus, status);
  return renderWithProviders(<SetupPage />, { client });
}

async function submit(passphrase: string, policy?: string) {
  await userEvent.type(screen.getByTestId("setup-code"), "ABCD-EFGH-JKLM");
  await userEvent.type(screen.getByTestId("setup-passphrase"), passphrase);
  await userEvent.type(screen.getByTestId("setup-confirm"), passphrase);
  if (policy) await userEvent.click(screen.getByTestId(`setup-policy-${policy}`));
  await userEvent.click(screen.getByTestId("setup-submit"));
}

describe("SetupPage", () => {
  beforeEach(() => {
    init.mockReset();
    authConfig.mockReset();
    authConfig.mockResolvedValue({ oidc_enabled: true, login_url: "/auth/login" });
  });

  it("shows the server's feedback when it refuses the passphrase", async () => {
    const refused = new ApiError("the passphrase is too easy to guess", 400, "weak_passphrase", {
      score: 2,
      acceptable: false,
      warning: "Names and surnames by themselves are easy to guess.",
      suggestions: ["Add another word or two."],
    });
    init.mockImplementation(() => Promise.reject(refused));
    renderSetup();
    await submit("margaret thatcher");
    const refusal = await screen.findByTestId("setup-weak");
    expect(refusal).toHaveTextContent("The server refused this passphrase");
    expect(refusal).toHaveTextContent("Names and surnames by themselves are easy to guess.");
    expect(refusal).toHaveTextContent("Add another word or two.");
    expect(screen.queryByTestId("admin-token")).toBeNull();
  });

  it("sends the chosen policy, shows the admin token with its expiry and keeps no copy in the query cache", async () => {
    const expires = Math.floor(Date.now() / 1000) + 3600;
    init.mockResolvedValue({
      status: { ...uninitialised, state: "unsealed" },
      admin_token: "skt_abc",
      admin_token_expires_at: expires,
    });
    const { client } = renderSetup();
    await submit("plum orbit gravel lantern", "remember");
    expect(await screen.findByTestId("admin-token")).toHaveTextContent("skt_abc");
    expect(init).toHaveBeenCalledWith({
      setup_code: "ABCD-EFGH-JKLM",
      mode: "passphrase",
      passphrase: "plum orbit gravel lantern",
      unlock_policy: "remember",
    });
    expect(screen.getByTestId("admin-token-help")).toHaveTextContent(/It is shown once and expires in 1 hour \(/);
    expect(screen.queryByTestId("admin-token-expiry")).toBeNull();
    expect(screen.getByTestId("admin-token-cli-copy")).toBeInTheDocument();
    expect(screen.getByTestId("admin-token-help")).toHaveTextContent("The web interface signs you in through your identity provider.");
    expect(screen.getByTestId("admin-token-cli")).toHaveTextContent("export SEKRET_TOKEN=<token>");
    expect(screen.getByTestId("setup-continue")).toHaveTextContent("I have saved it, continue");
    await waitFor(() => expect(client.getMutationCache().getAll()).toHaveLength(0));
  });

  it("masks the admin token after the page sits idle, and shows it again on request", async () => {
    init.mockResolvedValue({ status: { ...uninitialised, state: "unsealed" }, admin_token: "skt_abc" });
    renderSetup();
    await submit("plum orbit gravel lantern");
    const token = await screen.findByTestId("admin-token");
    expect(token).toHaveTextContent("skt_abc");

    act(() => idle.fire?.());
    expect(token).not.toHaveTextContent("skt_abc");
    // Masked, not dropped: it cannot be fetched again.
    await userEvent.click(screen.getByTestId("admin-token-show"));
    expect(token).toHaveTextContent("skt_abc");
    expect(screen.queryByTestId("admin-token-show")).toBeNull();
  });

  it("says web sign-in is not ready and how to turn it on when the server has no sign-in provider", async () => {
    authConfig.mockResolvedValue({ oidc_enabled: false, login_url: "/auth/login" });
    init.mockResolvedValue({ status: { ...uninitialised, state: "unsealed" }, admin_token: "skt_abc" });
    renderSetup();
    await submit("plum orbit gravel lantern");
    const notice = await screen.findByTestId("setup-no-oidc");
    expect(notice).toHaveTextContent("Web sign-in is not set up yet");
    expect(notice).toHaveTextContent("oidc.issuer");
    expect(screen.getByTestId("setup-oidc-docs-link")).toHaveAttribute("href", expect.stringContaining("configuration/#signing-in-with-oidc"));
    expect(screen.getByTestId("admin-token-help")).not.toHaveTextContent("signs you in through your identity provider");
  });

  it("leaves out the sign-in notice when a provider is configured", async () => {
    init.mockResolvedValue({ status: { ...uninitialised, state: "unsealed" }, admin_token: "skt_abc" });
    renderSetup();
    await submit("plum orbit gravel lantern");
    expect(await screen.findByTestId("admin-token")).toBeInTheDocument();
    await waitFor(() => expect(authConfig).toHaveBeenCalled());
    expect(screen.queryByTestId("setup-no-oidc")).toBeNull();
  });

  it("disables Remember with the reason when the server has no remember file", async () => {
    renderSetup({ ...uninitialised, remember_available: false });
    expect(screen.getByTestId("setup-policy-remember")).toBeDisabled();
    expect(screen.getByTestId("setup-policy-card-remember")).toHaveAttribute("data-unavailable", "true");
    expect(screen.getByTestId("setup-policy-unavailable")).toHaveTextContent(
      "Not available: the server configuration does not set seal.remember_file.",
    );
    expect(screen.getByTestId("setup-policy-remember")).toHaveAttribute(
      "aria-describedby",
      "setup-policy-remember-text setup-policy-remember-unavailable",
    );
    await userEvent.click(screen.getByTestId("setup-policy-card-remember"));
    expect(screen.getByTestId("setup-policy-manual")).toHaveAttribute("data-state", "checked");
    expect(screen.getByTestId("setup-policy-passphrase-file")).toBeEnabled();
  });

  it("says the remember file is in place when the server reports one", async () => {
    renderSetup({ ...uninitialised, remember_available: true });
    await userEvent.click(screen.getByTestId("setup-policy-remember"));
    expect(screen.getByTestId("setup-policy-needs")).toHaveTextContent("Uses the key file named by seal.remember_file.");
    expect(screen.queryByTestId("setup-policy-unavailable")).toBeNull();
  });

  it("keeps Remember selectable with a hedged note when the server does not say", async () => {
    renderSetup();
    expect(screen.getByTestId("setup-policy-remember")).toBeEnabled();
    await userEvent.click(screen.getByTestId("setup-policy-remember"));
    expect(screen.getByTestId("setup-policy-needs")).toHaveTextContent(
      "Only works if the server configuration sets seal.remember_file. If you are not sure, ask whoever runs the server.",
    );
  });

  it("moves focus to the setup code when it is wrong", async () => {
    init.mockRejectedValue(new ApiError("the setup code is wrong", 401, "invalid_setup_code"));
    renderSetup();
    await submit("plum orbit gravel lantern");
    const error = await screen.findByTestId("setup-code-error");
    expect(error).toHaveTextContent("That setup code is wrong. Check the latest one in the server log.");
    const input = screen.getByTestId("setup-code");
    expect(input).toHaveFocus();
    expect(input).toHaveAttribute("aria-describedby", error.id);
  });

  it("says why the button is disabled", async () => {
    renderSetup();
    expect(screen.getByTestId("setup-blocker")).toHaveTextContent("Enter the setup code to continue.");
    await userEvent.type(screen.getByTestId("setup-code"), "ABCD");
    await userEvent.type(screen.getByTestId("setup-passphrase"), "plum orbit gravel lantern");
    expect(screen.getByTestId("setup-blocker")).toHaveTextContent("Type the passphrase again to continue.");
    expect(screen.getByTestId("setup-submit")).toHaveAttribute("aria-describedby", "setup-blocker");
  });

  it("marks a too-short passphrase on the field once the person moves on", async () => {
    renderSetup();
    await userEvent.type(screen.getByTestId("setup-passphrase"), "short one");
    expect(screen.queryByTestId("setup-short")).toBeNull();
    await userEvent.click(screen.getByTestId("setup-confirm"));
    expect(screen.getByTestId("setup-short")).toHaveTextContent("Use at least 12 characters.");
    expect(screen.getByTestId("setup-passphrase")).toHaveAttribute("aria-invalid", "true");
    await userEvent.type(screen.getByTestId("setup-passphrase"), " made longer");
    expect(screen.queryByTestId("setup-short")).toBeNull();
  });

  it("names a policy fixed in configuration and does not offer a choice", () => {
    renderSetup({ ...uninitialised, configured: true, unlock_policy: "remember" });
    expect(screen.getByTestId("setup-policy-configured")).toHaveTextContent("Remember");
    expect(screen.getByTestId("setup-policy-configured-needs")).toHaveTextContent("seal.remember_file");
    expect(screen.queryByTestId("setup-policy-options")).toBeNull();
  });

  it("skips the passphrase when a key file is configured", async () => {
    init.mockResolvedValue({ status: { ...uninitialised, state: "unsealed", seal_mode: "key-file" }, admin_token: "skt_k" });
    renderSetup({ ...uninitialised, seal_mode: "key-file" });
    expect(screen.getByTestId("setup-key-file")).toHaveTextContent("root key file");
    expect(screen.queryByTestId("setup-passphrase")).toBeNull();
    await userEvent.type(screen.getByTestId("setup-code"), "ABCD-EFGH-JKLM");
    await userEvent.click(screen.getByTestId("setup-submit"));
    expect(await screen.findByTestId("admin-token")).toHaveTextContent("skt_k");
    expect(init).toHaveBeenCalledWith({ setup_code: "ABCD-EFGH-JKLM", mode: "key-file" });
  });

  it("labels the passphrase for password managers and uses an h1 and page title", () => {
    renderSetup();
    expect(screen.getByTestId("passphrase-account")).toHaveAttribute("autocomplete", "username");
    expect(screen.getByTestId("passphrase-account")).toHaveValue(`sekret passphrase (${window.location.host})`);
    expect(screen.getByTestId("setup-passphrase")).toHaveAttribute("autocomplete", "new-password");
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Set up sekret");
    expect(document.title).toBe("Set up · sekret");
  });

  it("points to the host without asking for a code when web setup is off", () => {
    renderSetup({ ...uninitialised, web_setup: false });
    expect(screen.getByTestId("setup-disabled")).toHaveTextContent(
      "Web setup is turned off. Run sekret admin init on the host, then restart the server.",
    );
    expect(screen.queryByTestId("setup-code")).toBeNull();
  });
});
