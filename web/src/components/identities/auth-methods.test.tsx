import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/api/endpoints";
import { renderWithProviders, testQueryClient } from "@/test/render";
import { AuthMethods } from "./auth-methods";

vi.mock("@/api/endpoints", () => ({
  api: {
    authMethods: vi.fn(),
    putAuthMethod: vi.fn(),
    deleteAuthMethod: vi.fn(),
    clientSecrets: vi.fn(),
  },
}));

const mocked = vi.mocked(api);
const TOKEN = "eyJhbGciOiJSUzI1NiJ9.reviewer.sig";

describe("AuthMethods", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocked.authMethods.mockResolvedValue([]);
    mocked.putAuthMethod.mockResolvedValue(undefined);
  });

  it("keeps no saved reviewer token in the mutation cache while the page stays open", async () => {
    // As in the app: a finished mutation goes once nothing observes it, so only a reset lets it go while mounted.
    const client = testQueryClient();
    client.setDefaultOptions({ ...client.getDefaultOptions(), mutations: { gcTime: 0 } });
    renderWithProviders(<AuthMethods identityId="id-1" canEdit />, { client });

    const k8s = await screen.findByTestId("auth-method-kubernetes");
    await userEvent.click(screen.getByTestId("auth-method-kubernetes-setup"));
    await userEvent.type(screen.getByTestId("k8s-host"), "https://k8s.example:6443");
    await userEvent.type(screen.getByTestId("k8s-reviewer-jwt"), TOKEN);
    await userEvent.type(screen.getByTestId("k8s-namespaces-input"), "billing{Enter}");
    await userEvent.type(screen.getByTestId("k8s-service-accounts-input"), "worker{Enter}");
    await userEvent.click(screen.getByTestId("k8s-save"));

    await waitFor(() => expect(mocked.putAuthMethod).toHaveBeenCalledTimes(1));
    expect(JSON.stringify(mocked.putAuthMethod.mock.calls[0])).toContain(TOKEN);
    await waitFor(() => expect(client.getMutationCache().getAll()).toHaveLength(0));
    expect(k8s).toBeInTheDocument();
  });

  it("lets go of the reviewer token after a failed save too, keeping it in the form to retry", async () => {
    mocked.putAuthMethod.mockRejectedValue(new Error("the cluster refused the token"));
    const client = testQueryClient();
    client.setDefaultOptions({ ...client.getDefaultOptions(), mutations: { gcTime: 0 } });
    renderWithProviders(<AuthMethods identityId="id-1" canEdit />, { client });

    await screen.findByTestId("auth-method-kubernetes");
    await userEvent.click(screen.getByTestId("auth-method-kubernetes-setup"));
    await userEvent.type(screen.getByTestId("k8s-host"), "https://k8s.example:6443");
    await userEvent.type(screen.getByTestId("k8s-reviewer-jwt"), TOKEN);
    await userEvent.type(screen.getByTestId("k8s-namespaces-input"), "billing{Enter}");
    await userEvent.type(screen.getByTestId("k8s-service-accounts-input"), "worker{Enter}");
    await userEvent.click(screen.getByTestId("k8s-save"));

    await waitFor(() => expect(mocked.putAuthMethod).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(client.getMutationCache().getAll()).toHaveLength(0));
    expect(screen.getByTestId("k8s-reviewer-jwt")).toHaveValue(TOKEN);
  });

  it("keeps unconfigured methods collapsed until someone sets one up, and Cancel collapses it again", async () => {
    renderWithProviders(<AuthMethods identityId="id-1" canEdit />);
    await userEvent.click(await screen.findByTestId("auth-method-oidc-setup"));
    expect(screen.getByTestId("oidc-form")).toBeInTheDocument();
    expect(screen.queryByTestId("k8s-host")).toBeNull();
    // No warning about unbound tokens before there is an issuer.
    expect(screen.queryByTestId("oidc-unbounded")).toBeNull();
    await userEvent.type(screen.getByTestId("oidc-issuer"), "https://issuer.example.com");
    expect(screen.getByTestId("oidc-unbounded")).toBeInTheDocument();
    await userEvent.click(screen.getByTestId("oidc-cancel"));
    expect(screen.queryByTestId("oidc-form")).toBeNull();
    expect(screen.getByTestId("auth-method-oidc-setup")).toBeInTheDocument();
  });

  it("shows configured methods in full, without a Cancel, and only a note to readers", async () => {
    mocked.authMethods.mockResolvedValue([
      {
        kind: "oidc",
        issuer: "https://issuer.example.com",
        jwks_url: null,
        max_token_lifetime: 3600,
        bindings: { audiences: ["sekret"], subjects: ["repo:a/b:*"], claims: {} },
      },
    ]);
    renderWithProviders(<AuthMethods identityId="id-1" canEdit={false} />);
    expect(await screen.findByTestId("oidc-form")).toBeInTheDocument();
    expect(screen.queryByTestId("oidc-cancel")).toBeNull();
    expect(screen.queryByTestId("auth-method-kubernetes-setup")).toBeNull();
    expect(screen.getByTestId("auth-method-kubernetes")).toHaveTextContent("Not set up.");
  });
});
