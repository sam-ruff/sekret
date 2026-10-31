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
});
