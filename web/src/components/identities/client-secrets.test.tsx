import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/api/endpoints";
import type { ClientSecret } from "@/api/types";
import { UNKNOWN_DATE } from "@/lib/format";
import { renderWithProviders } from "@/test/render";
import { ClientSecrets } from "./client-secrets";

vi.mock("@/api/endpoints", () => ({
  api: { clientSecrets: vi.fn(), revokeClientSecret: vi.fn(), createClientSecret: vi.fn() },
}));

const mocked = vi.mocked(api);

function secret(overrides: Partial<ClientSecret>): ClientSecret {
  return {
    id: "cs-1",
    description: "ci",
    prefix: "sks_abcdef",
    created_at: 1_800_000_000,
    expires_at: null,
    uses_remaining: null,
    revoked: false,
    last_used_at: null,
    ...overrides,
  };
}

describe("ClientSecrets", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocked.revokeClientSecret.mockResolvedValue(undefined);
  });

  it("lists and revokes a secret whose expiry is too far away for a date", async () => {
    // Roughly three million years: past what `Date` can hold, which used to crash the tab.
    mocked.clientSecrets.mockResolvedValue([secret({ expires_at: 1e14, last_used_at: 1e14, created_at: -1e14 })]);
    renderWithProviders(<ClientSecrets identityId="id-1" canEdit />);

    const row = await screen.findByTestId("client-secret-row-cs-1");
    expect(row).toHaveTextContent(UNKNOWN_DATE);
    await userEvent.click(screen.getByTestId("client-secret-revoke"));
    await userEvent.click(await screen.findByTestId("confirm-action"));
    await waitFor(() => expect(mocked.revokeClientSecret).toHaveBeenCalledWith("id-1", "cs-1"));
  });

  it("takes an expiry with units, offers presets and explains a bad one", async () => {
    mocked.clientSecrets.mockResolvedValue([]);
    mocked.createClientSecret.mockResolvedValue({ client_id: "id-1", client_secret: "sks_new", secret: secret({ id: "cs-2" }) });
    renderWithProviders(<ClientSecrets identityId="id-1" canEdit />);
    await userEvent.click(await screen.findByTestId("new-client-secret"));

    const ttl = screen.getByTestId("client-secret-ttl");
    expect(screen.getByTestId("client-secret-ttl-help")).toHaveTextContent("Empty means it never expires");
    await userEvent.type(ttl, "soon");
    const error = screen.getByTestId("client-secret-ttl-error");
    expect(error).toHaveTextContent("Enter a duration such as 3600, 12h or 90d.");
    expect(ttl).toHaveAttribute("aria-invalid", "true");
    expect(ttl).toHaveAttribute("aria-describedby", error.id);
    expect(screen.getByTestId("client-secret-create")).toBeDisabled();

    await userEvent.click(screen.getByTestId("client-secret-ttl-90d"));
    expect(ttl).toHaveValue("90d");
    expect(screen.getByTestId("client-secret-ttl-90d")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("client-secret-ttl-help")).toHaveTextContent("90 days");
    await userEvent.click(screen.getByTestId("client-secret-create"));
    await waitFor(() =>
      expect(mocked.createClientSecret).toHaveBeenCalledWith("id-1", { description: "", ttl: 90 * 86400, max_uses: null }),
    );
  });
});
