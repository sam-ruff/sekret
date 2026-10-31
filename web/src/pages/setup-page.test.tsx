import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { SysStatus } from "@/api/types";
import { TooltipProvider } from "@/components/ui/tooltip";
import { keys } from "@/hooks/queries";
import { ThemeProvider } from "@/lib/theme";
import { SetupPage } from "./setup-page";

vi.mock("@/api/endpoints", () => ({ api: { init: vi.fn(), sysStatus: vi.fn() } }));
// The local meter likes every passphrase here, so only the server can refuse one.
vi.mock("@/hooks/use-passphrase-strength", () => ({
  usePassphraseStrength: () => ({ score: 4, acceptable: true, warning: null, suggestions: [] }),
}));

const init = vi.mocked(api.init);

// Radix measures radio items; jsdom has no layout to measure.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", NoopResizeObserver);

const uninitialised: SysStatus = {
  state: "uninitialised",
  seal_mode: null,
  unlock_policy: null,
  configured: false,
  remembered: false,
  web_setup: true,
  version: "1.0.0",
};

function renderSetup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(keys.sysStatus, uninitialised);
  render(
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <TooltipProvider>
          <MemoryRouter>
            <SetupPage />
          </MemoryRouter>
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>,
  );
}

async function submit(passphrase: string, policy?: string) {
  await userEvent.type(screen.getByTestId("setup-code"), "ABCD-EFGH-JKLM");
  await userEvent.type(screen.getByTestId("setup-passphrase"), passphrase);
  await userEvent.type(screen.getByTestId("setup-confirm"), passphrase);
  if (policy) await userEvent.click(screen.getByTestId(`setup-policy-${policy}`));
  await userEvent.click(screen.getByTestId("setup-submit"));
}

describe("SetupPage", () => {
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

  it("sends the chosen policy and shows the admin token", async () => {
    init.mockResolvedValue({ status: { ...uninitialised, state: "unsealed" }, admin_token: "skt_abc" });
    renderSetup();
    await submit("plum orbit gravel lantern", "remember");
    expect(await screen.findByTestId("admin-token")).toHaveTextContent("skt_abc");
    expect(init).toHaveBeenCalledWith({
      setup_code: "ABCD-EFGH-JKLM",
      mode: "passphrase",
      passphrase: "plum orbit gravel lantern",
      unlock_policy: "remember",
    });
  });
});
