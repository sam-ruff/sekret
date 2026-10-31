import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { unwrap } from "@/api/client";
import { api } from "@/api/endpoints";
import type { SealState, SysStatus } from "@/api/types";
import { StatusGate } from "./status-gate";

vi.mock("@/api/endpoints", () => ({ api: { sysStatus: vi.fn() } }));

const sysStatus = vi.mocked(api.sysStatus);

const status = (state: SealState): SysStatus => ({
  state,
  seal_mode: state === "uninitialised" ? null : "passphrase",
  unlock_policy: state === "uninitialised" ? null : "manual",
  configured: false,
  remembered: false,
  web_setup: true,
  version: "1.0.0",
});

function Where() {
  const location = useLocation();
  return <p data-testid="where">{`${location.pathname}${location.search}`}</p>;
}

function renderGate(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <StatusGate>
          <Routes>
            <Route path="*" element={<Where />} />
          </Routes>
        </StatusGate>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** What any API call does when it meets the server's sealed gate. */
async function hitSealedGate(): Promise<void> {
  const pending = Promise.resolve({ error: { error: "sealed", message: "sealed" }, response: new Response(null, { status: 503 }) });
  await expect(unwrap(pending)).rejects.toMatchObject({ status: 503, code: "sealed" });
}

describe("StatusGate", () => {
  beforeEach(() => sysStatus.mockReset());

  it("waits for the status before showing anything", async () => {
    sysStatus.mockResolvedValue(status("unsealed"));
    renderGate("/projects");
    expect(screen.getByTestId("status-gate-loading")).toBeInTheDocument();
    expect(await screen.findByTestId("where")).toHaveTextContent("/projects");
  });

  it("sends a new server to setup", async () => {
    sysStatus.mockResolvedValue(status("uninitialised"));
    renderGate("/org/users");
    expect(await screen.findByTestId("where")).toHaveTextContent(/^\/setup$/);
  });

  it("sends a sealed server to unlock with a way back", async () => {
    sysStatus.mockResolvedValue(status("sealed"));
    renderGate("/org/users?page=2");
    expect(await screen.findByTestId("where")).toHaveTextContent("/unlock?return_to=%2Forg%2Fusers%3Fpage%3D2");
  });

  it("checks again and moves to unlock when a request finds the server sealed", async () => {
    sysStatus.mockResolvedValue(status("unsealed"));
    renderGate("/projects/app/secrets");
    expect(await screen.findByTestId("where")).toHaveTextContent("/projects/app/secrets");

    sysStatus.mockResolvedValue(status("sealed"));
    await hitSealedGate();
    expect(await screen.findByText("/unlock?return_to=%2Fprojects%2Fapp%2Fsecrets")).toBeInTheDocument();
    expect(sysStatus).toHaveBeenCalledTimes(2);
  });
});
