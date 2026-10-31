import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { unwrap } from "@/api/client";
import { api } from "@/api/endpoints";
import type { SealState, SysStatus } from "@/api/types";
import { keys } from "@/hooks/queries";
import { StatusGate } from "./status-gate";

vi.mock("@/api/endpoints", () => ({ api: { sysStatus: vi.fn() } }));

const sysStatus = vi.mocked(api.sysStatus);

const status = (state: SealState): SysStatus => ({
  state,
  seal_mode: state === "uninitialised" ? null : "passphrase",
  unlock_policy: state === "uninitialised" ? null : "manual",
  configured: false,
  remembered: false,
  unsealed_by: state === "unsealed" ? "passphrase" : null,
  web_setup: true,
  version: "1.0.0",
});

function Where() {
  const location = useLocation();
  return <p data-testid="where">{`${location.pathname}${location.search}`}</p>;
}

function renderGate(path: string): QueryClient {
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
  return client;
}

/** Shows a value only while it is cached, so a test can see the page lose it. */
function Revealed({ client }: { client: QueryClient }) {
  const values = client.getQueryData<Map<string, string>>(VALUES_KEY);
  const [shown] = useState(() => values?.get("TOKEN") ?? "none");
  return <p data-testid="revealed">{shown}</p>;
}

const VALUES_KEY = keys.secretValues("app", "dev", "/");

/** What any API call does when it meets the server's sealed gate. */
async function hitSealedGate(): Promise<void> {
  const pending = Promise.resolve({ error: { error: "sealed", message: "sealed" }, response: new Response(null, { status: 503 }) });
  await expect(unwrap(pending)).rejects.toMatchObject({ status: 503, code: "sealed" });
}

describe("StatusGate", () => {
  beforeEach(() => {
    sysStatus.mockReset();
  });

  it("drops every cached query but the status, and unmounts the pages, when a request finds the server sealed", async () => {
    sysStatus.mockResolvedValue(status("unsealed"));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    client.setQueryData(VALUES_KEY, new Map([["TOKEN", "s3cret"]]));
    client.setQueryData(keys.me, { id: "u1" });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/projects/app/secrets"]}>
          <StatusGate>
            <Revealed client={client} />
          </StatusGate>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByTestId("revealed")).toHaveTextContent("s3cret");

    sysStatus.mockResolvedValue(status("sealed"));
    await hitSealedGate();
    await waitFor(() => expect(screen.queryByTestId("revealed")).toBeNull());
    expect(client.getQueryData(VALUES_KEY)).toBeUndefined();
    expect(client.getQueryData(keys.me)).toBeUndefined();
    await waitFor(() => expect(client.getQueryData<SysStatus>(keys.sysStatus)?.state).toBe("sealed"));
  });

  it("drops cached secrets when the status itself turns locked, as after sealing from the server page", async () => {
    sysStatus.mockResolvedValue(status("unsealed"));
    const client = renderGate("/org/server");
    expect(await screen.findByTestId("where")).toHaveTextContent("/org/server");
    client.setQueryData(VALUES_KEY, new Map([["TOKEN", "s3cret"]]));
    act(() => client.setQueryData(keys.sysStatus, status("sealed")));
    await waitFor(() => expect(client.getQueryData(VALUES_KEY)).toBeUndefined());
    expect(await screen.findByTestId("where")).toHaveTextContent("/unlock?return_to=%2Forg%2Fserver");
  });

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
