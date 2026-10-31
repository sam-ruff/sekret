import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { forgetAllButStatus, keys, SEAL_WATCH_INTERVAL_MS, useSealWatch } from "./queries";

function wrapperFor(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useSealWatch", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => vi.useRealTimers());

  function watch(active: boolean) {
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, "invalidateQueries").mockResolvedValue(undefined);
    const hook = renderHook(({ on }) => useSealWatch(on), { initialProps: { on: active }, wrapper: wrapperFor(client) });
    return { invalidate, hook };
  }

  it("checks the status every 15 seconds and when the tab comes back while values are shown", () => {
    const { invalidate } = watch(true);
    expect(SEAL_WATCH_INTERVAL_MS).toBe(15_000);
    act(() => vi.advanceTimersByTime(15_000));
    expect(invalidate).toHaveBeenCalledTimes(1);
    expect(invalidate).toHaveBeenLastCalledWith({ queryKey: keys.sysStatus });

    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(invalidate).toHaveBeenCalledTimes(2);
  });

  it("stays quiet when nothing is revealed, and stops when values are hidden", () => {
    const { invalidate, hook } = watch(false);
    act(() => vi.advanceTimersByTime(60_000));
    expect(invalidate).not.toHaveBeenCalled();

    hook.rerender({ on: true });
    hook.rerender({ on: false });
    act(() => vi.advanceTimersByTime(60_000));
    expect(invalidate).not.toHaveBeenCalled();
  });
});

describe("forgetAllButStatus", () => {
  it("keeps only the server status", () => {
    const client = new QueryClient();
    client.setQueryData(keys.sysStatus, { state: "sealed" });
    client.setQueryData(keys.secretValues("p", "dev", "/"), new Map([["K", "v"]]));
    client.setQueryData(keys.versions("p", "dev", "/", "K"), []);
    forgetAllButStatus(client);
    expect(client.getQueryCache().getAll().map((q) => q.queryKey)).toEqual([keys.sysStatus]);
  });
});
