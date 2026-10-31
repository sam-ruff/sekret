import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { forgetAllButStatus, keys, SEAL_WATCH_INTERVAL_MS, useApiMutation, useSealWatch } from "./queries";

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

  it("checks the status and the session every 15 seconds and when the tab comes back while values are shown", () => {
    const { invalidate } = watch(true);
    expect(SEAL_WATCH_INTERVAL_MS).toBe(15_000);
    act(() => vi.advanceTimersByTime(15_000));
    expect(invalidate.mock.calls).toEqual([[{ queryKey: keys.sysStatus }], [{ queryKey: keys.me }]]);

    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(invalidate).toHaveBeenCalledTimes(4);
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

  it("drops finished mutations, whose variables can hold a passphrase", async () => {
    const client = new QueryClient();
    const observer = client.getMutationCache().build(client, { mutationFn: (passphrase: string) => Promise.resolve(passphrase) });
    await observer.execute("correct horse battery staple");
    expect(client.getMutationCache().getAll()).toHaveLength(1);
    forgetAllButStatus(client);
    expect(client.getMutationCache().getAll()).toHaveLength(0);
  });

  it("drops the admin status detail with everything else", () => {
    const client = new QueryClient();
    client.setQueryData(keys.sysStatusDetail, { remembered: true });
    forgetAllButStatus(client);
    expect(client.getQueryCache().find({ queryKey: keys.sysStatusDetail })).toBeUndefined();
  });
});

describe("useApiMutation", () => {
  it("lets a mutation leave the cache as soon as nothing uses it", async () => {
    const client = new QueryClient({ defaultOptions: { mutations: { gcTime: 0 } } });
    const hook = renderHook(
      () => useApiMutation({ mutationFn: (passphrase: string) => Promise.resolve(passphrase), gcTime: 0 }),
      { wrapper: wrapperFor(client) },
    );
    await act(async () => {
      await hook.result.current.mutateAsync("hunter2");
    });
    hook.unmount();
    await vi.waitFor(() => expect(client.getMutationCache().getAll()).toHaveLength(0));
  });

  it("keeps the client default when no gcTime is given", async () => {
    const client = new QueryClient({ defaultOptions: { mutations: { gcTime: 0 } } });
    const hook = renderHook(() => useApiMutation({ mutationFn: (value: string) => Promise.resolve(value) }), {
      wrapper: wrapperFor(client),
    });
    await act(async () => {
      await hook.result.current.mutateAsync("v");
    });
    expect(client.getMutationCache().getAll()[0]?.options.gcTime).toBe(0);
  });
});
