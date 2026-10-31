import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { REVEAL_IDLE_MS, useIdle } from "./use-idle";

describe("useIdle", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => vi.useRealTimers());

  it("fires after three minutes with nobody using the page", () => {
    expect(REVEAL_IDLE_MS).toBe(180_000);
    const onIdle = vi.fn();
    renderHook(() => useIdle(true, onIdle));
    act(() => vi.advanceTimersByTime(REVEAL_IDLE_MS - 1));
    expect(onIdle).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(1));
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it("starts again whenever someone types or clicks", () => {
    const onIdle = vi.fn();
    renderHook(() => useIdle(true, onIdle));
    act(() => vi.advanceTimersByTime(REVEAL_IDLE_MS - 1000));
    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "a" }));
    });
    act(() => vi.advanceTimersByTime(REVEAL_IDLE_MS - 1000));
    expect(onIdle).not.toHaveBeenCalled();
    act(() => {
      window.dispatchEvent(new Event("pointerdown"));
    });
    act(() => vi.advanceTimersByTime(REVEAL_IDLE_MS));
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it("does nothing while inactive", () => {
    const onIdle = vi.fn();
    const hook = renderHook(({ on }) => useIdle(on, onIdle), { initialProps: { on: false } });
    act(() => vi.advanceTimersByTime(REVEAL_IDLE_MS * 2));
    expect(onIdle).not.toHaveBeenCalled();
    hook.rerender({ on: true });
    hook.rerender({ on: false });
    act(() => vi.advanceTimersByTime(REVEAL_IDLE_MS * 2));
    expect(onIdle).not.toHaveBeenCalled();
  });
});
