import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IDLE_CHECK_MS, REVEAL_IDLE_MS, useIdle } from "./use-idle";

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

  it("fires as soon as the page is seen again after the machine slept", () => {
    const onIdle = vi.fn();
    renderHook(() => useIdle(true, onIdle));
    // Sleep moves the wall clock on while timers stay paused.
    vi.setSystemTime(Date.now() + REVEAL_IDLE_MS * 20);
    expect(onIdle).not.toHaveBeenCalled();
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it("fires on focus or page show once the wall clock has passed the limit", () => {
    for (const type of ["focus", "pageshow"]) {
      const onIdle = vi.fn();
      const hook = renderHook(() => useIdle(true, onIdle));
      vi.setSystemTime(Date.now() + REVEAL_IDLE_MS + 1);
      act(() => {
        window.dispatchEvent(new Event(type));
      });
      expect(onIdle).toHaveBeenCalledTimes(1);
      hook.unmount();
    }
  });

  it("catches up within a few seconds when a throttled timer is late", () => {
    const onIdle = vi.fn();
    renderHook(() => useIdle(true, onIdle));
    vi.setSystemTime(Date.now() + REVEAL_IDLE_MS);
    act(() => vi.advanceTimersByTime(IDLE_CHECK_MS));
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it("does not fire on focus while the page is still in use", () => {
    const onIdle = vi.fn();
    renderHook(() => useIdle(true, onIdle));
    act(() => vi.advanceTimersByTime(REVEAL_IDLE_MS / 2));
    act(() => {
      window.dispatchEvent(new Event("focus"));
    });
    expect(onIdle).not.toHaveBeenCalled();
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
