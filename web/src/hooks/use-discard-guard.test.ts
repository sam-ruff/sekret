import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useDiscardGuard } from "./use-discard-guard";

describe("useDiscardGuard", () => {
  it("closes a clean form at once", () => {
    const close = vi.fn();
    const { result } = renderHook(() => useDiscardGuard(false));
    act(() => result.current.guard(close));
    expect(close).toHaveBeenCalledTimes(1);
    expect(result.current.prompt.open).toBe(false);
  });

  it("asks first when there is unsaved input, and keeping it closes nothing", () => {
    const close = vi.fn();
    const { result } = renderHook(() => useDiscardGuard(true));
    act(() => result.current.guard(close));
    expect(close).not.toHaveBeenCalled();
    expect(result.current.prompt.open).toBe(true);
    act(() => result.current.prompt.onKeep());
    expect(result.current.prompt.open).toBe(false);
    expect(close).not.toHaveBeenCalled();
  });

  it("closes once the discard is confirmed", () => {
    const close = vi.fn();
    const { result } = renderHook(() => useDiscardGuard(true));
    act(() => result.current.guard(close));
    act(() => result.current.prompt.onDiscard());
    expect(close).toHaveBeenCalledTimes(1);
    expect(result.current.prompt.open).toBe(false);
  });
});
