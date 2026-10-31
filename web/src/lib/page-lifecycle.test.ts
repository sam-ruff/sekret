import { describe, expect, it, vi } from "vitest";
import { reloadWhenRestored } from "./page-lifecycle";

describe("reloadWhenRestored", () => {
  it("reloads only a page restored from the back-forward cache", () => {
    let listener: ((event: PageTransitionEvent) => void) | undefined;
    const reload = vi.fn();
    reloadWhenRestored({
      addEventListener: (_type, l) => {
        listener = l;
      },
      location: { reload },
    });
    listener?.(new PageTransitionEvent("pageshow", { persisted: false }));
    expect(reload).not.toHaveBeenCalled();
    listener?.(new PageTransitionEvent("pageshow", { persisted: true }));
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
