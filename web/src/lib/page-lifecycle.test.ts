import { describe, expect, it, vi } from "vitest";
import { forgetWhenHidden, reloadWhenRestored } from "./page-lifecycle";

type Listener = (event: PageTransitionEvent) => void;

function fakeWindow() {
  const listeners = new Map<string, Set<Listener>>();
  const reload = vi.fn();
  return {
    reload,
    fire(type: "pageshow" | "pagehide", persisted: boolean) {
      listeners.get(type)?.forEach((l) => l(new PageTransitionEvent(type, { persisted })));
    },
    win: {
      addEventListener: (type: string, l: Listener) => {
        const set = listeners.get(type) ?? new Set<Listener>();
        set.add(l);
        listeners.set(type, set);
      },
      removeEventListener: (type: string, l: Listener) => {
        listeners.get(type)?.delete(l);
      },
      location: { reload },
    },
  };
}

describe("reloadWhenRestored", () => {
  it("reloads only a page restored from the back-forward cache", () => {
    const f = fakeWindow();
    reloadWhenRestored(f.win);
    f.fire("pageshow", false);
    expect(f.reload).not.toHaveBeenCalled();
    f.fire("pageshow", true);
    expect(f.reload).toHaveBeenCalledTimes(1);
  });
});

describe("forgetWhenHidden", () => {
  it("forgets whenever the page is hidden, stored or not, until stopped", () => {
    const f = fakeWindow();
    const forget = vi.fn();
    const stop = forgetWhenHidden(forget, f.win);
    f.fire("pagehide", true);
    f.fire("pagehide", false);
    expect(forget).toHaveBeenCalledTimes(2);
    stop();
    f.fire("pagehide", true);
    expect(forget).toHaveBeenCalledTimes(2);
  });
});
