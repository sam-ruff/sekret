import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CLIPBOARD_CLEAR_MS,
  ClipboardGuard,
  clearBeforeLeaving,
  dismissNotClearedNotice,
  hasNotClearedNotice,
  rememberNotCleared,
  warnBeforeUnload,
  type ClipboardDeps,
} from "./clipboard";
import { beginLeaving, stopLeaving } from "./leaving";

function setup(overrides: Partial<ClipboardDeps> = {}) {
  let contents = "";
  let focused = true;
  const scheduled: { run: () => void; delay: number }[] = [];
  const clipboard = {
    writeText: vi.fn((text: string) => {
      contents = text;
      return Promise.resolve();
    }),
  };
  const onNotCleared = vi.fn();
  const guard = new ClipboardGuard({
    clipboard,
    hasFocus: () => focused,
    schedule: (run, delay) => scheduled.push({ run, delay }),
    onNotCleared,
    ...overrides,
  });
  const copy = async (text: string) => {
    await clipboard.writeText(text);
    guard.clearLater();
  };
  const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
  const runTimers = async () => {
    for (const timer of scheduled.splice(0)) timer.run();
    await settle();
  };
  return {
    guard,
    clipboard,
    copy,
    runTimers,
    settle,
    scheduled,
    onNotCleared,
    setFocused(value: boolean) {
      focused = value;
    },
    get contents() {
      return contents;
    },
    set contents(value: string) {
      contents = value;
    },
  };
}

describe("ClipboardGuard", () => {
  it("clears a copied secret after 45 seconds when nothing else happened", async () => {
    const c = setup();
    await c.copy("s3cret");
    expect(c.scheduled[0].delay).toBe(CLIPBOARD_CLEAR_MS);
    expect(CLIPBOARD_CLEAR_MS).toBe(45_000);
    await c.runTimers();
    expect(c.contents).toBe("");
    expect(c.onNotCleared).not.toHaveBeenCalled();
  });

  it("leaves the clipboard alone when it may have changed, and says so", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.guard.noteActivity();
    c.contents = "their own text";
    await c.runTimers();
    expect(c.contents).toBe("their own text");
    expect(c.onNotCleared).toHaveBeenCalledTimes(1);
  });

  it("waits for focus when the clear falls due in the background, then clears", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.setFocused(false);
    await c.runTimers();
    expect(c.contents).toBe("s3cret");
    expect(c.guard.hasPending()).toBe(true);

    // Still in the background: nothing happens yet.
    await expect(c.guard.retryPending()).resolves.toBe("deferred");
    expect(c.contents).toBe("s3cret");

    c.setFocused(true);
    await expect(c.guard.retryPending()).resolves.toBe("cleared");
    expect(c.contents).toBe("");
    expect(c.guard.hasPending()).toBe(false);
    await expect(c.guard.retryPending()).resolves.toBeNull();
  });

  it("shows the note when the tab comes back but the clipboard cannot be checked", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.setFocused(false);
    c.guard.noteActivity();
    await c.runTimers();
    expect(c.onNotCleared).not.toHaveBeenCalled();

    c.setFocused(true);
    await expect(c.guard.retryPending()).resolves.toBe("unverifiable");
    expect(c.contents).toBe("s3cret");
    expect(c.onNotCleared).toHaveBeenCalledTimes(1);
    expect(c.guard.hasPending()).toBe(false);
  });

  it("ignores an older copy's timer once a newer secret was copied", async () => {
    const c = setup();
    await c.copy("first");
    const older = c.scheduled.splice(0);
    await c.copy("second");
    for (const timer of older) timer.run();
    await c.settle();
    expect(c.contents).toBe("second");
    await c.runTimers();
    expect(c.contents).toBe("");
  });

  it("drops a waiting clear when a new secret is copied", async () => {
    const c = setup();
    await c.copy("first");
    c.setFocused(false);
    await c.runTimers();
    expect(c.guard.hasPending()).toBe(true);
    c.setFocused(true);
    await c.copy("second");
    expect(c.guard.hasPending()).toBe(false);
  });

  it("clears an outstanding secret at once when the page is going, even without focus", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.setFocused(false);
    expect(c.guard.hasOutstanding()).toBe(true);
    await expect(c.guard.clearNow()).resolves.toBe("cleared");
    expect(c.contents).toBe("");
    expect(c.guard.hasOutstanding()).toBe(false);
    // The timer that was waiting does nothing afterwards.
    c.contents = "later text";
    await c.runTimers();
    expect(c.contents).toBe("later text");
    await expect(c.guard.clearNow()).resolves.toBeNull();
  });

  it("overwrites the clipboard when the page is going, even after the window lost focus", async () => {
    const c = setup();
    await c.copy("s3cret");
    // Switching to a terminal to paste, then coming back to sign out.
    c.guard.noteActivity();
    await expect(c.guard.clearNow()).resolves.toBe("cleared");
    expect(c.contents).toBe("");
    expect(c.onNotCleared).not.toHaveBeenCalled();
  });

  it("reports when the browser refuses the clear as the page goes", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.clipboard.writeText.mockImplementationOnce(() => Promise.reject(new Error("NotAllowedError")));
    await expect(c.guard.clearNow()).resolves.toBe("unverifiable");
    expect(c.contents).toBe("s3cret");
  });

  it("clears nothing at once when no secret is outstanding", async () => {
    const c = setup();
    await c.copy("s3cret");
    await c.runTimers();
    c.contents = "their own text";
    await expect(c.guard.clearNow()).resolves.toBeNull();
    expect(c.contents).toBe("their own text");
  });

  it("does not wipe a later copy that was not a secret", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.contents = "https://example.com/docs";
    c.guard.noteReplaced();
    await c.runTimers();
    expect(c.contents).toBe("https://example.com/docs");
    expect(c.onNotCleared).not.toHaveBeenCalled();
    await expect(c.guard.clearNow()).resolves.toBeNull();
    expect(c.contents).toBe("https://example.com/docs");
  });

  it("survives a missing or failing clipboard", async () => {
    const onNotCleared = vi.fn();
    const missing = new ClipboardGuard({
      clipboard: undefined,
      hasFocus: () => true,
      schedule: () => undefined,
      onNotCleared,
    });
    await expect(missing.clearIfUnchanged(0)).resolves.toBe("unverifiable");

    const failing = setup();
    failing.clipboard.writeText.mockImplementationOnce(() => Promise.reject(new Error("denied")));
    await expect(failing.guard.clearIfUnchanged(0)).resolves.toBe("unverifiable");
  });
});

describe("clearBeforeLeaving", () => {
  afterEach(() => dismissNotClearedNotice());

  it("leaves a notice for the sign-in page only when the clear could not be done", async () => {
    await clearBeforeLeaving(() => Promise.resolve("cleared"));
    expect(hasNotClearedNotice()).toBe(false);
    await clearBeforeLeaving(() => Promise.resolve(null));
    expect(hasNotClearedNotice()).toBe(false);
    await clearBeforeLeaving(() => Promise.resolve("unverifiable"));
    expect(hasNotClearedNotice()).toBe(true);
    dismissNotClearedNotice();
    expect(hasNotClearedNotice()).toBe(false);
  });

  it("copes with storage that throws", () => {
    const broken = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    };
    expect(() => rememberNotCleared(broken)).not.toThrow();
    expect(hasNotClearedNotice(broken)).toBe(false);
  });
});

describe("warnBeforeUnload", () => {
  afterEach(() => stopLeaving());

  it("does nothing when no copied secret is outstanding", () => {
    const c = setup();
    const event = { preventDefault: vi.fn() };
    expect(warnBeforeUnload(c.guard, event)).toBe(false);
    expect(event.preventDefault).not.toHaveBeenCalled();
  });

  it("asks before the tab closes with a secret on the clipboard, and starts clearing it", async () => {
    const c = setup();
    await c.copy("s3cret");
    const event = { preventDefault: vi.fn() };
    expect(warnBeforeUnload(c.guard, event)).toBe(true);
    expect(event.preventDefault).toHaveBeenCalledTimes(1);
    await c.settle();
    expect(c.contents).toBe("");
    expect(c.guard.hasOutstanding()).toBe(false);
    expect(c.onNotCleared).not.toHaveBeenCalled();
  });

  it("tells the person when the clear was refused, in case they stay", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.clipboard.writeText.mockImplementationOnce(() => Promise.reject(new Error("NotAllowedError")));
    warnBeforeUnload(c.guard, { preventDefault: vi.fn() });
    await c.settle();
    expect(c.contents).toBe("s3cret");
    expect(c.onNotCleared).toHaveBeenCalledTimes(1);
  });

  it("does not ask while sekret itself is navigating away, such as signing out", async () => {
    const c = setup();
    await c.copy("s3cret");
    beginLeaving();
    const event = { preventDefault: vi.fn() };
    expect(warnBeforeUnload(c.guard, event)).toBe(false);
    expect(event.preventDefault).not.toHaveBeenCalled();
  });
});
