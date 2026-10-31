import { describe, expect, it, vi } from "vitest";
import { CLIPBOARD_CLEAR_MS, ClipboardGuard, type ClipboardDeps } from "./clipboard";

function setup(overrides: Partial<ClipboardDeps> = {}) {
  let contents = "";
  let focused = true;
  const scheduled: { run: () => void; delay: number }[] = [];
  const clipboard = {
    readText: vi.fn(() => Promise.resolve(contents)),
    writeText: vi.fn((text: string) => {
      contents = text;
      return Promise.resolve();
    }),
  };
  const onNotCleared = vi.fn();
  const guard = new ClipboardGuard({
    clipboard,
    canRead: () => Promise.resolve(false),
    hasFocus: () => focused,
    schedule: (run, delay) => scheduled.push({ run, delay }),
    onNotCleared,
    ...overrides,
  });
  const copy = async (text: string) => {
    await clipboard.writeText(text);
    guard.clearLater(text);
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

  it("leaves the clipboard alone when it may have changed and cannot be read, and says so", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.guard.noteActivity();
    c.contents = "their own text";
    await c.runTimers();
    expect(c.contents).toBe("their own text");
    expect(c.clipboard.readText).not.toHaveBeenCalled();
    expect(c.onNotCleared).toHaveBeenCalledTimes(1);
  });

  it("reads the clipboard when allowed and clears only if it still holds the secret", async () => {
    const c = setup({ canRead: () => Promise.resolve(true) });
    await c.copy("s3cret");
    c.guard.noteActivity();
    await c.runTimers();
    expect(c.contents).toBe("");

    await c.copy("s3cret");
    c.guard.noteActivity();
    c.contents = "something else";
    await c.runTimers();
    expect(c.contents).toBe("something else");
    expect(c.onNotCleared).not.toHaveBeenCalled();
  });

  it("waits for focus when the clear falls due in the background, then clears if allowed", async () => {
    const c = setup({ canRead: () => Promise.resolve(true) });
    await c.copy("s3cret");
    c.setFocused(false);
    c.guard.noteActivity();
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
    const c = setup({ canRead: () => Promise.resolve(true) });
    await c.copy("first");
    c.setFocused(false);
    await c.runTimers();
    expect(c.guard.hasPending()).toBe(true);
    c.setFocused(true);
    await c.copy("second");
    expect(c.guard.hasPending()).toBe(false);
  });

  it("survives a missing or failing clipboard", async () => {
    const onNotCleared = vi.fn();
    const missing = new ClipboardGuard({
      clipboard: undefined,
      canRead: () => Promise.resolve(true),
      hasFocus: () => true,
      schedule: () => undefined,
      onNotCleared,
    });
    await expect(missing.clearIfUnchanged("s3cret", 0)).resolves.toBe("unverifiable");

    const failing = setup();
    failing.clipboard.writeText.mockImplementationOnce(() => Promise.reject(new Error("denied")));
    await expect(failing.guard.clearIfUnchanged("x", 0)).resolves.toBe("unverifiable");
  });
});
