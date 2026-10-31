import { describe, expect, it, vi } from "vitest";
import { CLIPBOARD_CLEAR_MS, ClipboardGuard, type ClipboardDeps } from "./clipboard";

function setup(overrides: Partial<ClipboardDeps> = {}) {
  let contents = "";
  const scheduled: { run: () => void; delay: number }[] = [];
  const clipboard = {
    readText: vi.fn(() => Promise.resolve(contents)),
    writeText: vi.fn((text: string) => {
      contents = text;
      return Promise.resolve();
    }),
  };
  const guard = new ClipboardGuard({
    clipboard,
    canRead: () => Promise.resolve(false),
    hasFocus: () => true,
    schedule: (run, delay) => scheduled.push({ run, delay }),
    ...overrides,
  });
  const copy = async (text: string) => {
    await clipboard.writeText(text);
    guard.clearLater(text);
  };
  const runTimers = async () => {
    for (const timer of scheduled.splice(0)) timer.run();
    await new Promise((resolve) => setTimeout(resolve, 0));
  };
  return {
    guard,
    clipboard,
    copy,
    runTimers,
    scheduled,
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
  });

  it("leaves the clipboard alone after the person copied something else and it cannot be read", async () => {
    const c = setup();
    await c.copy("s3cret");
    c.guard.noteActivity();
    c.contents = "their own text";
    await c.runTimers();
    expect(c.contents).toBe("their own text");
    expect(c.clipboard.readText).not.toHaveBeenCalled();
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
  });

  it("does nothing without focus or a clipboard, and survives a failing clipboard", async () => {
    const unfocused = setup({ hasFocus: () => false });
    await unfocused.copy("s3cret");
    await unfocused.runTimers();
    expect(unfocused.contents).toBe("s3cret");

    const missing = new ClipboardGuard({
      clipboard: undefined,
      canRead: () => Promise.resolve(true),
      hasFocus: () => true,
      schedule: () => undefined,
    });
    await expect(missing.clearIfUnchanged("s3cret", 0)).resolves.toBe(false);

    const failing = setup();
    failing.clipboard.writeText.mockImplementationOnce(() => Promise.reject(new Error("denied")));
    await expect(failing.guard.clearIfUnchanged("x", 0)).resolves.toBe(false);
  });
});
