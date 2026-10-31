import { describe, expect, it, vi } from "vitest";
import { broadcast, listen, type TabChannel } from "./tab-sync";

/** Channels joined to one bus, delivering to every channel but the sender, as BroadcastChannel does. */
function bus() {
  const channels = new Set<FakeChannel>();
  class FakeChannel implements TabChannel {
    listeners = new Set<(event: MessageEvent) => void>();
    closed = false;
    constructor() {
      channels.add(this);
    }
    postMessage(message: unknown) {
      for (const other of channels) {
        if (other === this || other.closed) continue;
        other.listeners.forEach((l) => l(new MessageEvent("message", { data: message })));
      }
    }
    addEventListener(_type: "message", listener: (event: MessageEvent) => void) {
      this.listeners.add(listener);
    }
    removeEventListener(_type: "message", listener: (event: MessageEvent) => void) {
      this.listeners.delete(listener);
    }
    close() {
      this.closed = true;
      channels.delete(this);
    }
  }
  return { open: () => new FakeChannel(), channels };
}

describe("tab sync", () => {
  it("tells other tabs about sign-out and sealing", () => {
    const b = bus();
    const heard = vi.fn();
    const stop = listen(heard, b.open);
    broadcast("signed-out", b.open);
    broadcast("sealed", b.open);
    expect(heard.mock.calls).toEqual([["signed-out"], ["sealed"]]);
    stop();
    broadcast("sealed", b.open);
    expect(heard).toHaveBeenCalledTimes(2);
    expect(b.channels.size).toBe(0);
  });

  it("ignores anything that is not one of its messages", () => {
    const b = bus();
    const heard = vi.fn();
    listen(heard, b.open);
    const other = b.open();
    other.postMessage({ type: "signed-out" });
    other.postMessage("reveal-everything");
    expect(heard).not.toHaveBeenCalled();
  });

  it("does nothing where BroadcastChannel is missing", () => {
    expect(() => broadcast("sealed", () => null)).not.toThrow();
    const stop = listen(vi.fn(), () => null);
    expect(() => stop()).not.toThrow();
  });
});
