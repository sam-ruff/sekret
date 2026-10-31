/** What one tab tells the others so they drop secrets they still hold. */
export type TabMessage = "signed-out" | "sealed";

const CHANNEL = "sekret-tabs";
const MESSAGES: readonly TabMessage[] = ["signed-out", "sealed"];

export interface TabChannel {
  postMessage: (message: unknown) => void;
  addEventListener: (type: "message", listener: (event: MessageEvent) => void) => void;
  removeEventListener: (type: "message", listener: (event: MessageEvent) => void) => void;
  close: () => void;
}

function isTabMessage(value: unknown): value is TabMessage {
  return typeof value === "string" && (MESSAGES as readonly string[]).includes(value);
}

function openChannel(): TabChannel | null {
  if (typeof BroadcastChannel === "undefined") return null;
  return new BroadcastChannel(CHANNEL);
}

/** Tells every other open tab of this origin. A tab never receives its own message. */
export function broadcast(message: TabMessage, open: () => TabChannel | null = openChannel): void {
  const channel = open();
  if (!channel) return;
  channel.postMessage(message);
  channel.close();
}

/** Calls `handler` for each message from another tab; returns a function that stops listening. */
export function listen(handler: (message: TabMessage) => void, open: () => TabChannel | null = openChannel): () => void {
  const channel = open();
  if (!channel) return () => undefined;
  const onMessage = (event: MessageEvent) => {
    if (isTabMessage(event.data)) handler(event.data);
  };
  channel.addEventListener("message", onMessage);
  return () => {
    channel.removeEventListener("message", onMessage);
    channel.close();
  };
}
