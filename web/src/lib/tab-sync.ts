/** Someone signed in, possibly as a different person than the other tabs show. */
export interface SignedIn {
  kind: "signed-in";
  user: string;
}

/** What one tab tells the others so they drop secrets they still hold. */
export type TabMessage = "signed-out" | "sealed" | SignedIn;

const CHANNEL = "sekret-tabs";
const PLAIN_MESSAGES: readonly string[] = ["signed-out", "sealed"];

export interface TabChannel {
  postMessage: (message: unknown) => void;
  addEventListener: (type: "message", listener: (event: MessageEvent) => void) => void;
  removeEventListener: (type: "message", listener: (event: MessageEvent) => void) => void;
  close: () => void;
}

function isSignedIn(value: unknown): value is SignedIn {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SignedIn>;
  return candidate.kind === "signed-in" && typeof candidate.user === "string" && candidate.user !== "";
}

function isTabMessage(value: unknown): value is TabMessage {
  if (typeof value === "string") return PLAIN_MESSAGES.includes(value);
  return isSignedIn(value);
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
