import { toast } from "sonner";

/** How long a copied secret stays on the clipboard. */
export const CLIPBOARD_CLEAR_MS = 45_000;

export const NOT_CLEARED_NOTE = "Clipboard not cleared; clear it yourself";

/**
 * - `cleared`: the secret was wiped.
 * - `changed`: the clipboard holds something else now, so it was left alone.
 * - `unverifiable`: it may still hold the secret, but checking or clearing was not allowed.
 * - `deferred`: the tab has no focus, so the browser refuses clipboard access until it comes back.
 */
export type ClearOutcome = "cleared" | "changed" | "unverifiable" | "deferred";

export interface ClipboardDeps {
  clipboard: Pick<Clipboard, "readText" | "writeText"> | undefined;
  /** True only when reading the clipboard needs no prompt. */
  canRead: () => Promise<boolean>;
  hasFocus: () => boolean;
  schedule: (run: () => void, delay: number) => void;
  /** Tells the person the secret may still be on the clipboard. */
  onNotCleared: () => void;
}

interface Pending {
  text: string;
  seen: number;
  id: number;
}

/**
 * Clears copied secrets after a delay, only when the clipboard still holds them. Reading the
 * clipboard can prompt, so it is read only when already permitted; otherwise the clipboard is
 * trusted to be unchanged while this tab kept focus and nothing else was copied in it. A clear
 * that falls due while the tab is in the background waits for the tab to come back.
 */
export class ClipboardGuard {
  private readonly deps: ClipboardDeps;
  /** Bumped whenever the clipboard may have changed behind our back. */
  private activity = 0;
  /** The latest copy; an older one's timer does nothing once a newer secret was copied. */
  private latest = 0;
  private pending: Pending | undefined;

  constructor(deps: ClipboardDeps) {
    this.deps = deps;
  }

  noteActivity(): void {
    this.activity += 1;
  }

  /** Whether a clear fell due while the tab was in the background and is still waiting. */
  hasPending(): boolean {
    return this.pending !== undefined;
  }

  /** Call right after `text` was written to the clipboard. */
  clearLater(text: string, delay = CLIPBOARD_CLEAR_MS): void {
    this.latest += 1;
    this.pending = undefined;
    const due: Pending = { text, seen: this.activity, id: this.latest };
    this.deps.schedule(() => void this.attempt(due), delay);
  }

  /** Call when the tab regains focus or becomes visible, to finish a clear that had to wait. */
  async retryPending(): Promise<ClearOutcome | null> {
    const due = this.pending;
    if (!due) return null;
    return this.attempt(due);
  }

  async clearIfUnchanged(text: string, seen: number): Promise<ClearOutcome> {
    const { clipboard } = this.deps;
    if (!clipboard) return "unverifiable";
    if (!this.deps.hasFocus()) return "deferred";
    try {
      if (seen !== this.activity) {
        if (!(await this.deps.canRead())) return "unverifiable";
        if ((await clipboard.readText()) !== text) return "changed";
      }
      await clipboard.writeText("");
      return "cleared";
    } catch {
      return "unverifiable";
    }
  }

  private async attempt(due: Pending): Promise<ClearOutcome | null> {
    if (due.id !== this.latest) return null;
    const outcome = await this.clearIfUnchanged(due.text, due.seen);
    if (due.id !== this.latest) return outcome;
    this.pending = outcome === "deferred" ? due : undefined;
    if (outcome === "unverifiable") this.deps.onNotCleared();
    return outcome;
  }
}

async function readPermitted(): Promise<boolean> {
  try {
    const status = await navigator.permissions.query({ name: "clipboard-read" as PermissionName });
    return status.state === "granted";
  } catch {
    return false;
  }
}

let shared: ClipboardGuard | undefined;

/** The page's guard, watching for copies and lost focus that may change the clipboard. */
export function clipboardGuard(): ClipboardGuard {
  if (shared) return shared;
  const guard = new ClipboardGuard({
    clipboard: navigator.clipboard,
    canRead: readPermitted,
    hasFocus: () => document.hasFocus(),
    schedule: (run, delay) => void window.setTimeout(run, delay),
    onNotCleared: () => toast.warning(NOT_CLEARED_NOTE, { duration: 10_000 }),
  });
  const note = () => guard.noteActivity();
  document.addEventListener("copy", note, true);
  document.addEventListener("cut", note, true);
  window.addEventListener("blur", note);
  const retry = () => void guard.retryPending();
  window.addEventListener("focus", retry);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") retry();
  });
  shared = guard;
  return guard;
}
