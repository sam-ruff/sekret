import { toast } from "sonner";
import { isLeaving } from "./leaving";

/** How long a copied secret stays on the clipboard. */
export const CLIPBOARD_CLEAR_MS = 45_000;

export const NOT_CLEARED_NOTE = "Clipboard not cleared; clear it yourself";

/**
 * - `cleared`: the secret was wiped.
 * - `unverifiable`: it may still hold the secret, but clearing was not safe or not allowed.
 * - `deferred`: the tab has no focus, so the browser refuses clipboard access until it comes back.
 */
export type ClearOutcome = "cleared" | "unverifiable" | "deferred";

export interface ClipboardDeps {
  clipboard: Pick<Clipboard, "writeText"> | undefined;
  hasFocus: () => boolean;
  schedule: (run: () => void, delay: number) => void;
  /** Tells the person the secret may still be on the clipboard. */
  onNotCleared: () => void;
}

interface Pending {
  seen: number;
  id: number;
}

/**
 * Clears copied secrets after a delay. The page is not allowed to read the clipboard, so the timed
 * clear only overwrites it when this tab kept focus and nothing else was copied in it; otherwise
 * the person may have copied something of their own, so they are told instead. A clear that falls
 * due while the tab is in the background waits for the tab to come back. When the page is going,
 * the clipboard is overwritten regardless, since there is no later chance.
 */
export class ClipboardGuard {
  private readonly deps: ClipboardDeps;
  /** Bumped whenever the clipboard may have changed behind our back. */
  private activity = 0;
  /** The latest copy; an older one's timer does nothing once a newer secret was copied. */
  private latest = 0;
  private pending: Pending | undefined;
  /** The copied secret not yet cleared or known to be replaced. */
  private outstanding: Pending | undefined;

  constructor(deps: ClipboardDeps) {
    this.deps = deps;
  }

  noteActivity(): void {
    this.activity += 1;
  }

  /** Call after this page copied something that is not a secret, which replaced any secret copied before. */
  noteReplaced(): void {
    this.noteActivity();
    this.latest += 1;
    this.pending = undefined;
    this.outstanding = undefined;
  }

  /** Whether a clear fell due while the tab was in the background and is still waiting. */
  hasPending(): boolean {
    return this.pending !== undefined;
  }

  reportNotCleared(): void {
    this.deps.onNotCleared();
  }

  /** Whether a copied secret may still be on the clipboard. */
  hasOutstanding(): boolean {
    return this.outstanding !== undefined;
  }

  /** Call right after a secret was written to the clipboard. */
  clearLater(delay = CLIPBOARD_CLEAR_MS): void {
    this.latest += 1;
    this.pending = undefined;
    const due: Pending = { seen: this.activity, id: this.latest };
    this.outstanding = due;
    this.deps.schedule(() => void this.attempt(due), delay);
  }

  /**
   * Overwrites an outstanding secret straight away, for when the page is about to go, even if
   * something else may have been copied since. Focus is not waited for, since there is no later;
   * the browser may still refuse.
   */
  async clearNow(): Promise<ClearOutcome | null> {
    if (!this.outstanding) return null;
    this.latest += 1;
    this.pending = undefined;
    this.outstanding = undefined;
    return this.overwrite();
  }

  /** Call when the tab regains focus or becomes visible, to finish a clear that had to wait. */
  async retryPending(): Promise<ClearOutcome | null> {
    const due = this.pending;
    if (!due) return null;
    return this.attempt(due);
  }

  async clearIfUnchanged(seen: number): Promise<ClearOutcome> {
    if (!this.deps.clipboard) return "unverifiable";
    if (!this.deps.hasFocus()) return "deferred";
    if (seen !== this.activity) return "unverifiable";
    return this.overwrite();
  }

  private async overwrite(): Promise<ClearOutcome> {
    const { clipboard } = this.deps;
    if (!clipboard) return "unverifiable";
    try {
      await clipboard.writeText("");
      return "cleared";
    } catch {
      return "unverifiable";
    }
  }

  private async attempt(due: Pending): Promise<ClearOutcome | null> {
    if (due.id !== this.latest) return null;
    const outcome = await this.clearIfUnchanged(due.seen);
    if (due.id !== this.latest) return outcome;
    this.pending = outcome === "deferred" ? due : undefined;
    if (outcome !== "deferred") this.outstanding = undefined;
    if (outcome === "unverifiable") this.deps.onNotCleared();
    return outcome;
  }
}

/**
 * A clear started while the page unloads may be refused or cut short, so closing or reloading
 * the tab with a copied secret still outstanding asks first. The clear starts straight away;
 * if the person stays and it could not be done, they are told.
 */
export function warnBeforeUnload(guard: ClipboardGuard, event: Pick<BeforeUnloadEvent, "preventDefault">): boolean {
  if (!guard.hasOutstanding() || isLeaving()) return false;
  event.preventDefault();
  void guard.clearNow().then((outcome) => {
    if (outcome === "unverifiable") guard.reportNotCleared();
  });
  return true;
}

let shared: ClipboardGuard | undefined;

/** The page's guard, watching for copies and lost focus that may change the clipboard. */
export function clipboardGuard(): ClipboardGuard {
  if (shared) return shared;
  const guard = new ClipboardGuard({
    clipboard: navigator.clipboard,
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
  window.addEventListener("beforeunload", (event) => warnBeforeUnload(guard, event));
  window.addEventListener("pagehide", () => void guard.clearNow());
  shared = guard;
  return guard;
}

/** Clears a copied secret now, if this page copied one that may still be there. */
export async function clearCopiedSecret(): Promise<ClearOutcome | null> {
  return (await shared?.clearNow()) ?? null;
}

const NOT_CLEARED_KEY = "sekret.clipboard-not-cleared";

/** Leaves word for the sign-in page that a copied secret could not be cleared on the way out. */
export function rememberNotCleared(storage: Pick<Storage, "setItem"> | undefined = safeSessionStorage()): void {
  try {
    storage?.setItem(NOT_CLEARED_KEY, "1");
  } catch {
    // Without storage the notice is lost; nothing else can carry it across the navigation.
  }
}

export function hasNotClearedNotice(storage: Pick<Storage, "getItem"> | undefined = safeSessionStorage()): boolean {
  try {
    return storage?.getItem(NOT_CLEARED_KEY) === "1";
  } catch {
    return false;
  }
}

export function dismissNotClearedNotice(storage: Pick<Storage, "removeItem"> | undefined = safeSessionStorage()): void {
  try {
    storage?.removeItem(NOT_CLEARED_KEY);
  } catch {
    // Nothing to do.
  }
}

function safeSessionStorage(): Storage | undefined {
  try {
    return window.sessionStorage;
  } catch {
    return undefined;
  }
}

/** Clears a copied secret before the page leaves, leaving a notice for the next page when it could not. */
export async function clearBeforeLeaving(clear: () => Promise<ClearOutcome | null> = clearCopiedSecret): Promise<void> {
  if ((await clear()) === "unverifiable") rememberNotCleared();
}
