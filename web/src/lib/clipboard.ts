/** How long a copied secret stays on the clipboard. */
export const CLIPBOARD_CLEAR_MS = 45_000;

export interface ClipboardDeps {
  clipboard: Pick<Clipboard, "readText" | "writeText"> | undefined;
  /** True only when reading the clipboard needs no prompt. */
  canRead: () => Promise<boolean>;
  hasFocus: () => boolean;
  schedule: (run: () => void, delay: number) => void;
}

/**
 * Clears copied secrets after a delay, only when the clipboard still holds them. Reading the
 * clipboard can prompt, so it is read only when already permitted; otherwise the clipboard is
 * trusted to be unchanged while this tab kept focus and nothing else was copied in it.
 */
export class ClipboardGuard {
  private readonly deps: ClipboardDeps;
  /** Bumped whenever the clipboard may have changed behind our back. */
  private activity = 0;

  constructor(deps: ClipboardDeps) {
    this.deps = deps;
  }

  noteActivity(): void {
    this.activity += 1;
  }

  /** Call right after `text` was written to the clipboard. */
  clearLater(text: string, delay = CLIPBOARD_CLEAR_MS): void {
    const seen = this.activity;
    this.deps.schedule(() => void this.clearIfUnchanged(text, seen), delay);
  }

  async clearIfUnchanged(text: string, seen: number): Promise<boolean> {
    const { clipboard } = this.deps;
    if (!clipboard || !this.deps.hasFocus()) return false;
    try {
      const untouched = seen === this.activity;
      if (!untouched) {
        if (!(await this.deps.canRead())) return false;
        if ((await clipboard.readText()) !== text) return false;
      }
      await clipboard.writeText("");
      return true;
    } catch {
      return false;
    }
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
  });
  const note = () => guard.noteActivity();
  document.addEventListener("copy", note, true);
  document.addEventListener("cut", note, true);
  window.addEventListener("blur", note);
  shared = guard;
  return guard;
}
