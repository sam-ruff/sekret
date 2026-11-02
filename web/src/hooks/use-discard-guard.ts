import { useCallback, useState } from "react";

export interface DiscardPrompt {
  open: boolean;
  onKeep: () => void;
  onDiscard: () => void;
}

export interface DiscardGuard {
  /** Runs `discard` at once when nothing is unsaved, otherwise asks first. */
  guard: (discard: () => void) => void;
  prompt: DiscardPrompt;
}

/** Asks before a form with unsaved input closes on Escape or an outside click. */
export function useDiscardGuard(dirty: boolean): DiscardGuard {
  const [pending, setPending] = useState<(() => void) | null>(null);

  const guard = useCallback(
    (discard: () => void) => {
      if (!dirty) {
        discard();
        return;
      }
      setPending(() => discard);
    },
    [dirty],
  );

  return {
    guard,
    prompt: {
      open: pending !== null,
      onKeep: () => setPending(null),
      onDiscard: () => {
        setPending(null);
        pending?.();
      },
    },
  };
}
