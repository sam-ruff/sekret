import type { PassphraseStrength } from "@/api/types";

export const MIN_PASSPHRASE_LENGTH = 12;
export const MIN_PASSPHRASE_SCORE = 3;

/** Words that make a passphrase easier to guess here, matching the server's list. */
const USER_INPUTS = ["sekret"];

/** The parts of a zxcvbn result the verdict depends on. */
export interface ZxcvbnVerdict {
  score: number;
  feedback: { warning: string | null; suggestions: string[] };
}

export type StrengthChecker = (passphrase: string) => PassphraseStrength;

/** Applies the server's rules to a zxcvbn result, so the meter and the server agree. */
export function assess(passphrase: string, verdict: ZxcvbnVerdict): PassphraseStrength {
  const longEnough = Array.from(passphrase).length >= MIN_PASSPHRASE_LENGTH;
  let warning = verdict.feedback.warning || null;
  let suggestions = [...verdict.feedback.suggestions];
  if (!longEnough) {
    warning ??= `Use at least ${MIN_PASSPHRASE_LENGTH} characters.`;
    suggestions = dedupeAdjacent(["Use a few words, avoid common phrases.", ...suggestions]);
  } else if (verdict.score < MIN_PASSPHRASE_SCORE && !warning && suggestions.length === 0) {
    suggestions.push("Add another word or two.");
  }
  return {
    score: verdict.score,
    acceptable: longEnough && verdict.score >= MIN_PASSPHRASE_SCORE,
    warning,
    suggestions,
  };
}

function dedupeAdjacent(items: string[]): string[] {
  return items.filter((item, i) => i === 0 || item !== items[i - 1]);
}

let pending: Promise<StrengthChecker> | undefined;

/** Loads zxcvbn and its dictionaries on first use, keeping them out of the main bundle. */
export function loadStrengthChecker(): Promise<StrengthChecker> {
  pending ??= (async () => {
    const [{ ZxcvbnFactory }, common, en] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      import("@zxcvbn-ts/language-en"),
    ]);
    const zxcvbn = new ZxcvbnFactory({
      translations: en.translations,
      graphs: common.adjacencyGraphs,
      dictionary: { ...common.dictionary, ...en.dictionary },
    });
    return (passphrase: string) => assess(passphrase, zxcvbn.check(passphrase, USER_INPUTS));
  })().catch((error: unknown) => {
    pending = undefined;
    throw error;
  });
  return pending;
}

export type PassphraseProblem = "short" | "weak" | "mismatch";

/**
 * Why the form cannot be submitted yet, if anything. A missing strength means the meter has not loaded,
 * in which case only the length is checked and the server decides.
 */
export function passphraseProblem(
  passphrase: string,
  confirm: string,
  strength: PassphraseStrength | null,
): PassphraseProblem | undefined {
  if (Array.from(passphrase).length < MIN_PASSPHRASE_LENGTH) return "short";
  if (strength && !strength.acceptable) return "weak";
  if (passphrase !== confirm) return "mismatch";
  return undefined;
}

export const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"] as const;

export function strengthLabel(score: number): string {
  return STRENGTH_LABELS[Math.max(0, Math.min(STRENGTH_LABELS.length - 1, score))];
}
