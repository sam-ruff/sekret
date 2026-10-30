import type { Charset, Generator, PolicyOverride, SecretPolicy } from "@/api/types";

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 512;
export const MAX_ROTATION_DAYS = 3650;
export const DEFAULT_GENERATOR: Generator = { length: 32, charset: "alphanumeric" };

export const CHARSETS: readonly { value: Charset; label: string; hint: string }[] = [
  { value: "alphanumeric", label: "Letters and digits", hint: "A-Z a-z 0-9" },
  { value: "symbols", label: "With symbols", hint: "Adds !#%+,-.:=@^_~" },
  { value: "hex", label: "Hexadecimal", hint: "0-9 a-f" },
  { value: "base64url", label: "Base64 URL", hint: "A-Z a-z 0-9 - _" },
  { value: "numeric", label: "Digits only", hint: "0-9, for PINs" },
];

const CHARSET_NOUNS: Record<Charset, string> = {
  alphanumeric: "alphanumeric",
  symbols: "letter, digit and symbol",
  hex: "hex",
  base64url: "base64url",
  numeric: "digit",
};

/** The editable form of a generator and rotation period, held as strings while typed. */
export interface PolicyDraft {
  length: string;
  charset: Charset;
  rotate: boolean;
  days: string;
}

export const DEFAULT_DRAFT: PolicyDraft = { length: "32", charset: "alphanumeric", rotate: false, days: "90" };

export function describeGenerator(generator: Generator | null | undefined): string {
  const g = generator ?? DEFAULT_GENERATOR;
  return `${g.length} ${CHARSET_NOUNS[g.charset ?? "alphanumeric"]} characters`;
}

export function describeRotation(days: number | null | undefined): string {
  if (!days) return "Not rotated automatically";
  return days === 1 ? "Rotated every day" : `Rotated every ${days} days`;
}

export function isPolicyOff(policy: SecretPolicy): boolean {
  return !policy.generator && !policy.rotation_days;
}

export function lengthProblem(length: string): string | undefined {
  const n = Number(length);
  if (!/^\d+$/.test(length.trim()) || n < MIN_LENGTH || n > MAX_LENGTH) {
    return `Length must be between ${MIN_LENGTH} and ${MAX_LENGTH}`;
  }
  return undefined;
}

export function daysProblem(days: string): string | undefined {
  const n = Number(days);
  if (!/^\d+$/.test(days.trim()) || n < 1 || n > MAX_ROTATION_DAYS) {
    return `Rotation must be between 1 and ${MAX_ROTATION_DAYS} days`;
  }
  return undefined;
}

export function draftProblem(draft: PolicyDraft): string | undefined {
  return lengthProblem(draft.length) ?? (draft.rotate ? daysProblem(draft.days) : undefined);
}

export function generatorFromDraft(draft: Pick<PolicyDraft, "length" | "charset">): Generator {
  return { length: Number(draft.length), charset: draft.charset };
}

export function draftFromPolicy(policy: SecretPolicy | undefined): PolicyDraft {
  const generator = policy?.generator ?? DEFAULT_GENERATOR;
  return {
    length: String(generator.length),
    charset: generator.charset ?? "alphanumeric",
    rotate: !!policy?.rotation_days,
    days: String(policy?.rotation_days ?? DEFAULT_DRAFT.days),
  };
}

export function policyFromDraft(draft: PolicyDraft): SecretPolicy {
  return {
    generator: generatorFromDraft(draft),
    rotation_days: draft.rotate ? Number(draft.days) : null,
  };
}

export function overrideFromDraft(custom: boolean, draft: PolicyDraft): PolicyOverride {
  return custom ? { mode: "custom", ...policyFromDraft(draft) } : { mode: "inherit" };
}

/** Days until a unix time, rounded up so "due tomorrow" never reads as zero. */
export function daysUntil(at: number, nowSeconds = Date.now() / 1000): number {
  return Math.max(0, Math.ceil((at - nowSeconds) / 86400));
}
