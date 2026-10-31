import { CheckCircle2 } from "lucide-react";
import type { PassphraseStrength } from "@/api/types";
import { MIN_PASSPHRASE_LENGTH, STRENGTH_LABELS, strengthLabel } from "@/lib/passphrase";
import { cn } from "@/lib/utils";

function barColour(strength: PassphraseStrength): string {
  if (strength.acceptable) return "bg-success";
  if (strength.score >= 2) return "bg-warning";
  return "bg-destructive";
}

interface PassphraseMeterProps {
  strength: PassphraseStrength | null;
  testId?: string;
  /** For the input's `aria-describedby`; the region is announced politely as it changes. */
  id?: string;
}

/** A score bar with zxcvbn's warning and suggestions. */
export function PassphraseMeter({ strength, testId = "passphrase-meter", id }: PassphraseMeterProps) {
  return (
    <div id={id} aria-live="polite" data-testid={`${testId}-region`}>
      <MeterBody strength={strength} testId={testId} />
    </div>
  );
}

function MeterBody({ strength, testId }: { strength: PassphraseStrength | null; testId: string }) {
  if (!strength) {
    return (
      <p className="text-sm text-muted-foreground" data-testid={testId}>
        At least {MIN_PASSPHRASE_LENGTH} characters. A few unrelated words work well.
      </p>
    );
  }
  const filled = strength.score + 1;
  return (
    <div className="space-y-2" data-testid={testId} data-score={strength.score} data-acceptable={strength.acceptable}>
      <div className="flex gap-1" aria-hidden>
        {STRENGTH_LABELS.map((label, i) => (
          <div key={label} className={cn("h-1.5 flex-1 rounded-full bg-muted", i < filled && barColour(strength))} />
        ))}
      </div>
      <div className="flex items-center justify-between gap-2 text-xs">
        <span className="font-medium" data-testid={`${testId}-label`}>
          {strengthLabel(strength.score)}
        </span>
        {strength.acceptable && (
          <span className="flex items-center gap-1 text-success">
            <CheckCircle2 className="size-3.5" />
            Strong enough
          </span>
        )}
      </div>
      <StrengthFeedback strength={strength} testId={`${testId}-feedback`} />
    </div>
  );
}

export function StrengthFeedback({ strength, testId }: { strength: PassphraseStrength; testId?: string }) {
  if (!strength.warning && strength.suggestions.length === 0) return null;
  return (
    <div className="space-y-1 text-xs text-muted-foreground" data-testid={testId}>
      {strength.warning && <p className="text-foreground">{strength.warning}</p>}
      {strength.suggestions.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-4">
          {strength.suggestions.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
