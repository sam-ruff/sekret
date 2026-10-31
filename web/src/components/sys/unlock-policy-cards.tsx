import { ExternalLink, Info, Settings2 } from "lucide-react";
import type { ReactNode } from "react";
import type { UnlockPolicy } from "@/api/types";
import { UNLOCK_POLICIES } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { DOCS_URL } from "@/lib/links";
import { POLICY_NAMES } from "@/lib/sys-gate";
import { cn } from "@/lib/utils";

const POLICY_TEXT: Record<UnlockPolicy, string> = {
  manual:
    "Someone types the passphrase after every restart, including after a power cut. The key is only ever in memory, so a stolen disk or backup is useless. Pair it with an alert so someone knows when to unlock.",
  remember:
    "Type the passphrase once. The server saves a key file on its own disk and unlocks itself after restarts. Leaked backups and database dumps stay safe, but anyone who takes the whole disk can unlock it unless a remember secret is configured.",
  "passphrase-file":
    "The server reads the passphrase from a file or environment variable at start and unlocks itself. Anyone who can read that file or the service's environment can unlock the server. You set the file up on the host.",
};

/** What the host needs before the policy works, shown when it is chosen. */
const POLICY_NEEDS: Partial<Record<UnlockPolicy, ReactNode>> = {
  remember: (
    <>
      Needs <code className="font-mono">seal.remember_file</code> set in the server configuration.
    </>
  ),
  "passphrase-file": (
    <>
      Before the next restart, put the passphrase in the file named by{" "}
      <code className="font-mono">seal.passphrase_file</code>, or in{" "}
      <code className="font-mono">SEKRET_UNLOCK_PASSPHRASE</code>. Without it the server stays locked.
    </>
  ),
};

function PolicyTitle({ policy, id }: { policy: UnlockPolicy; id?: string }) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
      <span id={id}>{POLICY_NAMES[policy]}</span>
      {policy === "manual" && <Badge variant="secondary">Default, most secure</Badge>}
    </div>
  );
}

function PolicyNeeds({ policy, testId }: { policy: UnlockPolicy; testId: string }) {
  const needs = POLICY_NEEDS[policy];
  if (!needs) return null;
  return (
    <p className="flex gap-2 rounded-md bg-muted/60 px-3 py-2 text-sm text-muted-foreground" data-testid={testId}>
      <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>{needs}</span>
    </p>
  );
}

export function UnlockDocsLink() {
  return (
    <a
      href={`${DOCS_URL}unlocking/`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 text-sm text-primary underline-offset-4 hover:underline"
      data-testid="unlock-docs-link"
    >
      Read more about unlocking
      <ExternalLink className="size-3.5" aria-hidden />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}

interface UnlockPolicyCardsProps {
  idPrefix: string;
  value: UnlockPolicy;
  onChange: (policy: UnlockPolicy) => void;
  disabled?: boolean;
}

export function UnlockPolicyCards({ idPrefix, value, onChange, disabled }: UnlockPolicyCardsProps) {
  const select = (next: string) => {
    const policy = UNLOCK_POLICIES.find((p) => p === next);
    if (policy) onChange(policy);
  };
  return (
    <div className="space-y-3">
      <RadioGroup value={value} onValueChange={select} disabled={disabled} aria-label="Unlock policy" data-testid={`${idPrefix}-policy-options`}>
        {UNLOCK_POLICIES.map((policy) => {
          const id = `${idPrefix}-policy-${policy}`;
          return (
            <label
              key={policy}
              htmlFor={id}
              className={cn(
                "flex gap-3 rounded-lg border p-4 transition-colors has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-primary/5",
                "has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring has-[:focus-visible]:ring-offset-2 has-[:focus-visible]:ring-offset-background",
                disabled ? "cursor-not-allowed opacity-70" : "cursor-pointer hover:bg-accent/50",
              )}
              data-testid={`${idPrefix}-policy-card-${policy}`}
            >
              <RadioGroupItem
                value={policy}
                id={id}
                aria-labelledby={`${id}-title`}
                aria-describedby={`${id}-text`}
                className="mt-0.5"
                data-testid={id}
              />
              <div className="min-w-0 space-y-1">
                <PolicyTitle policy={policy} id={`${id}-title`} />
                <p id={`${id}-text`} className="text-sm text-muted-foreground">
                  {POLICY_TEXT[policy]}
                </p>
              </div>
            </label>
          );
        })}
      </RadioGroup>
      <PolicyNeeds policy={value} testId={`${idPrefix}-policy-needs`} />
    </div>
  );
}

/** The policy when it comes from server configuration, which the API cannot change. */
export function ConfiguredPolicy({ policy, testId }: { policy: UnlockPolicy | null | undefined; testId: string }) {
  return (
    <div className="space-y-3">
      <div className="flex gap-3 rounded-lg border bg-muted/40 p-4" data-testid={testId}>
        <Settings2 className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
        <div className="min-w-0 space-y-1">
          {policy && <PolicyTitle policy={policy} />}
          {policy && <p className="text-sm text-muted-foreground">{POLICY_TEXT[policy]}</p>}
          <p className="text-sm text-muted-foreground">
            {policy
              ? "Set in the server configuration, so it cannot be changed here."
              : "The unlock policy is set in the server configuration, so it cannot be chosen here."}
          </p>
        </div>
      </div>
      {policy && <PolicyNeeds policy={policy} testId={`${testId}-needs`} />}
    </div>
  );
}
