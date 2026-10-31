import { ExternalLink, Settings2 } from "lucide-react";
import type { UnlockPolicy } from "@/api/types";
import { UNLOCK_POLICIES } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { DOCS_URL } from "@/lib/links";
import { POLICY_NAMES } from "@/lib/sys-gate";
import { cn } from "@/lib/utils";

const POLICY_TEXT: Record<UnlockPolicy, string> = {
  manual:
    "After every restart, including a power cut, someone unlocks the server by hand. The passphrase is only ever held in memory, which suits anyone who can respond to an alert.",
  remember:
    "Unlock by hand once. The server then keeps a key file on its own disk and unlocks itself after restarts until that file is lost, which suits a machine nobody is likely to take.",
  "passphrase-file":
    "The server reads the passphrase from a file or environment variable at start, so it comes back by itself after a power cut. Convenient, but the passphrase sits on disk.",
};

function PolicyTitle({ policy }: { policy: UnlockPolicy }) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
      {POLICY_NAMES[policy]}
      {policy === "manual" && <Badge variant="secondary">Most secure</Badge>}
    </div>
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
      <ExternalLink className="size-3.5" />
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
    <RadioGroup value={value} onValueChange={select} disabled={disabled} aria-label="Unlock policy" data-testid={`${idPrefix}-policy-options`}>
      {UNLOCK_POLICIES.map((policy) => (
        <label
          key={policy}
          htmlFor={`${idPrefix}-policy-${policy}`}
          className={cn(
            "flex gap-3 rounded-lg border p-4 transition-colors has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-primary/5",
            disabled ? "cursor-not-allowed opacity-70" : "cursor-pointer hover:bg-accent/50",
          )}
          data-testid={`${idPrefix}-policy-card-${policy}`}
        >
          <RadioGroupItem
            value={policy}
            id={`${idPrefix}-policy-${policy}`}
            className="mt-0.5"
            data-testid={`${idPrefix}-policy-${policy}`}
          />
          <div className="min-w-0 space-y-1">
            <PolicyTitle policy={policy} />
            <p className="text-sm text-muted-foreground">{POLICY_TEXT[policy]}</p>
          </div>
        </label>
      ))}
    </RadioGroup>
  );
}

/** The policy when it comes from server configuration, which the API cannot change. */
export function ConfiguredPolicy({ policy, testId }: { policy: UnlockPolicy | null | undefined; testId: string }) {
  return (
    <div className="flex gap-3 rounded-lg border bg-muted/40 p-4" data-testid={testId}>
      <Settings2 className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
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
  );
}
