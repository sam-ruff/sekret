import { useDeferredValue, useEffect, useMemo, useState } from "react";
import type { PassphraseStrength } from "@/api/types";
import { loadStrengthChecker, type StrengthChecker } from "@/lib/passphrase";

/** zxcvbn's verdict on the passphrase as it is typed, or null until the checker has loaded. */
export function usePassphraseStrength(passphrase: string): PassphraseStrength | null {
  const [checker, setChecker] = useState<StrengthChecker | null>(null);
  const deferred = useDeferredValue(passphrase);

  useEffect(() => {
    let live = true;
    loadStrengthChecker()
      .then((loaded) => {
        if (live) setChecker(() => loaded);
      })
      .catch(() => {
        // Without the meter the server's verdict on submit still applies.
      });
    return () => {
      live = false;
    };
  }, []);

  return useMemo(() => (checker && deferred ? checker(deferred) : null), [checker, deferred]);
}
