import type { SealState, SysStatus, UnlockPolicy } from "@/api/types";
import { safeReturnTo } from "./safe-url";

export const SETUP_PATH = "/setup";
export const UNLOCK_PATH = "/unlock";

interface Place {
  pathname: string;
  search: string;
}

export function unlockPath(returnTo: string): string {
  if (returnTo === "/" || returnTo === "") return UNLOCK_PATH;
  return `${UNLOCK_PATH}?return_to=${encodeURIComponent(returnTo)}`;
}

/** Where the app must go before it can show `place`, or null to stay. */
export function gateRedirect(state: SealState, place: Place, origin = window.location.origin): string | null {
  if (state === "uninitialised") return place.pathname === SETUP_PATH ? null : SETUP_PATH;
  if (state === "sealed") {
    if (place.pathname === UNLOCK_PATH) return null;
    if (place.pathname === SETUP_PATH) return UNLOCK_PATH;
    return unlockPath(`${place.pathname}${place.search}`);
  }
  if (place.pathname !== UNLOCK_PATH) return null;
  return safeReturnTo(new URLSearchParams(place.search).get("return_to"), origin);
}

export const POLICY_NAMES: Record<UnlockPolicy, string> = {
  manual: "Manual",
  remember: "Remember",
  "passphrase-file": "Passphrase file",
};

/** One line on how this server gets unlocked, for the unlock page. */
export function unlockPolicyLine(status: Pick<SysStatus, "unlock_policy" | "remembered" | "configured">): string | null {
  const origin = status.configured ? " This is set in the server configuration." : "";
  switch (status.unlock_policy) {
    case "manual":
      return `Unlock policy: manual. The server needs its passphrase after every start.${origin}`;
    case "remember":
      return status.remembered
        ? `Unlock policy: remember. It unlocks itself after a restart, but not after being sealed by hand.${origin}`
        : `Unlock policy: remember. The remembered unlock was lost; unlocking now will remember it again.${origin}`;
    case "passphrase-file":
      return `Unlock policy: passphrase file. It unlocks itself at start unless the passphrase could not be read or it was sealed by hand.${origin}`;
    default:
      return null;
  }
}
