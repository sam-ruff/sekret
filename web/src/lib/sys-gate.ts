import type { SealState, SysStatus, UnlockPolicy, UnsealedBy } from "@/api/types";
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
        ? `Unlock policy: remember. It unlocks itself after a restart, but after locking by hand someone has to type the passphrase.${origin}`
        : `Unlock policy: remember. It is not remembered at the moment; unlocking now remembers it again.${origin}`;
    case "passphrase-file":
      return `Unlock policy: passphrase file. It unlocks itself at start unless the passphrase could not be read or it was locked by hand.${origin}`;
    default:
      return null;
  }
}

export const UNSEALED_BY_NAMES: Record<UnsealedBy, string> = {
  passphrase: "Passphrase, typed by a person",
  remember: "Remembered unlock",
  "key-file": "Root key file",
  "passphrase-file": "Passphrase file",
};

/** A key file given at start unlocks a passphrase-mode server without its passphrase. */
export function keyFileOverride(status: Pick<SysStatus, "seal_mode" | "unsealed_by">): boolean {
  return status.seal_mode === "passphrase" && status.unsealed_by === "key-file";
}
