import type { SealState, SysStatus, UnlockPolicy, UnsealedBy } from "@/api/types";
import { safeReturnTo } from "./safe-url";

export const SETUP_PATH = "/setup";
export const UNLOCK_PATH = "/unlock";

interface Place {
  pathname: string;
  search: string;
}

/** Navigation state for the unlock page; `interrupted` when someone was signed in as the server locked. */
export interface UnlockState {
  interrupted?: boolean;
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
