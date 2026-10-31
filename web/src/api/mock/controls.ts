import type { SealMode, SealState, UnlockPolicy, UnsealedBy } from "../types";
import { SEAL_MODES, UNLOCK_POLICIES, UNSEALED_BY } from "../types";

const STORAGE_KEY = "sekret-mock-controls";
const PREFIX = "mock-";
const SEAL_STATES: readonly SealState[] = ["uninitialised", "sealed", "unsealed"];

/** Query parameters that pick the fake server's situation, such as `?mock-state=sealed`. */
export interface MockControls {
  state?: SealState;
  webSetup?: boolean;
  /** A seal mode fixed by configuration, such as `key-file` before setup. */
  sealMode?: SealMode;
  /** An unlock policy fixed by configuration. */
  configuredPolicy?: UnlockPolicy;
  /** How the running server was unlocked. */
  unsealedBy?: UnsealedBy;
  /** Replaces the signed-in user's organisation roles. */
  orgRole?: string;
}

export function parseControls(search: string): MockControls {
  const params = new URLSearchParams(search);
  const webSetup = params.get("mock-web-setup");
  return {
    state: SEAL_STATES.find((s) => s === params.get("mock-state")),
    webSetup: webSetup === null ? undefined : webSetup !== "false",
    sealMode: SEAL_MODES.find((m) => m === params.get("mock-seal-mode")),
    configuredPolicy: UNLOCK_POLICIES.find((p) => p === params.get("mock-unlock")),
    unsealedBy: UNSEALED_BY.find((u) => u === params.get("mock-unsealed-by")),
    orgRole: params.get("mock-org-role") ?? undefined,
  };
}

export function hasControls(controls: MockControls): boolean {
  return Object.values(controls).some((value) => value !== undefined);
}

/** Moves `mock-` parameters out of the address bar before the app reads it, so they never reach return links. */
export function stashControls(): void {
  const url = new URL(window.location.href);
  const picked = new URLSearchParams();
  url.searchParams.forEach((value, key) => {
    if (key.startsWith(PREFIX)) picked.set(key, value);
  });
  if (picked.size === 0) return;
  picked.forEach((_, key) => url.searchParams.delete(key));
  try {
    window.sessionStorage.setItem(STORAGE_KEY, picked.toString());
  } catch {
    // Without storage the controls are simply ignored.
  }
  window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
}

/** The stashed controls, once; the fake server applies them and keeps the result for the session. */
export function takeControls(): MockControls {
  try {
    const saved = window.sessionStorage.getItem(STORAGE_KEY);
    if (saved === null) return {};
    window.sessionStorage.removeItem(STORAGE_KEY);
    return parseControls(saved);
  } catch {
    return {};
  }
}
