import type { SealState, SysStatus } from "../types";
import type { MockControls } from "./controls";
import type { MockSys } from "./state";

export const MOCK_SETUP_CODE = "MOCK-SETUP-CODE";
export const MOCK_PASSPHRASE = "correct horse battery staple";
export const MOCK_VERSION = "0.0.0-mock";
/** Wrong passphrases allowed before the fake starts backing off, as the server does. */
export const MAX_FAILED_UNSEALS = 5;
/** Kept short so the countdown can be watched to its end. */
export const MOCK_BACKOFF_SECONDS = 3;
/** Typing this makes the fake answer as if another unlock were running. */
export const MOCK_KDF_BUSY_PASSPHRASE = "mock kdf busy";
/** Unlocking with this plays a server whose database was replaced, so the key it opens is not recognised. */
export const MOCK_FOREIGN_KEY_PASSPHRASE = "mock restored database";
/** CLI login codes starting with this need a fresh sign-in before they can be approved. */
export const MOCK_REAUTH_CODE_PREFIX = "AUTH";
/** Where every pending CLI login in the fake says it came from. */
export const MOCK_CLI_ADDRESS = "203.0.113.24";
export const MOCK_CLI_USER_AGENT = "sekret/0.0.0-mock (linux; x86_64)";
/** CLI login codes starting with this say they came from the approving browser's own address. */
export const MOCK_SAME_ADDRESS_CODE_PREFIX = "SAME";
/** The identity provider's logout page, with `?mock-idp-logout`. */
export const MOCK_IDP_LOGOUT_URL = "https://idp.example.test/logout";

export function mockSys(state: SealState = "unsealed"): MockSys {
  const initialised = state !== "uninitialised";
  return {
    state,
    mode: initialised ? "passphrase" : null,
    unlockPolicy: initialised ? "manual" : null,
    configured: false,
    remembered: false,
    unsealedBy: state === "unsealed" ? "passphrase" : null,
    webSetup: true,
    rememberFile: true,
    passphrase: initialised ? MOCK_PASSPHRASE : "",
    failedUnseals: 0,
    backoffUntil: 0,
  };
}

export function statusOf(sys: MockSys): SysStatus {
  const rememberAvailable = sys.rememberFile && sys.mode !== "key-file";
  if (sys.state === "uninitialised") {
    // Only what configuration has decided, so the wizard can skip it.
    const keyFile = sys.mode === "key-file";
    return {
      state: sys.state,
      seal_mode: sys.mode,
      unlock_policy: sys.configured && !keyFile ? sys.unlockPolicy : null,
      configured: sys.configured,
      remember_available: rememberAvailable,
      remembered: false,
      unsealed_by: null,
      web_setup: sys.webSetup,
      version: MOCK_VERSION,
    };
  }
  const passphrase = sys.mode === "passphrase";
  return {
    state: sys.state,
    seal_mode: sys.mode,
    unlock_policy: passphrase ? sys.unlockPolicy : null,
    configured: sys.configured,
    remember_available: rememberAvailable,
    remembered: passphrase && sys.remembered,
    unsealed_by: sys.state === "unsealed" ? sys.unsealedBy : null,
    web_setup: sys.webSetup,
    version: MOCK_VERSION,
  };
}

/** What anyone may see once set up: the state and little else, as the server's public status. */
export function publicStatusOf(sys: MockSys): SysStatus {
  if (sys.state === "uninitialised") return statusOf(sys);
  return {
    state: sys.state,
    seal_mode: null,
    unlock_policy: null,
    configured: false,
    remember_available: false,
    remembered: false,
    unsealed_by: null,
    web_setup: sys.webSetup,
    version: MOCK_VERSION,
  };
}

/** A fresh seal state for the controls, keeping the current one where they say nothing. */
export function sysFromControls(current: MockSys, controls: MockControls): MockSys {
  const sys = controls.state ? mockSys(controls.state) : { ...current };
  if (controls.webSetup !== undefined) sys.webSetup = controls.webSetup;
  if (controls.rememberFile !== undefined) sys.rememberFile = controls.rememberFile;
  if (controls.sealMode) sys.mode = controls.sealMode;
  if (controls.configuredPolicy) {
    sys.configured = true;
    sys.unlockPolicy = controls.configuredPolicy;
  }
  if (controls.unsealedBy && sys.state === "unsealed") sys.unsealedBy = controls.unsealedBy;
  return sys;
}

/** `20261030T224200Z`, as the server names backups. */
export function compactUtc(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}
