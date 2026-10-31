import type { SealState, SysStatus } from "../types";
import type { MockControls } from "./controls";
import type { MockSys } from "./state";

export const MOCK_SETUP_CODE = "MOCK-SETUP-CODE";
export const MOCK_PASSPHRASE = "correct horse battery staple";
export const MOCK_VERSION = "0.0.0-mock";
/** Wrong passphrases allowed before the fake answers 429, mimicking the server's rate limit. */
export const MAX_FAILED_UNSEALS = 5;

export function mockSys(state: SealState = "unsealed"): MockSys {
  const initialised = state !== "uninitialised";
  return {
    state,
    mode: initialised ? "passphrase" : null,
    unlockPolicy: initialised ? "manual" : null,
    configured: false,
    remembered: false,
    webSetup: true,
    passphrase: initialised ? MOCK_PASSPHRASE : "",
    failedUnseals: 0,
  };
}

export function statusOf(sys: MockSys): SysStatus {
  const passphrase = sys.mode === "passphrase";
  return {
    state: sys.state,
    seal_mode: sys.mode,
    unlock_policy: passphrase ? sys.unlockPolicy : null,
    configured: sys.configured,
    remembered: passphrase && sys.remembered,
    web_setup: sys.webSetup,
    version: MOCK_VERSION,
  };
}

/** A fresh seal state for the controls, keeping the current one where they say nothing. */
export function sysFromControls(current: MockSys, controls: MockControls): MockSys {
  const sys = controls.state ? mockSys(controls.state) : { ...current };
  if (controls.webSetup !== undefined) sys.webSetup = controls.webSetup;
  if (controls.configuredPolicy) {
    sys.configured = true;
    if (sys.state !== "uninitialised") sys.unlockPolicy = controls.configuredPolicy;
  }
  return sys;
}

/** `20261030T224200Z`, as the server names backups. */
export function compactUtc(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}
