import { describe, expect, it } from "vitest";
import { gateRedirect, keyFileOverride, unlockPath, unlockPolicyLine } from "./sys-gate";

const ORIGIN = "https://sekret.example";
const at = (pathname: string, search = "") => ({ pathname, search });

describe("gateRedirect", () => {
  it("sends every page to setup until the server is set up", () => {
    expect(gateRedirect("uninitialised", at("/projects"), ORIGIN)).toBe("/setup");
    expect(gateRedirect("uninitialised", at("/unlock"), ORIGIN)).toBe("/setup");
    expect(gateRedirect("uninitialised", at("/setup"), ORIGIN)).toBeNull();
  });

  it("sends a sealed server to unlock, remembering where the user was going", () => {
    expect(gateRedirect("sealed", at("/org/users", "?page=2"), ORIGIN)).toBe("/unlock?return_to=%2Forg%2Fusers%3Fpage%3D2");
    expect(gateRedirect("sealed", at("/"), ORIGIN)).toBe("/unlock");
    expect(gateRedirect("sealed", at("/setup"), ORIGIN)).toBe("/unlock");
    expect(gateRedirect("sealed", at("/unlock", "?return_to=%2Fprojects"), ORIGIN)).toBeNull();
  });

  it("leaves an unlocked server alone, except to leave the unlock page", () => {
    expect(gateRedirect("unsealed", at("/projects"), ORIGIN)).toBeNull();
    expect(gateRedirect("unsealed", at("/setup"), ORIGIN)).toBeNull();
    expect(gateRedirect("unsealed", at("/unlock", "?return_to=%2Forg%2Fusers"), ORIGIN)).toBe("/org/users");
    expect(gateRedirect("unsealed", at("/unlock"), ORIGIN)).toBe("/");
  });

  it("never returns to another origin after unlocking", () => {
    expect(gateRedirect("unsealed", at("/unlock", "?return_to=https%3A%2F%2Fevil.example"), ORIGIN)).toBe("/");
    expect(gateRedirect("unsealed", at("/unlock", "?return_to=%2F%2Fevil.example"), ORIGIN)).toBe("/");
  });
});

describe("unlockPath", () => {
  it("omits a return to the root", () => {
    expect(unlockPath("/")).toBe("/unlock");
    expect(unlockPath("/projects/app/secrets")).toBe("/unlock?return_to=%2Fprojects%2Fapp%2Fsecrets");
  });
});

describe("unlockPolicyLine", () => {
  it("explains a remember policy with nothing remembered", () => {
    expect(unlockPolicyLine({ unlock_policy: "remember", remembered: false, configured: false })).toBe(
      "Unlock policy: remember. It is not remembered at the moment; unlocking now remembers it again.",
    );
  });

  it("does not claim a restart happened or that locking forgot the unlock", () => {
    const line = unlockPolicyLine({ unlock_policy: "remember", remembered: true, configured: false }) ?? "";
    expect(line).toContain("after locking by hand someone has to type the passphrase");
    expect(line).not.toMatch(/sealed|restarted/);
  });

  it("notes a policy set in configuration", () => {
    expect(unlockPolicyLine({ unlock_policy: "manual", remembered: false, configured: true })).toContain(
      "set in the server configuration",
    );
  });

  it("says nothing without a policy", () => {
    expect(unlockPolicyLine({ unlock_policy: null, remembered: false, configured: false })).toBeNull();
  });
});

describe("keyFileOverride", () => {
  it("flags a passphrase-mode server unlocked by a key file", () => {
    expect(keyFileOverride({ seal_mode: "passphrase", unsealed_by: "key-file" })).toBe(true);
    expect(keyFileOverride({ seal_mode: "key-file", unsealed_by: "key-file" })).toBe(false);
    expect(keyFileOverride({ seal_mode: "passphrase", unsealed_by: "passphrase" })).toBe(false);
    expect(keyFileOverride({ seal_mode: "passphrase", unsealed_by: null })).toBe(false);
  });
});
