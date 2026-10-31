import { describe, expect, it } from "vitest";
import { GENERIC_LOGIN_ERROR, loginErrorText } from "./login-errors";

describe("loginErrorText", () => {
  it("maps each server code to fixed text", () => {
    expect(loginErrorText("not_allowed")).toBe("Your account is not allowed to use sekret.");
    expect(loginErrorText("account_disabled")).toBe("Your sekret account has been disabled.");
    expect(loginErrorText("other_browser")).toContain("another browser");
    for (const code of ["provider_refused", "incomplete_response", "expired", "reauth_not_performed"]) {
      expect(loginErrorText(code)).not.toBe(GENERIC_LOGIN_ERROR);
    }
  });

  it("never echoes the parameter, even for prose or inherited property names", () => {
    for (const code of ["Call +1 555 0100 to verify your account", "constructor", "__proto__", "toString", ""]) {
      expect(loginErrorText(code)).toBe(GENERIC_LOGIN_ERROR);
    }
  });

  it("returns nothing without an error", () => {
    expect(loginErrorText(null)).toBeNull();
  });
});
