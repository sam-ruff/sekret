import { describe, expect, it } from "vitest";
import { approveBlocker, codesMatch, isCompleteCode, normaliseUserCode, type ApproveState } from "./cli-code";

describe("approveBlocker", () => {
  const ready: ApproveState = { typed: "BCDF-2345", mismatch: false, loaded: true, otherAddress: false, confirmedOwn: false };

  it("is clear once everything is in place", () => {
    expect(approveBlocker(ready)).toBeUndefined();
    expect(approveBlocker({ ...ready, otherAddress: true, confirmedOwn: true })).toBeUndefined();
  });

  it("names the first thing still missing", () => {
    expect(approveBlocker({ ...ready, typed: "BCD" })).toBe("Type the code from your terminal to approve.");
    expect(approveBlocker({ ...ready, mismatch: true })).toBe("The code does not match this request.");
    expect(approveBlocker({ ...ready, loaded: false })).toBe("Checking the request…");
    expect(approveBlocker({ ...ready, otherAddress: true })).toBe('Tick "I started this sign-in myself" to approve.');
  });
});

describe("CLI login codes", () => {
  it("normalise case, spacing and the dash as the server does", () => {
    expect(normaliseUserCode(" bcdf 2345 ")).toBe("BCDF-2345");
    expect(normaliseUserCode("bcdf-2345")).toBe("BCDF-2345");
    expect(normaliseUserCode("BCDF2345")).toBe("BCDF-2345");
    expect(normaliseUserCode("bcd")).toBe("BCD");
  });

  it("are complete only with eight letters and digits", () => {
    expect(isCompleteCode("BCDF-2345")).toBe(true);
    expect(isCompleteCode("BCDF-234")).toBe(false);
    expect(isCompleteCode("BCDF-23456")).toBe(false);
  });

  it("match only the same code", () => {
    expect(codesMatch("bcdf 2345", "BCDF-2345")).toBe(true);
    expect(codesMatch("BCDF-2346", "BCDF-2345")).toBe(false);
    expect(codesMatch("BCDF", "BCDF")).toBe(false);
  });
});
