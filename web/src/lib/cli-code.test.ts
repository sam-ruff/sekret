import { describe, expect, it } from "vitest";
import { codesMatch, isCompleteCode, normaliseUserCode } from "./cli-code";

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
