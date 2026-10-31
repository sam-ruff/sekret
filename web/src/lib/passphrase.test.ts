import { describe, expect, it } from "vitest";
import {
  assess,
  hasControlCharacters,
  loadStrengthChecker,
  passphraseBytes,
  passphraseProblem,
  precheck,
  problemText,
  strengthLabel,
} from "./passphrase";

const verdict = (score: number, warning: string | null = null, suggestions: string[] = []) => ({
  score,
  feedback: { warning, suggestions },
});

describe("assess", () => {
  it("accepts only a long passphrase scoring 4, as the server does", () => {
    expect(assess("plum orbit gravel lantern", verdict(4))).toEqual({
      score: 4,
      acceptable: true,
      warning: null,
      suggestions: [],
    });
    expect(assess("twelve chars", verdict(3)).acceptable).toBe(false);
  });

  it("refuses a short passphrase whatever its score, as the server does", () => {
    const strength = assess("Zq9!vL2#", verdict(4));
    expect(strength.acceptable).toBe(false);
    expect(strength.warning).toBe("Use at least 12 characters.");
    expect(strength.suggestions[0]).toBe("Use a few words, avoid common phrases.");
  });

  it("keeps zxcvbn's own warning for a short passphrase", () => {
    expect(assess("password", verdict(0, "This is a top-10 common password.")).warning).toBe(
      "This is a top-10 common password.",
    );
  });

  it("suggests more words when a weak passphrase gets no other feedback", () => {
    expect(assess("aaaaaaaaaaaaaa", verdict(2)).suggestions).toEqual(["Add another word or two."]);
  });

  it("counts characters, not UTF-16 units", () => {
    expect(assess("🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑", verdict(4)).acceptable).toBe(false);
  });
});

describe("loadStrengthChecker", () => {
  it("scores with zxcvbn and its English dictionaries", async () => {
    const check = await loadStrengthChecker();
    const weak = check("password1234");
    expect(weak.acceptable).toBe(false);
    expect(weak.warning).toMatch(/commonly used password/);
    expect(check("plum orbit gravel lantern").acceptable).toBe(true);
    expect(check("sekretsekret").acceptable).toBe(false);
  });

  it("refuses control characters and oversized input before zxcvbn", async () => {
    const check = await loadStrengthChecker();
    expect(check("plum orbit\tgravel lantern")).toMatchObject({ acceptable: false, warning: expect.stringMatching(/control characters/) });
    expect(check("plum orbit gravel lantern\u007f").acceptable).toBe(false);
    expect(check("a".repeat(1025))).toMatchObject({ acceptable: false, warning: "Use at most 1024 bytes." });
  });
});

describe("precheck", () => {
  it("counts bytes, not characters", () => {
    expect(passphraseBytes("é")).toBe(2);
    expect(precheck("é".repeat(512))).toBeNull();
    expect(precheck("é".repeat(513))?.warning).toBe("Use at most 1024 bytes.");
  });

  it("finds control characters but allows spaces and punctuation", () => {
    expect(hasControlCharacters("plum orbit, gravel! lantern?")).toBe(false);
    expect(hasControlCharacters("line\nbreak")).toBe(true);
  });
});

describe("passphraseProblem", () => {
  const strong = { score: 4, acceptable: true, warning: null, suggestions: [] };
  const weak = { score: 1, acceptable: false, warning: null, suggestions: [] };

  it("checks length, strength, then the confirmation", () => {
    expect(passphraseProblem("short", "short", strong)).toBe("short");
    expect(passphraseProblem("password1234", "password1234", weak)).toBe("weak");
    expect(passphraseProblem("plum orbit gravel", "plum orbit", strong)).toBe("mismatch");
    expect(passphraseProblem("plum orbit gravel", "plum orbit gravel", strong)).toBeUndefined();
  });

  it("refuses control characters even before the meter has loaded", () => {
    expect(passphraseProblem("plum orbit\ngravel", "plum orbit\ngravel", null)).toBe("weak");
  });

  it("says why the form cannot be sent yet", () => {
    expect(problemText("mismatch")).toBe("Type the passphrase again to continue.");
  });

  it("leaves strength to the server until the meter has loaded", () => {
    expect(passphraseProblem("password1234", "password1234", null)).toBeUndefined();
  });
});

describe("strengthLabel", () => {
  it("clamps out-of-range scores", () => {
    expect(strengthLabel(0)).toBe("Very weak");
    expect(strengthLabel(4)).toBe("Strong");
    expect(strengthLabel(9)).toBe("Strong");
  });
});
