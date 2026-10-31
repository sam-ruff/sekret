import { describe, expect, it } from "vitest";
import { assess, loadStrengthChecker, passphraseProblem, strengthLabel } from "./passphrase";

const verdict = (score: number, warning: string | null = null, suggestions: string[] = []) => ({
  score,
  feedback: { warning, suggestions },
});

describe("assess", () => {
  it("accepts a long passphrase scoring 3 or more", () => {
    expect(assess("plum orbit gravel lantern", verdict(4))).toEqual({
      score: 4,
      acceptable: true,
      warning: null,
      suggestions: [],
    });
    expect(assess("twelve chars", verdict(3)).acceptable).toBe(true);
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
