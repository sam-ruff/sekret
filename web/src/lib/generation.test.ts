import { describe, expect, it } from "vitest";
import {
  daysUntil,
  describeEffectiveGenerator,
  describeGenerator,
  describeRotation,
  draftFromPolicy,
  draftProblem,
  isPolicyOff,
  lengthProblem,
  overrideFromDraft,
  policyFromDraft,
} from "./generation";

describe("generation model", () => {
  it("describes generators and rotation in words", () => {
    expect(describeGenerator(null)).toBe("32 alphanumeric characters");
    expect(describeGenerator({ length: 64, charset: "hex" })).toBe("64 hex characters");
    expect(describeGenerator({ length: 6, charset: "numeric" })).toBe("6 digit characters");
    expect(describeRotation(null)).toBe("Not rotated automatically");
    expect(describeRotation(1)).toBe("Rotated every day");
    expect(describeRotation(90)).toBe("Rotated every 90 days");
  });

  it("does not claim a generator is set when only the built-in default applies", () => {
    expect(describeEffectiveGenerator(null)).toBe("No generator chosen. Rotating now makes 32 random letters and digits.");
    expect(describeEffectiveGenerator({ length: 64, charset: "hex" })).toBe("Generates 64 hex characters");
  });

  it("treats no generator and no rotation as off", () => {
    expect(isPolicyOff({})).toBe(true);
    expect(isPolicyOff({ generator: null, rotation_days: null })).toBe(true);
    expect(isPolicyOff({ rotation_days: 7 })).toBe(false);
  });

  it("round-trips a policy through the editable draft", () => {
    const policy = { generator: { length: 40, charset: "symbols" as const }, rotation_days: 30 };
    expect(policyFromDraft(draftFromPolicy(policy))).toEqual(policy);
    expect(policyFromDraft({ ...draftFromPolicy(policy), rotate: false })).toEqual({ ...policy, rotation_days: null });
    expect(draftFromPolicy(undefined)).toMatchObject({ length: "32", charset: "alphanumeric", rotate: false });
  });

  it("builds tagged overrides", () => {
    const draft = draftFromPolicy({ generator: { length: 16, charset: "numeric" }, rotation_days: 7 });
    expect(overrideFromDraft(false, draft)).toEqual({ mode: "inherit" });
    expect(overrideFromDraft(true, draft)).toEqual({ mode: "custom", generator: { length: 16, charset: "numeric" }, rotation_days: 7 });
  });

  it("checks the bounds the server enforces", () => {
    expect(lengthProblem("8")).toBeUndefined();
    expect(lengthProblem("512")).toBeUndefined();
    expect(lengthProblem("7")).toMatch(/between 8 and 512/);
    expect(lengthProblem("513")).toBeDefined();
    expect(lengthProblem("1.5")).toBeDefined();
    const ok = draftFromPolicy({ generator: null, rotation_days: 1 });
    expect(draftProblem(ok)).toBeUndefined();
    expect(draftProblem({ ...ok, days: "0" })).toMatch(/between 1 and 3650/);
    expect(draftProblem({ ...ok, days: "3651" })).toBeDefined();
    expect(draftProblem({ ...ok, rotate: false, days: "0" })).toBeUndefined();
  });

  it("counts days until a rotation, rounding up", () => {
    expect(daysUntil(1000 + 86400, 1000)).toBe(1);
    expect(daysUntil(1000 + 86401, 1000)).toBe(2);
    expect(daysUntil(500, 1000)).toBe(0);
  });
});
