import { describe, expect, it } from "vitest";
import { assess } from "@/lib/passphrase";
import { MockBackend, MockError } from "./backend";
import { parseControls } from "./controls";
import { emptyState } from "./seed";
import type { MockState } from "./state";
import { MAX_FAILED_UNSEALS, MOCK_PASSPHRASE, MOCK_SETUP_CODE, mockSys } from "./sys";

/** A stand-in for zxcvbn: anything with a space scores 4. */
const check = (passphrase: string) => assess(passphrase, { score: passphrase.includes(" ") ? 4 : 1, feedback: { warning: null, suggestions: [] } });

function backend(sys = mockSys()): { b: MockBackend; state: MockState } {
  const state = emptyState(1_000_000);
  state.sys = sys;
  return { b: new MockBackend(state, () => 1_000_000), state };
}

function failure(fn: () => unknown): MockError {
  try {
    fn();
  } catch (error) {
    if (error instanceof MockError) return error;
    throw error;
  }
  throw new Error("expected a MockError");
}

describe("mock setup", () => {
  it("checks the setup code and passphrase strength, then unlocks", () => {
    const { b } = backend(mockSys("uninitialised"));
    const request = { setup_code: MOCK_SETUP_CODE, mode: "passphrase" as const, passphrase: "plum orbit gravel lantern" };
    expect(failure(() => b.init({ ...request, setup_code: "nope" }, check)).code).toBe("invalid_setup_code");
    const weak = failure(() => b.init({ ...request, passphrase: "password1234" }, check));
    expect(weak.code).toBe("weak_passphrase");
    expect(weak.extra.strength).toMatchObject({ acceptable: false });

    const response = b.init({ ...request, unlock_policy: "remember" }, check);
    expect(response.admin_token).toMatch(/^skt_/);
    expect(response.status).toMatchObject({ state: "unsealed", unlock_policy: "remember", remembered: true });
    expect(failure(() => b.init(request, check)).status).toBe(409);
  });

  it("refuses when web setup is off", () => {
    const { b } = backend({ ...mockSys("uninitialised"), webSetup: false });
    expect(failure(() => b.init({ setup_code: MOCK_SETUP_CODE, mode: "passphrase", passphrase: "a b c d e f g" }, check)).code).toBe(
      "setup_disabled",
    );
  });
});

describe("mock unsealing", () => {
  it("rate limits wrong passphrases", () => {
    const { b } = backend(mockSys("sealed"));
    for (let i = 0; i < MAX_FAILED_UNSEALS; i += 1) {
      expect(failure(() => b.unseal("wrong")).code).toBe("invalid_passphrase");
    }
    expect(failure(() => b.unseal("wrong")).status).toBe(429);
    expect(b.unseal(MOCK_PASSPHRASE).state).toBe("unsealed");
  });

  it("gates other routes until unlocked", () => {
    const { b } = backend(mockSys("sealed"));
    expect(failure(() => b.requireUnsealed()).code).toBe("sealed");
    b.unseal(MOCK_PASSPHRASE);
    expect(() => b.requireUnsealed()).not.toThrow();
  });
});

describe("mock administration", () => {
  it("keeps sealing and policy changes for organisation admins", () => {
    const { b, state } = backend();
    b.setMyOrgRole("backup-reader");
    expect(failure(() => b.seal()).status).toBe(403);
    expect(b.backup().filename).toMatch(/^sekret-backup-\d{8}T\d{6}Z\.skb$/);

    state.orgBindings = [{ principal_kind: "user", principal_id: state.me.id, role: "org-admin" }];
    expect(b.setUnlockPolicy("remember")).toMatchObject({ unlock_policy: "remember", remembered: true });
    expect(b.forgetUnlock().remembered).toBe(false);
    expect(b.seal().state).toBe("sealed");
  });

  it("refuses to change a configured policy", () => {
    const { b } = backend({ ...mockSys(), configured: true });
    expect(failure(() => b.setUnlockPolicy("remember")).status).toBe(409);
  });

  it("starts the backup with the real magic", () => {
    const { b } = backend();
    expect(new TextDecoder().decode(b.backup().bytes.slice(0, 4))).toBe("SKB1");
  });
});

describe("parseControls", () => {
  it("reads known values and ignores the rest", () => {
    expect(parseControls("?mock-state=sealed&mock-unlock=remember&mock-web-setup=false&mock-org-role=org-member")).toEqual({
      state: "sealed",
      configuredPolicy: "remember",
      webSetup: false,
      orgRole: "org-member",
    });
    expect(parseControls("?mock-state=melted&mock-unlock=never")).toEqual({
      state: undefined,
      configuredPolicy: undefined,
      webSetup: undefined,
      orgRole: undefined,
    });
  });
});
