import { afterEach, describe, expect, it, vi } from "vitest";
import { assess } from "@/lib/passphrase";
import { MockBackend, MockError } from "./backend";
import { parseControls } from "./controls";
import { emptyState } from "./seed";
import type { MockState } from "./state";
import {
  MAX_FAILED_UNSEALS,
  MOCK_BACKOFF_SECONDS,
  MOCK_CLI_ADDRESS,
  MOCK_FOREIGN_KEY_PASSPHRASE,
  MOCK_KDF_BUSY_PASSPHRASE,
  MOCK_PASSPHRASE,
  MOCK_SETUP_CODE,
  MOCK_VERSION,
  mockSys,
  publicStatusOf,
  statusOf,
  sysFromControls,
} from "./sys";

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

describe("mock status before setup", () => {
  it("reports the configured policy, as the server does", () => {
    const sys = sysFromControls(mockSys("uninitialised"), { configuredPolicy: "passphrase-file" });
    expect(statusOf(sys)).toMatchObject({
      state: "uninitialised",
      seal_mode: null,
      unlock_policy: "passphrase-file",
      configured: true,
      unsealed_by: null,
    });
    expect(statusOf(mockSys("uninitialised")).unlock_policy).toBeNull();
  });

  it("reports a configured key-file mode and sets up without a passphrase", () => {
    const { b } = backend(sysFromControls(mockSys("uninitialised"), { sealMode: "key-file" }));
    expect(b.sysStatus()).toMatchObject({ seal_mode: "key-file", unlock_policy: null });
    const response = b.init({ setup_code: MOCK_SETUP_CODE, mode: "key-file" }, check);
    expect(response.status).toMatchObject({ state: "unsealed", seal_mode: "key-file", unsealed_by: "key-file" });
  });

  it("gives the admin token's expiry", () => {
    const { b } = backend(mockSys("uninitialised"));
    const response = b.init({ setup_code: MOCK_SETUP_CODE, mode: "passphrase", passphrase: "plum orbit gravel lantern" }, check);
    expect(response.admin_token_expires_at).toBeGreaterThan(Date.now() / 1000);
    expect(response.status.unsealed_by).toBe("passphrase");
  });
});

describe("mock unsealing", () => {
  afterEach(() => vi.useRealTimers());

  it("backs off after wrong passphrases, then lets the right one through", () => {
    vi.useFakeTimers();
    const { b } = backend(mockSys("sealed"));
    for (let i = 0; i < MAX_FAILED_UNSEALS; i += 1) {
      expect(failure(() => b.unseal("wrong")).code).toBe("invalid_passphrase");
    }
    const refused = failure(() => b.unseal(MOCK_PASSPHRASE));
    expect(refused).toMatchObject({ status: 429, code: "passphrase_backoff" });
    expect(refused.message).toContain(`${MOCK_BACKOFF_SECONDS} seconds`);
    vi.advanceTimersByTime(MOCK_BACKOFF_SECONDS * 1000);
    expect(b.unseal(MOCK_PASSPHRASE)).toMatchObject({ state: "unsealed", unsealed_by: "passphrase" });
  });

  it("answers kdf_busy for the busy stand-in", () => {
    const { b } = backend(mockSys("sealed"));
    expect(failure(() => b.unseal(MOCK_KDF_BUSY_PASSPHRASE))).toMatchObject({ status: 429, code: "kdf_busy" });
  });

  it("answers root_key_not_recognised for the restored-database stand-in and stays locked", () => {
    const { b } = backend(mockSys("sealed"));
    expect(failure(() => b.unseal(MOCK_FOREIGN_KEY_PASSPHRASE))).toMatchObject({ status: 409, code: "root_key_not_recognised" });
    expect(b.sysStatus().state).toBe("sealed");
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
    expect(b.setUnlockPolicy("remember", MOCK_PASSPHRASE)).toMatchObject({ unlock_policy: "remember", remembered: true });
    expect(b.forgetUnlock().remembered).toBe(false);
    expect(b.seal()).toMatchObject({ state: "sealed", unsealed_by: null });
  });

  it("asks for the passphrase before weakening the policy", () => {
    const { b } = backend();
    expect(failure(() => b.setUnlockPolicy("remember"))).toMatchObject({ status: 400, code: "passphrase_required" });
    expect(failure(() => b.setUnlockPolicy("passphrase-file", "wrong"))).toMatchObject({
      status: 401,
      code: "invalid_passphrase",
    });
    expect(b.setUnlockPolicy("passphrase-file", MOCK_PASSPHRASE).unlock_policy).toBe("passphrase-file");
    expect(b.setUnlockPolicy("manual").unlock_policy).toBe("manual");
  });

  it("keeps a remembered unlock through sealing", () => {
    const { b } = backend();
    b.setUnlockPolicy("remember", MOCK_PASSPHRASE);
    expect(b.seal()).toMatchObject({ state: "sealed", remembered: true });
  });

  it("says who is an organisation admin", () => {
    const { b } = backend();
    expect(b.me()).toMatchObject({ is_org_admin: true, org_roles: ["org-admin"] });
    b.setMyOrgRole("backup-reader");
    expect(b.me()).toMatchObject({ is_org_admin: false, org_roles: ["backup-reader"] });
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

describe("mock CLI approval", () => {
  it("asks for a fresh sign-in for reauthentication codes", () => {
    const { b } = backend();
    const refused = failure(() => b.approveCli("AUTH-2345"));
    expect(refused).toMatchObject({ status: 403, code: "reauthentication_required" });
    expect(refused.message).toContain("/auth/login?reauth=1&return_to=%2Fcli-login%3Fcode%3DAUTH-2345");
    b.signIn(true);
    expect(() => b.approveCli("AUTH-2345")).not.toThrow();
    expect(() => b.approveCli("BCDF-2345")).not.toThrow();
  });
});

describe("parseControls", () => {
  it("reads known values and ignores the rest", () => {
    expect(
      parseControls(
        "?mock-state=sealed&mock-unlock=remember&mock-web-setup=false&mock-org-role=org-member&mock-seal-mode=key-file&mock-unsealed-by=key-file",
      ),
    ).toEqual({
      state: "sealed",
      configuredPolicy: "remember",
      webSetup: false,
      orgRole: "org-member",
      sealMode: "key-file",
      unsealedBy: "key-file",
    });
    expect(parseControls("?mock-state=melted&mock-unlock=never&mock-seal-mode=paper")).toEqual({
      state: undefined,
      configuredPolicy: undefined,
      webSetup: undefined,
      orgRole: undefined,
      sealMode: undefined,
      unsealedBy: undefined,
    });
  });
});

describe("mock public status", () => {
  it("reports a remember file before setup and to admins, and never for a key-file server", () => {
    expect(statusOf(mockSys("uninitialised")).remember_available).toBe(true);
    expect(statusOf({ ...mockSys("uninitialised"), rememberFile: false }).remember_available).toBe(false);
    expect(statusOf({ ...mockSys(), mode: "key-file" }).remember_available).toBe(false);
    expect(publicStatusOf(mockSys("uninitialised")).remember_available).toBe(true);
    expect(parseControls("?mock-remember-file=false&mock-oidc=false")).toMatchObject({ rememberFile: false, oidc: false });
  });

  it("shows anyone only the state, web setup and version once set up", () => {
    const sys = { ...mockSys(), unlockPolicy: "remember" as const, remembered: true };
    expect(publicStatusOf(sys)).toEqual({
      state: "unsealed",
      seal_mode: null,
      unlock_policy: null,
      configured: false,
      remember_available: false,
      remembered: false,
      unsealed_by: null,
      web_setup: true,
      version: MOCK_VERSION,
    });
    expect(statusOf(sys)).toMatchObject({
      remembered: true,
      unsealed_by: "passphrase",
      unlock_policy: "remember",
      remember_available: true,
    });
  });

  it("keeps what configuration decided before setup, for the wizard", () => {
    const sys = { ...mockSys("uninitialised"), mode: "key-file" as const };
    expect(publicStatusOf(sys)).toEqual(statusOf(sys));
  });
});

describe("mock CLI login", () => {
  it("describes a waiting login and refuses unknown codes", () => {
    const { b } = backend();
    const pending = b.pendingCli("bcdf 2345");
    expect(pending.requested_from_ip).toBe(MOCK_CLI_ADDRESS);
    expect(pending.code_hint).toBeNull();
    expect(pending.expires_at).toBeGreaterThan(pending.created_at);
    expect(failure(() => b.pendingCli("XXXX-0000")).status).toBe(404);
    expect(failure(() => b.approveCli("BCDF")).status).toBe(404);
  });
});
