import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, onSealResponse, redirectToLogin, unwrap } from "@/api/client";
import { keys } from "@/hooks/queries";
import { dismissNotClearedNotice, hasNotClearedNotice } from "./clipboard";
import { browserNavigation, isLeaving, stopLeaving } from "./leaving";
import { signOut } from "./session";

const IDP_LOGOUT = "https://idp.example.test/logout?client_id=sekret";

function deferred<T>() {
  let resolve: (value: T) => void = () => undefined;
  let reject: (error: unknown) => void = () => undefined;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** What any API call does when it finds the session gone. */
async function hitExpiredSession(): Promise<void> {
  const pending = Promise.resolve({ error: { error: "unauthorised" }, response: new Response(null, { status: 401 }) });
  await expect(unwrap(pending)).rejects.toMatchObject({ status: 401 });
}

async function hitSealedServer(): Promise<void> {
  const pending = Promise.resolve({ error: { error: "sealed" }, response: new Response(null, { status: 503 }) });
  await expect(unwrap(pending)).rejects.toMatchObject({ status: 503 });
}

describe("signOut", () => {
  afterEach(() => {
    stopLeaving();
    vi.restoreAllMocks();
  });

  it("reaches the identity provider's logout once, whatever else answers 401 or 503 meanwhile", async () => {
    const assign = vi.spyOn(browserNavigation, "assign").mockImplementation(() => undefined);
    const sealed = vi.fn();
    const stopWatching = onSealResponse(sealed);
    const logout = deferred<{ logout_url: string }>();
    const client = new QueryClient();
    client.setQueryData(keys.secretValues("p", "dev", "/"), new Map([["K", "v"]]));

    const done = signOut(client, { logout: () => logout.promise, assign: (url) => browserNavigation.assign(url) });
    expect(isLeaving()).toBe(true);
    // Queries still in flight come back with the session already gone, or the server sealed.
    await hitExpiredSession();
    await hitSealedServer();
    void redirectToLogin();
    logout.resolve({ logout_url: IDP_LOGOUT });
    await done;

    expect(assign).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith(IDP_LOGOUT);
    expect(sealed).not.toHaveBeenCalled();
    expect(client.getQueryData(keys.secretValues("p", "dev", "/"))).toBeUndefined();
    stopWatching();
  });

  it("goes to the login page when there is no provider logout, or an unsafe one", async () => {
    const assign = vi.fn();
    await signOut(new QueryClient(), { logout: () => Promise.resolve({ logout_url: null }), assign });
    stopLeaving();
    await signOut(new QueryClient(), { logout: () => Promise.resolve({ logout_url: "javascript:alert(1)" }), assign });
    expect(assign.mock.calls).toEqual([["/login"], ["/login"]]);
  });

  it("treats an already ended session as signed out", async () => {
    const assign = vi.fn();
    const logout = () => Promise.reject(new ApiError("gone", 401, "unauthorised"));
    await signOut(new QueryClient(), { logout, assign });
    expect(assign).toHaveBeenCalledWith("/login");
  });

  it("stays put and lets navigation happen again when the server refuses", async () => {
    const assign = vi.fn();
    const logout = () => Promise.reject(new ApiError("boom", 500, "internal"));
    await signOut(new QueryClient(), { logout, assign });
    expect(assign).not.toHaveBeenCalled();
    expect(isLeaving()).toBe(false);
  });

  it("clears a copied secret before leaving and leaves a notice when it could not", async () => {
    const order: string[] = [];
    const assign = vi.fn(() => order.push("assign"));
    const clearClipboard = vi.fn(() => {
      order.push("clear");
      return Promise.resolve("unverifiable" as const);
    });
    await signOut(new QueryClient(), { logout: () => Promise.resolve({ logout_url: null }), assign, clearClipboard });
    expect(order).toEqual(["clear", "assign"]);
    expect(hasNotClearedNotice()).toBe(true);
    dismissNotClearedNotice();
  });

  it("leaves no notice when the clipboard was cleared", async () => {
    const clearClipboard = () => Promise.resolve("cleared" as const);
    await signOut(new QueryClient(), { logout: () => Promise.resolve({ logout_url: null }), assign: vi.fn(), clearClipboard });
    expect(hasNotClearedNotice()).toBe(false);
  });

  it("does not start a second sign-out while one is under way", async () => {
    const logout = vi.fn(() => new Promise<{ logout_url: null }>(() => undefined));
    void signOut(new QueryClient(), { logout, assign: vi.fn() });
    void signOut(new QueryClient(), { logout, assign: vi.fn() });
    expect(logout).toHaveBeenCalledTimes(1);
  });
});

describe("redirectToLogin", () => {
  afterEach(() => {
    stopLeaving();
    vi.restoreAllMocks();
  });

  it("sends the browser to sign in once, keeping where it was", async () => {
    const assign = vi.spyOn(browserNavigation, "assign").mockImplementation(() => undefined);
    window.history.replaceState(null, "", "/projects/app?x=1");
    await Promise.all([redirectToLogin(), redirectToLogin()]);
    expect(assign).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith("/login?return_to=%2Fprojects%2Fapp%3Fx%3D1");
  });
});
