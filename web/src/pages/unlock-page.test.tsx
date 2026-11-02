import { act, fireEvent, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { SysStatus } from "@/api/types";
import { keys } from "@/hooks/queries";
import { REVEAL_IDLE_MS } from "@/hooks/use-idle";
import { renderWithProviders, testQueryClient } from "@/test/render";
import { UnlockPage } from "./unlock-page";

vi.mock("@/api/endpoints", () => ({ api: { unseal: vi.fn(), sysStatus: vi.fn() } }));

const unseal = vi.mocked(api.unseal);

const sealed: SysStatus = {
  state: "sealed",
  seal_mode: "passphrase",
  unlock_policy: "manual",
  configured: false,
  remembered: false,
  unsealed_by: null,
  web_setup: true,
  version: "1.0.0",
};

function renderUnlock(status: SysStatus = sealed) {
  const client = testQueryClient();
  client.setQueryData(keys.sysStatus, status);
  return renderWithProviders(<UnlockPage />, { client });
}

/** Types and submits, then lets the rejected request settle. */
async function attempt(passphrase: string) {
  fireEvent.change(screen.getByTestId("unlock-passphrase"), { target: { value: passphrase } });
  fireEvent.click(screen.getByTestId("unlock-submit"));
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
}

describe("UnlockPage", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    unseal.mockReset();
  });
  afterEach(() => vi.useRealTimers());

  it("says the server is locked without claiming a restart", () => {
    renderUnlock();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Unlock sekret");
    expect(screen.getByTestId("unlock-description")).toHaveTextContent(
      "The server is locked, so secrets cannot be read until someone with the server passphrase unlocks it.",
    );
    expect(screen.getByTestId("unlock-card")).not.toHaveTextContent(/restart/i);
    expect(document.title).toBe("Unlock · sekret");
    expect(screen.getByTestId("passphrase-account")).toHaveAttribute("autocomplete", "username");
  });

  it("does not claim a session was interrupted, or offer to end one, on a deep link after a restart", () => {
    const client = testQueryClient();
    client.setQueryData(keys.sysStatus, sealed);
    renderWithProviders(<UnlockPage />, { client, path: "/unlock?return_to=%2Fprojects" });
    expect(screen.getByTestId("unlock-description")).not.toHaveTextContent("while you were using it");
    expect(screen.queryByTestId("unlock-sign-out")).not.toBeInTheDocument();
  });

  it("says the server was locked mid-session, once, and offers to sign out", () => {
    const client = testQueryClient();
    client.setQueryData(keys.sysStatus, sealed);
    renderWithProviders(<UnlockPage />, { client, path: "/unlock?return_to=%2Fprojects", state: { interrupted: true } });
    expect(screen.getByTestId("unlock-description")).toHaveTextContent(
      "The server was locked while you were using it, so secrets cannot be read until someone with the server passphrase unlocks it.",
    );
    expect(screen.getByTestId("unlock-sign-out")).toHaveTextContent("Sign out");
  });

  it("shows and hides the passphrase on request", () => {
    renderUnlock();
    const field = screen.getByTestId("unlock-passphrase");
    expect(field).toHaveAttribute("type", "password");
    fireEvent.click(screen.getByRole("button", { name: "Show passphrase" }));
    expect(field).toHaveAttribute("type", "text");
    fireEvent.click(screen.getByRole("button", { name: "Hide passphrase" }));
    expect(field).toHaveAttribute("type", "password");
  });

  it("explains an empty submit instead of disabling the button", () => {
    renderUnlock();
    expect(screen.getByTestId("unlock-submit")).toBeEnabled();
    fireEvent.click(screen.getByTestId("unlock-submit"));
    expect(screen.getByTestId("unlock-empty")).toHaveTextContent("Enter the passphrase to unlock.");
    expect(screen.getByTestId("unlock-passphrase")).toHaveFocus();
    expect(unseal).not.toHaveBeenCalled();
  });

  it("clears a typed passphrase once the page has sat idle", async () => {
    renderUnlock();
    fireEvent.change(screen.getByTestId("unlock-passphrase"), { target: { value: "near miss" } });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(REVEAL_IDLE_MS - 10_000);
    });
    expect(screen.getByTestId("unlock-passphrase")).toHaveValue("near miss");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000);
    });
    expect(screen.getByTestId("unlock-passphrase")).toHaveValue("");
  });

  it("points the input at the wrong-passphrase error", async () => {
    unseal.mockRejectedValue(new ApiError("the passphrase is wrong", 401, "invalid_passphrase"));
    renderUnlock();
    await attempt("nope");
    const wrong = screen.getByTestId("unlock-wrong");
    expect(screen.getByTestId("unlock-passphrase")).toHaveAttribute("aria-describedby", wrong.id);
  });

  it("counts down a passphrase backoff and keeps the button disabled until it ends", async () => {
    unseal.mockRejectedValue(
      new ApiError("too many wrong passphrases; try again in 3 seconds", 429, "passphrase_backoff"),
    );
    renderUnlock();
    await attempt("nope");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });
    const alert = screen.getByTestId("unlock-backoff");
    expect(alert).toHaveTextContent("Too many wrong passphrases");
    expect(alert).toHaveTextContent("Wait a few seconds, then try again.");
    expect(screen.getByTestId("unlock-countdown")).toHaveTextContent("3");
    // The ticking number is hidden from screen readers, so the alert is not read out every second.
    expect(screen.getByTestId("unlock-countdown-text")).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByTestId("unlock-submit")).toBeDisabled();
    expect(screen.getByTestId("unlock-submit")).toHaveAttribute("aria-describedby", "unlock-wait");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(screen.getByTestId("unlock-countdown")).toHaveTextContent("2");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2_100);
    });
    expect(screen.queryByTestId("unlock-countdown")).toBeNull();
    expect(screen.queryByTestId("unlock-backoff")).toBeNull();
    const over = screen.getByTestId("unlock-backoff-over");
    expect(over).toHaveTextContent("You can try again now.");
    expect(over).toHaveAttribute("role", "status");
    expect(over).toHaveAttribute("aria-live", "polite");
    expect(screen.getByTestId("unlock-submit")).toBeEnabled();
  });

  it("asks to wait when another unlock is running", async () => {
    unseal.mockRejectedValue(new ApiError("another passphrase check is running", 429, "kdf_busy"));
    renderUnlock();
    await attempt("plum orbit gravel lantern");
    expect(screen.getByTestId("unlock-busy")).toHaveTextContent("Another unlock is in progress. Try again in a moment.");
    expect(screen.getByTestId("unlock-submit")).toBeEnabled();
  });

  it("explains a key the server does not recognise and how to fix it after a restore", async () => {
    unseal.mockRejectedValue(new ApiError("the passphrase opened a root key this server does not recognise", 409, "root_key_not_recognised"));
    renderUnlock();
    await attempt("plum orbit gravel lantern");
    const alert = screen.getByTestId("unlock-key-not-recognised");
    expect(alert).toHaveTextContent("This passphrase opened a key this server does not recognise");
    expect(alert).toHaveTextContent("sekret admin reset-epoch");
    expect(screen.queryByTestId("unlock-error")).toBeNull();
    expect(screen.queryByTestId("unlock-wrong")).toBeNull();
  });

  it("says a refusal from a proxy in front was not a wrong passphrase", async () => {
    unseal.mockRejectedValue(new ApiError("You do not have permission to do that.", 403, "http-403"));
    renderUnlock();
    await attempt("plum orbit gravel lantern");
    const alert = screen.getByTestId("unlock-blocked");
    expect(alert).toHaveTextContent("the passphrase was not checked");
    expect(alert).toHaveTextContent("sekret sys unseal --socket");
    expect(screen.queryByTestId("unlock-error")).toBeNull();
    expect(screen.queryByTestId("unlock-wrong")).toBeNull();
  });

  it("keeps the general rate limit message for other 429s", async () => {
    unseal.mockRejectedValue(new ApiError("too many requests", 429, "rate_limited"));
    renderUnlock();
    await attempt("plum orbit gravel lantern");
    expect(screen.getByTestId("unlock-limited")).toHaveTextContent("Too many attempts");
  });

  it("keeps no copy of the passphrase once unlocked", async () => {
    unseal.mockResolvedValue({ ...sealed, state: "unsealed" });
    const { client } = renderUnlock();
    await attempt("plum orbit gravel lantern");
    expect(unseal).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("unlock-passphrase")).toHaveValue("");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });
    expect(client.getMutationCache().getAll()).toHaveLength(0);
  });

  it("marks the passphrase field as a secret but keeps the password manager hint", () => {
    renderUnlock();
    const field = screen.getByTestId("unlock-passphrase");
    expect(field).toHaveAttribute("spellcheck", "false");
    expect(field).toHaveAttribute("data-gramm", "false");
    expect(field).toHaveAttribute("autocomplete", "current-password");
  });
});
