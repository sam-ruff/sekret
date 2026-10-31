import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/api/client";
import { api } from "@/api/endpoints";
import type { Me, SysStatus } from "@/api/types";
import { renderWithProviders } from "@/test/render";
import { ServerPage } from "./server-page";

vi.mock("@/api/endpoints", () => ({
  api: {
    sysStatus: vi.fn(),
    sysStatusDetail: vi.fn(),
    me: vi.fn(),
    seal: vi.fn(),
    setUnlockPolicy: vi.fn(),
    forgetUnlock: vi.fn(),
    changePassphrase: vi.fn(),
    backup: vi.fn(),
  },
}));

const mocked = vi.mocked(api);

const unlocked: SysStatus = {
  state: "unsealed",
  seal_mode: "passphrase",
  unlock_policy: "manual",
  configured: false,
  remembered: false,
  unsealed_by: "passphrase",
  web_setup: true,
  version: "1.2.3",
};

const admin: Me = {
  id: "u1",
  name: "Alice",
  email: "alice@example.com",
  kind: "user",
  groups: [],
  org_roles: ["org-admin"],
  is_org_admin: true,
  // The flag decides, not the rules, so an admin with no listed rules still sees the controls.
  org_rules: [],
};

const backupReader: Me = {
  ...admin,
  org_roles: ["backup-reader"],
  is_org_admin: false,
  org_rules: [{ effect: "allow", subject: "backups", actions: ["read"] }],
};

/** What the server shows anyone once set up. */
const publicView = (status: SysStatus): SysStatus => ({
  ...status,
  seal_mode: null,
  unlock_policy: null,
  configured: false,
  remembered: false,
  unsealed_by: null,
});

/** `status` is the detail an admin may read; the public status carries only the state. */
function renderServer(status: SysStatus = unlocked, me: Me = admin) {
  mocked.sysStatus.mockResolvedValue(publicView(status));
  mocked.sysStatusDetail.mockResolvedValue(status);
  mocked.me.mockResolvedValue(me);
  return renderWithProviders(<ServerPage />);
}

describe("ServerPage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("shows how the server is protected and unlocked, with locking explained", async () => {
    renderServer();
    expect(await screen.findByTestId("server-mode")).toHaveTextContent("Passphrase");
    expect(screen.getByText("Protected by")).toBeInTheDocument();
    expect(screen.getByTestId("server-unsealed-by")).toHaveTextContent("Passphrase, typed by a person");
    expect(screen.getByTestId("server-state")).toHaveTextContent("Unlocked");
    expect(screen.getByText("Lock (seal) the server")).toBeInTheDocument();
    expect(screen.getByTestId("lock-help")).toHaveTextContent(
      "Locking drops the key from memory straight away. Everything that reads secrets gets errors until someone unlocks it with the passphrase.",
    );
    expect(screen.queryByTestId("server-key-file-override")).toBeNull();
    expect(document.title).toBe("Server · sekret");

    await userEvent.click(screen.getByTestId("seal-now"));
    const dialog = await screen.findByTestId("seal-dialog");
    expect(dialog).toHaveTextContent("Lock the server now?");
    // Nothing is remembered here, so the dialog does not claim it unlocks after a restart.
    expect(dialog).not.toHaveTextContent("remembered unlock");
  });

  it("mentions the remembered unlock in the lock dialog only when one is remembered", async () => {
    renderServer({ ...unlocked, unlock_policy: "remember", remembered: true });
    await userEvent.click(await screen.findByTestId("seal-now"));
    expect(await screen.findByTestId("seal-dialog")).toHaveTextContent("A remembered unlock still unlocks it after a restart.");
  });

  it("asks before changing the passphrase, leading with what it means", async () => {
    mocked.changePassphrase.mockResolvedValue(undefined);
    renderServer();
    const card = await screen.findByTestId("server-passphrase");
    expect(screen.getByTestId("change-passphrase-help").firstElementChild).toHaveTextContent(
      "Every secret is re-encrypted. Backups made before this still need the old passphrase.",
    );
    await userEvent.type(screen.getByTestId("current-passphrase"), "correct horse battery staple");
    await userEvent.type(screen.getByTestId("change-passphrase"), "plum orbit gravel lantern");
    await userEvent.type(screen.getByTestId("change-confirm"), "plum orbit gravel lantern");
    await waitFor(() => expect(screen.getByTestId("change-submit")).toBeEnabled());
    await userEvent.click(screen.getByTestId("change-submit"));
    const dialog = await screen.findByTestId("change-passphrase-dialog");
    expect(mocked.changePassphrase).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByTestId("confirm-action"));
    await waitFor(() => expect(mocked.changePassphrase).toHaveBeenCalledTimes(1));
    expect(card).toBeInTheDocument();
  });

  it("warns when a key file unlocked a passphrase server", async () => {
    renderServer({ ...unlocked, unsealed_by: "key-file" });
    expect(await screen.findByTestId("server-key-file-override")).toHaveTextContent("A key file unlocked this server");
  });

  it("uses is_org_admin, offering backup readers only the download", async () => {
    renderServer(unlocked, backupReader);
    expect(await screen.findByTestId("backup-download")).toBeInTheDocument();
    expect(screen.getByText("See whether this sekret server is unlocked and download encrypted backups.")).toBeInTheDocument();
    expect(screen.queryByTestId("seal-now")).toBeNull();
    expect(screen.queryByTestId("server-unlock-policy")).toBeNull();
    expect(screen.queryByTestId("server-passphrase")).toBeNull();
    // Backup readers get only the public status: no admin-only detail is asked for or shown.
    expect(mocked.sysStatusDetail).not.toHaveBeenCalled();
    expect(screen.queryByTestId("server-unsealed-by")).toBeNull();
    expect(screen.queryByTestId("server-mode")).toBeNull();
    expect(screen.getByTestId("server-backup")).toHaveTextContent(
      "Restoring it needs the passphrase or root key file that was in use when it was made.",
    );
    expect(screen.getByTestId("server-status-help")).toHaveTextContent("Whether the server is unlocked.");
  });

  it("shows people with no access a plain header and the refusal", async () => {
    renderServer(unlocked, { ...admin, org_roles: [], is_org_admin: false, org_rules: [] });
    expect(await screen.findByText("Only organisation admins and backup readers can see this page.")).toBeInTheDocument();
    expect(screen.getByTestId("page-title")).toHaveTextContent("Server");
    expect(screen.queryByText(/download encrypted backups/)).toBeNull();
  });

  it("reads how the server was unlocked from the admin detail, not the public status", async () => {
    renderServer({ ...unlocked, unlock_policy: "remember", remembered: true, unsealed_by: "remember" });
    expect(await screen.findByTestId("server-unsealed-by")).toHaveTextContent("Remembered unlock");
    expect(screen.getByTestId("server-remembered")).toHaveTextContent("Remembered: yes");
    expect(mocked.sysStatusDetail).toHaveBeenCalled();
  });

  it("shows an error when the admin detail cannot be read", async () => {
    mocked.sysStatus.mockResolvedValue(publicView(unlocked));
    mocked.sysStatusDetail.mockRejectedValue(new ApiError("You do not have permission to do that.", 403, "forbidden"));
    mocked.me.mockResolvedValue(admin);
    renderWithProviders(<ServerPage />);
    expect(await screen.findByTestId("error-state")).toHaveTextContent("You do not have permission to do that.");
  });

  it("forgets the policy passphrase from the mutation cache once saved", async () => {
    mocked.setUnlockPolicy.mockResolvedValue({ ...unlocked, unlock_policy: "remember", remembered: true });
    const { client } = renderServer();
    await userEvent.click(await screen.findByTestId("server-policy-card-remember"));
    await userEvent.click(screen.getByTestId("policy-save"));
    const dialog = await screen.findByTestId("policy-dialog");
    await userEvent.type(within(dialog).getByTestId("policy-passphrase"), "the right one");
    await userEvent.click(within(dialog).getByTestId("confirm-action"));
    await waitFor(() => expect(screen.queryByTestId("policy-dialog")).toBeNull());
    await waitFor(() => expect(client.getMutationCache().getAll()).toHaveLength(0));
  });

  it("marks every passphrase field as a secret for spellcheckers and writing assistants", async () => {
    renderServer();
    await screen.findByTestId("current-passphrase");
    for (const id of ["current-passphrase", "change-passphrase", "change-confirm"]) {
      const field = screen.getByTestId(id);
      expect(field).toHaveAttribute("spellcheck", "false");
      expect(field).toHaveAttribute("data-gramm", "false");
      expect(field).toHaveAttribute("autocorrect", "off");
      expect(field).toHaveAttribute("autocapitalize", "off");
    }
    expect(screen.getByTestId("current-passphrase")).toHaveAttribute("autocomplete", "current-password");
    expect(screen.getByTestId("change-passphrase")).toHaveAttribute("autocomplete", "new-password");
  });

  it("asks for the current passphrase before switching to remember", async () => {
    renderServer();
    await userEvent.click(await screen.findByTestId("server-policy-card-remember"));
    expect(screen.getByTestId("server-policy-needs")).toHaveTextContent("seal.remember_file");
    await userEvent.click(screen.getByTestId("policy-save"));
    const dialog = await screen.findByTestId("policy-dialog");
    expect(dialog).toHaveTextContent("Confirm with the current passphrase. This lets the server unlock without a person.");

    await userEvent.click(within(dialog).getByTestId("confirm-action"));
    expect(await within(dialog).findByTestId("policy-passphrase-error")).toHaveTextContent("Enter the current passphrase.");
    expect(mocked.setUnlockPolicy).not.toHaveBeenCalled();

    mocked.setUnlockPolicy.mockRejectedValueOnce(new ApiError("the passphrase is wrong", 401, "invalid_passphrase"));
    await userEvent.type(within(dialog).getByTestId("policy-passphrase"), "not it");
    await userEvent.click(within(dialog).getByTestId("confirm-action"));
    expect(await within(dialog).findByTestId("policy-passphrase-error")).toHaveTextContent("That passphrase is wrong.");
    expect(screen.getByTestId("policy-dialog")).toBeInTheDocument();

    mocked.setUnlockPolicy.mockResolvedValueOnce({ ...unlocked, unlock_policy: "remember", remembered: true });
    await userEvent.clear(within(dialog).getByTestId("policy-passphrase"));
    await userEvent.type(within(dialog).getByTestId("policy-passphrase"), "the right one");
    await userEvent.click(within(dialog).getByTestId("confirm-action"));
    await waitFor(() => expect(screen.queryByTestId("policy-dialog")).toBeNull());
    expect(mocked.setUnlockPolicy).toHaveBeenLastCalledWith("remember", "the right one");
  });

  it("switches back to manual without a passphrase", async () => {
    mocked.setUnlockPolicy.mockResolvedValue(unlocked);
    renderServer({ ...unlocked, unlock_policy: "remember", remembered: false });
    await userEvent.click(await screen.findByTestId("server-policy-card-manual"));
    await userEvent.click(screen.getByTestId("policy-save"));
    await waitFor(() => expect(mocked.setUnlockPolicy).toHaveBeenCalledWith("manual", undefined));
    expect(screen.queryByTestId("policy-dialog")).toBeNull();
  });

  it("confirms before forgetting a remembered unlock, and says locking keeps it", async () => {
    mocked.forgetUnlock.mockResolvedValue({ ...unlocked, unlock_policy: "remember", remembered: false });
    renderServer({ ...unlocked, unlock_policy: "remember", remembered: true });
    const box = await screen.findByTestId("server-remembered-box");
    expect(box).toHaveTextContent("Locking the server does not forget this.");
    expect(screen.getAllByTestId("server-remembered")).toHaveLength(1);

    await userEvent.click(screen.getByTestId("forget-unlock"));
    const dialog = await screen.findByTestId("forget-dialog");
    expect(dialog).toHaveTextContent("Forget the remembered unlock?");
    expect(dialog).toHaveTextContent("The key file is deleted. After the next restart someone has to unlock the server with the passphrase.");
    expect(mocked.forgetUnlock).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByTestId("confirm-action"));
    await waitFor(() => expect(mocked.forgetUnlock).toHaveBeenCalledTimes(1));
  });

  it("explains what changing the passphrase does and why the button waits", async () => {
    renderServer();
    expect(await screen.findByTestId("change-passphrase-help")).toHaveTextContent(
      "A remembered unlock is forgotten, so the next restart needs the new passphrase.",
    );
    expect(screen.getByTestId("change-blocker")).toHaveTextContent("Enter the current passphrase to continue.");
  });
});
