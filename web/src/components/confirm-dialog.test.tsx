import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { PassphraseAccountField } from "@/components/sys/passphrase-fields";
import { Input } from "@/components/ui/input";
import { renderWithProviders } from "@/test/render";
import { ConfirmDialog } from "./confirm-dialog";

describe("ConfirmDialog", () => {
  it("confirms when Enter is pressed in a field, even beside a hidden username", async () => {
    const onConfirm = vi.fn(() => Promise.resolve());
    const onOpenChange = vi.fn();
    renderWithProviders(
      <ConfirmDialog open onOpenChange={onOpenChange} title="Switch?" confirmLabel="Save" onConfirm={onConfirm}>
        <PassphraseAccountField />
        <Input data-testid="field" />
      </ConfirmDialog>,
    );
    await userEvent.type(screen.getByTestId("field"), "secret{Enter}");
    await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
  });

  it("ignores Enter while the confirm button is disabled", async () => {
    const onConfirm = vi.fn(() => Promise.resolve());
    renderWithProviders(
      <ConfirmDialog open onOpenChange={vi.fn()} title="Delete?" confirmLabel="Delete" confirmDisabled onConfirm={onConfirm}>
        <Input data-testid="field" />
      </ConfirmDialog>,
    );
    await userEvent.type(screen.getByTestId("field"), "wrong{Enter}");
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("cancels without confirming", async () => {
    const onConfirm = vi.fn(() => Promise.resolve());
    const onOpenChange = vi.fn();
    renderWithProviders(
      <ConfirmDialog open onOpenChange={onOpenChange} title="Delete?" confirmLabel="Delete" onConfirm={onConfirm} />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onConfirm).not.toHaveBeenCalled();
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("gives focus back to the control that opened it when it closes", async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Roll back
          </button>
          <ConfirmDialog open={open} onOpenChange={setOpen} title="Roll back?" confirmLabel="Roll back" onConfirm={() => Promise.resolve()} />
        </>
      );
    }
    renderWithProviders(<Harness />);
    const opener = screen.getByRole("button", { name: "Roll back" });
    await userEvent.click(opener);
    await screen.findByRole("alertdialog");
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(opener).toHaveFocus();
  });

  it("keeps Escape from also closing a sheet underneath", async () => {
    const below = vi.fn();
    document.addEventListener("keydown", below, { capture: true });
    const onOpenChange = vi.fn();
    renderWithProviders(<ConfirmDialog open onOpenChange={onOpenChange} title="Roll back?" confirmLabel="Roll back" onConfirm={() => Promise.resolve()} />);
    await screen.findByRole("alertdialog");
    await userEvent.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(below).not.toHaveBeenCalled();
    document.removeEventListener("keydown", below, { capture: true });
  });

  it("leaves focus to the caller when it says where focus goes", async () => {
    const onCloseAutoFocus = vi.fn((event: Event) => event.preventDefault());
    function Harness() {
      const [open, setOpen] = useState(true);
      return (
        <ConfirmDialog
          open={open}
          onOpenChange={setOpen}
          title="Delete?"
          confirmLabel="Delete"
          onConfirm={() => Promise.resolve()}
          onCloseAutoFocus={onCloseAutoFocus}
        />
      );
    }
    renderWithProviders(<Harness />);
    await userEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(onCloseAutoFocus).toHaveBeenCalledTimes(1));
  });
});
