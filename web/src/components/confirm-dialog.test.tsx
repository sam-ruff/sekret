import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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
});
