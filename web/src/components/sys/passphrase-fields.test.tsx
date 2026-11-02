import { fireEvent, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { renderWithProviders } from "@/test/render";
import { PassphraseFields } from "./passphrase-fields";

function Harness({ initial = "" }: { initial?: string }) {
  const [passphrase, setPassphrase] = useState(initial);
  const [confirm, setConfirm] = useState("");
  return (
    <PassphraseFields
      idPrefix="setup"
      label="Passphrase"
      passphrase={passphrase}
      confirm={confirm}
      strength={null}
      onPassphraseChange={setPassphrase}
      onConfirmChange={setConfirm}
    />
  );
}

const typeConfirm = (value: string) => fireEvent.change(screen.getByTestId("setup-confirm"), { target: { value } });

describe("PassphraseFields", () => {
  it("does not call the second copy wrong while it is still being typed", () => {
    renderWithProviders(<Harness initial="plum orbit gravel" />);
    for (const partial of ["p", "plum", "plum orbit grav"]) {
      typeConfirm(partial);
      expect(screen.queryByTestId("setup-mismatch")).not.toBeInTheDocument();
      expect(screen.getByTestId("setup-confirm")).toHaveAttribute("aria-invalid", "false");
    }
    typeConfirm("plum orbit gravel");
    expect(screen.queryByTestId("setup-mismatch")).not.toBeInTheDocument();
  });

  it("says they differ once the second copy is as long, or the person moves on", () => {
    renderWithProviders(<Harness initial="plum orbit gravel" />);
    typeConfirm("plum orbit gravex");
    expect(screen.getByTestId("setup-mismatch")).toHaveTextContent("The passphrases do not match.");

    typeConfirm("plum");
    expect(screen.queryByTestId("setup-mismatch")).not.toBeInTheDocument();
    fireEvent.blur(screen.getByTestId("setup-confirm"));
    expect(screen.getByTestId("setup-mismatch")).toBeInTheDocument();
    expect(screen.getByTestId("setup-confirm")).toHaveAttribute("aria-describedby", "setup-mismatch");
  });
});
