import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PassphraseMeter } from "./passphrase-meter";

describe("PassphraseMeter", () => {
  it("shows the length hint before anything is typed", () => {
    render(<PassphraseMeter strength={null} />);
    expect(screen.getByTestId("passphrase-meter")).toHaveTextContent("At least 12 characters");
  });

  it("shows the score with zxcvbn's warning and suggestions", () => {
    render(
      <PassphraseMeter
        strength={{
          score: 1,
          acceptable: false,
          warning: "This is similar to a commonly used password.",
          suggestions: ["Add more words that are less common."],
        }}
      />,
    );
    const meter = screen.getByTestId("passphrase-meter");
    expect(meter).toHaveAttribute("data-score", "1");
    expect(meter).toHaveAttribute("data-acceptable", "false");
    expect(screen.getByTestId("passphrase-meter-label")).toHaveTextContent("Weak");
    expect(screen.getByTestId("passphrase-meter-feedback")).toHaveTextContent("commonly used password");
    expect(screen.getByRole("listitem")).toHaveTextContent("Add more words that are less common.");
    expect(meter).not.toHaveTextContent("Strong enough");
  });

  it("announces changes politely under the id the input points at", () => {
    render(<PassphraseMeter strength={null} id="setup-meter" />);
    const region = screen.getByTestId("passphrase-meter-region");
    expect(region).toHaveAttribute("aria-live", "polite");
    expect(region).toHaveAttribute("id", "setup-meter");
  });

  it("says when a passphrase is strong enough", () => {
    render(<PassphraseMeter strength={{ score: 4, acceptable: true, warning: null, suggestions: [] }} />);
    // One verdict, not "Strong" beside "Strong enough".
    expect(screen.getByTestId("passphrase-meter-label")).toHaveTextContent(/^Strong enough$/);
    expect(screen.getByTestId("passphrase-meter").textContent?.match(/Strong/g)).toHaveLength(1);
    expect(screen.queryByTestId("passphrase-meter-feedback")).toBeNull();
  });
});
