import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { ListInput } from "./list-input";

function Harness({ ariaLabel }: { ariaLabel?: string }) {
  const [value, setValue] = useState<string[]>([]);
  return (
    <ListInput
      value={value}
      onChange={setValue}
      ariaLabel={ariaLabel}
      validate={(entry) => (entry.includes(" ") ? "No spaces" : undefined)}
      testId="list"
    />
  );
}

describe("ListInput", () => {
  it("is named by its label even once chips replace the placeholder", async () => {
    render(<Harness ariaLabel="Globs for claim repository_owner" />);
    const input = screen.getByLabelText("Globs for claim repository_owner");
    await userEvent.type(input, "acme{Enter}");
    expect(screen.getByTestId("list-chip")).toHaveTextContent("acme");
    expect(screen.getByLabelText("Globs for claim repository_owner")).toBe(input);
  });

  it("ties a refused entry's message to the input so it is announced", async () => {
    render(<Harness ariaLabel="Tags" />);
    const input = screen.getByLabelText("Tags");
    expect(input).not.toHaveAttribute("aria-invalid");
    await userEvent.type(input, "has space{Enter}");
    const problem = screen.getByTestId("list-problem");
    expect(problem).toHaveTextContent("No spaces");
    expect(problem).toHaveAttribute("role", "alert");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAttribute("aria-describedby", problem.id);

    await userEvent.type(input, "x");
    expect(screen.queryByTestId("list-problem")).toBeNull();
    expect(input).not.toHaveAttribute("aria-describedby");
  });
});
