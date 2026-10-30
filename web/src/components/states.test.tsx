import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiError } from "@/api/client";
import { ErrorState } from "./states";

const retry = () => undefined;

describe("ErrorState", () => {
  it("offers a retry for errors that may be temporary", () => {
    render(<ErrorState error={new ApiError("boom", 500, "internal")} onRetry={retry} />);
    expect(screen.getByText("That did not load")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /try again/i })).toBeInTheDocument();
  });

  it("names a missing resource and does not offer a pointless retry", () => {
    render(<ErrorState error={new ApiError("Project not found", 404, "not_found")} onRetry={retry} />);
    expect(screen.getByText("Not found")).toBeInTheDocument();
    expect(screen.getByText("Project not found")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /try again/i })).toBeNull();
  });

  it("explains a refused permission", () => {
    render(<ErrorState error={new ApiError("nope", 403, "forbidden")} onRetry={retry} />);
    expect(screen.getByText("You do not have access")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /try again/i })).toBeNull();
  });
});
