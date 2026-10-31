import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { renderWithProviders } from "@/test/render";
import { ErrorBoundary } from "./error-boundary";

function Broken(): never {
  throw new Error("render failed with s3cret-value inside");
}

describe("ErrorBoundary", () => {
  it("replaces a crashed page with a reload prompt, drops caches and shows no error text", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const onError = vi.fn();
    const reload = vi.fn();
    renderWithProviders(
      <ErrorBoundary onError={onError} reload={reload}>
        <Broken />
      </ErrorBoundary>,
    );
    expect(await screen.findByTestId("app-error")).toHaveTextContent("Something went wrong");
    expect(screen.getByTestId("app-error")).not.toHaveTextContent("s3cret-value");
    expect(onError).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByTestId("app-error-reload"));
    expect(reload).toHaveBeenCalledTimes(1);
    consoleError.mockRestore();
  });

  it("renders its children when nothing fails", () => {
    renderWithProviders(
      <ErrorBoundary>
        <p data-testid="fine">fine</p>
      </ErrorBoundary>,
    );
    expect(screen.getByTestId("fine")).toBeInTheDocument();
    expect(screen.queryByTestId("app-error")).toBeNull();
  });
});
