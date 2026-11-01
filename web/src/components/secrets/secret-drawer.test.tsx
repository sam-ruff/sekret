import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/api/endpoints";
import type { SecretVersion } from "@/api/types";
import { renderWithProviders } from "@/test/render";
import { SecretDrawer } from "./secret-drawer";

vi.mock("@/api/endpoints", () => ({
  api: { versions: vi.fn(), rollback: vi.fn(), secretPolicy: vi.fn(() => new Promise(() => undefined)) },
}));

const versions = vi.mocked(api.versions);

function version(n: number, value: string, values: boolean): SecretVersion {
  return {
    version: n,
    value: values ? value : null,
    value_hidden: !values,
    deleted: false,
    comment: "",
    tags: [],
    actor: "alice",
    created_at: 1_700_000_000 + n,
  };
}

function drawer(secretKey: string | null, onClose = () => undefined) {
  return (
    <SecretDrawer
      project="app"
      env="dev"
      envName="Development"
      path="/"
      secretKey={secretKey}
      canRollback={false}
      canEditPolicy={false}
      onRotate={() => undefined}
      onClose={onClose}
    />
  );
}

describe("SecretDrawer", () => {
  beforeEach(() => {
    versions.mockReset();
    versions.mockImplementation((_at, _key, values) =>
      Promise.resolve([version(1, "info", values), version(2, "warn", values)]),
    );
  });

  it("fetches history without values and shows them only after the toggle", async () => {
    renderWithProviders(drawer("LOG_LEVEL"));
    expect(await screen.findByTestId("version-2")).toBeInTheDocument();
    expect(versions).toHaveBeenCalledWith({ project: "app", env: "dev", path: "/" }, "LOG_LEVEL", false);
    expect(versions).not.toHaveBeenCalledWith(expect.anything(), "LOG_LEVEL", true);
    expect(screen.getByTestId("history-values-hidden")).toHaveTextContent("Showing them is recorded in the audit log.");
    expect(screen.queryByTestId("diff-output")).toBeNull();
    expect(screen.getByTestId("version-value-2")).toHaveTextContent("••••");
    expect(screen.getByTestId("version-value-2")).not.toHaveTextContent("warn");

    await userEvent.click(screen.getByTestId("history-values-toggle"));
    expect(await screen.findByTestId("diff-output")).toHaveTextContent("warn");
    expect(versions).toHaveBeenCalledWith({ project: "app", env: "dev", path: "/" }, "LOG_LEVEL", true);
    expect(screen.getByTestId("version-value-1")).toHaveTextContent("info");
    expect(screen.getByTestId("history-values-toggle")).toHaveAttribute("aria-pressed", "true");

    await userEvent.click(screen.getByTestId("history-values-toggle"));
    expect(screen.queryByTestId("diff-output")).toBeNull();
    expect(screen.getByTestId("version-value-1")).not.toHaveTextContent("info");
  });

  it("hides values again when the secret changes or the drawer closes", async () => {
    const view = renderWithProviders(drawer("LOG_LEVEL"));
    await userEvent.click(await screen.findByTestId("history-values-toggle"));
    expect(await screen.findByTestId("diff-output")).toBeInTheDocument();

    view.rerender(drawer("OTHER"));
    expect(await screen.findByTestId("history-values-hidden")).toBeInTheDocument();
    expect(screen.queryByTestId("diff-output")).toBeNull();

    view.rerender(drawer(null));
    view.rerender(drawer("OTHER"));
    expect(await screen.findByTestId("history-values-hidden")).toBeInTheDocument();
  });

  it("drops hidden values from the cache and asks the server again on the next reveal", async () => {
    const { client } = renderWithProviders(drawer("LOG_LEVEL"));
    const valuesKey = ["project", "app", "versions", "dev", "/", "LOG_LEVEL", "values"];
    await userEvent.click(await screen.findByTestId("history-values-toggle"));
    expect(await screen.findByTestId("diff-output")).toBeInTheDocument();
    expect(client.getQueryData(valuesKey)).toBeDefined();

    await userEvent.click(screen.getByTestId("history-values-toggle"));
    await waitFor(() => expect(client.getQueryCache().find({ queryKey: valuesKey })).toBeUndefined());

    // A refused second reveal shows the error, not the values from before.
    versions.mockImplementation((_at, _key, values) =>
      values ? Promise.reject(new Error("refused")) : Promise.resolve([version(1, "info", false), version(2, "warn", false)]),
    );
    await userEvent.click(screen.getByTestId("history-values-toggle"));
    expect(await screen.findByTestId("error-state")).toBeInTheDocument();
    expect(screen.queryByTestId("diff-output")).toBeNull();
    expect(versions.mock.calls.filter((call) => call[2] === true)).toHaveLength(2);
  });
});
