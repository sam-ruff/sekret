import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/api/endpoints";
import type { Environment, SecretList } from "@/api/types";
import { environmentDeleteText } from "@/lib/environment-delete";
import { renderWithProviders } from "@/test/render";
import { DeleteEnvironmentDialog } from "./delete-environment-dialog";

vi.mock("@/api/endpoints", () => ({ api: { secretsUnder: vi.fn() } }));

const secretsUnder = vi.mocked(api.secretsUnder);
const qa: Environment = { id: "env-qa", name: "QA", slug: "qa", position: 3 };

function list(count: number): SecretList {
  return {
    folders: [],
    secrets: Array.from({ length: count }, (_, i) => ({
      id: `sec-${i}`,
      key: `K${i}`,
      environment: "qa",
      path: "/",
      version: 1,
      value: null,
      value_hidden: true,
      comment: "",
      tags: [],
      updated_at: 1_700_000_000,
      updated_by: "sam",
    })),
  };
}

describe("environmentDeleteText", () => {
  it("blocks an environment that still holds secrets, as the server would", () => {
    expect(environmentDeleteText(12, false)).toEqual({
      blocked: true,
      text: "It still holds 12 secrets, counting its folders. Only an empty environment can be deleted, so delete those secrets first.",
    });
    expect(environmentDeleteText(1, false).text).toContain("It still holds 1 secret,");
  });

  it("says what deleting an empty one loses", () => {
    const empty = environmentDeleteText(0, false);
    expect(empty.blocked).toBe(false);
    expect(empty.text).toContain("The history of every secret that was in it and all of its snapshots are deleted for good.");
    expect(environmentDeleteText(undefined, true)).toMatchObject({ blocked: false });
    expect(environmentDeleteText(undefined, false).text).toBe("Checking what is in it...");
  });
});

describe("DeleteEnvironmentDialog", () => {
  beforeEach(() => {
    secretsUnder.mockReset();
  });

  it("needs the environment ID typed before it deletes an empty environment", async () => {
    secretsUnder.mockResolvedValue(list(0));
    const onDelete = vi.fn(() => Promise.resolve());
    renderWithProviders(<DeleteEnvironmentDialog project="app" env={qa} onClose={() => undefined} onDelete={onDelete} />);
    const field = await screen.findByTestId("delete-env-slug");
    expect(secretsUnder).toHaveBeenCalledWith({ project: "app", env: "qa", path: "/" });
    expect(screen.getByTestId("delete-env-contents")).toHaveTextContent("It holds no secrets you can see.");

    const confirm = screen.getByTestId("confirm-action");
    expect(confirm).toBeDisabled();
    await userEvent.type(field, "QA");
    expect(confirm).toBeDisabled();
    await userEvent.clear(field);
    await userEvent.type(field, "qa");
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    await waitFor(() => expect(onDelete).toHaveBeenCalledWith(qa));
  });

  it("offers no delete while the environment still holds secrets", async () => {
    secretsUnder.mockResolvedValue(list(2));
    renderWithProviders(<DeleteEnvironmentDialog project="app" env={qa} onClose={() => undefined} onDelete={vi.fn()} />);
    await waitFor(() => expect(screen.getByTestId("delete-env-contents")).toHaveTextContent("It still holds 2 secrets"));
    expect(screen.getByText("QA is not empty")).toBeInTheDocument();
    expect(screen.getByTestId("delete-env-contents")).not.toHaveTextContent("move");
    expect(screen.getByTestId("delete-env-open")).toHaveAttribute("href", "/projects/app/secrets/qa");
    expect(screen.queryByTestId("confirm-action")).toBeNull();
    expect(screen.queryByTestId("delete-env-slug")).toBeNull();
  });
});
