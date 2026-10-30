import { describe, expect, it } from "vitest";
import { listQuery, listSearchParams, pageCount, pageSummary, parseListParams, toggleSort, type SortSpec } from "./list-params";

type Sort = "name" | "email" | "created" | "last_login";
const spec: SortSpec<Sort> = { sorts: ["name", "email", "created", "last_login"], fallback: "name", descending: ["created", "last_login"] };

describe("list params", () => {
  it("defaults to the first page by name", () => {
    expect(parseListParams(new URLSearchParams(), spec)).toEqual({ q: "", status: "", sort: "name", order: "asc", page: 1 });
  });

  it("gives date sorts their natural newest-first order", () => {
    expect(parseListParams(new URLSearchParams("sort=created"), spec).order).toBe("desc");
    expect(listSearchParams({ q: "", status: "", sort: "created", order: "desc", page: 1 }, spec).toString()).toBe("sort=created");
  });

  it("round-trips non-default values and rejects junk", () => {
    const list = { q: "ops", status: "disabled" as const, sort: "email" as const, order: "desc" as const, page: 3 };
    expect(parseListParams(listSearchParams(list, spec), spec)).toEqual(list);
    const junk = parseListParams(new URLSearchParams("sort=password&status=deleted&page=-2&order=up"), spec);
    expect(junk).toEqual({ q: "", status: "", sort: "name", order: "asc", page: 1 });
  });

  it("turns a page number into an offset", () => {
    expect(listQuery({ q: "", status: "", sort: "name", order: "asc", page: 3 }, 25)).toEqual({
      sort: "name",
      order: "asc",
      offset: 50,
      limit: 25,
    });
  });

  it("flips the active column and starts others in their natural order", () => {
    const list = { q: "x", status: "" as const, sort: "name" as const, order: "asc" as const, page: 4 };
    expect(toggleSort(list, spec, "name")).toMatchObject({ order: "desc", page: 1 });
    expect(toggleSort(list, spec, "last_login")).toMatchObject({ sort: "last_login", order: "desc", page: 1 });
  });

  it("summarises the page", () => {
    expect(pageSummary(1, 25, 42)).toBe("Showing 1-25 of 42");
    expect(pageSummary(2, 17, 42)).toBe("Showing 26-42 of 42");
    expect(pageSummary(1, 0, 0)).toBe("No results");
    expect(pageSummary(3, 0, 42)).toBe("Nothing on this page of 42");
    expect(pageCount(0)).toBe(1);
    expect(pageCount(51, 25)).toBe(3);
  });
});
