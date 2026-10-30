import { describe, expect, it } from "vitest";
import { formatDuration, formatRelative, initials, slugify } from "./format";
import { crumbs, isValidFolderName, joinPath, normalisePath, parentPath } from "./paths";

describe("formatDuration", () => {
  it("formats common TTLs compactly", () => {
    expect(formatDuration(3600)).toBe("1h");
    expect(formatDuration(900)).toBe("15m");
    expect(formatDuration(86400 + 6 * 3600)).toBe("1d 6h");
    expect(formatDuration(45)).toBe("45s");
  });
});

describe("formatRelative", () => {
  it("describes past times in plain words", () => {
    expect(formatRelative(1000, 1010)).toBe("just now");
    expect(formatRelative(0, 7200)).toBe("2 hours ago");
    expect(formatRelative(0, 86400)).toBe("yesterday");
  });
});

describe("text helpers", () => {
  it("builds initials and slugs", () => {
    expect(initials("Sam Taylor")).toBe("ST");
    expect(initials("priya@example.com")).toBe("PE");
    expect(slugify("  My Shiny App!  ")).toBe("my-shiny-app");
  });
});

describe("paths", () => {
  it("normalises, joins and walks up", () => {
    expect(normalisePath("")).toBe("/");
    expect(normalisePath("//a//b/")).toBe("/a/b");
    expect(joinPath("/", "app")).toBe("/app");
    expect(joinPath("/app", "db")).toBe("/app/db");
    expect(parentPath("/app/db")).toBe("/app");
    expect(parentPath("/app")).toBe("/");
    expect(parentPath("/")).toBe("/");
  });

  it("builds breadcrumbs from the root", () => {
    expect(crumbs("/a/b")).toEqual([
      { name: "root", path: "/" },
      { name: "a", path: "/a" },
      { name: "b", path: "/a/b" },
    ]);
  });

  it("validates folder names", () => {
    expect(isValidFolderName("payments")).toBe(true);
    expect(isValidFolderName("..")).toBe(false);
    expect(isValidFolderName("a/b")).toBe(false);
    expect(isValidFolderName("has space")).toBe(false);
  });
});
