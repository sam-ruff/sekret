import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatDateTime,
  formatDuration,
  formatDurationWords,
  formatExpiry,
  formatRelative,
  initials,
  slugify,
  UNKNOWN_DATE,
} from "./format";
import { crumbs, folderLabel, isValidFolderName, joinPath, normalisePath, parentPath } from "./paths";

describe("formatDuration", () => {
  it("formats common TTLs compactly", () => {
    expect(formatDuration(3600)).toBe("1h");
    expect(formatDuration(900)).toBe("15m");
    expect(formatDuration(86400 + 6 * 3600)).toBe("1d 6h");
    expect(formatDuration(45)).toBe("45s");
  });
});

describe("formatBytes", () => {
  it("uses bytes below a kilobyte and one decimal above", () => {
    expect(formatBytes(1)).toBe("1 byte");
    expect(formatBytes(186)).toBe("186 bytes");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(3 * 1024 * 1024)).toBe("3.0 MB");
  });
});

describe("formatDurationWords", () => {
  it("spells durations out", () => {
    expect(formatDurationWords(3600)).toBe("1 hour");
    expect(formatDurationWords(900)).toBe("15 minutes");
    expect(formatDurationWords(86400 + 6 * 3600 + 30)).toBe("1 day 6 hours");
    expect(formatDurationWords(1)).toBe("1 second");
    expect(formatDurationWords(0)).toBe("0 seconds");
  });
});

describe("formatExpiry", () => {
  it("puts the relative time first and the clock time after", () => {
    const now = new Date(2026, 9, 31, 3, 18).getTime() / 1000;
    expect(formatExpiry(now + 9 * 60, now)).toBe("in 9 minutes (03:27)");
    expect(formatExpiry(now + 3600, now)).toBe("in 1 hour (04:18)");
    expect(formatExpiry(now + 3598, now)).toBe("in 1 hour (04:17)");
    expect(formatExpiry(now + 20, now)).toBe("in less than a minute (03:18)");
  });

  it("adds the date when it is not today", () => {
    const now = new Date(2026, 9, 31, 23, 30).getTime() / 1000;
    expect(formatExpiry(now + 3600, now)).toBe("in 1 hour (1 Nov 2026, 00:30)");
  });
});

describe("formatRelative", () => {
  it("describes past times in plain words", () => {
    expect(formatRelative(1000, 1010)).toBe("just now");
    expect(formatRelative(0, 7200)).toBe("2 hours ago");
    expect(formatRelative(0, 86400)).toBe("yesterday");
  });
});

describe("dates the browser cannot hold", () => {
  // About three million years ahead, past the largest date `Date` can represent.
  const huge = 1e14;
  const now = 1_800_000_000;

  it("shows a placeholder instead of throwing", () => {
    for (const seconds of [huge, -huge, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(formatDateTime(seconds)).toBe(UNKNOWN_DATE);
      expect(formatRelative(seconds, now)).toBe(UNKNOWN_DATE);
      expect(formatExpiry(seconds, now)).toBe(UNKNOWN_DATE);
    }
  });

  it("still formats the far edge of the valid range", () => {
    expect(formatDateTime(8.64e12)).not.toBe(UNKNOWN_DATE);
    expect(formatRelative(8.64e12, now)).toMatch(/^in /);
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
      { name: "/", path: "/" },
      { name: "a", path: "/a" },
      { name: "b", path: "/a/b" },
    ]);
  });

  it("names the top folder / in copy, like its subfolders", () => {
    expect(folderLabel("/")).toBe("/");
    expect(folderLabel("")).toBe("/");
    expect(folderLabel("/app/db/")).toBe("/app/db");
  });

  it("validates folder names", () => {
    expect(isValidFolderName("payments")).toBe(true);
    expect(isValidFolderName("..")).toBe(false);
    expect(isValidFolderName("a/b")).toBe(false);
    expect(isValidFolderName("has space")).toBe(false);
  });
});
