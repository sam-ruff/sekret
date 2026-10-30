import { describe, expect, it } from "vitest";
import { safeHttpUrl, safeLogoUrl, safeReturnTo } from "./safe-url";

const origin = "https://sekret.example";

describe("safeReturnTo", () => {
  it("keeps same-origin paths with their query and hash", () => {
    expect(safeReturnTo("/projects/app/secrets?path=%2Fx#top", origin)).toBe("/projects/app/secrets?path=%2Fx#top");
  });

  it.each([
    ["https://evil.example/"],
    ["//evil.example/"],
    ["/\\evil.example/"],
    ["/\t/evil.example"],
    ["javascript:alert(1)"],
    ["projects"],
    [""],
  ])("falls back to the root for %j", (value) => {
    expect(safeReturnTo(value, origin)).toBe("/");
  });

  it("falls back for a missing value", () => {
    expect(safeReturnTo(null, origin)).toBe("/");
  });
});

describe("safeHttpUrl", () => {
  it("accepts http and https links", () => {
    expect(safeHttpUrl("https://idp.example/logout?x=1")).toBe("https://idp.example/logout?x=1");
    expect(safeHttpUrl("http://localhost:8080/")).toBe("http://localhost:8080/");
  });

  it.each(["javascript:alert(1)", " JavaScript:alert(1)", "data:text/html,<script>1</script>", "vbscript:x", "/relative", "not a url", ""])(
    "refuses %j",
    (value) => {
      expect(safeHttpUrl(value)).toBeUndefined();
    },
  );
});

describe("safeLogoUrl", () => {
  it("accepts versioned API paths on this origin", () => {
    expect(safeLogoUrl("/api/v1/projects/p1/logo?v=12", origin)).toBe("/api/v1/projects/p1/logo?v=12");
  });

  it.each([
    "https://evil.example/api/v1/projects/p1/logo",
    "//evil.example/api/v1/logo",
    "/api/v1/../../evil",
    "javascript:alert(1)",
    "data:image/svg+xml,<svg onload=alert(1)>",
    "/static/logo.png",
    "/api/v1/projects/p1/logo\\x",
  ])("refuses %j", (value) => {
    expect(safeLogoUrl(value, origin)).toBeUndefined();
  });

  it("refuses nothing at all", () => {
    expect(safeLogoUrl(null, origin)).toBeUndefined();
  });
});
